//! A small HTTPS client for the Vantax API.
//!
//! HTTP/1.1 over TLS 1.2/1.3 (rustls with the ring provider and the Mozilla
//! root store from `webpki-roots`; no OpenSSL). Extra trusted roots, for a
//! TLS-inspecting corporate proxy, come from `VANTAX_CA_BUNDLE` or
//! `SSL_CERT_FILE` (PEM). `HTTPS_PROXY`/`HTTP_PROXY` and `NO_PROXY` are
//! honoured. Plain `http://` is only allowed to loopback addresses, so an API
//! key never crosses a network unencrypted.

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

/// Scheme, host, port and base path of a URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    scheme: Scheme,
    host: String,
    port: u16,
    base_path: String,
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

impl Endpoint {
    /// Parse `https://host[:port][/base]` (or `http://` for loopback).
    pub fn parse(url: &str) -> Result<Self, String> {
        let url = url.trim();
        let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
            (Scheme::Https, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (Scheme::Http, r)
        } else {
            return Err(format!("{url:?} must start with https://"));
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.is_empty() || authority.contains('@') {
            return Err(format!("{url:?} has no valid host"));
        }
        let default_port = if scheme == Scheme::Https { 443 } else { 80 };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let end = v6
                .find(']')
                .ok_or_else(|| format!("{url:?}: unclosed IPv6 bracket"))?;
            let host = &v6[..end];
            let port = match &v6[end + 1..] {
                "" => default_port,
                p => p
                    .strip_prefix(':')
                    .and_then(|p| p.parse().ok())
                    .ok_or_else(|| format!("{url:?}: bad port"))?,
            };
            (host.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (
                    h.to_string(),
                    p.parse().map_err(|_| format!("{url:?}: bad port"))?,
                ),
                None => (authority.to_string(), default_port),
            }
        };
        if host.is_empty() {
            return Err(format!("{url:?} has no host"));
        }
        if scheme == Scheme::Http && !is_loopback(&host) {
            return Err(format!(
                "{url:?}: plain http:// is only allowed to localhost; use https:// so the API key is encrypted"
            ));
        }
        Ok(Self {
            scheme,
            host,
            port,
            base_path: path.trim_end_matches('/').to_string(),
        })
    }

    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.scheme == Scheme::Https {
            443
        } else {
            80
        };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// The URL, for messages.
    pub fn display(&self) -> String {
        let scheme = if self.scheme == Scheme::Https {
            "https"
        } else {
            "http"
        };
        format!("{scheme}://{}{}", self.authority(), self.base_path)
    }
}

/// An HTTP proxy from the environment.
#[derive(Clone, Debug)]
struct Proxy {
    host: String,
    port: u16,
    authorization: Option<String>,
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn env_any(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|n| std::env::var(n).ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn no_proxy(host: &str) -> bool {
    if is_loopback(host) {
        return true;
    }
    let Some(list) = env_any(&["NO_PROXY", "no_proxy"]) else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    list.split(',')
        .map(|e| e.trim().to_ascii_lowercase())
        .any(|e| {
            let e = e.trim_start_matches("*.").trim_start_matches('.');
            e == "*" || (!e.is_empty() && (host == e || host.ends_with(&format!(".{e}"))))
        })
}

fn proxy_for(endpoint: &Endpoint) -> Result<Option<Proxy>, String> {
    if no_proxy(&endpoint.host) {
        return Ok(None);
    }
    let var = match endpoint.scheme {
        Scheme::Https => env_any(&["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]),
        Scheme::Http => env_any(&["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]),
    };
    let Some(url) = var else { return Ok(None) };
    let rest = url
        .strip_prefix("http://")
        .or_else(|| (!url.contains("://")).then_some(url.as_str()))
        .ok_or_else(|| format!("proxy {url:?}: only http:// proxies are supported"))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (
            h.trim_matches(['[', ']']).to_string(),
            p.parse().map_err(|_| format!("proxy {url:?}: bad port"))?,
        ),
        None => (hostport.to_string(), 80),
    };
    let authorization = userinfo.map(|u| {
        let (user, pass) = u.split_once(':').unwrap_or((u, ""));
        format!(
            "Basic {}",
            base64(format!("{}:{}", percent_decode(user), percent_decode(pass)).as_bytes())
        )
    });
    Ok(Some(Proxy {
        host,
        port,
        authorization,
    }))
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    if let Some(bundle) = env_any(&["VANTAX_CA_BUNDLE", "SSL_CERT_FILE"]) {
        let mut added = 0;
        for cert in CertificateDer::pem_file_iter(&bundle)
            .map_err(|e| format!("CA bundle {bundle}: {e}"))?
        {
            let cert = cert.map_err(|e| format!("CA bundle {bundle}: {e}"))?;
            if roots.add(cert).is_ok() {
                added += 1;
            }
        }
        if added == 0 {
            return Err(format!("CA bundle {bundle}: no usable certificates"));
        }
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

/// An HTTP response.
#[derive(Debug)]
pub struct Response {
    /// Status code.
    pub status: u16,
    headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl Response {
    /// A header value (case-insensitive name).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The body as JSON.
    pub fn json(&self) -> Result<serde_json::Value, String> {
        serde_json::from_slice(&self.body).map_err(|_| {
            format!(
                "the server answered {} with a body that is not JSON",
                self.status
            )
        })
    }
}

/// A client for one base URL.
pub struct Client {
    endpoint: Endpoint,
    proxy: Option<Proxy>,
    tls: Option<Arc<rustls::ClientConfig>>,
}

trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}

fn connect(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, format!("{host} did not resolve"));
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => {
                s.set_read_timeout(Some(IO_TIMEOUT))?;
                s.set_write_timeout(Some(IO_TIMEOUT))?;
                s.set_nodelay(true)?;
                return Ok(s);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Read a response head (through the blank line) from a proxy.
fn read_head(stream: &mut TcpStream) -> io::Result<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 || head.len() > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy closed the connection",
            ));
        }
        head.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

fn decode_chunked(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("malformed chunked response")?;
        let size_text = std::str::from_utf8(&body[..line_end]).map_err(|_| "malformed chunk")?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "malformed chunk size")?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size + 2 {
            return Err("truncated chunked response".into());
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

/// Whether `raw` holds a whole response: headers plus a body of the declared
/// length, or a finished chunked body. A response with neither ends at EOF.
fn is_complete(raw: &[u8]) -> bool {
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    let body = &raw[split + 4..];
    let header = |name: &str| {
        head.split("\r\n")
            .skip(1)
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.trim() == name)
            .map(|(_, v)| v.trim().to_string())
    };
    if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        return decode_chunked(body).is_ok();
    }
    match header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        Some(len) => body.len() >= len,
        None => false,
    }
}

fn parse_response(raw: &[u8]) -> Result<Response, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("the server closed the connection before answering")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("unexpected response: {status_line:?}"))?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let mut body = raw[split + 4..].to_vec();
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    if header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        body = decode_chunked(&body)?;
    } else if let Some(len) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        if body.len() < len {
            return Err("the response was cut off".into());
        }
        body.truncate(len);
    }
    Ok(Response {
        status,
        headers,
        body,
    })
}

impl Client {
    /// A client for `base_url`.
    pub fn new(base_url: &str) -> Result<Self, String> {
        let endpoint = Endpoint::parse(base_url)?;
        let proxy = proxy_for(&endpoint)?;
        let tls = match endpoint.scheme {
            Scheme::Https => Some(tls_config()?),
            Scheme::Http => None,
        };
        Ok(Self {
            endpoint,
            proxy,
            tls,
        })
    }

    fn open(&self) -> Result<Box<dyn Stream>, String> {
        let ep = &self.endpoint;
        let unreachable = |e: io::Error| format!("cannot reach {}: {e}", ep.display());
        let tcp = match &self.proxy {
            None => connect(&ep.host, ep.port).map_err(unreachable)?,
            Some(p) => {
                let mut s = connect(&p.host, p.port)
                    .map_err(|e| format!("cannot reach proxy {}:{}: {e}", p.host, p.port))?;
                if ep.scheme == Scheme::Https {
                    let target = format!("{}:{}", ep.host_for_connect(), ep.port);
                    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
                    if let Some(auth) = &p.authorization {
                        req.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
                    }
                    req.push_str("\r\n");
                    s.write_all(req.as_bytes()).map_err(unreachable)?;
                    let head = read_head(&mut s).map_err(unreachable)?;
                    let ok = head
                        .split_whitespace()
                        .nth(1)
                        .is_some_and(|code| code == "200");
                    if !ok {
                        return Err(format!(
                            "proxy refused the tunnel: {}",
                            head.lines().next().unwrap_or("")
                        ));
                    }
                }
                s
            }
        };
        match &self.tls {
            None => Ok(Box::new(tcp)),
            Some(config) => {
                let name = ServerName::try_from(ep.host.clone())
                    .map_err(|_| format!("{} is not a valid TLS server name", ep.host))?;
                let conn = rustls::ClientConnection::new(config.clone(), name)
                    .map_err(|e| e.to_string())?;
                Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
            }
        }
    }

    /// Send a request and read the whole response.
    pub fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<Response, String> {
        let ep = &self.endpoint;
        let full_path = format!("{}{}", ep.base_path, path);
        // Through a plain-HTTP proxy, requests use the absolute form.
        let target = if self.proxy.is_some() && ep.scheme == Scheme::Http {
            format!("{}{}", ep.display(), path)
        } else {
            full_path
        };
        let mut head = format!(
            "{method} {target} HTTP/1.1\r\nHost: {}\r\nUser-Agent: vantax/{}\r\nAccept: application/json\r\nConnection: close\r\n",
            ep.authority(),
            env!("CARGO_PKG_VERSION")
        );
        if let (Some(p), Scheme::Http) = (&self.proxy, ep.scheme) {
            if let Some(auth) = &p.authorization {
                head.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
            }
        }
        for (k, v) in headers {
            if v.contains(['\r', '\n']) {
                return Err(format!("header {k} contains a line break"));
            }
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        if let Some(b) = body {
            head.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                b.len()
            ));
        }
        head.push_str("\r\n");

        let mut stream = self.open()?;
        let io_err = |e: io::Error| format!("talking to {}: {e}", ep.display());
        stream.write_all(head.as_bytes()).map_err(io_err)?;
        if let Some(b) = body {
            stream.write_all(b).map_err(io_err)?;
        }
        stream.flush().map_err(io_err)?;

        // Stop as soon as the response is complete: some servers and proxies
        // reset the connection after answering instead of closing it.
        let mut raw = Vec::new();
        let mut buf = [0u8; 16 * 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&buf[..n]);
                    if raw.len() > MAX_RESPONSE_BYTES {
                        return Err("the response is too large".into());
                    }
                    if is_complete(&raw) {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                // A close without TLS close_notify, or a reset, after a full
                // response is not an error; parse_response catches truncation.
                Err(e)
                    if !raw.is_empty()
                        && matches!(
                            e.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                        ) =>
                {
                    break
                }
                Err(e) => return Err(io_err(e)),
            }
        }
        parse_response(&raw)
    }
}

impl Endpoint {
    fn host_for_connect(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        let e = Endpoint::parse("https://api.vantax-cybersecurity.com").unwrap();
        assert_eq!(
            (e.host.as_str(), e.port, e.base_path.as_str()),
            ("api.vantax-cybersecurity.com", 443, "")
        );
        let e = Endpoint::parse("https://example.com:8443/vantax/").unwrap();
        assert_eq!((e.port, e.base_path.as_str()), (8443, "/vantax"));
        assert_eq!(e.display(), "https://example.com:8443/vantax");
        let e = Endpoint::parse("http://127.0.0.1:8080").unwrap();
        assert_eq!(e.authority(), "127.0.0.1:8080");
        let e = Endpoint::parse("http://[::1]:9000").unwrap();
        assert_eq!((e.host.as_str(), e.port), ("::1", 9000));
        assert!(
            Endpoint::parse("http://api.example.com").is_err(),
            "no plain http off-box"
        );
        assert!(Endpoint::parse("ftp://x").is_err());
        assert!(Endpoint::parse("https://user:pw@example.com").is_err());
        assert!(Endpoint::parse("https://example.com:notaport").is_err());
    }

    #[test]
    fn responses() {
        let r = parse_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Quota-Remaining: 9\r\n\r\n{}junk",
        )
        .unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, b"{}".as_slice()));
        assert_eq!(r.header("x-quota-remaining"), Some("9"));
        let r = parse_response(
            b"HTTP/1.1 402 Payment Required\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(r.status, 402);
        assert_eq!(r.json().unwrap()["a"], 1);
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n{}").is_err());
        assert!(parse_response(b"garbage").is_err());

        assert!(is_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
        ));
        assert!(!is_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}"
        ));
        assert!(!is_complete(b"HTTP/1.1 200 OK\r\nContent-Len"));
        assert!(is_complete(
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
        ));
        assert!(!is_complete(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n"
        ));
        assert!(!is_complete(
            b"HTTP/1.1 200 OK\r\n\r\nno length: read to the end"
        ));
    }

    #[test]
    fn helpers() {
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(percent_decode("p%40ss%3Aword"), "p@ss:word");
        assert_eq!(percent_decode("100%"), "100%");
        assert!(is_loopback("localhost") && is_loopback("127.0.0.1") && is_loopback("::1"));
        assert!(!is_loopback("10.0.0.1"));
    }
}
