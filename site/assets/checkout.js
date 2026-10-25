/* Vantax checkout: buy a VantaxBot licence (or any product the store offers)
   with a card in your own currency, SOL, USDC, USDT, $VANTAX, or any Solana
   token Jupiter can route. Talks to the VantaxBot store (meta vantax-store).

   Mount:  VantaxCheckout.mount(document.getElementById("checkout"), { pkg: "lifetime" })
   Resume: the page URL carries ?order=…&token=… after Stripe or a reload.     */
(function () {
  "use strict";
  var doc = document;
  var STORE = ((doc.querySelector('meta[name="vantax-store"]') || {}).content || "").replace(/\/$/, "");
  var KEEP = "vantax-order";
  var USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
  var SOL_MINT = "So11111111111111111111111111111111111111112";
  var POPULAR = [
    ["JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN", "JUP"],
    ["DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263", "BONK"],
    ["EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm", "WIF"],
    ["4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R", "RAY"],
    ["HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3", "PYTH"],
    ["Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", "USDT"],
    ["J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn", "JitoSOL"],
    ["mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So", "mSOL"]
  ];

  function el(tag, cls, text) { var e = doc.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function money() { return (window.Vantax && window.Vantax.money) || null; }
  function fmtSol(n) { return Number(n).toLocaleString(undefined, { maximumFractionDigits: 4 }) + " SOL"; }
  function inLocal(sol) {
    var m = money(); if (!m || !m.rates) return "";
    var v = m.convert(sol, "SOL"); if (v == null || m.currency === "SOL") return "";
    return "≈ " + m.format(v, m.currency, { round: v >= 20 });
  }
  function keep(o) { try { if (o) localStorage.setItem(KEEP, JSON.stringify(o)); else localStorage.removeItem(KEEP); } catch (e) {} }
  function kept() { try { return JSON.parse(localStorage.getItem(KEEP) || "null"); } catch (e) { return null; } }
  function b64(bytes) { var s = ""; for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); }
  function unb64(s) { var bin = atob(s), out = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }
  var B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  function b58(bytes) {
    var digits = [0];
    for (var i = 0; i < bytes.length; i++) { var c = bytes[i]; for (var j = 0; j < digits.length; j++) { c += digits[j] << 8; digits[j] = c % 58; c = (c / 58) | 0; } while (c) { digits.push(c % 58); c = (c / 58) | 0; } }
    var s = ""; for (var k = 0; k < bytes.length && bytes[k] === 0; k++) s += "1";
    for (var q = digits.length - 1; q >= 0; q--) s += B58[digits[q]];
    return s;
  }
  function isAddress(a) { return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test((a || "").trim()); }

  function call(method, path, body) {
    return fetch(STORE + path, {
      method: method, headers: body ? { "Content-Type": "application/json", Accept: "application/json" } : { Accept: "application/json" },
      body: body ? JSON.stringify(body) : undefined
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) { if (!r.ok) { var e = new Error(d.error || ("HTTP " + r.status)); e.status = r.status; e.data = d; throw e; } return d; });
    });
  }

  /* ── Wallets: Wallet Standard first, injected providers as a fallback ── */
  var standard = [];
  function register(w) { if (w && w.features && w.features["standard:connect"] && standard.indexOf(w) < 0 && (w.chains || []).some(function (c) { return /^solana:/.test(c); })) standard.push(w); }
  try {
    window.addEventListener("wallet-standard:register-wallet", function (e) { try { e.detail({ register: register }); } catch (x) {} });
    window.dispatchEvent(new CustomEvent("wallet-standard:app-ready", { detail: { register: register } }));
  } catch (e) {}
  function wallets() {
    var out = standard.map(function (w) { return { name: w.name, icon: w.icon, std: w }; });
    var names = out.map(function (w) { return w.name.toLowerCase(); }), win = window;
    function add(name, p) { if (p && names.indexOf(name.toLowerCase()) < 0) { out.push({ name: name, inj: p }); names.push(name.toLowerCase()); } }
    if (win.phantom && win.phantom.solana && win.phantom.solana.isPhantom) add("Phantom", win.phantom.solana);
    if (win.solflare && win.solflare.isSolflare) add("Solflare", win.solflare);
    if (win.backpack && win.backpack.signMessage) add("Backpack", win.backpack);
    if (!out.length && win.solana && win.solana.signMessage) add("Your wallet", win.solana);
    return out;
  }
  function Session(w) { this.w = w; this.address = ""; this.account = null; }
  Session.prototype.connect = function () {
    var self = this, w = this.w;
    if (w.std) return w.std.features["standard:connect"].connect().then(function (r) {
      var acc = (r && r.accounts && r.accounts[0]) || (w.std.accounts || [])[0];
      if (!acc) throw new Error("no account"); self.account = acc; self.address = acc.address; return self.address;
    });
    return Promise.resolve(w.inj.connect()).then(function (r) {
      var pk = (r && r.publicKey) || w.inj.publicKey; self.address = pk && pk.toBase58 ? pk.toBase58() : String(pk || ""); if (!self.address) throw new Error("no address"); return self.address;
    });
  };
  Session.prototype.signMessage = function (text) {
    var bytes = new TextEncoder().encode(text), w = this.w;
    if (w.std && w.std.features["solana:signMessage"]) return w.std.features["solana:signMessage"].signMessage({ account: this.account, message: bytes }).then(function (r) { return new Uint8Array(r[0].signature); });
    if (w.inj) return Promise.resolve(w.inj.signMessage(bytes, "utf8")).then(function (r) { return new Uint8Array(r && r.signature ? r.signature : r); });
    return Promise.reject(new Error("This wallet can't sign messages."));
  };
  Session.prototype.signAndSend = function (txBytes) {
    var w = this.w;
    if (w.std && w.std.features["solana:signAndSendTransaction"]) return w.std.features["solana:signAndSendTransaction"].signAndSendTransaction({ account: this.account, chain: "solana:mainnet", transaction: txBytes }).then(function (r) { return b58(new Uint8Array(r[0].signature)); });
    return Promise.reject(new Error("Use the QR code or open the payment in your wallet app."));
  };
  Session.prototype.signOnly = function (txBytes) {
    var w = this.w;
    if (w.std && w.std.features["solana:signTransaction"]) return w.std.features["solana:signTransaction"].signTransaction({ account: this.account, chain: "solana:mainnet", transaction: txBytes }).then(function (r) { return new Uint8Array(r[0].signedTransaction); });
    return Promise.reject(new Error("This wallet can't sign a swap here. Try Phantom, Solflare or Backpack."));
  };
  function rejected(e) { return !!e && (e.code === 4001 || /reject|denied|cancel|declined/i.test(String(e.message || e))); }

  /* ── The checkout ──────────────────────────────────────────────────── */
  function mount(root, opts) {
    opts = opts || {};
    var st = { offer: null, pkg: opts.pkg || "lifetime", method: "sol", inputMint: "", wallet: "", session: null, holder: null, order: null, token: "", timer: null };
    root.classList.add("checkout");
    root.innerHTML = '<p class="small mute"><span class="spinner" aria-hidden="true"></span> Loading packages…</p>';

    function error(box, text) { var n = box.querySelector(".co-error"); if (!n) { n = el("p", "notice bad co-error"); n.setAttribute("role", "alert"); box.appendChild(n); } n.textContent = text; n.hidden = !text; }
    function pkgById(id) { return (st.offer.packages || []).filter(function (p) { return p.id === id; })[0]; }
    function price(p) { return st.holder && p.holder_price_sol != null ? p.holder_price_sol : p.price_sol; }

    /* Step 1: package, wallet, method */
    function drawForm() {
      var o = st.offer, f = el("form", "form co-form"); f.noValidate = true;
      // Packages
      var fs = el("fieldset", "co-fs"); fs.appendChild(el("legend", "lbl", "Package"));
      var list = el("div", "choices");
      (o.packages || []).filter(function (p) { return p.price_sol > 0; }).forEach(function (p) {
        var lab = el("label", "choice"), r = el("input"); r.type = "radio"; r.name = "pkg"; r.value = p.id; r.checked = p.id === st.pkg;
        r.addEventListener("change", function () { st.pkg = p.id; refreshPrices(); });
        var mid = el("div"); mid.appendChild(el("b", null, p.name || (p.id.charAt(0).toUpperCase() + p.id.slice(1)))); mid.appendChild(el("span", null, p.summary || ""));
        var em = el("em"); em.setAttribute("data-pkg-price", p.id);
        lab.appendChild(r); lab.appendChild(mid); lab.appendChild(em); list.appendChild(lab);
      });
      fs.appendChild(list); f.appendChild(fs);

      // Wallet
      var wf = el("div", "fld");
      var wl = el("label", null, "Trading wallet"); wl.htmlFor = "co-wallet";
      var wi = el("input", "mono"); wi.id = "co-wallet"; wi.placeholder = "The Solana address the bot will trade from"; wi.autocomplete = "off"; wi.spellcheck = false; wi.value = st.wallet;
      wi.addEventListener("input", function () { st.wallet = wi.value.trim(); wi.removeAttribute("aria-invalid"); if (st.holder && st.holder.wallet !== st.wallet) { st.holder = null; refreshPrices(); drawHolder(); } });
      var wh = el("p", "hint", "Your licence is tied to this address. Live trading only runs from it. Paper mode works with any wallet.");
      wf.appendChild(wl); wf.appendChild(wi); wf.appendChild(wh);
      var connectRow = el("div", "cluster co-connect"); wf.appendChild(connectRow); f.appendChild(wf);
      drawConnect(connectRow, wi);

      // Holder price
      var hb = el("div", "co-holder"); f.appendChild(hb);
      function drawHolder() {
        hb.textContent = "";
        var h = o.holder || {}; if (!h.enabled) return;
        if (st.holder) { hb.appendChild(el("p", "notice ok", "Holder price applied: this wallet holds at least " + Number(h.min_tokens).toLocaleString("en-GB") + " $VANTAX.")); return; }
        var p = el("p", "small mute"); p.appendChild(doc.createTextNode("Hold " + Number(h.min_tokens).toLocaleString("en-GB") + " $VANTAX in this wallet? Holders pay " + (h.discount_pct || 30) + "% less. "));
        var b = el("button", "btn sm", "Prove it by signing a message"); b.type = "button";
        b.addEventListener("click", function () { holderSign(b); });
        p.appendChild(b); hb.appendChild(p);
      }
      st.drawHolder = drawHolder; drawHolder();

      // Payment method
      var ms = el("fieldset", "co-fs"); ms.appendChild(el("legend", "lbl", "Pay with"));
      var ml = el("div", "choices co-methods");
      (o.pay && o.pay.methods || []).forEach(function (m) {
        var lab = el("label", "choice"), r = el("input"); r.type = "radio"; r.name = "method"; r.value = m.id; r.checked = m.id === st.method;
        r.addEventListener("change", function () { st.method = m.id; tokenBox.hidden = m.id !== "token"; refreshPrices(); });
        var mid = el("div"); mid.appendChild(el("b", null, m.label)); mid.appendChild(el("span", null, m.note || ""));
        var em = el("em"); em.setAttribute("data-method-price", m.id);
        lab.appendChild(r); lab.appendChild(mid); lab.appendChild(em); ml.appendChild(lab);
      });
      ms.appendChild(ml);
      var tokenBox = el("div", "fld co-token"); tokenBox.hidden = st.method !== "token";
      var tl = el("label", null, "Which token?"); tl.htmlFor = "co-mint";
      var ts = el("select"); ts.id = "co-mint";
      POPULAR.forEach(function (t) { var op = el("option", null, t[1]); op.value = t[0]; ts.appendChild(op); });
      var other = el("option", null, "Another token (paste its address)"); other.value = "other"; ts.appendChild(other);
      var tm = el("input", "mono"); tm.placeholder = "Token mint address"; tm.hidden = true; tm.spellcheck = false;
      ts.addEventListener("change", function () { tm.hidden = ts.value !== "other"; st.inputMint = ts.value === "other" ? tm.value.trim() : ts.value; });
      tm.addEventListener("input", function () { st.inputMint = tm.value.trim(); });
      st.inputMint = ts.value;
      tokenBox.appendChild(tl); tokenBox.appendChild(ts); tokenBox.appendChild(tm);
      tokenBox.appendChild(el("p", "hint", "Jupiter swaps it to USDC in the same transaction, so we receive the exact price. You need a browser wallet for this one."));
      ms.appendChild(tokenBox); f.appendChild(ms);

      // Email (receipts, and manual products)
      var ef = el("div", "fld"); var el2 = el("label", null, "Email for your receipt (optional)"); el2.htmlFor = "co-email";
      var ei = el("input"); ei.type = "email"; ei.id = "co-email"; ei.autocomplete = "email"; ef.appendChild(el2); ef.appendChild(ei); f.appendChild(ef);

      // Consent (UK and EU digital content rules)
      var cc = el("label", "check"), cb = el("input"); cb.type = "checkbox"; cb.required = true;
      cc.appendChild(cb); cc.appendChild(el("span", null, "I want my licence and the download straight away, and I understand that once the download starts I lose the 14-day right to cancel."));
      f.appendChild(cc);

      var go = el("button", "btn p wide", "Continue to payment"); go.type = "submit"; f.appendChild(go);
      f.addEventListener("submit", function (e) {
        e.preventDefault(); error(f, "");
        if (!isAddress(wi.value)) { wi.setAttribute("aria-invalid", "true"); wi.focus(); return error(f, "Enter the Solana address the bot will trade from."); }
        if (st.method === "token" && !isAddress(st.inputMint)) return error(f, "Pick a token, or paste a valid token mint address.");
        if (!cb.checked) return error(f, "Tick the box to confirm you want the download now.");
        go.disabled = true; go.innerHTML = '<span class="spinner" aria-hidden="true"></span> Creating your order…';
        var body = { package: st.pkg, wallet: wi.value.trim(), method: st.method, consent: true };
        if (st.method === "token") body.input_mint = st.inputMint;
        if (ei.value.trim()) body.email = ei.value.trim();
        if (st.holder) body.holder = { message: st.holder.message, challenge: st.holder.challenge, signature: st.holder.signature };
        call("POST", "/api/v1/bot/order", body).then(function (order) {
          st.order = order; st.token = order.token; keep({ id: order.order_id, token: order.token });
          history.replaceState(null, "", "?order=" + encodeURIComponent(order.order_id) + "&token=" + encodeURIComponent(order.token) + location.hash);
          if (order.checkout_url) { location.href = order.checkout_url; return; }
          drawPay();
        }).catch(function (e) {
          go.disabled = false; go.textContent = "Continue to payment";
          var d = e.data || {};
          if (e.status === 402) error(f, "This wallet holds " + Number(d.held || 0).toLocaleString("en-GB") + " $VANTAX. The holder price needs " + Number(d.required || 0).toLocaleString("en-GB") + ".");
          else if (e.status === 400) error(f, d.error || "Check the details and try again.");
          else if (e.status === 503) error(f, d.error || "The store can't reach Solana right now. Try again in a minute.");
          else error(f, e instanceof TypeError ? "Can't reach the Vantax store. Check your connection and try again." : (d.error || e.message));
        });
      });
      root.textContent = ""; root.appendChild(f); refreshPrices();
    }

    function drawConnect(row, input) {
      row.textContent = "";
      if (st.session) {
        row.appendChild(el("span", "small mute", "Connected to " + st.session.w.name + "."));
        var sw = el("button", "btn sm", "Use a different wallet"); sw.type = "button";
        sw.addEventListener("click", function () { st.session = null; st.holder = null; drawConnect(row, input); if (st.drawHolder) st.drawHolder(); refreshPrices(); });
        row.appendChild(sw); return;
      }
      var found = wallets();
      found.forEach(function (w) {
        var b = el("button", "btn sm", "Fill from " + w.name); b.type = "button";
        b.addEventListener("click", function () {
          var s = new Session(w); b.disabled = true;
          s.connect().then(function (addr) { st.session = s; st.wallet = addr; input.value = addr; drawConnect(row, input); }).catch(function (e) { b.disabled = false; if (!rejected(e)) error(row.parentNode, "Couldn't connect to " + w.name + ". Unlock it and try again."); });
        });
        row.appendChild(b);
      });
      if (!found.length) setTimeout(function () { if (!st.session && wallets().length) drawConnect(row, input); }, 700);
    }

    function holderSign(btn) {
      var f = root.querySelector(".co-form"), addr = (root.querySelector("#co-wallet") || {}).value || "";
      error(f, "");
      if (!isAddress(addr)) return error(f, "Enter or connect the wallet that holds your $VANTAX first.");
      var go = function (s) {
        btn.disabled = true; btn.innerHTML = '<span class="spinner" aria-hidden="true"></span> Check your wallet';
        var ch;
        return call("POST", "/api/v1/bot/holder/challenge", { wallet: addr }).then(function (c) { ch = c; return s.signMessage(c.message); })
          .then(function (sig) { st.holder = { wallet: addr, message: ch.message, challenge: ch.challenge, signature: b64(sig) }; st.drawHolder(); refreshPrices(); })
          .catch(function (e) { btn.disabled = false; btn.textContent = "Prove it by signing a message"; error(f, rejected(e) ? "You cancelled the signature. Nothing was signed." : (e.data && e.data.error) || "Your wallet couldn't sign the message."); });
      };
      if (st.session && st.session.address === addr) return go(st.session);
      var found = wallets(); if (!found.length) return error(f, "Signing needs a browser wallet (Phantom, Solflare or Backpack). On a phone, open this page in your wallet app.");
      var s = new Session(found[0]);
      s.connect().then(function (a) { if (a !== addr) throw new Error("mismatch"); st.session = s; return go(s); })
        .catch(function (e) { if (e && e.message === "mismatch") error(f, "Your wallet is on a different address. Switch to " + addr.slice(0, 4) + "…" + addr.slice(-4) + " and try again."); else if (!rejected(e)) error(f, "Couldn't connect to your wallet."); });
    }

    function refreshPrices() {
      if (!st.offer) return;
      root.querySelectorAll("[data-pkg-price]").forEach(function (n) {
        var p = pkgById(n.getAttribute("data-pkg-price")); if (!p) return;
        n.textContent = fmtSol(price(p)); var loc = inLocal(price(p)); if (loc) { n.appendChild(doc.createElement("br")); var s = el("small", "mute", loc); n.appendChild(s); }
      });
      var p = pkgById(st.pkg), sol = p ? price(p) : 0, m = money(), usd = m && m.rates ? m.convert(sol, "SOL", "USD") : null;
      root.querySelectorAll("[data-method-price]").forEach(function (n) {
        var id = n.getAttribute("data-method-price"), t = "";
        if (id === "sol") t = fmtSol(sol);
        else if ((id === "usdc" || id === "usdt") && usd != null) t = "≈ " + usd.toFixed(2) + " " + id.toUpperCase();
        else if (id === "card" && m && m.rates) { var v = m.convert(sol, "SOL", m.currency === "SOL" || m.currency === "USDC" ? "USD" : m.currency); if (v != null) t = "≈ " + m.format(v, m.currency === "SOL" || m.currency === "USDC" ? "USD" : m.currency, { round: v >= 20 }); }
        else if (id === "token" && usd != null) t = "≈ $" + usd.toFixed(2);
        n.textContent = t;
      });
    }
    doc.addEventListener("vantax:money", refreshPrices);

    /* Step 2: pay */
    function drawPay() {
      var o = st.order, box = el("div", "co-pay");
      var head = el("div", "co-pay-head");
      head.appendChild(el("h3", null, "Pay " + o.amount.ui + " " + o.amount.symbol));
      head.appendChild(el("p", "small mute", "Order " + o.order_id + " for the " + o.package_name + " licence, tied to " + o.wallet.slice(0, 4) + "…" + o.wallet.slice(-4) + ". The price is held until " + new Date(o.expires_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) + "."));
      box.appendChild(head);

      if (o.method === "token") {
        box.appendChild(el("p", null, "Your wallet will show a single swap: your " + (o.input_symbol || "tokens") + " in, " + o.amount.ui + " USDC out to Vantax. Approve it to pay."));
        var sb = el("button", "btn p", "Pay with " + (o.input_symbol || "your token")); sb.type = "button"; box.appendChild(sb);
        sb.addEventListener("click", function () { payBySwap(sb, box); });
      } else {
        var grid = el("div", "co-qr-grid");
        var qr = el("div", "qr"); var img = el("img"); img.alt = "Solana Pay QR code for this payment"; img.width = 220; img.height = 220; img.src = o.qr; qr.appendChild(img); grid.appendChild(qr);
        var right = el("div", "stack");
        right.appendChild(el("p", null, "Scan with Phantom, Solflare or any Solana Pay wallet, or pay from this browser."));
        var actions = el("div", "cluster");
        var wb = el("button", "btn p", "Pay with browser wallet"); wb.type = "button";
        wb.addEventListener("click", function () { payByTransfer(wb, box); });
        if (wallets().length) actions.appendChild(wb);
        var open = el("a", "btn", "Open in wallet app"); open.href = o.solana_pay; actions.appendChild(open);
        right.appendChild(actions);
        var dl = el("dl", "kv");
        [["Amount", o.amount.ui + " " + o.amount.symbol], ["To", o.pay_to], ["Reference", o.reference]].forEach(function (r) { dl.appendChild(el("dt", null, r[0])); dl.appendChild(el("dd", null, r[1])); });
        right.appendChild(dl);
        right.appendChild(el("p", "tiny mute", "Sending by hand? Only a transfer made from the QR code or the button carries this order's reference, which is how the payment is matched. Don't send from an exchange."));
        grid.appendChild(right); box.appendChild(grid);
      }
      var status = el("p", "notice co-status", "Waiting for your payment…"); status.setAttribute("role", "status"); box.appendChild(status);
      var link = el("p", "tiny mute"); link.appendChild(doc.createTextNode("Keep this page's address: it reopens your order and your downloads. "));
      var copy = el("button", "btn sm", "Copy order link"); copy.type = "button"; copy.setAttribute("data-copy-text", location.href);
      copy.addEventListener("click", function () { if (navigator.clipboard) navigator.clipboard.writeText(location.href).then(function () { copy.textContent = "Copied"; }); });
      link.appendChild(copy); box.appendChild(link);
      root.textContent = ""; root.appendChild(box); poll();
    }

    function payByTransfer(btn, box) {
      var o = st.order, found = wallets(); error(box, "");
      if (!found.length) return error(box, "No browser wallet found. Scan the QR code instead.");
      var s = st.session || new Session(found[0]);
      btn.disabled = true; btn.innerHTML = '<span class="spinner" aria-hidden="true"></span> Check your wallet';
      (s.address ? Promise.resolve(s.address) : s.connect()).then(function (account) {
        st.session = s;
        return call("POST", "/api/v1/bot/order/" + encodeURIComponent(o.order_id) + "/transaction?token=" + encodeURIComponent(st.token), { account: account });
      }).then(function (t) { return s.signAndSend(unb64(t.transaction)); })
        .then(function (sig) { btn.textContent = "Sent"; box.querySelector(".co-status").textContent = "Payment sent. Waiting for Solana to confirm it…"; st.sent = sig; poll(true); })
        .catch(function (e) { btn.disabled = false; btn.textContent = "Pay with browser wallet"; error(box, rejected(e) ? "You cancelled in your wallet. Nothing was sent." : (e.data && e.data.error) || e.message || "Your wallet couldn't send the payment."); });
    }

    function payBySwap(btn, box) {
      var o = st.order, found = wallets(); error(box, "");
      if (!found.length) return error(box, "Paying with another token needs a browser wallet. On a phone, open this page in Phantom or Solflare.");
      var s = st.session || new Session(found[0]), req;
      btn.disabled = true; btn.innerHTML = '<span class="spinner" aria-hidden="true"></span> Getting a quote';
      (s.address ? Promise.resolve(s.address) : s.connect()).then(function (account) {
        st.session = s;
        return call("POST", "/api/v1/bot/order/" + encodeURIComponent(o.order_id) + "/transaction?token=" + encodeURIComponent(st.token), { account: account });
      }).then(function (t) {
        req = t; btn.innerHTML = '<span class="spinner" aria-hidden="true"></span> Approve in your wallet';
        box.querySelector(".co-status").textContent = "Quote: " + t.in_ui + " " + (t.in_symbol || o.input_symbol || "") + " for " + o.amount.ui + " USDC. Approve it in your wallet.";
        return s.signOnly(unb64(t.transaction));
      }).then(function (signed) {
        btn.innerHTML = '<span class="spinner" aria-hidden="true"></span> Swapping';
        return call("POST", "/api/v1/bot/order/" + encodeURIComponent(o.order_id) + "/execute?token=" + encodeURIComponent(st.token), { signed_transaction: b64(signed), request_id: req.request_id });
      }).then(function () { btn.textContent = "Swapped"; poll(true); })
        .catch(function (e) { btn.disabled = false; btn.textContent = "Pay with " + (o.input_symbol || "your token"); error(box, rejected(e) ? "You cancelled in your wallet. Nothing was sent." : (e.data && e.data.error) || e.message || "The swap didn't go through. Nothing was taken."); });
    }

    function poll(soon) {
      clearTimeout(st.timer);
      st.timer = setTimeout(function check() {
        call("GET", "/api/v1/bot/order/" + encodeURIComponent(st.order.order_id) + "?token=" + encodeURIComponent(st.token)).then(function (o) {
          st.order = o;
          if (o.status === "paid") return drawDone();
          if (o.status === "expired") return drawExpired();
          var n = root.querySelector(".co-status");
          if (n && o.status === "confirming") n.textContent = "Payment seen. Waiting for Solana to finalise it…";
          st.timer = setTimeout(check, 4000);
        }).catch(function (e) { if (e.status === 404) { keep(null); return drawStart("That order link isn't valid any more."); } st.timer = setTimeout(check, 8000); });
      }, soon ? 1500 : 3000);
    }

    function drawExpired() {
      keep(null);
      var box = el("div", "co-pay"); box.appendChild(el("h3", null, "This order expired"));
      box.appendChild(el("p", "mute", "No payment arrived while the price was held, so nothing was taken. Start again for a fresh price. If you did pay after the time ran out, it still counts for a day: reopen this page's link and your licence will be there."));
      var b = el("button", "btn p", "Start again"); b.type = "button"; b.addEventListener("click", function () { history.replaceState(null, "", location.pathname + location.hash); st.order = null; drawForm(); });
      box.appendChild(b); root.textContent = ""; root.appendChild(box);
    }

    function drawDone() {
      var o = st.order, box = el("div", "co-done stack");
      box.appendChild(el("p", "notice ok", "Paid. Thank you. Your licence is ready."));
      box.appendChild(el("h3", null, "Your downloads"));
      var ul = el("ul", "co-downloads");
      (o.downloads || []).forEach(function (d) {
        var li = el("li"), a = el("a", "btn" + (d.file === "licence.json" ? " p" : ""), d.label || d.file);
        a.href = STORE + d.path; a.setAttribute("download", d.file);
        li.appendChild(a); if (d.sha256) li.appendChild(el("code", "tiny", "sha256 " + d.sha256.slice(0, 16) + "…")); ul.appendChild(li);
      });
      box.appendChild(ul);
      if (o.licence) {
        var dl = el("dl", "kv");
        [["Licence", o.licence.id], ["Package", o.package_name], ["Wallet", o.licence.wallet], ["Valid until", o.licence.expires_at ? new Date(o.licence.expires_at * 1000).toLocaleDateString() : "No end date"], ["Signed by", "Vantax issuer " + String(o.licence.issuer_fingerprint || "").slice(0, 16) + "…"]]
          .forEach(function (r) { dl.appendChild(el("dt", null, r[0])); dl.appendChild(el("dd", null, r[1])); });
        box.appendChild(dl);
      }
      box.appendChild(el("h3", null, "Start it"));
      var pre = el("pre", "code");
      pre.textContent = "tar xzf vantaxbot-*.tar.gz && cd vantaxbot\n./vantaxbot licence install ~/Downloads/licence.json\n./vantaxbot check-config\n./vantaxbot run              # paper mode until you set mode = \"live\"";
      box.appendChild(pre);
      box.appendChild(el("p", "small mute", "The full setup guide is in the download (README.md). Lost this page? Your order link reopens it."));
      root.textContent = ""; root.appendChild(box);
    }

    function drawStart(note) {
      call("GET", "/api/v1/bot").then(function (offer) {
        st.offer = offer;
        if (note) { drawForm(); error(root.querySelector(".co-form"), note); } else drawForm();
      }).catch(function () {
        root.textContent = "";
        var n = el("div", "notice warn"); n.appendChild(el("b", null, "The store isn't answering right now. "));
        n.appendChild(doc.createTextNode("Nothing has been charged. Try again in a minute, or message @VantaxFounder on X."));
        root.appendChild(n);
      });
    }

    // Resume from the URL (after Stripe, or a reload) or from this browser.
    var q = new URLSearchParams(location.search), id = q.get("order"), tok = q.get("token");
    if (!id) { var k = kept(); if (k && k.id) { id = k.id; tok = k.token; } }
    if (id && tok) {
      st.token = tok;
      call("GET", "/api/v1/bot").then(function (offer) { st.offer = offer; }).catch(function () {});
      call("GET", "/api/v1/bot/order/" + encodeURIComponent(id) + "?token=" + encodeURIComponent(tok)).then(function (o) {
        st.order = o;
        if (o.status === "paid") return drawDone();
        if (o.status === "expired") return drawExpired();
        drawPay();
      }).catch(function () { keep(null); drawStart(); });
    } else drawStart();
  }

  window.VantaxCheckout = { mount: mount };
})();
