//! Bitcoin: tagged-hash commitments anchored with `OP_RETURN`, and full
//! address validation (Bech32, Bech32m, Base58Check).
//!
//! Bitcoin script cannot hold a 2592-byte ML-DSA-87 key (520-byte stack
//! element limit) or compute this hash on-chain. The anchor is a public,
//! timestamped commitment that off-chain verifiers check: proof that the
//! holder of a Bitcoin key also controls a post-quantum key, made before any
//! quantum computer exists. Proposals such as BIP-360 are still drafts; this
//! adapter does not claim compatibility with any of them.

use crate::{sha256, validate_decimal, Anchor, ChainAdapter, BTC_MAX_SATS};
use sha2::{Digest, Sha256};
use vantax_core::VantaxError;

/// BIP-340-style tag for commitment hashes.
pub const COMMITMENT_TAG: &str = "Vantax/PQCommitment";
const OP_RETURN: u8 = 0x6a;
const ANCHOR_MAGIC: &[u8; 4] = b"VTX1";
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// A Bitcoin network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinNetwork {
    /// Mainnet (`bc1…`, `1…`, `3…`).
    Mainnet,
    /// Testnet and signet (`tb1…`, `m…`, `n…`, `2…`).
    Testnet,
    /// Regtest (`bcrt1…`).
    Regtest,
}

impl BitcoinNetwork {
    /// Network name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Regtest => "regtest",
        }
    }

    fn hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "bc",
            Self::Testnet => "tb",
            Self::Regtest => "bcrt",
        }
    }

    fn base58_versions(self) -> [u8; 2] {
        match self {
            Self::Mainnet => [0x00, 0x05],
            Self::Testnet | Self::Regtest => [0x6f, 0xc4],
        }
    }

    /// CAIP-2 reference: the first 32 hex characters of the genesis block hash.
    fn genesis_prefix(self) -> &'static str {
        match self {
            Self::Mainnet => "000000000019d6689c085ae165831e93",
            Self::Testnet => "000000000933ea01ad0ee984209779ba",
            Self::Regtest => "0f9188f13cb7b2c71f2a335e3a4fc328",
        }
    }
}

/// The Bitcoin adapter.
pub struct BitcoinAdapter {
    network: BitcoinNetwork,
}

impl BitcoinAdapter {
    /// An adapter for one network.
    pub fn new(network: BitcoinNetwork) -> Self {
        Self { network }
    }

    /// Which network this adapter serves.
    pub fn bitcoin_network(&self) -> BitcoinNetwork {
        self.network
    }
}

/// BIP-340 tagged hash: `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)`.
pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let t = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(msg);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

impl ChainAdapter for BitcoinAdapter {
    fn chain(&self) -> &str {
        "bitcoin"
    }
    fn name(&self) -> &str {
        "Bitcoin"
    }
    fn network(&self) -> &str {
        self.network.name()
    }
    fn caip2(&self) -> String {
        format!("bip122:{}", self.network.genesis_prefix())
    }
    fn supports_smart_contracts(&self) -> bool {
        false
    }
    fn commitment_scheme(&self) -> &'static str {
        "sha256-tagged(Vantax/PQCommitment)"
    }
    fn anchor_kind(&self) -> &'static str {
        "op_return"
    }
    fn commitment_hash(&self, preimage: &[u8]) -> [u8; 32] {
        tagged_hash(COMMITMENT_TAG, preimage)
    }
    fn anchor(&self, commitment: &[u8; 32]) -> Anchor {
        let mut payload = Vec::with_capacity(36);
        payload.extend_from_slice(ANCHOR_MAGIC);
        payload.extend_from_slice(commitment);
        // A direct push: for 1..=75 bytes the opcode is the length.
        let mut script = vec![OP_RETURN, payload.len() as u8];
        script.extend_from_slice(&payload);
        Anchor::BitcoinOpReturn {
            script_hex: hex::encode(&script),
            asm: format!("OP_RETURN {}", hex::encode(&payload)),
        }
    }
    fn validate_address(&self, address: &str) -> Result<(), VantaxError> {
        let hrp = self.network.hrp();
        if address.to_ascii_lowercase().starts_with(&format!("{hrp}1")) {
            validate_segwit(address, hrp)
        } else {
            validate_base58check(address, self.network)
        }
    }
    fn validate_amount(&self, amount: &str) -> Result<(), VantaxError> {
        validate_decimal(amount, BTC_MAX_SATS)
    }
    fn validate_reference(&self, reference: &str) -> Result<(), VantaxError> {
        if reference.len() == 64 && reference.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(())
        } else {
            Err(VantaxError::InvalidInput(
                "Bitcoin reference must be a 64-hex-character block hash or txid".into(),
            ))
        }
    }
}

fn invalid(msg: &str) -> VantaxError {
    VantaxError::InvalidInput(format!("invalid Bitcoin address: {msg}"))
}

#[derive(PartialEq, Eq)]
enum Variant {
    Bech32,
    Bech32m,
}

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    out.push(0);
    out.extend(hrp.bytes().map(|b| b & 31));
    out
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1 << to) - 1;
    let max_acc: u32 = (1 << (from + to - 1)) - 1;
    let mut out = Vec::with_capacity(data.len() * from as usize / to as usize + 1);
    for &value in data {
        let v = u32::from(value);
        if v >> from != 0 {
            return None;
        }
        acc = ((acc << from) | v) & max_acc;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

fn validate_segwit(address: &str, expected_hrp: &str) -> Result<(), VantaxError> {
    if address.len() > 90 {
        return Err(invalid("longer than 90 characters"));
    }
    let has_lower = address.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = address.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(invalid("mixed case"));
    }
    let address = address.to_ascii_lowercase();
    let sep = address
        .rfind('1')
        .ok_or_else(|| invalid("missing separator"))?;
    let (hrp, data_part) = (&address[..sep], &address[sep + 1..]);
    if hrp != expected_hrp {
        return Err(invalid("wrong network prefix"));
    }
    if data_part.len() < 7 {
        return Err(invalid("too short"));
    }
    let data: Vec<u8> = data_part
        .bytes()
        .map(|c| BECH32_CHARSET.iter().position(|&x| x == c).map(|p| p as u8))
        .collect::<Option<_>>()
        .ok_or_else(|| invalid("character outside the Bech32 alphabet"))?;
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&data);
    let variant = match polymod(&values) {
        1 => Variant::Bech32,
        BECH32M_CONST => Variant::Bech32m,
        _ => return Err(invalid("checksum mismatch")),
    };
    let payload = &data[..data.len() - 6];
    let version = payload[0];
    let program = convert_bits(&payload[1..], 5, 8, false)
        .ok_or_else(|| invalid("bad witness program padding"))?;
    match version {
        0 if variant != Variant::Bech32 => Err(invalid("witness v0 must use Bech32")),
        0 if program.len() == 20 || program.len() == 32 => Ok(()),
        0 => Err(invalid("witness v0 program must be 20 or 32 bytes")),
        1 if variant != Variant::Bech32m => Err(invalid("witness v1 must use Bech32m")),
        1 if program.len() == 32 => Ok(()),
        1 => Err(invalid("Taproot (v1) program must be 32 bytes")),
        2..=16 => Err(invalid(&format!(
            "witness version {version} is not active on Bitcoin; outputs to it can be spent by anyone"
        ))),
        _ => Err(invalid("bad witness version")),
    }
}

fn validate_base58check(address: &str, network: BitcoinNetwork) -> Result<(), VantaxError> {
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|_| invalid("not Bech32 or Base58"))?;
    if bytes.len() != 25 {
        return Err(invalid("Base58 payload must be 25 bytes"));
    }
    let (payload, checksum) = bytes.split_at(21);
    let double = sha256(&sha256(payload));
    if &double[..4] != checksum {
        return Err(invalid("Base58Check checksum mismatch"));
    }
    if !network.base58_versions().contains(&payload[0]) {
        return Err(invalid(&format!("not a {} address", network.name())));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mainnet() -> BitcoinAdapter {
        BitcoinAdapter::new(BitcoinNetwork::Mainnet)
    }

    #[test]
    fn accepts_valid_addresses() {
        // BIP-173 and BIP-350 test vectors, plus well-known Base58 addresses.
        for a in [
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        ] {
            mainnet()
                .validate_address(a)
                .unwrap_or_else(|e| panic!("{a}: {e}"));
        }
        BitcoinAdapter::new(BitcoinNetwork::Testnet)
            .validate_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
            .unwrap();
    }

    #[test]
    fn rejects_invalid_addresses() {
        for a in [
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            "bc1qw508d6qejxtdg4y5R3zarvary0c5xw7kv8f3t4",
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            "bc1zw508d6qejxtdg4y5r3zarvary3c5xw7kvz7nf4",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",
            "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
            "bc1q",
            "",
        ] {
            assert!(
                mainnet().validate_address(a).is_err(),
                "{a} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_inactive_witness_versions() {
        let err = mainnet()
            .validate_address("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs")
            .unwrap_err();
        assert!(err.to_string().contains("not active"), "{err}");
    }

    #[test]
    fn op_return_anchor_shape() {
        let c = [7u8; 32];
        match mainnet().anchor(&c) {
            Anchor::BitcoinOpReturn { script_hex, asm } => {
                assert_eq!(&script_hex[..12], "6a2456545831");
                assert!(asm.starts_with("OP_RETURN 56545831"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn tagged_hash_matches_definition() {
        let t = sha256(b"T");
        let expected = sha256(&[&t[..], &t[..], b"m"].concat());
        assert_eq!(tagged_hash("T", b"m"), expected);
    }
}
