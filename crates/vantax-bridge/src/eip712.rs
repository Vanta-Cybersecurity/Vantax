//! EIP-712 typed-data digests for the destination contract.
//!
//! Each signer signs the digest below with its Ethereum key (ECDSA over
//! secp256k1, done by the signer's own wallet or HSM); the bridge contract
//! recovers the addresses on-chain and requires them strictly ascending.
//!
//! ```text
//! EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
//! Mint(bytes32 eventId,address token,address recipient,uint256 amount,uint256 sourceNonce)
//! digest = keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct(Mint))
//! ```

use crate::BridgeError;
use sha3::{Digest, Keccak256};

/// `keccak256` of `data`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// Parse a `0x` + 40 hex character address (any case).
pub fn parse_address(s: &str) -> Result<[u8; 20], BridgeError> {
    let hex_part = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| BridgeError::Invalid(format!("address {s:?} must start with 0x")))?;
    let bytes = hex::decode(hex_part)
        .map_err(|_| BridgeError::Invalid(format!("address {s:?} is not hex")))?;
    bytes
        .try_into()
        .map_err(|_| BridgeError::Invalid(format!("address {s:?} must be 20 bytes")))
}

/// The address in lowercase `0x…` form.
pub fn normalize_address(s: &str) -> Result<String, BridgeError> {
    Ok(format!("0x{}", hex::encode(parse_address(s)?)))
}

/// ABI word for an address (left-padded to 32 bytes).
pub fn word_address(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// ABI word for an unsigned integer.
pub fn word_u128(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

/// `keccak256(abi.encode(words…))`.
pub fn hash_words(words: &[[u8; 32]]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(words.len() * 32);
    for w in words {
        buf.extend_from_slice(w);
    }
    keccak256(&buf)
}

/// The EIP-712 domain separator.
pub fn domain_separator(
    name: &str,
    version: &str,
    chain_id: u64,
    verifying_contract: &[u8; 20],
) -> [u8; 32] {
    hash_words(&[
        keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        ),
        keccak256(name.as_bytes()),
        keccak256(version.as_bytes()),
        word_u128(u128::from(chain_id)),
        word_address(verifying_contract),
    ])
}

/// The `Mint` type string.
pub const MINT_TYPE: &str =
    "Mint(bytes32 eventId,address token,address recipient,uint256 amount,uint256 sourceNonce)";

/// `hashStruct(Mint)`.
pub fn mint_struct_hash(
    event_id: &[u8; 32],
    token: &[u8; 20],
    recipient: &[u8; 20],
    amount: u128,
    source_nonce: u64,
) -> [u8; 32] {
    hash_words(&[
        keccak256(MINT_TYPE.as_bytes()),
        *event_id,
        word_address(token),
        word_address(recipient),
        word_u128(amount),
        word_u128(u128::from(source_nonce)),
    ])
}

/// The final digest the signers' Ethereum keys sign.
pub fn typed_data_digest(domain_separator: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(66);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(domain_separator);
    buf.extend_from_slice(struct_hash);
    keccak256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> String {
        hex::encode(keccak256(s.as_bytes()))
    }

    #[test]
    fn keccak_known_values() {
        assert_eq!(
            h(""),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex::encode(&keccak256(b"transfer(address,uint256)")[..4]),
            "a9059cbb"
        );
    }

    /// The worked example from the EIP-712 specification (Ether Mail).
    #[test]
    fn eip712_specification_example() {
        let contract = parse_address("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC").unwrap();
        let ds = domain_separator("Ether Mail", "1", 1, &contract);
        assert_eq!(
            hex::encode(ds),
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
        );
        let person_type = keccak256(b"Person(string name,address wallet)");
        let mail_type = keccak256(
            b"Mail(Person from,Person to,string contents)Person(string name,address wallet)",
        );
        let person = |name: &str, wallet: &str| {
            hash_words(&[
                person_type,
                keccak256(name.as_bytes()),
                word_address(&parse_address(wallet).unwrap()),
            ])
        };
        let mail = hash_words(&[
            mail_type,
            person("Cow", "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"),
            person("Bob", "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
            keccak256(b"Hello, Bob!"),
        ]);
        assert_eq!(
            hex::encode(mail),
            "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
        );
        assert_eq!(
            hex::encode(typed_data_digest(&ds, &mail)),
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        );
    }

    #[test]
    fn addresses() {
        assert!(parse_address("0x1234").is_err());
        assert!(parse_address("1234567890123456789012345678901234567890").is_err());
        assert_eq!(
            normalize_address("0xABCDEFabcdef0123456789ABCDEFabcdef012345").unwrap(),
            "0xabcdefabcdef0123456789abcdefabcdef012345"
        );
    }
}
