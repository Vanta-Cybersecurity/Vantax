//! # vantax-wasm
//!
//! Vantax in the browser, as one WebAssembly module with no imports:
//!
//! - **ML-DSA-87 keys, signing and verification**, byte-compatible with
//!   `vantax-core` and the `vantax` CLI (same key, public key and signature
//!   JSON). A key made in the browser verifies with the CLI and back.
//! - **The triple hash** (SHA3-512 → BLAKE3 → SHA3-512).
//! - **Provably fair verification**: recompute outcomes and check signed
//!   receipts, reveals and seed chains from `vantax-fairness`, so a player can
//!   check a casino without installing anything.
//!
//! Pure Rust (RustCrypto `ml-dsa`), so it builds for
//! `wasm32-unknown-unknown`:
//!
//! ```text
//! cargo build -p vantax-wasm --release --target wasm32-unknown-unknown
//! # → target/wasm32-unknown-unknown/release/vantax_wasm.wasm
//! ```
//!
//! The browser side is `js/vantax.js` (no build step, no dependencies). The
//! module never asks the browser for randomness itself: key seeds and signing
//! randomness are passed in from `crypto.getRandomValues`.
//!
//! **Keys in a browser live in page memory.** Use browser signing for keys
//! that guard little or for demos; keep high-value keys in the CLI, an HSM or
//! a vault. This crate has not had an independent third-party audit.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod api;
pub mod crypto;
pub mod ffi;

pub use api::call;
