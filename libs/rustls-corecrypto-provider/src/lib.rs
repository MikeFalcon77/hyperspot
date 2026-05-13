//! `rustls::crypto::CryptoProvider` backed by Apple corecrypto via
//! Security.framework and CommonCrypto.
//!
//! See `README.md` for scope and compliance notes.
//!
//! ## Architecture
//!
//! - [`ffi`] — raw `extern "C"` declarations for CommonCrypto.
//! - [`hash`] — SHA-2 implementations (`Hash` trait).
//! - [`hmac`] — HMAC-SHA-2 (`Hmac` trait).
//! - [`hkdf`] — HKDF on top of HMAC (`tls13::Hkdf` trait).
//! - [`aead`] — AES-128/256-GCM (`Tls13AeadAlgorithm` / `Tls12AeadAlgorithm`).
//! - [`random`] — `SecureRandom` via `SecRandomCopyBytes`.
//! - [`kx`] — `SupportedKxGroup` for P-256 / P-384.
//! - [`verify`] — signature verification algorithms.
//! - [`signer`] — server-side `KeyProvider` (stub; not supported).
//! - [`tls13`], [`tls12`] — cipher suite registrations.
//! - [`provider`] — assembly of the final `CryptoProvider`.
//!
//! The entire crate is gated on `cfg(target_os = "macos")`. On other
//! platforms the public surface is empty.

#![cfg(target_os = "macos")]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod ffi;

pub mod aead;
pub mod hash;
pub mod hkdf;
pub mod hmac;
pub mod kx;
pub mod provider;
pub mod random;
pub mod signer;
pub mod tls12;
pub mod tls13;
pub mod verify;

pub use provider::default_provider;
