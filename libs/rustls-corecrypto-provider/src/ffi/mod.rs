//! Foreign function interface bindings to Apple's user-space crypto APIs.
//!
//! `security-framework` covers high-level objects (`SecKey`, `SecRandom`) but
//! does not expose symmetric primitives. `CommonCrypto` is the canonical
//! lower-level user-space C API that, on macOS, terminates inside the
//! FIPS-validated `libcorecrypto.dylib`. We bind only the entry points we
//! need, with explicit `#[link(name = "System", kind = "framework")]` so the
//! library link is unambiguous in the dependency manifest.

pub mod commoncrypto;
pub mod security;
