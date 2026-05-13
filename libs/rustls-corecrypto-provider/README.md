# cf-rustls-corecrypto-provider

A `rustls::crypto::CryptoProvider` backed by Apple **corecrypto** (the FIPS
140-3 validated cryptographic module shipped inside macOS) via
`Security.framework` and `CommonCrypto`.

## Why

Apple's `corecrypto` user-space module carries its own FIPS 140-3 certificates
per macOS release. Routing rustls through it gives a macOS-valid FIPS claim
without leaving the rustls ecosystem — same TLS state machine, same
`HttpsConnector` type, same APIs as on Linux (aws-lc-rs FIPS) or Windows
(future `rustls-cng-crypto`).

This crate **only compiles on macOS** (`cfg(target_os = "macos")`); on other
platforms the public API is empty.

## Scope

| Category | Algorithms |
|---|---|
| TLS 1.3 | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384` |
| TLS 1.2 | `ECDHE_ECDSA/RSA_WITH_AES_128/256_GCM_SHA256/384` |
| Key exchange | NIST P-256, P-384 |
| Signature verify | ECDSA P-256/P-384, RSA-PSS, RSA PKCS#1 v1.5 (SHA-256/384/512) |
| Hash / HMAC / HKDF | SHA-256, SHA-384 |
| AEAD | AES-128-GCM, AES-256-GCM |
| Random | `SecRandomCopyBytes` |

Out of scope: CBC ciphers, X25519, ChaCha20-Poly1305, server-side TLS,
ED25519. Minimum macOS version: 11 (Big Sur).

## Usage

```rust
let provider = rustls_corecrypto_provider::default_provider();
provider.install_default().expect("install crypto provider");
```

## Compliance caveat

A FIPS 140-3 claim under this provider rests on the Apple corecrypto cert
covering the **exact running macOS version + arch**. Verify against the
current CMVP entry at <https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search>
before relying on the claim.
