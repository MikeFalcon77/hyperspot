//! TLS 1.2 cipher suite registrations + PRF.
//!
//! Four FIPS-approved GCM cipher suites:
//! - `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
//! - `ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
//! - `ECDHE_RSA_WITH_AES_128_GCM_SHA256`
//! - `ECDHE_RSA_WITH_AES_256_GCM_SHA384`
//!
//! ## Wire format (RFC 5288)
//!
//! Each record body is `explicit_nonce(8) || ciphertext || tag(16)`. The
//! full AEAD nonce is `implicit_iv(4) || explicit_nonce(8)`, where the
//! implicit IV comes from the TLS 1.2 key_block (`fixed_iv_len = 4`) and the
//! explicit nonce is the (per-record) 8-byte counter sent in the clear.
//!
//! AAD = `seq_num(8) || ContentType(1) || ProtocolVersion(2) || Length(2)`
//! (constructed via [`make_tls12_aad`]). Length is plaintext length, NOT
//! including the explicit nonce or tag.

use rustls::ConnectionTrafficSecrets;
use rustls::crypto::ActiveKeyExchange;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls12AeadAlgorithm, UnsupportedOperationError, make_tls12_aad,
};
use rustls::crypto::hmac::Hmac;
use rustls::crypto::tls12::{Prf, PrfUsingHmac};
use zeroize::Zeroizing;

use crate::aead;
use crate::hmac::{HMAC_SHA256, HMAC_SHA384};

const EXPLICIT_NONCE_LEN: usize = 8;
const IMPLICIT_IV_LEN: usize = 4;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = aead::TAG_LEN;

// =========================================================================
// AEAD algorithm wrappers
// =========================================================================

#[derive(Debug)]
pub struct Aes128Gcm;
#[derive(Debug)]
pub struct Aes256Gcm;

impl Tls12AeadAlgorithm for Aes128Gcm {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _extra: &[u8]) -> Box<dyn MessageEncrypter> {
        make_encrypter(key, iv)
    }
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        make_decrypter(key, iv)
    }
    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: aead::AES128_KEY_LEN,
            fixed_iv_len: IMPLICIT_IV_LEN,
            explicit_nonce_len: EXPLICIT_NONCE_LEN,
        }
    }
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm {
            key,
            iv: build_iv(iv, explicit),
        })
    }
    fn fips(&self) -> bool {
        true
    }
}

impl Tls12AeadAlgorithm for Aes256Gcm {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _extra: &[u8]) -> Box<dyn MessageEncrypter> {
        make_encrypter(key, iv)
    }
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        make_decrypter(key, iv)
    }
    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: aead::AES256_KEY_LEN,
            fixed_iv_len: IMPLICIT_IV_LEN,
            explicit_nonce_len: EXPLICIT_NONCE_LEN,
        }
    }
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm {
            key,
            iv: build_iv(iv, explicit),
        })
    }
    fn fips(&self) -> bool {
        true
    }
}

fn build_iv(iv: &[u8], explicit: &[u8]) -> rustls::crypto::cipher::Iv {
    debug_assert_eq!(iv.len(), IMPLICIT_IV_LEN);
    debug_assert_eq!(explicit.len(), EXPLICIT_NONCE_LEN);
    let mut full = [0u8; NONCE_LEN];
    full[..IMPLICIT_IV_LEN].copy_from_slice(iv);
    full[IMPLICIT_IV_LEN..].copy_from_slice(explicit);
    rustls::crypto::cipher::Iv::copy(&full)
}

fn make_encrypter(key: AeadKey, iv: &[u8]) -> Box<dyn MessageEncrypter> {
    debug_assert_eq!(iv.len(), IMPLICIT_IV_LEN);
    let mut implicit = [0u8; IMPLICIT_IV_LEN];
    implicit.copy_from_slice(iv);
    Box::new(Tls12Encrypter {
        key: Zeroizing::new(key.as_ref().to_vec()),
        implicit_iv: implicit,
    })
}

fn make_decrypter(key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
    debug_assert_eq!(iv.len(), IMPLICIT_IV_LEN);
    let mut implicit = [0u8; IMPLICIT_IV_LEN];
    implicit.copy_from_slice(iv);
    Box::new(Tls12Decrypter {
        key: Zeroizing::new(key.as_ref().to_vec()),
        implicit_iv: implicit,
    })
}

// =========================================================================
// Encrypter / Decrypter
// =========================================================================

struct Tls12Encrypter {
    /// AEAD session key. `Zeroizing` wipes the bytes on drop.
    key: Zeroizing<Vec<u8>>,
    implicit_iv: [u8; IMPLICIT_IV_LEN],
}

impl MessageEncrypter for Tls12Encrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let pt_len = msg.payload.len();
        // Build the full nonce: implicit_iv(4) || explicit(8 = seq_num BE).
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..IMPLICIT_IV_LEN].copy_from_slice(&self.implicit_iv);
        nonce[IMPLICIT_IV_LEN..].copy_from_slice(&seq.to_be_bytes());

        let aad = make_tls12_aad(seq, msg.typ, msg.version, pt_len);

        // `Zeroizing` wipes the plaintext on drop after the encrypt call.
        let mut pt: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(pt_len));
        msg.payload.copy_to_vec(&mut pt);

        let mut ct = vec![0u8; pt_len];
        let tag = aead::encrypt(&self.key, &nonce, aad.as_ref(), &pt, &mut ct)
            .map_err(|e| rustls::Error::General(format!("AES-GCM encrypt: {e}")))?;

        // Wire: explicit_nonce(8) || ciphertext || tag(16).
        let mut payload = PrefixedPayload::with_capacity(EXPLICIT_NONCE_LEN + ct.len() + TAG_LEN);
        payload.extend_from_slice(&nonce[IMPLICIT_IV_LEN..]); // explicit
        payload.extend_from_slice(&ct);
        payload.extend_from_slice(&tag);

        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        EXPLICIT_NONCE_LEN + payload_len + TAG_LEN
    }
}

struct Tls12Decrypter {
    /// AEAD session key. `Zeroizing` wipes the bytes on drop.
    key: Zeroizing<Vec<u8>>,
    implicit_iv: [u8; IMPLICIT_IV_LEN],
}

impl MessageDecrypter for Tls12Decrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload_len = msg.payload.len();
        if payload_len < EXPLICIT_NONCE_LEN + TAG_LEN {
            return Err(rustls::Error::DecryptError);
        }
        let ct_len = payload_len - EXPLICIT_NONCE_LEN - TAG_LEN;

        // Split: explicit_nonce(8) | ciphertext(ct_len) | tag(16).
        let payload = &mut msg.payload[..];
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..IMPLICIT_IV_LEN].copy_from_slice(&self.implicit_iv);
        nonce[IMPLICIT_IV_LEN..].copy_from_slice(&payload[..EXPLICIT_NONCE_LEN]);

        let aad = make_tls12_aad(seq, msg.typ, msg.version, ct_len);

        let ct_start = EXPLICIT_NONCE_LEN;
        let tag_start = payload_len - TAG_LEN;
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&payload[tag_start..]);

        // `Zeroizing` wipes the decrypted plaintext from this temp on drop.
        let mut pt: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; ct_len]);
        aead::decrypt(
            &self.key,
            &nonce,
            aad.as_ref(),
            &payload[ct_start..tag_start],
            &mut pt,
            &tag,
        )
        .map_err(|_| rustls::Error::DecryptError)?;

        // Shift the plaintext to the front of the payload, truncate.
        payload[..ct_len].copy_from_slice(&pt);
        msg.payload.truncate(ct_len);
        Ok(msg.into_plain_message())
    }
}

// =========================================================================
// Public statics
// =========================================================================

pub static AES_128_GCM: Aes128Gcm = Aes128Gcm;
pub static AES_256_GCM: Aes256Gcm = Aes256Gcm;

// rustls's `PrfUsingHmac` hardcodes `fips() = false`, which would poison
// our cipher-suite-level FIPS claim. We wrap it in a thin Prf impl that
// delegates everything but overrides `fips()` to delegate to the inner
// HMAC (which is our corecrypto-backed FIPS-validated HMAC).

/// TLS 1.2 PRF using HMAC-SHA-256 — FIPS-aware wrapper.
#[derive(Debug)]
pub struct PrfSha256;
/// TLS 1.2 PRF using HMAC-SHA-384 — FIPS-aware wrapper.
#[derive(Debug)]
pub struct PrfSha384;

pub static PRF_SHA256: PrfSha256 = PrfSha256;
pub static PRF_SHA384: PrfSha384 = PrfSha384;

impl Prf for PrfSha256 {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        PrfUsingHmac(&HMAC_SHA256).for_key_exchange(output, kx, peer_pub_key, label, seed)
    }
    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        PrfUsingHmac(&HMAC_SHA256).for_secret(output, secret, label, seed)
    }
    fn fips(&self) -> bool {
        HMAC_SHA256.fips()
    }
}

impl Prf for PrfSha384 {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        PrfUsingHmac(&HMAC_SHA384).for_key_exchange(output, kx, peer_pub_key, label, seed)
    }
    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        PrfUsingHmac(&HMAC_SHA384).for_secret(output, secret, label, seed)
    }
    fn fips(&self) -> bool {
        HMAC_SHA384.fips()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::cipher::OutboundChunks;
    use rustls::{ContentType, ProtocolVersion};

    fn aead_key_256() -> AeadKey {
        // See tls13.rs tests — public API only constructs 32-byte AeadKey,
        // so AES-128 unit-tests aren't expressible here. AES-128 is
        // exercised end-to-end by handshake_smoke.
        AeadKey::from([0x99u8; 32])
    }
    fn implicit_iv() -> [u8; 4] {
        [0x77u8; 4]
    }

    /// TLS 1.2 record encrypt → decrypt roundtrip for AES-256-GCM with the
    /// explicit-nonce wire format. Catches: wrong AAD construction (TLS 1.2
    /// uses seq||type||version||length, different from TLS 1.3), wrong
    /// nonce assembly (implicit_iv(4) || explicit_seq(8)), broken extraction
    /// of explicit-nonce prefix on decrypt.
    #[test]
    fn aes256_gcm_record_roundtrip() {
        let mut enc =
            Tls12AeadAlgorithm::encrypter(&AES_256_GCM, aead_key_256(), &implicit_iv(), &[]);
        let mut dec = Tls12AeadAlgorithm::decrypter(&AES_256_GCM, aead_key_256(), &implicit_iv());

        let payload: &[u8] = b"tls 1.2 application data";
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(payload),
        };
        let opaque = enc.encrypt(msg, 100).expect("encrypt");

        let wire = opaque.encode();
        let mut body = wire[5..].to_vec(); // strip 5-byte record header

        let inbound = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            body.as_mut_slice(),
        );
        let plain = dec.decrypt(inbound, 100).expect("decrypt");
        assert_eq!(plain.payload, payload);
        assert_eq!(plain.typ, ContentType::ApplicationData);
    }

    /// Wrong sequence number on decrypt must fail — the seq feeds both the
    /// nonce (via explicit prefix on wire == seq on rustls side) and the AAD.
    #[test]
    fn aes256_gcm_wrong_seq_fails() {
        let mut enc =
            Tls12AeadAlgorithm::encrypter(&AES_256_GCM, aead_key_256(), &implicit_iv(), &[]);
        let mut dec = Tls12AeadAlgorithm::decrypter(&AES_256_GCM, aead_key_256(), &implicit_iv());

        let payload: &[u8] = b"x";
        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(payload),
        };
        let opaque = enc.encrypt(msg, 11).expect("encrypt");
        let wire = opaque.encode();
        let mut body = wire[5..].to_vec();
        let inbound = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            body.as_mut_slice(),
        );
        // seq=99 ≠ 11 → AAD mismatch → tag mismatch.
        assert!(dec.decrypt(inbound, 99).is_err());
    }

    /// `encrypted_payload_len(N)` exactly equals N + 8 (explicit nonce) +
    /// 16 (tag). Catches drift between this accessor and `encrypt` output.
    #[test]
    fn encrypted_payload_len_matches_encrypt_output() {
        let mut enc =
            Tls12AeadAlgorithm::encrypter(&AES_256_GCM, aead_key_256(), &implicit_iv(), &[]);
        let payload: &[u8] = b"abcdef";

        let predicted = enc.encrypted_payload_len(payload.len());

        let msg = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(payload),
        };
        let opaque = enc.encrypt(msg, 1).expect("encrypt");
        let body_len = opaque.encode().len() - 5;

        assert_eq!(predicted, body_len);
        assert_eq!(predicted, payload.len() + EXPLICIT_NONCE_LEN + TAG_LEN);
    }

    /// `key_block_shape` contract: AES-128 / AES-256 differ only in
    /// `enc_key_len`; both use the same 4-byte implicit IV + 8-byte
    /// explicit nonce. rustls derives the TLS 1.2 key_block layout from
    /// these numbers.
    #[test]
    fn key_block_shape_contract() {
        let s128 = Tls12AeadAlgorithm::key_block_shape(&AES_128_GCM);
        let s256 = Tls12AeadAlgorithm::key_block_shape(&AES_256_GCM);
        assert_eq!(s128.enc_key_len, 16);
        assert_eq!(s256.enc_key_len, 32);
        assert_eq!(s128.fixed_iv_len, IMPLICIT_IV_LEN);
        assert_eq!(s256.fixed_iv_len, IMPLICIT_IV_LEN);
        assert_eq!(s128.explicit_nonce_len, EXPLICIT_NONCE_LEN);
        assert_eq!(s256.explicit_nonce_len, EXPLICIT_NONCE_LEN);
    }

    /// `extract_keys` returns the right `ConnectionTrafficSecrets` variant
    /// for both AES widths. Required by callers exporting keys.
    #[test]
    fn extract_keys_aes128_variant() {
        let secrets = Tls12AeadAlgorithm::extract_keys(
            &AES_128_GCM,
            aead_key_256(),
            &implicit_iv(),
            &[0u8; 8],
        )
        .expect("extract");
        assert!(matches!(
            secrets,
            rustls::ConnectionTrafficSecrets::Aes128Gcm { .. }
        ));
    }

    #[test]
    fn extract_keys_aes256_variant() {
        let secrets = Tls12AeadAlgorithm::extract_keys(
            &AES_256_GCM,
            aead_key_256(),
            &implicit_iv(),
            &[0u8; 8],
        )
        .expect("extract");
        assert!(matches!(
            secrets,
            rustls::ConnectionTrafficSecrets::Aes256Gcm { .. }
        ));
    }

    /// FIPS-claim contract for both AEAD variants.
    #[test]
    fn aead_fips_contract() {
        assert!(Tls12AeadAlgorithm::fips(&AES_128_GCM));
        assert!(Tls12AeadAlgorithm::fips(&AES_256_GCM));
    }

    /// PRF FIPS contract — both wrappers must inherit the HMAC's FIPS claim.
    /// A regression flipping `PrfUsingHmac::fips()` (which hardcodes false)
    /// into our chain would silently break `Tls12CipherSuite::fips()`.
    #[test]
    fn prf_fips_contract() {
        assert!(PRF_SHA256.fips());
        assert!(PRF_SHA384.fips());
    }

    /// Decryption of a too-short payload (< explicit_nonce + tag) must
    /// error rather than panic — boundary safety against malformed records.
    #[test]
    fn aes256_gcm_too_short_payload_errors() {
        let mut dec = Tls12AeadAlgorithm::decrypter(&AES_256_GCM, aead_key_256(), &implicit_iv());
        let mut buf = [0u8; 10]; // < EXPLICIT_NONCE_LEN + TAG_LEN
        let inbound = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut buf[..],
        );
        assert!(dec.decrypt(inbound, 0).is_err());
    }

    /// PRF `for_secret`: HMAC-based P_hash must produce deterministic
    /// output. Catches a bug where PRF accidentally uses non-deterministic
    /// state (e.g. uninit memory).
    #[test]
    fn prf_for_secret_is_deterministic() {
        let secret = b"premaster_secret_dummy";
        let label = b"key expansion";
        let seed = b"server_random || client_random";
        let mut a = [0u8; 48];
        let mut b = [0u8; 48];
        PRF_SHA256.for_secret(&mut a, secret, label, seed);
        PRF_SHA256.for_secret(&mut b, secret, label, seed);
        assert_eq!(a, b);
        // Output must not be all zeros (a broken PRF that returns the
        // initial buffer would).
        assert!(a.iter().any(|&x| x != 0));
    }
}
