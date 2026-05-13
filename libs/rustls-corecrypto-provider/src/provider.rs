//! Final assembly of the [`rustls::crypto::CryptoProvider`].
//!
//! Combines:
//! - 2 TLS 1.3 cipher suites (AES-128/256-GCM with SHA-256/384)
//! - 4 TLS 1.2 GCM cipher suites (ECDHE_ECDSA / ECDHE_RSA × AES-128/256)
//! - 2 key exchange groups (P-256, P-384)
//! - 8 signature verification algorithms (ECDSA + RSA-PSS + RSA-PKCS#1)
//! - Apple `SecRandom` as `SecureRandom`
//! - `KeyProvider` stub (server-side TLS unsupported)
//!
//! All operations route through Apple corecrypto (FIPS-validated module).

use rustls::crypto::CipherSuiteCommon;
use rustls::crypto::CryptoProvider;
use rustls::crypto::KeyExchangeAlgorithm;
use rustls::{
    CipherSuite, SignatureScheme, SupportedCipherSuite, Tls12CipherSuite, Tls13CipherSuite,
};

use crate::hash::{SHA256, SHA384};
use crate::hkdf::{HKDF_SHA256, HKDF_SHA384};
use crate::kx::{SECP256R1, SECP384R1};
use crate::random::CoreCryptoRandom;
use crate::signer::CoreCryptoKeyProvider;
use crate::tls12;
use crate::tls13;
use crate::verify::SUPPORTED_SIG_ALGS;

// =========================================================================
// TLS 1.3 cipher suites
// =========================================================================

pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            // RFC 8446 §5.5 / TLS WG guidance for AES-GCM: limit to 2^23.5
            // records before rekey. We use the conservative 2^23.
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &HKDF_SHA256,
        aead_alg: &tls13::AES_128_GCM,
        quic: None,
    });

pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &HKDF_SHA384,
        aead_alg: &tls13::AES_256_GCM,
        quic: None,
    });

// =========================================================================
// TLS 1.2 cipher suites
// =========================================================================

pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: ECDSA_SIG_SCHEMES,
        aead_alg: &tls12::AES_128_GCM,
        prf_provider: &tls12::PRF_SHA256,
    });

pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: ECDSA_SIG_SCHEMES,
        aead_alg: &tls12::AES_256_GCM,
        prf_provider: &tls12::PRF_SHA384,
    });

pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: RSA_SIG_SCHEMES,
        aead_alg: &tls12::AES_128_GCM,
        prf_provider: &tls12::PRF_SHA256,
    });

pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            hash_provider: &SHA384,
            confidentiality_limit: 1 << 23,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: RSA_SIG_SCHEMES,
        aead_alg: &tls12::AES_256_GCM,
        prf_provider: &tls12::PRF_SHA384,
    });

const ECDSA_SIG_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
];

const RSA_SIG_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
];

// =========================================================================
// Default cipher-suite list
// =========================================================================

pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    // TLS 1.3 preferred.
    TLS13_AES_256_GCM_SHA384,
    TLS13_AES_128_GCM_SHA256,
    // TLS 1.2 fallback, ECDSA first then RSA, AES-256 first.
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];

// =========================================================================
// CryptoProvider construction
// =========================================================================

static SECURE_RANDOM: CoreCryptoRandom = CoreCryptoRandom;
static KEY_PROVIDER: CoreCryptoKeyProvider = CoreCryptoKeyProvider;

/// Construct the corecrypto-backed [`CryptoProvider`].
///
/// All operations route through Apple corecrypto (FIPS-validated module).
/// The returned provider can be installed process-wide via
/// `provider.install_default()` or passed to
/// `rustls::ClientConfig::builder_with_provider`.
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: vec![&SECP256R1, &SECP384R1],
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &SECURE_RANDOM,
        key_provider: &KEY_PROVIDER,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    /// The provider's `secure_random` must produce distinct output across
    /// calls. A broken delegation (e.g. returning a constant) would fail.
    #[test]
    fn secure_random_produces_distinct_output_across_calls() {
        let p = default_provider();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        p.secure_random.fill(&mut a).expect("fill a");
        p.secure_random.fill(&mut b).expect("fill b");
        assert_ne!(a, b);
    }

    /// The provider's `key_provider` rejects private keys (server-side TLS
    /// is intentionally unsupported).
    #[test]
    fn key_provider_refuses_private_keys() {
        let p = default_provider();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0u8; 16]));
        let result = p.key_provider.load_private_key(key);
        match result {
            Err(rustls::Error::General(msg)) => {
                assert!(
                    msg.contains("server-side TLS"),
                    "rejection should reference server-side TLS; got {msg:?}"
                );
            }
            other => panic!("expected Error::General, got {other:?}"),
        }
    }

    /// 2 TLS 1.3 + 4 TLS 1.2 cipher suites are exposed — without all of them,
    /// rustls would fail to negotiate with peers that only offer a subset.
    #[test]
    fn provider_exposes_six_cipher_suites() {
        let p = default_provider();
        assert_eq!(p.cipher_suites.len(), 6);
    }

    /// Both NIST P-curves are exposed.
    #[test]
    fn provider_exposes_two_kx_groups() {
        let p = default_provider();
        assert_eq!(p.kx_groups.len(), 2);
        // ECDHE relies on at least P-256 being available; assert both are.
        let names: Vec<_> = p.kx_groups.iter().map(|g| g.name()).collect();
        assert!(names.contains(&rustls::NamedGroup::secp256r1));
        assert!(names.contains(&rustls::NamedGroup::secp384r1));
    }

    /// `CryptoProvider::fips()` must return true — this asserts that EVERY
    /// constituent component (each cipher suite's hash/HKDF/AEAD/PRF, every
    /// kx group, every signature alg, the RNG, the key provider) advertises
    /// FIPS. Catches a regression where any one component flips its `fips()`
    /// override to false.
    #[test]
    fn provider_advertises_fips_across_all_components() {
        let p = default_provider();
        // Component-by-component diagnostic so a regression points at the
        // exact failing component.
        for cs in &p.cipher_suites {
            assert!(cs.fips(), "cipher suite {:?} not FIPS", cs.suite());
        }
        for kx in &p.kx_groups {
            assert!(kx.fips(), "kx group {:?} not FIPS", kx.name());
        }
        assert!(
            p.signature_verification_algorithms.fips(),
            "sig algs not FIPS"
        );
        assert!(p.secure_random.fips(), "secure_random not FIPS");
        assert!(p.key_provider.fips(), "key_provider not FIPS");
        assert!(p.fips(), "overall provider not FIPS");
    }

    /// A `ClientConfig` built with our provider AND with EMS required (the
    /// TLS-protocol-level NIST recommendation) must advertise FIPS.
    #[test]
    fn client_config_with_ems_required_advertises_fips() {
        let mut config = rustls::ClientConfig::builder_with_provider(default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("protocol versions")
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        // ClientConfig::fips() in tls12-enabled rustls also gates on EMS.
        // Setting it explicitly mirrors how a FIPS-conscious caller would
        // configure rustls.
        config.require_ems = true;

        assert!(
            config.fips(),
            "ClientConfig built from corecrypto provider with require_ems=true must advertise FIPS"
        );
    }
}
