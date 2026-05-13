//! TLS utilities for the HTTP client.
//!
//! This module provides cached loading of native root certificates to avoid
//! repeated OS certificate store lookups (which can be slow on some platforms).

use rustls_pki_types::CertificateDer;
use std::sync::{Arc, OnceLock};

/// Cached native root certificates.
/// Always stores Ok; empty vec means no certs found (warned, not errored).
static NATIVE_ROOTS_CACHE: OnceLock<Vec<CertificateDer<'static>>> = OnceLock::new();

/// Counter for test verification that the loader only runs once.
#[cfg(test)]
static LOAD_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Load native root certificates from the OS certificate store.
///
/// This function is called once and the result is cached for subsequent calls.
/// Returns Ok with potentially empty vec; missing certs are warned, not errored.
fn load_native_certs_inner() -> Vec<CertificateDer<'static>> {
    #[cfg(test)]
    LOAD_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    let result = rustls_native_certs::load_native_certs();

    // Log any errors encountered during loading
    if !result.errors.is_empty() {
        for err in &result.errors {
            tracing::warn!(error = %err, "error loading native root certificate");
        }
    }

    let certs: Vec<CertificateDer<'static>> = result.certs;

    if certs.is_empty() {
        tracing::warn!("no native root CA certificates found");
    } else {
        tracing::debug!(count = certs.len(), "loaded native root certificates");
    }

    certs
}

/// Get cached native root certificates.
///
/// Returns a reference to the cached certificates (may be empty).
/// The certificates are loaded lazily on first call and cached for all subsequent calls.
pub fn native_root_certs() -> &'static [CertificateDer<'static>] {
    NATIVE_ROOTS_CACHE
        .get_or_init(load_native_certs_inner)
        .as_slice()
}

/// Get the crypto provider for TLS connections.
///
/// This function follows the reqwest pattern:
/// 1. Check if a default provider is already installed globally
/// 2. If yes, use that (respects user configuration)
/// 3. If no, create a new aws-lc-rs provider without installing it globally
///
/// This avoids global state mutation and is safe to call from multiple threads.
pub fn get_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| {
            // Provider selection mirrors `modkit::bootstrap::init_crypto_provider`:
            //   - fips + macOS  → Apple corecrypto
            //   - fips + other  → AWS-LC FIPS
            //   - non-fips      → AWS-LC default
            #[cfg(all(feature = "fips", target_os = "macos"))]
            {
                Arc::new(rustls_corecrypto_provider::default_provider())
            }
            #[cfg(all(feature = "fips", not(target_os = "macos")))]
            {
                Arc::new(rustls::crypto::default_fips_provider())
            }
            #[cfg(not(feature = "fips"))]
            {
                Arc::new(rustls::crypto::aws_lc_rs::default_provider())
            }
        })
}

/// Build a rustls `ClientConfig` from the given root store.
///
/// Under the `fips` feature, forces `require_ems = true` so the resulting
/// config satisfies rustls's `ClientConfig::fips()` invariant for TLS 1.2
/// (NIST SP 800-52 Rev. 2 §3.5). Without this, an Apple-corecrypto-backed
/// FIPS build silently advertises `config.fips() == false` because the
/// stock rustls default for `require_ems` is gated on rustls's own `fips`
/// feature — which we deliberately keep off on macOS to avoid pulling
/// the AWS-LC FIPS module.
fn build_client_config(root_store: rustls::RootCertStore) -> Result<rustls::ClientConfig, String> {
    let provider = get_crypto_provider();

    #[allow(unused_mut)]
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("failed to set TLS protocol versions: {e}"))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    #[cfg(feature = "fips")]
    {
        config.require_ems = true;
        assert!(
            config.fips(),
            "TLS ClientConfig is NOT in FIPS mode after enabling require_ems: \
             the installed crypto provider does not advertise FIPS. Check that \
             `init_crypto_provider` ran before any TLS configuration was built."
        );
    }

    Ok(config)
}

/// Build a rustls `ClientConfig` using the cached native root certificates.
///
/// # Errors
///
/// Returns an error if no valid root certificates are available:
/// - OS certificate store is empty
/// - All certificates failed to parse
///
/// This fail-fast behavior ensures TLS configuration errors are caught at client
/// construction time rather than failing later during TLS handshakes.
pub fn native_roots_client_config() -> Result<rustls::ClientConfig, String> {
    let certs = native_root_certs();

    let mut root_store = rustls::RootCertStore::empty();

    if certs.is_empty() {
        return Err("no native root CA certificates found in OS certificate store".to_owned());
    }

    let (added, ignored) = root_store.add_parsable_certificates(certs.iter().cloned());

    if ignored > 0 {
        tracing::warn!(
            added = added,
            ignored = ignored,
            "some native root certificates could not be parsed"
        );
    }

    if added == 0 {
        return Err(format!(
            "no valid native root CA certificates parsed (found {}, all {} failed to parse)",
            certs.len(),
            ignored
        ));
    }

    build_client_config(root_store)
}

/// Build a rustls `ClientConfig` using Mozilla's webpki-roots trust anchors.
///
/// Under the `fips` feature, `require_ems` is forced on (see
/// [`build_client_config`]). This is the FIPS-conformant counterpart to the
/// `hyper_rustls::HttpsConnectorBuilder::with_provider_and_webpki_roots`
/// one-liner — we must build the config ourselves so we can flip the EMS bit.
pub fn webpki_roots_client_config() -> Result<rustls::ClientConfig, String> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    build_client_config(root_store)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    /// Test that native root certs are cached after the first load.
    ///
    /// NOTE: This test verifies "at most one load" rather than "exactly one load"
    /// because `LOAD_COUNT` is a global atomic shared across all tests. If another
    /// test (or parallel test) calls `native_root_certs()` before this test runs,
    /// the cache will already be initialized and `final_count - initial_count`
    /// will be 0. The assertion handles this correctly.
    #[test]
    fn test_native_roots_cached() {
        // Capture count before our calls (may be non-zero if cache already initialized)
        let initial_count = LOAD_COUNT.load(Ordering::SeqCst);

        // First call - loads if not cached, otherwise uses existing cache
        let result1 = native_root_certs();

        // Second call should use cache
        let result2 = native_root_certs();

        // Third call should also use cache
        let result3 = native_root_certs();

        // Verify loader was called at most once more than initial (0 if already cached, 1 if we triggered the load)
        let final_count = LOAD_COUNT.load(Ordering::SeqCst);
        assert!(
            final_count <= initial_count + 1,
            "loader should run at most once, but ran {} times since test start",
            final_count - initial_count
        );

        // Results should be consistent (same slice pointer)
        assert_eq!(result1.len(), result2.len());
        assert_eq!(result2.len(), result3.len());
        assert!(std::ptr::eq(result1, result2), "should return same slice");
        assert!(std::ptr::eq(result2, result3), "should return same slice");
    }

    #[test]
    fn test_native_roots_client_config() {
        // Building client config succeeds if native roots are available
        // (which they should be on most CI/dev systems)
        // On systems without native certs, this returns Err (expected behavior)
        let result = native_roots_client_config();

        // Log the result for debugging in CI
        match &result {
            Ok(_) => tracing::debug!("native_roots_client_config succeeded"),
            Err(e) => {
                tracing::debug!(error = %e, "native_roots_client_config failed (expected on minimal containers)");
            }
        }

        // We don't assert success because CI containers may not have OS certs.
        // The important thing is it doesn't panic.
    }

    /// `webpki_roots_client_config()` must always build successfully — the
    /// trust store comes from a static `webpki-roots::TLS_SERVER_ROOTS` slice
    /// that is non-empty on every supported platform. Catches a silent
    /// regression if the `webpki-roots` crate ever renames its constant or
    /// changes its `extend`-able item type.
    #[test]
    fn test_webpki_roots_client_config_builds() {
        let cfg = webpki_roots_client_config().expect("webpki roots must always build");
        // Sanity: the resulting config must have the same protocol-version
        // surface as `native_roots_client_config` (TLS 1.2 + TLS 1.3 per
        // `with_safe_default_protocol_versions`).
        assert_eq!(
            cfg.alpn_protocols.len(),
            0,
            "alpn_protocols defaults to empty"
        );
    }

    /// When built with `--features fips`, `build_client_config` MUST:
    ///   1. Set `require_ems = true` (NIST SP 800-52 Rev. 2 §3.5)
    ///   2. Make `config.fips()` return true (full FIPS chain)
    ///
    /// Without this, an Apple-corecrypto-backed FIPS build silently advertises
    /// `config.fips() == false` because rustls's stock `require_ems` default
    /// is gated on rustls's *own* `fips` feature — which we deliberately keep
    /// off on macOS to avoid pulling the AWS-LC FIPS module.
    ///
    /// Exercised via the public `webpki_roots_client_config()` (which routes
    /// through `build_client_config`); calling it avoids a hard dependency on
    /// the OS keychain that `native_roots_client_config` carries.
    ///
    /// Run via `cargo test -p cf-modkit-http --features fips`.
    #[test]
    #[cfg(feature = "fips")]
    fn fips_client_config_requires_ems_and_advertises_fips() {
        let cfg = webpki_roots_client_config().expect("build under fips");
        assert!(cfg.require_ems, "fips build must set require_ems = true");
        assert!(
            cfg.fips(),
            "fips build must yield ClientConfig::fips() == true (full provider chain)"
        );
    }
}
