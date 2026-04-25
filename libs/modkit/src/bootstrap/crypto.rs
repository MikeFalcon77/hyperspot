use std::sync::Once;

/// Error returned when the crypto provider cannot be installed.
#[derive(Debug, thiserror::Error)]
pub enum CryptoProviderError {
    /// Another crypto provider was already installed (FIPS mode).
    #[error("failed to install FIPS crypto provider - another provider is already installed")]
    FipsProviderConflict,
}

static INSTALLED: Once = Once::new();

/// Install the process-wide default rustls [`CryptoProvider`](rustls::crypto::CryptoProvider).
///
/// - **FIPS mode** (`fips` feature): installs the FIPS-validated AWS-LC provider
///   (`aws-lc-fips-sys`, NIST Certificate #4816).
/// - **Standard mode**: installs the `aws-lc-rs` provider explicitly. This is
///   required because both `ring` and `aws-lc-rs` are compiled into the binary
///   (ring via `aliri`/`pingora-rustls`), and rustls 0.23 panics when it cannot
///   auto-detect a single provider.
///
/// This **must** be called before any TLS configuration, HTTP client, database
/// connection, or JWT operation is created.
///
/// Safe to call multiple times — only the first invocation has an effect.
///
/// # Errors
///
/// Returns [`CryptoProviderError::FipsProviderConflict`] if the `fips` feature is
/// enabled and another crypto provider has already been installed.
pub fn init_crypto_provider() -> Result<(), CryptoProviderError> {
    #[allow(unused_mut)]
    let mut result = Ok(());

    INSTALLED.call_once(|| {
        #[cfg(feature = "fips")]
        {
            if rustls::crypto::default_fips_provider()
                .install_default()
                .is_err()
            {
                result = Err(CryptoProviderError::FipsProviderConflict);
                return;
            }
            tracing::info!("FIPS-140-3 crypto provider installed (AWS-LC FIPS module)");
        }

        #[cfg(not(feature = "fips"))]
        {
            #[allow(clippy::let_underscore_must_use)]
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
    });

    result
}
