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
/// Dispatch:
///
/// - **`fips` feature + macOS**: installs the Apple corecrypto-backed
///   provider from `cf-rustls-corecrypto-provider`. corecrypto is shipped
///   inside macOS and validated by Apple under FIPS 140-3 per OS release;
///   see <https://csrc.nist.gov/projects/cryptographic-module-validation-program>
///   for the cert matching the running macOS version.
///   Note: `rustls/fips` is still enabled in the workspace, so the AWS-LC
///   FIPS dylib is also compiled in but **not invoked** for any TLS data
///   path on macOS — it is dead code at runtime. Cleanup of that dep
///   pull-through is a separate workspace-level task.
/// - **`fips` feature + non-macOS** (Linux, etc.): installs the AWS-LC
///   FIPS-validated provider (`aws-lc-fips-sys`, NIST cert #4816). The
///   cert's OE covers Linux but not Darwin, which is why the macOS branch
///   uses a different provider.
/// - **Standard mode** (no `fips` feature): installs the standard
///   `aws-lc-rs` provider explicitly. This is required because both `ring`
///   and `aws-lc-rs` are compiled into the binary (ring via
///   `aliri`/`pingora-rustls`), and rustls 0.23 panics when it cannot
///   auto-detect a single provider.
///
/// This **must** be called before any TLS configuration, HTTP client,
/// database connection, or JWT operation is created.
///
/// Safe to call multiple times — only the first invocation has an effect.
///
/// # Errors
///
/// Returns [`CryptoProviderError::FipsProviderConflict`] if the `fips`
/// feature is enabled and another crypto provider has already been
/// installed.
pub fn init_crypto_provider() -> Result<(), CryptoProviderError> {
    // `mut` is only needed in the `fips` branches (which reassign `result`
    // on provider conflict); the non-fips branch never writes to it.
    #[cfg(feature = "fips")]
    let mut result = Ok(());
    #[cfg(not(feature = "fips"))]
    let result = Ok(());

    INSTALLED.call_once(|| {
        #[cfg(all(feature = "fips", target_os = "macos"))]
        {
            if rustls_corecrypto_provider::default_provider()
                .install_default()
                .is_err()
            {
                result = Err(CryptoProviderError::FipsProviderConflict);
                return;
            }
            tracing::info!("FIPS-140-3 crypto provider installed (Apple corecrypto, macOS)");
        }

        #[cfg(all(feature = "fips", not(target_os = "macos")))]
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
            // A provider may already have been installed (e.g. by tests); ignore that case.
            let _ignored = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
    });

    result
}
