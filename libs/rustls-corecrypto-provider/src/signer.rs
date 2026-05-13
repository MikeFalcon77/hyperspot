//! `KeyProvider` stub.
//!
//! hyperspot does not terminate TLS server-side in production (the gateway
//! handles HTTPS termination); the only `rustls::ServerConfig` usage in the
//! codebase is an E2E test in `oagw`. We therefore expose a `KeyProvider`
//! that refuses to load private keys. The trait is required to construct a
//! valid [`rustls::crypto::CryptoProvider`].

use std::sync::Arc;

use rustls::Error;
use rustls::crypto::KeyProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;

#[derive(Debug, Default)]
pub struct CoreCryptoKeyProvider;

impl KeyProvider for CoreCryptoKeyProvider {
    fn load_private_key(
        &self,
        _key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        Err(Error::General(
            "cf-rustls-corecrypto-provider: server-side TLS (private-key signing) is not supported"
                .to_owned(),
        ))
    }

    fn fips(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivatePkcs8KeyDer;

    /// The stub must reject every input with `Error::General` containing
    /// the documented marker text. A future maintainer accidentally wiring
    /// a real signer would break this test.
    #[test]
    fn load_private_key_rejects_with_documented_message() {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0u8; 16]));
        let err = CoreCryptoKeyProvider
            .load_private_key(key)
            .expect_err("stub must reject");
        match err {
            Error::General(msg) => {
                assert!(
                    msg.contains("server-side TLS"),
                    "error must explain that server-side TLS is unsupported; got {msg:?}"
                );
            }
            other => panic!("expected Error::General, got {other:?}"),
        }
    }

    /// FIPS-claim contract: KeyProvider must advertise FIPS so that rustls's
    /// `ClientConfig::fips()` invariant remains true when our provider is in
    /// use. Returning `false` here would silently disable rustls's FIPS
    /// assertions in downstream `tls.rs`.
    #[test]
    fn advertises_fips_to_rustls() {
        assert!(CoreCryptoKeyProvider.fips());
    }
}
