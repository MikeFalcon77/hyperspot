//! End-to-end handshake smoke against `openssl s_server`.
//!
//! Verifies that the entire provider stack — AEAD wire framing, HKDF key
//! schedule, ECDH key exchange, signature verification — composes correctly
//! into a working TLS client. A failure here points at integration bugs
//! that unit tests cannot catch (wrong AAD format, wrong nonce derivation,
//! missing or wrong cipher-suite wiring, etc.).
//!
//! Each test spins up a local openssl s_server on an ephemeral port,
//! performs one full handshake using rustls + our provider, exchanges a
//! short HTTP request/response, and tears the server down.

#![cfg(target_os = "macos")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, Stream};
use rustls_corecrypto_provider::default_provider;

/// Custom verifier that accepts any server certificate but routes
/// signature verification through our provider's `SUPPORTED_SIG_ALGS`.
/// This isolates the test from cert chain validity while still
/// exercising the signature verification path on TLS 1.2 ServerKeyExchange
/// and TLS 1.3 CertificateVerify.
#[derive(Debug)]
struct AcceptAnyServerCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Spawn openssl s_server with a fresh self-signed cert/key.
///
/// Returns (child handle, listening port, tempdir holding cert files).
fn spawn_s_server(extra_args: &[&str]) -> (Child, u16, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cert = tmp.path().join("cert.pem");
    let key = tmp.path().join("key.pem");

    // Generate self-signed RSA 2048 cert valid for localhost.
    let req = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            cert.to_str().unwrap(),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("openssl req");
    assert!(req.success(), "openssl req failed");

    // Reserve an ephemeral port from the OS, then release it immediately
    // so openssl can bind to the same number. There's a tiny TOCTOU race
    // window, but in practice the OS doesn't recycle ports that fast — and
    // if a collision happens we retry up to 5 times.
    for _ in 0..5 {
        let port = match TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l.local_addr().expect("local_addr").port(),
            Err(_) => continue,
        };
        // Listener dropped here; openssl can reclaim the port.

        let mut cmd = Command::new("openssl");
        cmd.args([
            "s_server",
            "-cert",
            cert.to_str().unwrap(),
            "-key",
            key.to_str().unwrap(),
            "-accept",
            &port.to_string(),
            "-www",
            "-quiet",
        ]);
        for a in extra_args {
            cmd.arg(a);
        }
        let Ok(mut child) = cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn() else {
            continue;
        };

        // Wait briefly for the server to bind. Up to 1s.
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(50));
            if TcpStream::connect(("localhost", port)).is_ok() {
                return (child, port, tmp);
            }
        }
        let _ = child.kill();
    }
    panic!("could not bind openssl s_server on an ephemeral port after 5 attempts");
}

fn client_config() -> ClientConfig {
    let provider = Arc::new(default_provider());
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("default versions")
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)));
    config
}

fn do_handshake_and_get(
    config: ClientConfig,
    port: u16,
) -> (
    rustls::ProtocolVersion,
    rustls::SupportedCipherSuite,
    Vec<u8>,
) {
    let mut sock = TcpStream::connect(("localhost", port)).expect("tcp connect");
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let server = ServerName::try_from("localhost").unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), server).expect("client conn");
    let mut tls = Stream::new(&mut conn, &mut sock);

    tls.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .expect("write");
    tls.flush().expect("flush");

    let mut buf = Vec::with_capacity(4096);
    let _ = tls.read_to_end(&mut buf);

    let version = conn.protocol_version().expect("negotiated version");
    let suite = conn.negotiated_cipher_suite().expect("negotiated suite");
    (version, suite, buf)
}

/// Full TLS 1.3 handshake: AES-128-GCM-SHA256. Exercises HKDF-SHA-256,
/// ECDHE P-256, RSA-PSS-SHA256 signature verification, AEAD encrypt+decrypt
/// of TLS 1.3 wire records.
#[test]
fn handshake_tls13_aes128_gcm_sha256() {
    let (mut server, port, _tmp) =
        spawn_s_server(&["-tls1_3", "-ciphersuites", "TLS_AES_128_GCM_SHA256"]);
    let (version, suite, body) = do_handshake_and_get(client_config(), port);
    let _ = server.kill();

    assert_eq!(version, rustls::ProtocolVersion::TLSv1_3);
    assert_eq!(suite.suite(), rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
    assert!(!body.is_empty(), "expected non-empty HTTP response");
    assert!(
        body.windows(4).any(|w| w == b"HTTP"),
        "expected HTTP response, got {:?}",
        String::from_utf8_lossy(&body[..body.len().min(200)])
    );
}

/// Full TLS 1.3 handshake: AES-256-GCM-SHA384. Different hash, HKDF, and
/// AEAD key length — catches bugs that only manifest with the longer suite.
#[test]
fn handshake_tls13_aes256_gcm_sha384() {
    let (mut server, port, _tmp) =
        spawn_s_server(&["-tls1_3", "-ciphersuites", "TLS_AES_256_GCM_SHA384"]);
    let (version, suite, body) = do_handshake_and_get(client_config(), port);
    let _ = server.kill();

    assert_eq!(version, rustls::ProtocolVersion::TLSv1_3);
    assert_eq!(suite.suite(), rustls::CipherSuite::TLS13_AES_256_GCM_SHA384);
    assert!(!body.is_empty());
    assert!(body.windows(4).any(|w| w == b"HTTP"));
}

/// Full TLS 1.2 handshake: ECDHE_RSA_AES_256_GCM_SHA384. Different
/// key-schedule (PRF P_hash, not HKDF), explicit-nonce AEAD wire format,
/// distinct ServerKeyExchange + CertificateVerify flow.
#[test]
fn handshake_tls12_ecdhe_rsa_aes256_gcm_sha384() {
    let (mut server, port, _tmp) =
        spawn_s_server(&["-tls1_2", "-cipher", "ECDHE-RSA-AES256-GCM-SHA384"]);
    let (version, suite, body) = do_handshake_and_get(client_config(), port);
    let _ = server.kill();

    assert_eq!(version, rustls::ProtocolVersion::TLSv1_2);
    assert_eq!(
        suite.suite(),
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    );
    assert!(!body.is_empty());
    assert!(body.windows(4).any(|w| w == b"HTTP"));
}
