use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use crate::halo_protocol::discovery::{DISCOVERY_ALPN, decode_observed_addr};

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Query a `halo-discovery` QUIC server using the provided bound UDP socket so
/// the discovered external `SocketAddr` reflects this exact socket's port/mapping.
pub async fn discover_external_addr(
    socket: &std::net::UdpSocket,
    server: SocketAddr,
) -> Result<SocketAddr> {
    let sock_clone = socket
        .try_clone()
        .context("failed to clone UDP socket for discovery")?;
    let runtime = quinn::default_runtime().context("no async runtime available")?;

    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        sock_clone,
        runtime,
    )
    .context("failed to create discovery QUIC endpoint")?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    // shortcut: skips TLS cert verification for self-signed discovery server, pin server cert/key before production
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![DISCOVERY_ALPN.to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_crypto)));

    let conn = tokio::time::timeout(DISCOVERY_TIMEOUT, endpoint.connect(server, "localhost")?)
        .await
        .with_context(|| format!("timed out connecting to discovery server {server}"))?
        .with_context(|| format!("failed to connect to discovery server {server}"))?;

    let mut stream = tokio::time::timeout(DISCOVERY_TIMEOUT, conn.accept_uni())
        .await
        .context("timed out waiting for discovery response stream")?
        .context("discovery server closed connection before responding")?;

    let bytes = tokio::time::timeout(DISCOVERY_TIMEOUT, stream.read_to_end(32))
        .await
        .context("timed out reading discovery response")?
        .context("failed to read discovery response")?;

    let observed = decode_observed_addr(&bytes)?;
    conn.close(0u32.into(), b"ok");
    let _ = tokio::time::timeout(Duration::from_millis(500), endpoint.wait_idle()).await;
    drop(endpoint);

    tracing::info!(%server, %observed, "discovered external address");
    Ok(observed)
}

#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
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
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
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
