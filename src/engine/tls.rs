//! TLS handshake time measurement module

use crate::model::TlsSummary;
use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Install the ring crypto provider if not already installed.
fn ensure_crypto_provider() {
    // Install the ring provider as the default crypto provider.
    // This is safe to call multiple times - it will be a no-op if already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Measure TLS handshake time for a given hostname.
///
/// This measures only the TLS handshake, not including TCP connection time.
/// Returns a `TlsSummary` with handshake time, protocol version, and cipher suite.
pub async fn measure_tls_handshake(
    hostname: &str,
    port: u16,
    cert_path: Option<&std::path::Path>,
) -> Result<TlsSummary> {
    // Ensure the crypto provider is installed
    ensure_crypto_provider();

    // Create root certificate store from webpki-roots, plus any user-supplied CA.
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = cert_path {
        for cert in super::cert::load_rustls_certificates(path)? {
            root_store
                .add(cert)
                .with_context(|| format!("failed to add custom CA from {}", path.display()))?;
        }
    }

    // Build TLS client config
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    // First establish TCP connection (we don't time this)
    let addr = format!("{}:{}", hostname, port);
    let tcp_stream = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("TCP connection failed to {}", addr))?;

    // Parse server name for TLS
    let server_name: ServerName<'static> = hostname
        .to_string()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid DNS name: {}", hostname))?;

    // Time only the TLS handshake
    let start = Instant::now();
    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .with_context(|| format!("TLS handshake failed with {}", hostname))?;
    let handshake_time = start.elapsed();

    // Extract TLS session info
    let (_, session) = tls_stream.get_ref();

    let protocol_version = session.protocol_version().map(|v| format!("{:?}", v));

    let cipher_suite = session
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()));

    Ok(TlsSummary {
        handshake_time_ms: handshake_time.as_secs_f64() * 1000.0,
        protocol_version,
        cipher_suite,
    })
}

/// Extract hostname and port from a URL string.
pub fn extract_host_port(url: &str) -> Option<(String, u16)> {
    reqwest::Url::parse(url).ok().and_then(|u| {
        let host = u.host_str()?.to_string();
        let port = u.port_or_known_default().unwrap_or(443);
        Some((host, port))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host_port() {
        assert_eq!(
            extract_host_port("https://speed.cloudflare.com"),
            Some(("speed.cloudflare.com".to_string(), 443))
        );
        assert_eq!(
            extract_host_port("https://example.com:8443/path"),
            Some(("example.com".to_string(), 8443))
        );
        assert_eq!(
            extract_host_port("http://example.com"),
            Some(("example.com".to_string(), 80))
        );
    }
}
