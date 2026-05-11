//! TLS handshake time measurement module

use crate::model::{IpVersionFilter, TlsSummary};
use anyhow::{anyhow, Context, Result};
use rustls::pki_types::ServerName;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{lookup_host, TcpSocket};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// Per-address TCP connect timeout. Kept short so unreachable addresses
/// (e.g. blackholed IPv6) fall through to the next candidate quickly instead
/// of stalling on the kernel's SYN retransmit timer (~75-180s).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Overall TLS handshake timeout, applied separately from TCP connect.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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
///
/// When `bind_ip` is set, candidate addresses are filtered to the bind IP's
/// family and the TCP socket is bound to that source IP before connect. This
/// keeps the measurement on the same interface the rest of the test runs on
/// (e.g. `--interface wg0`).
pub async fn measure_tls_handshake(
    hostname: &str,
    port: u16,
    cert_path: Option<&std::path::Path>,
    bind_ip: Option<IpAddr>,
    filter: IpVersionFilter,
) -> Result<TlsSummary> {
    // Ensure the crypto provider is installed
    ensure_crypto_provider();

    // Create root certificate store from webpki-roots, plus any user-supplied CA.
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Native stores can include legacy certs rustls won't parse; skip those rather than failing.
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = root_store.add(cert);
    }

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

    // Resolve and connect, trying each address until one succeeds.
    // Candidates are filtered by both the IP-version filter (--ipv4-only / --ipv6-only)
    // and the bind IP family so the kernel can actually reach them.
    let tcp_stream = connect_tcp(hostname, port, bind_ip, filter).await?;

    // Parse server name for TLS
    let server_name: ServerName<'static> = hostname
        .to_string()
        .try_into()
        .map_err(|_| anyhow!("Invalid DNS name: {}", hostname))?;

    // Time only the TLS handshake
    let start = Instant::now();
    let tls_stream = timeout(HANDSHAKE_TIMEOUT, connector.connect(server_name, tcp_stream))
        .await
        .with_context(|| format!("TLS handshake timed out after {:?}", HANDSHAKE_TIMEOUT))?
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

/// Resolve `hostname:port` and connect to the first reachable address whose
/// family matches `bind_ip` (or any family if `bind_ip` is None). Binds the
/// socket to `bind_ip` before connecting when set, and applies a per-address
/// connect timeout so unreachable addresses don't stall the test.
async fn connect_tcp(
    hostname: &str,
    port: u16,
    bind_ip: Option<IpAddr>,
    filter: IpVersionFilter,
) -> Result<tokio::net::TcpStream> {
    let lookup_target = format!("{}:{}", hostname, port);
    let resolved: Vec<SocketAddr> = lookup_host(&lookup_target)
        .await
        .with_context(|| format!("DNS lookup failed for {}", hostname))?
        .collect();

    if resolved.is_empty() {
        return Err(anyhow!("DNS returned no addresses for {}", hostname));
    }

    // Filter by IP-version selection first, then by bind family if set.
    let candidates: Vec<SocketAddr> = resolved
        .iter()
        .copied()
        .filter(|a| filter.allows_socket(*a))
        .filter(|a| match bind_ip {
            Some(IpAddr::V4(_)) => a.is_ipv4(),
            Some(IpAddr::V6(_)) => a.is_ipv6(),
            None => true,
        })
        .collect();

    if candidates.is_empty() {
        return Err(anyhow!(
            "no resolved address for {} matches the requested IP family / bind IP",
            hostname
        ));
    }

    let mut last_err: Option<anyhow::Error> = None;
    for addr in candidates {
        let socket = match if addr.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        } {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(anyhow!(e).context("failed to create socket"));
                continue;
            }
        };

        if let Some(ip) = bind_ip {
            if let Err(e) = socket.bind(SocketAddr::new(ip, 0)) {
                last_err = Some(anyhow!(e).context(format!("failed to bind to {}", ip)));
                continue;
            }
        }

        match timeout(CONNECT_TIMEOUT, socket.connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last_err = Some(anyhow!(e).context(format!("connect to {} failed", addr))),
            Err(_) => {
                last_err = Some(anyhow!(
                    "connect to {} timed out after {:?}",
                    addr,
                    CONNECT_TIMEOUT
                ))
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow!("no addresses to try for {}", hostname)))
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
