use anyhow::{Context, Result};
use reqwest::ClientBuilder;
use std::net::{IpAddr, SocketAddr};

/// Get the IP address of a network interface using the `if-addrs` crate
pub fn get_interface_ip(interface: &str) -> Result<IpAddr> {
    use if_addrs::get_if_addrs;

    let addrs = get_if_addrs().context("Failed to enumerate network interfaces")?;

    // Prefer IPv4 addresses
    for addr in &addrs {
        if addr.name == interface {
            if let if_addrs::IfAddr::V4(v4) = &addr.addr {
                return Ok(IpAddr::V4(v4.ip));
            }
        }
    }

    // Fallback to IPv6 if no IPv4 found
    for addr in &addrs {
        if addr.name == interface {
            if let if_addrs::IfAddr::V6(v6) = &addr.addr {
                return Ok(IpAddr::V6(v6.ip));
            }
        }
    }

    Err(anyhow::anyhow!(
        "Interface {} not found or has no IP address assigned",
        interface
    ))
}

/// Resolve binding address from interface name or source IP
pub fn resolve_bind_address(
    interface: Option<&String>,
    source_ip: Option<&String>,
) -> Result<Option<SocketAddr>> {
    if let Some(ip_str) = source_ip {
        let ip: IpAddr = ip_str.parse().context("Invalid source IP address format")?;
        return Ok(Some(SocketAddr::new(ip, 0)));
    }

    if let Some(iface) = interface {
        let ip = get_interface_ip(iface)
            .with_context(|| format!("Failed to get IP for interface {}", iface))?;
        return Ok(Some(SocketAddr::new(ip, 0)));
    }

    Ok(None)
}

/// Apply local address binding to a reqwest client builder.
/// If `bind_ip` is Some, binds the client to that local address.
pub fn apply_local_address(builder: ClientBuilder, bind_ip: Option<IpAddr>) -> ClientBuilder {
    match bind_ip {
        Some(ip) => builder.local_address(ip),
        None => builder,
    }
}

/// Reverse-lookup: find the interface name that owns a given IP address.
pub fn get_interface_for_ip(ip_str: &str) -> Option<String> {
    let target_ip: IpAddr = ip_str.parse().ok()?;
    let addrs = if_addrs::get_if_addrs().ok()?;

    for addr in &addrs {
        let iface_ip = match &addr.addr {
            if_addrs::IfAddr::V4(v4) => IpAddr::V4(v4.ip),
            if_addrs::IfAddr::V6(v6) => IpAddr::V6(v6.ip),
        };
        if iface_ip == target_ip {
            return Some(addr.name.clone());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Name of the loopback interface on the current platform.
    /// Linux/Android call it "lo"; macOS and the BSDs call it "lo0".
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const LOOPBACK_IFACE: &str = "lo";
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const LOOPBACK_IFACE: &str = "lo0";

    #[test]
    fn test_get_interface_for_ip_loopback() {
        // 127.0.0.1 is bound to the loopback interface ("lo" on Linux, "lo0" on macOS/BSD)
        let iface = get_interface_for_ip("127.0.0.1");
        assert_eq!(iface, Some(LOOPBACK_IFACE.to_string()));
    }

    #[test]
    fn test_get_interface_for_ip_not_found() {
        // No interface should own this arbitrary IP
        let iface = get_interface_for_ip("198.51.100.99");
        assert_eq!(iface, None);
    }

    #[test]
    fn test_get_interface_for_ip_invalid() {
        let iface = get_interface_for_ip("not-an-ip");
        assert_eq!(iface, None);
    }

    #[test]
    fn test_get_interface_ip_loopback() {
        let ip = get_interface_ip(LOOPBACK_IFACE).unwrap();
        assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_get_interface_ip_nonexistent() {
        let result = get_interface_ip("nonexistent_iface_xyz");
        assert!(result.is_err());
    }

    #[test]
    fn test_roundtrip_interface_to_ip_and_back() {
        // Get the IP for loopback, then reverse-lookup should return the loopback name
        let ip = get_interface_ip(LOOPBACK_IFACE).unwrap();
        let iface = get_interface_for_ip(&ip.to_string());
        assert_eq!(iface, Some(LOOPBACK_IFACE.to_string()));
    }

    #[test]
    fn test_resolve_bind_address_none() {
        let result = resolve_bind_address(None, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_bind_address_source_ip() {
        let source = "127.0.0.1".to_string();
        let result = resolve_bind_address(None, Some(&source)).unwrap();
        let addr = result.unwrap();
        assert_eq!(addr.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_resolve_bind_address_invalid_source() {
        let source = "not-an-ip".to_string();
        let result = resolve_bind_address(None, Some(&source));
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_bind_address_interface() {
        let iface = LOOPBACK_IFACE.to_string();
        let result = resolve_bind_address(Some(&iface), None).unwrap();
        let addr = result.unwrap();
        assert_eq!(addr.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_resolve_bind_address_source_takes_priority() {
        // When both are provided, source_ip wins
        let iface = LOOPBACK_IFACE.to_string();
        let source = "192.168.1.1".to_string();
        let result = resolve_bind_address(Some(&iface), Some(&source)).unwrap();
        let addr = result.unwrap();
        assert_eq!(addr.ip(), "192.168.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_apply_local_address_none() {
        // Should build successfully without binding
        let builder = reqwest::Client::builder();
        let client = apply_local_address(builder, None).build();
        assert!(client.is_ok());
    }

    #[test]
    fn test_apply_local_address_some() {
        // Should build successfully with binding
        let builder = reqwest::Client::builder();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let client = apply_local_address(builder, Some(ip)).build();
        assert!(client.is_ok());
    }
}
