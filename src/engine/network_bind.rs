use crate::model::IpVersionFilter;
use anyhow::{Context, Result};
use reqwest::ClientBuilder;
use std::net::{IpAddr, SocketAddr};

/// Get the IP address of a network interface using the `if-addrs` crate.
///
/// When `filter` is `V4Only` or `V6Only`, only addresses of that family are
/// considered. With `Auto`, IPv4 is preferred and IPv6 is used as a fallback.
pub fn get_interface_ip(interface: &str, filter: IpVersionFilter) -> Result<IpAddr> {
    use if_addrs::get_if_addrs;

    let addrs = get_if_addrs().context("Failed to enumerate network interfaces")?;

    let want_v4 = matches!(filter, IpVersionFilter::Auto | IpVersionFilter::V4Only);
    let want_v6 = matches!(filter, IpVersionFilter::Auto | IpVersionFilter::V6Only);

    if want_v4 {
        for addr in &addrs {
            if addr.name == interface {
                if let if_addrs::IfAddr::V4(v4) = &addr.addr {
                    return Ok(IpAddr::V4(v4.ip));
                }
            }
        }
    }

    if want_v6 {
        for addr in &addrs {
            if addr.name == interface {
                if let if_addrs::IfAddr::V6(v6) = &addr.addr {
                    return Ok(IpAddr::V6(v6.ip));
                }
            }
        }
    }

    match filter {
        IpVersionFilter::Auto => Err(anyhow::anyhow!(
            "Interface {} not found or has no IP address assigned",
            interface
        )),
        _ => Err(anyhow::anyhow!(
            "Interface {} has no {} address assigned",
            interface,
            filter.label()
        )),
    }
}

/// Resolve binding address from interface name or source IP.
///
/// `filter` enforces that the resulting bind address matches the requested
/// IP version: `--source` IPs of the wrong family are rejected, and interface
/// lookup picks an address of the matching family.
pub fn resolve_bind_address(
    interface: Option<&String>,
    source_ip: Option<&String>,
    filter: IpVersionFilter,
) -> Result<Option<SocketAddr>> {
    if let Some(ip_str) = source_ip {
        let ip: IpAddr = ip_str.parse().context("Invalid source IP address format")?;
        if !filter.allows_ip(ip) {
            return Err(anyhow::anyhow!(
                "--source {} is not an {} address (conflicts with --{}-only)",
                ip,
                filter.label(),
                filter.label().to_lowercase()
            ));
        }
        return Ok(Some(SocketAddr::new(ip, 0)));
    }

    if let Some(iface) = interface {
        let ip = get_interface_ip(iface, filter)
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
    use crate::model::IpVersionFilter;

    #[test]
    fn test_get_interface_for_ip_loopback() {
        // 127.0.0.1 is always bound to "lo" on Linux
        let iface = get_interface_for_ip("127.0.0.1");
        assert_eq!(iface, Some("lo".to_string()));
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
        let ip = get_interface_ip("lo", IpVersionFilter::Auto).unwrap();
        assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_get_interface_ip_nonexistent() {
        let result = get_interface_ip("nonexistent_iface_xyz", IpVersionFilter::Auto);
        assert!(result.is_err());
    }

    #[test]
    fn test_roundtrip_interface_to_ip_and_back() {
        // Get the IP for loopback, then reverse-lookup should return "lo"
        let ip = get_interface_ip("lo", IpVersionFilter::Auto).unwrap();
        let iface = get_interface_for_ip(&ip.to_string());
        assert_eq!(iface, Some("lo".to_string()));
    }

    #[test]
    fn test_resolve_bind_address_none() {
        let result = resolve_bind_address(None, None, IpVersionFilter::Auto).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_bind_address_source_ip() {
        let source = "127.0.0.1".to_string();
        let result = resolve_bind_address(None, Some(&source), IpVersionFilter::Auto).unwrap();
        let addr = result.unwrap();
        assert_eq!(addr.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_resolve_bind_address_invalid_source() {
        let source = "not-an-ip".to_string();
        let result = resolve_bind_address(None, Some(&source), IpVersionFilter::Auto);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_bind_address_source_family_mismatch() {
        // --source IPv4 with --ipv6-only is contradictory
        let source = "127.0.0.1".to_string();
        let result = resolve_bind_address(None, Some(&source), IpVersionFilter::V6Only);
        assert!(result.is_err());

        let source = "::1".to_string();
        let result = resolve_bind_address(None, Some(&source), IpVersionFilter::V4Only);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_bind_address_interface() {
        let iface = "lo".to_string();
        let result = resolve_bind_address(Some(&iface), None, IpVersionFilter::Auto).unwrap();
        let addr = result.unwrap();
        assert_eq!(addr.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_resolve_bind_address_source_takes_priority() {
        // When both are provided, source_ip wins
        let iface = "lo".to_string();
        let source = "192.168.1.1".to_string();
        let result =
            resolve_bind_address(Some(&iface), Some(&source), IpVersionFilter::Auto).unwrap();
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
