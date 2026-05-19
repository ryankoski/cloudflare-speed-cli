use crate::cli::Cli;
use crate::model::RunResult;
use serde_json::Value;
use std::process::Command;

/// Extracted metadata fields from Cloudflare response
#[derive(Debug, Clone, Default)]
pub struct ExtractedMetadata {
    pub ip: Option<String>,
    pub colo: Option<String>,
    pub asn: Option<String>,
    pub as_org: Option<String>,
}

/// Extract metadata fields (IP, colo, ASN, org) from Cloudflare JSON response.
/// Handles multiple possible field names for compatibility.
pub fn extract_metadata(meta: &Value) -> ExtractedMetadata {
    let ip = ["clientIp", "ip", "clientIP"]
        .iter()
        .find_map(|key| meta.get(*key))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let colo = meta
        .get("colo")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let asn = meta.get("asn").and_then(|v| {
        v.as_i64()
            .map(|n| n.to_string())
            .or_else(|| v.as_str().map(|s| s.to_string()))
    });

    let as_org = ["asOrganization", "asnOrg"]
        .iter()
        .find_map(|key| meta.get(*key))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    ExtractedMetadata {
        ip,
        colo,
        asn,
        as_org,
    }
}

/// Network information gathered from the system
pub struct NetworkInfo {
    pub interface_name: Option<String>,
    pub network_name: Option<String>,
    pub is_wireless: Option<bool>,
    pub interface_mac: Option<String>,
    pub local_ipv4: Option<String>,
    pub local_ipv6: Option<String>,
}

/// Gather network interface information based on CLI arguments
pub fn gather_network_info(args: &Cli) -> NetworkInfo {
    // Determine the interface: explicit --interface, reverse-lookup from --source, or auto-detect
    let resolved_iface = args.interface.clone().or_else(|| {
        args.source.as_ref().and_then(|ip| {
            crate::engine::network_bind::get_interface_for_ip(ip)
        })
    });

    let (interface_name, network_name, is_wireless, interface_mac) =
        if let Some(ref iface) = resolved_iface {
            let is_wireless = check_if_wireless(iface);
            let network_name = if is_wireless.unwrap_or(false) {
                get_wireless_ssid(iface)
            } else {
                None
            };
            let mac = get_interface_mac(iface);
            (Some(iface.clone()), network_name, is_wireless, mac)
        } else {
            // Auto-detect default interface
            gather_default_network_info()
        };

    let (local_ipv4, local_ipv6) = get_interface_ips(interface_name.as_deref());

    NetworkInfo {
        interface_name,
        network_name,
        is_wireless,
        interface_mac,
        local_ipv4,
        local_ipv6,
    }
}

/// Gather network interface information for the default interface
fn gather_default_network_info() -> (Option<String>, Option<String>, Option<bool>, Option<String>) {
    // Get default interface by trying to connect to a remote address
    let interface_name = get_default_interface();

    if let Some(ref iface) = interface_name {
        let is_wireless = check_if_wireless(iface);
        let network_name = if is_wireless.unwrap_or(false) {
            get_wireless_ssid(iface)
        } else {
            None
        };
        let mac = get_interface_mac(iface);
        (Some(iface.clone()), network_name, is_wireless, mac)
    } else {
        (None, None, None, None)
    }
}

/// Get the default network interface name
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn get_default_interface() -> Option<String> {
    // Try to get interface from default route
    if let Ok(output) = Command::new("ip")
        .args(&["route", "show", "default"])
        .output()
    {
        if let Ok(output_str) = String::from_utf8(output.stdout) {
            // Look for "dev <interface>" in the output
            for line in output_str.lines() {
                if let Some(dev_pos) = line.find("dev ") {
                    let rest = &line[dev_pos + 4..];
                    return if let Some(space_pos) = rest.find(' ') {
                        Some(rest[..space_pos].to_string())
                    } else {
                        Some(rest.to_string())
                    };
                }
            }
        }
    }

    // Fallback: try to find first non-loopback interface
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str != "lo" && !name_str.starts_with("docker") && !name_str.starts_with("br-") {
                return Some(name_str.to_string());
            }
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn get_default_interface() -> Option<String> {
    // Use `route -n get default` to find the default interface
    if let Ok(output) = Command::new("route").args(&["-n", "get", "default"]).output() {
        if output.status.success() {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                for line in output_str.lines() {
                    let line = line.trim();
                    if line.starts_with("interface:") {
                        if let Some(iface) = line.splitn(2, ':').nth(1) {
                            let iface = iface.trim().to_string();
                            if !iface.is_empty() {
                                return Some(iface);
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

#[cfg(target_os = "windows")]
fn get_default_interface() -> Option<String> {
    let output = Command::new("powershell")
        .args(&[
            "-NoProfile",
            "-Command",
            "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceAlias",
        ])
        .output()
        .ok()?;

    if output.status.success() {
        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !name.is_empty() {
            return Some(name);
        }
    }

    // Fallback: Get any active adapter
    let output = Command::new("powershell")
        .args(&[
            "-NoProfile",
            "-Command",
            "Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1 -ExpandProperty InterfaceAlias",
        ])
        .output()
        .ok()?;

    if output.status.success() {
        let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !name.is_empty() {
            return Some(name);
        }
    }

    None
}

/// Check if interface is wireless
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn check_if_wireless(iface: &str) -> Option<bool> {
    // Check if /sys/class/net/<iface>/wireless exists
    let wireless_path = format!("/sys/class/net/{}/wireless", iface);
    Some(std::path::Path::new(&wireless_path).exists())
}

#[cfg(target_os = "macos")]
fn check_if_wireless(iface: &str) -> Option<bool> {
    // Parse `networksetup -listallhardwareports` to check if the interface is Wi-Fi
    if let Ok(output) = Command::new("networksetup").arg("-listallhardwareports").output() {
        if let Ok(output_str) = String::from_utf8(output.stdout) {
            let mut is_wifi_section = false;
            for line in output_str.lines() {
                let line = line.trim();
                if line.starts_with("Hardware Port:") {
                    let port_name = line.splitn(2, ':').nth(1).unwrap_or("").trim().to_lowercase();
                    is_wifi_section = port_name.contains("wi-fi") || port_name.contains("airport");
                } else if line.starts_with("Device:") {
                    if let Some(device) = line.splitn(2, ':').nth(1) {
                        if device.trim() == iface {
                            return Some(is_wifi_section);
                        }
                    }
                }
            }
        }
    }
    Some(false)
}

#[cfg(target_os = "windows")]
fn check_if_wireless(iface: &str) -> Option<bool> {
    let output = Command::new("netsh")
        .args(&["wlan", "show", "interfaces"])
        .output()
        .ok()?;

    if output.status.success() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        return Some(output_str.contains(iface));
    }
    Some(false)
}

/// Get wireless SSID for an interface
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn get_wireless_ssid(iface: &str) -> Option<String> {
    // Try iwgetid first (most reliable)
    if let Ok(output) = Command::new("iwgetid").arg("-r").arg(iface).output() {
        if let Ok(ssid) = String::from_utf8(output.stdout) {
            let ssid = ssid.trim().to_string();
            if !ssid.is_empty() {
                return Some(ssid);
            }
        }
    }

    // Fallback: try iw command
    if let Ok(output) = Command::new("iw").args(&["dev", iface, "info"]).output() {
        if let Ok(output_str) = String::from_utf8(output.stdout) {
            for line in output_str.lines() {
                if line.trim().starts_with("ssid ") {
                    let ssid = line.trim().strip_prefix("ssid ").unwrap_or("").trim();
                    if !ssid.is_empty() {
                        return Some(ssid.to_string());
                    }
                }
            }
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn get_wireless_ssid(iface: &str) -> Option<String> {
    // Try `networksetup -getairportnetwork <iface>` (public API)
    if let Ok(output) = Command::new("networksetup")
        .args(&["-getairportnetwork", iface])
        .output()
    {
        if let Ok(output_str) = String::from_utf8(output.stdout) {
            let output_str = output_str.trim();
            if let Some(ssid) = output_str.strip_prefix("Current Wi-Fi Network:") {
                let ssid = ssid.trim().to_string();
                if !ssid.is_empty() {
                    return Some(ssid);
                }
            }
        }
    }

    // Fallback: try the airport command (deprecated in newer macOS but widely available)
    let airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
    if let Ok(output) = Command::new(airport).arg("-I").output() {
        if let Ok(output_str) = String::from_utf8(output.stdout) {
            for line in output_str.lines() {
                let line = line.trim();
                if line.starts_with("SSID:") {
                    if let Some(ssid) = line.splitn(2, ':').nth(1) {
                        let ssid = ssid.trim().to_string();
                        if !ssid.is_empty() {
                            return Some(ssid);
                        }
                    }
                }
            }
        }
    }

    None
}

#[cfg(target_os = "windows")]
fn get_wireless_ssid(iface: &str) -> Option<String> {
    let output = Command::new("netsh")
        .args(&["wlan", "show", "interfaces"])
        .output()
        .ok()?;

    if output.status.success() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut current_iface = String::new();
        for line in output_str.lines() {
            let line = line.trim();
            if line.starts_with("Name") {
                if let Some(name) = line.split(':').nth(1) {
                    current_iface = name.trim().to_string();
                }
            }
            if current_iface == iface && line.starts_with("SSID") {
                if let Some(ssid) = line.split(':').nth(1) {
                    let ssid = ssid.trim().to_string();
                    if !ssid.is_empty() {
                        return Some(ssid);
                    }
                }
            }
        }
    }
    None
}

/// Get MAC address of interface
#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn get_interface_mac(iface: &str) -> Option<String> {
    let mac_path = format!("/sys/class/net/{}/address", iface);
    std::fs::read_to_string(mac_path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "macos")]
fn get_interface_mac(iface: &str) -> Option<String> {
    // Use `ifconfig <iface>` and parse the `ether` line
    if let Ok(output) = Command::new("ifconfig").arg(iface).output() {
        if output.status.success() {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                for line in output_str.lines() {
                    let line = line.trim();
                    if line.starts_with("ether ") {
                        if let Some(mac) = line.split_whitespace().nth(1) {
                            return Some(mac.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn get_interface_mac(iface: &str) -> Option<String> {
    let output = Command::new("powershell")
        .args(&[
            "-NoProfile",
            "-Command",
            &format!("(Get-NetAdapter -Name '{}').LinkLayerAddress", iface),
        ])
        .output()
        .ok()?;

    if output.status.success() {
        let mac = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !mac.is_empty() {
            return Some(mac.replace('-', ":"));
        }
    }
    None
}

/// Get IPv4 and IPv6 addresses for an interface
fn get_interface_ips(interface_name: Option<&str>) -> (Option<String>, Option<String>) {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return (None, None);
    };

    let mut ipv4: Option<String> = None;
    let mut ipv6: Option<String> = None;

    for iface in interfaces {
        // If interface name is specified, only look at that interface
        if let Some(target) = interface_name {
            if iface.name != target {
                continue;
            }
        }

        // Skip loopback
        if iface.is_loopback() {
            continue;
        }

        match iface.addr {
            if_addrs::IfAddr::V4(ref addr) => {
                if ipv4.is_none() {
                    ipv4 = Some(addr.ip.to_string());
                }
            }
            if_addrs::IfAddr::V6(ref addr) => {
                // Skip link-local addresses (fe80::)
                let ip = addr.ip;
                if !ip.is_loopback() && !is_link_local_v6(&ip) {
                    if ipv6.is_none() {
                        ipv6 = Some(ip.to_string());
                    }
                }
            }
        }
    }

    (ipv4, ipv6)
}

/// Check if an IPv6 address is link-local (fe80::/10)
fn is_link_local_v6(ip: &std::net::Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

/// Enrich RunResult with network information and metadata
pub fn enrich_result(result: &RunResult, network_info: &NetworkInfo) -> RunResult {
    let mut enriched = result.clone();

    // Add network interface information
    enriched.interface_name = network_info.interface_name.clone();
    enriched.network_name = network_info.network_name.clone();
    enriched.is_wireless = network_info.is_wireless;
    enriched.interface_mac = network_info.interface_mac.clone();
    enriched.local_ipv4 = network_info.local_ipv4.clone();
    enriched.local_ipv6 = network_info.local_ipv6.clone();

    // Extract metadata from result.meta if available
    if let Some(meta) = result.meta.as_ref() {
        let extracted = extract_metadata(meta);
        enriched.ip = extracted.ip;
        enriched.colo = extracted.colo;
        enriched.asn = extracted.asn;
        enriched.as_org = extracted.as_org;
    }

    // Server should already be set from RunResult.server, but preserve it
    // (no need to override)

    enriched
}
