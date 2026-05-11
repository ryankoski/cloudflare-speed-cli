use crate::engine::{EngineControl, TestEngine};
use crate::model::{IpVersionFilter, RunConfig, TestEvent};
use anyhow::{Context, Result};
use clap::Parser;
use rand::RngCore;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug, Parser, Clone)]
#[command(
    name = "cloudflare-speed-cli",
    version,
    about = "Cloudflare-based speed test with optional TUI"
)]
pub struct Cli {
    /// Base URL for the Cloudflare speed test service
    #[arg(long, default_value = "https://speed.cloudflare.com")]
    pub base_url: String,

    /// Print JSON result and exit (no TUI)
    #[arg(long)]
    pub json: bool,

    /// Print text summary and exit (no TUI)
    #[arg(long)]
    pub text: bool,

    /// Run silently: suppress all output except errors (for cron usage)
    #[arg(long)]
    pub silent: bool,

    /// Download phase duration
    #[arg(long, default_value = "10s")]
    pub download_duration: humantime::Duration,

    /// Upload phase duration
    #[arg(long, default_value = "10s")]
    pub upload_duration: humantime::Duration,

    /// Idle latency probe duration (pre-test)
    #[arg(long, default_value = "2s")]
    pub idle_latency_duration: humantime::Duration,

    /// Concurrency for download/upload workers
    #[arg(long, default_value_t = 6)]
    pub concurrency: usize,

    /// Bytes per download request
    #[arg(long, default_value_t = 10_000_000)]
    pub download_bytes_per_req: u64,

    /// Bytes per upload request
    #[arg(long, default_value_t = 5_000_000)]
    pub upload_bytes_per_req: u64,

    /// Probe interval in milliseconds
    #[arg(long, default_value_t = 250)]
    pub probe_interval_ms: u64,

    /// Probe timeout in milliseconds
    #[arg(long, default_value_t = 2000)]
    pub probe_timeout_ms: u64,

    /// Reserved for future experimental features
    #[arg(long)]
    pub experimental: bool,

    /// Export results as JSON
    #[arg(long)]
    pub export_json: Option<std::path::PathBuf>,

    /// Export results as CSV
    #[arg(long)]
    pub export_csv: Option<std::path::PathBuf>,

    /// Use --auto-save true or --auto-save false to override
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub auto_save: bool,

    /// Bind to a specific network interface (e.g., ens18, eth0)
    #[arg(long)]
    pub interface: Option<String>,

    /// Bind to a specific source IP address (e.g., 192.168.10.0)
    #[arg(long)]
    pub source: Option<String>,

    /// Route traffic through a proxy (HTTP, HTTPS, or SOCKS5)
    #[arg(long)]
    pub proxy: Option<String>,

    /// Path to a custom TLS certificate file (PEM or DER format). Not needed if the CA is already trusted by your OS truststore.
    #[arg(long)]
    pub certificate: Option<std::path::PathBuf>,

    /// Automatically start a test when the app launches
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub test_on_launch: bool,

    /// Attach custom comments to this run
    #[arg(long)]
    pub comments: Option<String>,

    /// Compare IPv4 vs IPv6 performance
    #[arg(long)]
    pub compare_ip_versions: bool,

    /// Run traceroute to Cloudflare edge
    #[arg(long)]
    pub traceroute: bool,

    /// Maximum number of hops for traceroute
    #[arg(long, default_value_t = 30)]
    pub traceroute_max_hops: u8,

    /// Force IPv4 only (no IPv6)
    #[arg(long, conflicts_with_all = ["ipv6_only", "compare_ip_versions"])]
    pub ipv4_only: bool,

    /// Force IPv6 only (no IPv4)
    #[arg(long, conflicts_with_all = ["ipv4_only", "compare_ip_versions"])]
    pub ipv6_only: bool,

    /// Skip default diagnostic measurements (DNS, TLS)
    #[arg(long)]
    pub skip_diagnostics: bool,

    /// Number of UDP packets to send for packet loss measurement
    #[arg(long, default_value_t = 50)]
    pub udp_packets: u64,

    /// Redact identifying network info (IP, MAC, SSID, ISP, server location) in the TUI display.
    /// Useful for sharing screenshots or recording demos. Toggle at runtime with Shift+H.
    #[arg(long)]
    pub hide_network_info: bool,
}

pub async fn run(args: Cli) -> Result<()> {
    // Validate that --silent can only be used with --json
    if args.silent && !args.json {
        return Err(anyhow::anyhow!(
            "--silent can only be used with --json. Use --silent --json together."
        ));
    }

    // Warn when using a proxy
    if let Some(ref proxy_url) = args.proxy {
        eprintln!(
            "Warning: using proxy {}. Speed results reflect performance through the proxy, not your direct connection.",
            proxy_url
        );
    }

    // Silent mode takes precedence over other output modes
    if args.silent {
        return run_test_engine(args, true).await;
    }

    if !args.json && !args.text {
        #[cfg(feature = "tui")]
        {
            return crate::tui::run(args).await;
        }
        #[cfg(not(feature = "tui"))]
        {
            // Fallback when built without TUI support.
            return run_text(args).await;
        }
    }

    if args.json {
        return run_test_engine(args, false).await;
    }

    run_text(args).await
}

/// Generate a random measurement ID for the speed test.
fn gen_meas_id() -> String {
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    u64::from_le_bytes(b).to_string()
}

/// Build a `RunConfig` from CLI arguments.
pub fn build_config(args: &Cli) -> Result<RunConfig> {
    use crate::engine::network_bind;

    // DNS and TLS run by default unless --skip-diagnostics is set
    let skip = args.skip_diagnostics;

    let ip_version = if args.ipv4_only {
        IpVersionFilter::V4Only
    } else if args.ipv6_only {
        IpVersionFilter::V6Only
    } else {
        IpVersionFilter::Auto
    };

    // Resolve bind address once from --interface or --source.
    // Pass the IP-version filter so an interface lookup picks the matching family
    // and a --source IP whose family conflicts is rejected.
    let resolved_bind_ip = network_bind::resolve_bind_address(
        args.interface.as_ref(),
        args.source.as_ref(),
        ip_version,
    )?
    .map(|addr| addr.ip());

    if let Some(ip) = resolved_bind_ip {
        if let Some(ref iface) = args.interface {
            eprintln!("Binding HTTP connections to interface {} (IP: {})", iface, ip);
        } else {
            eprintln!("Binding HTTP connections to source IP: {}", ip);
        }
    }

    // A proxy terminates our connection and performs its own DNS/dialing, so we
    // cannot pin the address family for traffic routed through it. Direct
    // measurements (TLS, UDP, traceroute) still honour the filter, so warn
    // rather than error.
    if args.proxy.is_some() && ip_version != IpVersionFilter::Auto {
        eprintln!(
            "warning: --{}-only cannot be enforced for HTTP traffic routed through --proxy; \
             the proxy selects the address family for those requests",
            ip_version.label().to_lowercase()
        );
    }

    Ok(RunConfig {
        base_url: args.base_url.clone(),
        meas_id: gen_meas_id(),
        comments: args.comments.clone(),
        download_bytes_per_req: args.download_bytes_per_req,
        upload_bytes_per_req: args.upload_bytes_per_req,
        concurrency: args.concurrency,
        idle_latency_duration: Duration::from(args.idle_latency_duration),
        download_duration: Duration::from(args.download_duration),
        upload_duration: Duration::from(args.upload_duration),
        probe_interval_ms: args.probe_interval_ms,
        probe_timeout_ms: args.probe_timeout_ms,
        user_agent: format!("cloudflare-speed-cli/{}", env!("CARGO_PKG_VERSION")),
        experimental: args.experimental,
        interface: args.interface.clone(),
        source_ip: args.source.clone(),
        resolved_bind_ip,
        proxy: args.proxy.clone(),
        certificate_path: args.certificate.clone(),
        // Diagnostic options: DNS and TLS run by default unless --skip-diagnostics
        measure_dns: !skip,
        measure_tls: !skip,
        compare_ip_versions: args.compare_ip_versions,
        traceroute: args.traceroute,
        traceroute_max_hops: args.traceroute_max_hops,
        ip_version,
        udp_packets: args.udp_packets,
    })
}

/// Common function to run the test engine and process results.
/// `silent` controls whether JSON is printed and whether save errors propagate.
async fn run_test_engine(args: Cli, silent: bool) -> Result<()> {
    let cfg = build_config(&args)?;
    let network_info = crate::network::gather_network_info(&args);

    let (evt_tx, mut evt_rx) = mpsc::channel::<TestEvent>(2048);
    let (_, ctrl_rx) = mpsc::channel::<EngineControl>(16);

    let engine = TestEngine::new(cfg);
    let handle = tokio::spawn(async move { engine.run(evt_tx, ctrl_rx).await });

    // Collect throughput samples for connection-quality computation.
    let run_start = std::time::Instant::now();
    let mut dl_points: Vec<(f64, f64)> = Vec::new();
    let mut ul_points: Vec<(f64, f64)> = Vec::new();

    while let Some(ev) = evt_rx.recv().await {
        if let TestEvent::ThroughputTick {
            phase, bps_instant, ..
        } = ev
        {
            if matches!(
                phase,
                crate::model::Phase::Download | crate::model::Phase::Upload
            ) {
                let elapsed = run_start.elapsed().as_secs_f64();
                let mbps = (bps_instant * 8.0) / 1_000_000.0;
                match phase {
                    crate::model::Phase::Download => dl_points.push((elapsed, mbps)),
                    crate::model::Phase::Upload => ul_points.push((elapsed, mbps)),
                    _ => {}
                }
            }
        }
    }

    let mut result = handle
        .await
        .context("test engine task failed")?
        .context("speed test failed")?;

    result.connection_quality = crate::quality::compute(&result, &dl_points, &ul_points);

    let enriched = crate::network::enrich_result(&result, &network_info);

    // Handle exports (errors will propagate)
    handle_exports(&args, &enriched)?;

    if !silent {
        // Print JSON output in non-silent mode
        println!("{}", serde_json::to_string_pretty(&enriched)?);
    }

    // Save results if auto_save is enabled
    if args.auto_save {
        if silent {
            crate::storage::save_run(&enriched).context("failed to save run results")?;
        } else if let Ok(p) = crate::storage::save_run(&enriched) {
            eprintln!("{}", crate::event_format::format_saved_line(&p));
        }
    }

    Ok(())
}

async fn run_text(args: Cli) -> Result<()> {
    let cfg = build_config(&args)?;
    let (evt_tx, mut evt_rx) = mpsc::channel::<TestEvent>(2048);
    let (_, ctrl_rx) = mpsc::channel::<EngineControl>(16);

    let engine = TestEngine::new(cfg);
    let handle = tokio::spawn(async move { engine.run(evt_tx, ctrl_rx).await });

    // Collect raw samples for metric computation (same as TUI)
    let run_start = std::time::Instant::now();
    let mut idle_latency_samples: Vec<f64> = Vec::new();
    let mut loaded_dl_latency_samples: Vec<f64> = Vec::new();
    let mut loaded_ul_latency_samples: Vec<f64> = Vec::new();
    let mut dl_points: Vec<(f64, f64)> = Vec::new();
    let mut ul_points: Vec<(f64, f64)> = Vec::new();

    while let Some(ev) = evt_rx.recv().await {
        // Single source of truth for the per-event line(s). The same
        // formatter feeds the TUI dashboard's Test Activity panel so the two
        // modes can't drift apart.
        for line in crate::event_format::format_event_lines(&ev) {
            eprintln!("{}", line);
        }

        // After printing, capture the data text mode needs locally for the
        // end-of-run metric computation.
        match ev {
            TestEvent::ThroughputTick {
                phase, bps_instant, ..
            } if matches!(
                phase,
                crate::model::Phase::Download | crate::model::Phase::Upload
            ) =>
            {
                let elapsed = run_start.elapsed().as_secs_f64();
                let mbps = (bps_instant * 8.0) / 1_000_000.0;
                match phase {
                    crate::model::Phase::Download => dl_points.push((elapsed, mbps)),
                    crate::model::Phase::Upload => ul_points.push((elapsed, mbps)),
                    _ => {}
                }
            }
            TestEvent::LatencySample {
                phase,
                ok: true,
                rtt_ms: Some(ms),
                during,
            } => match (phase, during) {
                (crate::model::Phase::IdleLatency, None) => {
                    idle_latency_samples.push(ms);
                }
                (crate::model::Phase::Download, Some(crate::model::Phase::Download)) => {
                    loaded_dl_latency_samples.push(ms);
                }
                (crate::model::Phase::Upload, Some(crate::model::Phase::Upload)) => {
                    loaded_ul_latency_samples.push(ms);
                }
                _ => {}
            },
            _ => {}
        }
    }

    let mut result = handle.await??;

    result.connection_quality =
        crate::quality::compute(&result, &dl_points, &ul_points);

    // Gather network information and enrich result
    let network_info = crate::network::gather_network_info(&args);
    let enriched = crate::network::enrich_result(&result, &network_info);

    handle_exports(&args, &enriched)?;

    // Both text mode and the TUI dashboard print the same summary, from the
    // same function. No per-mode customization.
    for line in crate::event_format::format_result_summary(
        &enriched,
        &dl_points,
        &ul_points,
        &idle_latency_samples,
        &loaded_dl_latency_samples,
        &loaded_ul_latency_samples,
    ) {
        println!("{}", line);
    }
    if args.auto_save {
        if let Ok(p) = crate::storage::save_run(&enriched) {
            eprintln!("{}", crate::event_format::format_saved_line(&p));
        }
    }
    Ok(())
}

/// Handle export operations (JSON and CSV) for both text and JSON modes.
fn handle_exports(args: &Cli, result: &crate::model::RunResult) -> Result<()> {
    if let Some(p) = args.export_json.as_deref() {
        crate::storage::export_json(p, result)?;
    }
    if let Some(p) = args.export_csv.as_deref() {
        crate::storage::export_csv(p, result)?;
    }
    Ok(())
}
