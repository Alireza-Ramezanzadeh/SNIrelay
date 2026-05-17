// =============================================================================
// SNIrelay — SNI-aware transparent L4 proxy with upstream HTTP CONNECT / SOCKS5 support.
//
// Architecture:
//   Client ──TLS/HTTP──► [SNIrelay] ──SOCKS5/HTTP-CONNECT──► [upstream proxy] ──► Origin
//
// The proxy NEVER terminates TLS.  It reads only the SNI extension from the
// ClientHello (or the Host header for plain HTTP) and blindly forwards the
// raw bytes to the origin through the configured upstream proxy.
// =============================================================================

mod config;
mod hosts;
mod limits;
mod proxy_connector;
mod sni;
mod service;
mod metrics;

use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::AppConfig;
use crate::service::SniProxyService;

/// SNIrelay — transparent SNI/Host proxy with SOCKS5 / HTTP CONNECT upstream
#[derive(Parser, Debug)]
#[command(name = "snirelay", version, about)]
struct Cli {
    /// Path to YAML configuration file
    #[arg(short, long, default_value = "/etc/sniproxy/config.yaml")]
    config: String,

    /// Override upstream proxy (e.g. "socks5 127.0.0.1 10808")
    #[arg(short, long)]
    proxy: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Run in daemon/background mode
    #[arg(short, long)]
    daemon: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // ── Logging ──────────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .with_target(true)
        .with_thread_ids(true)
        .init();

    // ── Config ───────────────────────────────────────────────────────────────
    let mut cfg = AppConfig::load(&cli.config)?;

    // CLI --proxy overrides config file
    if let Some(proxy_str) = cli.proxy {
        cfg.upstream_proxy = crate::config::parse_proxy_string(&proxy_str)?;
    }

    cfg.remap_docker_loopback_upstream();

    info!("Starting SNIrelay v{}", env!("CARGO_PKG_VERSION"));
    info!("Upstream proxy: {:?}", cfg.upstream_proxy);
    for listener in &cfg.listens {
        info!(
            "Listen [{}] {} proto={}",
            listener.label(),
            listener.addr,
            listener.proto_str()
        );
    }
    if let Some(ref hosts) = cfg.hosts_table {
        let (exact, patterns) = hosts.stats();
        info!("Hosts table: {exact} exact + {patterns} pattern mapping(s)");
    }

    let probe_timeout = Duration::from_secs(cfg.connect_timeout_secs);
    crate::proxy_connector::probe_upstream(&cfg.upstream_proxy, probe_timeout).await?;

    let process_limits = limits::apply(&cfg)?;
    info!(
        "Resource limits: nofile soft={}, max_connections={}",
        process_limits.soft_nofile, process_limits.max_connections
    );

    // ── Metrics ──────────────────────────────────────────────────────────────
    if let Some(ref metrics_addr) = cfg.metrics_addr {
        metrics::start_metrics_server(metrics_addr.clone(), cfg.metrics_refresh_secs).await?;
    }

    // ── Run service ──────────────────────────────────────────────────────────
    let service = SniProxyService::new(cfg, process_limits.max_connections);
    service.run().await
}
