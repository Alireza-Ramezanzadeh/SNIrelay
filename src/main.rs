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
mod domain_limiter;
mod hosts;
mod limits;
mod logging;
mod proxy_connector;
mod sni;
mod service;
mod metrics;

use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

use tracing::info;

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

    /// Log level (trace, debug, info, warn, error). Overridden by RUST_LOG if set.
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Append logs to this file (stdout logging remains enabled)
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Run in daemon/background mode
    #[arg(short, long)]
    daemon: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // ── Config (load before logging so `log_file` from YAML can be used) ─────
    let mut cfg = AppConfig::load(&cli.config)?;

    let log_file = cli
        .log_file
        .clone()
        .or_else(|| cfg.log_file.as_ref().map(PathBuf::from))
        .or_else(|| std::env::var("LOG_FILE").ok().map(PathBuf::from));

    logging::init(&cli.log_level, log_file.as_deref())?;

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
    if !cfg.domain_limits.is_empty() {
        info!("Domain limits: {} domain(s) configured", cfg.domain_limits.len());
        for (domain, limit) in &cfg.domain_limits {
            info!(
                "  {domain}: bandwidth={} connections={}",
                limit.daily_bandwidth.map_or("unlimited".to_string(), |b| format!("{} bytes/day", b.0)),
                limit.daily_connections.map_or("unlimited".to_string(), |c| format!("{c}/day")),
            );
        }
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
