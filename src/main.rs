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
mod panel;
mod proxy_connector;
mod self_loop;
mod sni;
mod service;
mod metrics;
mod upstream_registry;
mod upstream_monitor;
mod client_acl;
mod ufw;
mod telegram;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
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

    // Config loading happens before tracing is initialized, so report its source here.
    if let Ok(path) = std::fs::canonicalize(&cli.config) {
        info!(config_file = %path.display(), "Loaded configuration file");
    } else {
        tracing::warn!(config_file = %cli.config, "Configuration file missing; using defaults and environment overrides");
    }
    let upstream_source = if cli.proxy.is_some() {
        "CLI --proxy"
    } else if let Ok(value) = std::env::var("PROXY") {
        if crate::config::parse_proxy_string(&value).is_ok() {
            "PROXY environment variable"
        } else {
            tracing::warn!("Invalid PROXY environment variable ignored; expected '<type> <host> <port>'");
            "configuration/defaults"
        }
    } else {
        "configuration/defaults"
    };

    // CLI --proxy overrides the default upstream profile only
    if let Some(proxy_str) = cli.proxy {
        cfg.apply_default_proxy_override(crate::config::parse_proxy_string(&proxy_str)?);
        cfg.normalize_upstreams()?;
    }

    cfg.remap_docker_loopback_upstream();

    info!("Starting SNIrelay v{}", env!("CARGO_PKG_VERSION"));
    info!(
        source = upstream_source,
        default = cfg.default_upstream_name(),
        profiles = cfg.upstreams.len(),
        client_routes = cfg.client_upstreams.len(),
        "Upstream proxy: {} (default profile)",
        cfg.upstream_proxy
    );
    for (name, proxy) in &cfg.upstreams {
        let marker = if name == cfg.default_upstream_name() {
            " [default]"
        } else {
            ""
        };
        info!("  upstream profile '{name}'{marker}: {proxy}");
    }
    for listener in &cfg.listens {
        info!(
            "Configured listener [{}] {} proto={} (not bound yet)",
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
    let probe_wait = Duration::from_secs(cfg.upstream_probe_wait_secs);
    let probe_interval = Duration::from_secs(cfg.upstream_probe_interval_secs.max(1));
    info!(
        connect_timeout_secs = cfg.connect_timeout_secs,
        wait_secs = cfg.upstream_probe_wait_secs,
        interval_secs = cfg.upstream_probe_interval_secs.max(1),
        required = cfg.upstream_probe_required,
        default = cfg.default_upstream_name(),
        "Checking default upstream before binding listeners"
    );
    let upstream_ready = crate::proxy_connector::ensure_upstream_ready(
        &cfg.upstream_proxy,
        probe_timeout,
        probe_wait,
        probe_interval,
        cfg.upstream_probe_required,
    )
    .await?;

    // Soft-probe other named profiles (warn only).
    let default_name = cfg.default_upstream_name().to_string();
    for (name, proxy) in &cfg.upstreams {
        if name == &default_name {
            continue;
        }
        match crate::proxy_connector::probe_upstream(proxy, probe_timeout).await {
            Ok(()) => info!(profile = %name, "Upstream profile reachable"),
            Err(e) => tracing::warn!(profile = %name, error = %e, "Upstream profile unreachable"),
        }
    }

    let process_limits = limits::apply(&cfg)?;
    info!(
        "Resource limits: nofile soft={}, max_connections={}",
        process_limits.soft_nofile, process_limits.max_connections
    );

    // ── Metrics ──────────────────────────────────────────────────────────────
    if let Some(ref metrics_addr) = cfg.metrics_addr {
        metrics::start_metrics_server(metrics_addr.clone(), cfg.metrics_refresh_secs).await?;
    }

    let upstream_registry = crate::upstream_registry::shared_from_config(&cfg);
    let client_acl = crate::client_acl::shared_from_config(&cfg);
    if client_acl.read().is_open() {
        info!("Client whitelist: open (all IPs allowed)");
    } else {
        info!(
            count = client_acl.read().len(),
            ufw_sync = client_acl.read().ufw_sync(),
            "Client whitelist ACL active"
        );
    }
    let cfg = Arc::new(cfg);
    let upstream_ok = Arc::new(AtomicBool::new(upstream_ready));
    let (traffic, hosts_live) = crate::panel::start_panel(
        cfg.clone(),
        upstream_ok.clone(),
        upstream_registry.clone(),
        client_acl.clone(),
    )
    .await?;

    crate::upstream_monitor::start(cfg.clone(), upstream_registry.clone());

    // ── Run service ──────────────────────────────────────────────────────────
    let service = SniProxyService::new(
        cfg,
        process_limits.max_connections,
        Some(traffic),
        hosts_live,
        upstream_registry,
        client_acl,
    );
    service.run().await
}
