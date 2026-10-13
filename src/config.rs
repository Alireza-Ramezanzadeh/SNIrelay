// config.rs — Configuration loading and types
//
// Supports YAML file config + env-variable overrides.
// The "proxy string" format mirrors the zhpjy/sniproxy-proxychains PROXY env var:
//   "<type> <host> <port>"   e.g.  "socks5 127.0.0.1 10808"
//                                   "http   192.168.1.1 3128"

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use crate::hosts::HostsTable;

// ── ByteSize — human-readable byte quantity ───────────────────────────────────
//
// Accepts "100GB", "20MiB", "500MB", a plain integer (bytes), etc.
// SI: KB=1000, MB=1e6, GB=1e9, TB=1e12
// IEC: KiB=1024, MiB=2^20, GiB=2^30, TiB=2^40

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ByteSize(pub u64);

fn parse_byte_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    const SUFFIXES: &[(&str, u64)] = &[
        ("TiB", 1_099_511_627_776),
        ("GiB", 1_073_741_824),
        ("MiB", 1_048_576),
        ("KiB", 1_024),
        ("TB",  1_000_000_000_000),
        ("GB",  1_000_000_000),
        ("MB",  1_000_000),
        ("KB",  1_000),
        ("B",   1),
    ];
    for (suffix, factor) in SUFFIXES {
        if s.len() >= suffix.len()
            && s[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        {
            let num_str = &s[..s.len() - suffix.len()];
            let n: f64 = num_str.trim().parse()
                .map_err(|_| format!("invalid number before '{suffix}' in '{s}'"))?;
            if n < 0.0 {
                return Err(format!("byte size cannot be negative: '{s}'"));
            }
            return Ok((n * *factor as f64) as u64);
        }
    }
    s.parse::<u64>().map_err(|_| format!("cannot parse '{s}' as a byte size (try e.g. \"100GB\")"))
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ByteSizeVisitor;

        impl<'de> serde::de::Visitor<'de> for ByteSizeVisitor {
            type Value = ByteSize;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a byte size string like \"100GB\" or a raw integer")
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<ByteSize, E> {
                Ok(ByteSize(v))
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<ByteSize, E> {
                if v < 0 {
                    Err(E::custom("byte size cannot be negative"))
                } else {
                    Ok(ByteSize(v as u64))
                }
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<ByteSize, E> {
                parse_byte_size(s).map(ByteSize).map_err(E::custom)
            }

            fn visit_string<E: serde::de::Error>(self, s: String) -> Result<ByteSize, E> {
                self.visit_str(&s)
            }
        }

        deserializer.deserialize_any(ByteSizeVisitor)
    }
}

// ── Per-domain traffic/connection limits ──────────────────────────────────────

/// Limits for a single domain, applied per UTC calendar day.
/// Both fields are optional — omit to leave that dimension unlimited.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DomainLimitConfig {
    /// Maximum bytes (upload + download combined) per calendar day (UTC).
    /// Accepts "100GB", "20MiB", or a raw integer (bytes).
    #[serde(default)]
    pub daily_bandwidth: Option<ByteSize>,

    /// Maximum new connections per calendar day (UTC).
    #[serde(default)]
    pub daily_connections: Option<u64>,
}

// ── Upstream proxy kind ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum UpstreamProxy {
    /// SOCKS5 upstream (e.g. v2ray / xray inbound)
    Socks5 {
        host: String,
        port: u16,
        /// Optional SOCKS5 username
        #[serde(default)]
        username: Option<String>,
        /// Optional SOCKS5 password
        #[serde(default)]
        password: Option<String>,
    },
    /// HTTP CONNECT upstream (Squid-style)
    Http {
        host: String,
        port: u16,
        /// Optional Proxy-Authorization header value (base64 user:pass)
        #[serde(default)]
        auth: Option<String>,
    },
    /// No upstream — direct connection (for testing / local use)
    Direct,
}

impl UpstreamProxy {
    pub fn host_port(&self) -> Option<(&str, u16)> {
        match self {
            UpstreamProxy::Socks5 { host, port, .. } => Some((host, *port)),
            UpstreamProxy::Http { host, port, .. } => Some((host, *port)),
            UpstreamProxy::Direct => None,
        }
    }
}

impl std::fmt::Display for UpstreamProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamProxy::Socks5 { host, port, .. } => write!(f, "socks5 {host}:{port}"),
            UpstreamProxy::Http { host, port, .. }   => write!(f, "http {host}:{port}"),
            UpstreamProxy::Direct                      => write!(f, "direct"),
        }
    }
}

// ── Listener configuration ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    /// Optional label for logs (e.g. "public-https").
    #[serde(default)]
    pub name: Option<String>,
    /// Bind address, e.g. "0.0.0.0:443"
    pub addr: String,
    /// Protocol: "tls" (SNI-based) or "http" (Host-header based).
    /// If omitted, inferred from the port (80/8080 → http, otherwise tls).
    #[serde(default)]
    pub proto: Option<String>,
    /// Deprecated: ignored. Use global [`AppConfig::hosts`] for allowlist and DNS.
    #[serde(default, skip_serializing)]
    routes: Vec<serde_yaml::Value>,
}

impl ListenerConfig {
    /// Stable id for log lines.
    pub fn label(&self) -> String {
        self.name.clone().unwrap_or_else(|| format!("{}@{}", self.proto_str(), self.addr))
    }

    pub fn proto_str(&self) -> &str {
        self.proto.as_deref().unwrap_or("tls")
    }

    pub fn is_tls(&self) -> bool {
        self.proto_str() == "tls"
    }

    pub fn is_http(&self) -> bool {
        self.proto_str() == "http"
    }

    /// Port this listener is bound to (used as the default upstream port for `target: "*"`).
    pub fn listen_port(&self) -> Result<u16> {
        self.addr
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid listen addr '{}'", self.addr))
            .map(|a| a.port())
    }

    /// Normalize and infer `proto` from the bind port when not set explicitly.
    pub fn normalize_proto(&mut self) -> Result<()> {
        if let Some(ref p) = self.proto {
            let lower = p.to_lowercase();
            if lower != "tls" && lower != "http" {
                bail!("proto must be 'tls' or 'http', got '{p}'");
            }
            self.proto = Some(lower);
            return Ok(());
        }

        let port = self
            .addr
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid listen addr '{}'", self.addr))?
            .port();

        self.proto = Some(match port {
            80 | 8000 | 8080 | 8888 => "http",
            _ => "tls",
        }
        .to_string());
        Ok(())
    }
}

// ── Root config ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// All listen sockets (TLS and HTTP). Preferred over `tls_listen` / `http_listen`.
    #[serde(default)]
    pub listens: Vec<ListenerConfig>,

    /// Legacy: TLS (HTTPS) listeners (merged into `listens` when `listens` is empty).
    #[serde(default)]
    pub tls_listen: Vec<ListenerConfig>,

    /// Legacy: plain HTTP listeners (merged into `listens` when `listens` is empty).
    #[serde(default)]
    pub http_listen: Vec<ListenerConfig>,

    /// Upstream proxy to tunnel traffic through (legacy single-upstream / default profile).
    /// When `upstreams` is empty, this becomes the sole profile named `"default"`.
    #[serde(default)]
    pub upstream_proxy: UpstreamProxy,

    /// Named upstream profiles (SOCKS5 / HTTP / direct). Keys are profile names
    /// (e.g. `middle-east`, `europe`). Empty → synthesized from `upstream_proxy`.
    #[serde(default)]
    pub upstreams: HashMap<String, UpstreamProxy>,

    /// Profile name used when a client IP is not listed in `client_upstreams`.
    #[serde(default)]
    pub default_upstream: Option<String>,

    /// Exact client IP → upstream profile name.
    #[serde(default)]
    pub client_upstreams: HashMap<String, String>,

    /// When true, if the chosen upstream profile fails to connect, try other
    /// profiles (preferred first, then `default_upstream`, then remaining names).
    /// Default false — stick to the selected profile only.
    #[serde(default)]
    pub upstream_failover: bool,

    /// Client IP allowlist for proxy listeners. Empty = allow all.
    /// Panel (9080) is never filtered by this ACL.
    ///
    /// YAML accepts either a bare IP string or `{ ip, username }` objects.
    #[serde(default)]
    pub client_whitelist: Vec<WhitelistEntry>,

    /// When true, panel add/remove also runs `ufw allow/delete from <ip>`.
    #[serde(default = "default_true")]
    pub client_whitelist_ufw: bool,

    /// Optional path to the `ufw` binary (default `/usr/sbin/ufw` or `ufw` on PATH).
    #[serde(default)]
    pub ufw_bin: Option<String>,

    /// Periodic upstream health checks + optional Telegram alerts.
    #[serde(default)]
    pub upstream_monitor: UpstreamMonitorConfig,

    /// Telegram bot for monitor notifications (`TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID`).
    #[serde(default)]
    pub telegram: TelegramConfig,

    /// Connection timeout to upstream proxy (seconds)
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,

    /// How long to retry the upstream reachability probe at startup (seconds).
    /// Covers Docker Compose races where Xray/SOCKS starts after SNIrelay.
    /// Override with `UPSTREAM_PROBE_WAIT_SECS`.
    #[serde(default = "default_upstream_probe_wait_secs")]
    pub upstream_probe_wait_secs: u64,

    /// Delay between upstream probe attempts (seconds).
    #[serde(default = "default_upstream_probe_interval_secs")]
    pub upstream_probe_interval_secs: u64,

    /// If true, exit when the upstream is still unreachable after `upstream_probe_wait_secs`.
    /// If false (default), log a warning and start listeners anyway so a later SOCKS recovery
    /// does not require a container restart. Override with `UPSTREAM_PROBE_REQUIRED=true`.
    #[serde(default = "default_upstream_probe_required")]
    pub upstream_probe_required: bool,

    /// Per-connection read/write timeout (seconds)
    #[serde(default = "default_rw_timeout")]
    pub rw_timeout_secs: u64,

    /// Worker thread count. 0 = number of logical CPUs.
    #[serde(default)]
    pub workers: usize,

    /// Optional Prometheus metrics endpoint, e.g. "0.0.0.0:9090"
    #[serde(default)]
    pub metrics_addr: Option<String>,

    /// Append logs to this path (stdout logging remains enabled).
    /// Overridden by `--log-file` or the `LOG_FILE` environment variable.
    #[serde(default)]
    pub log_file: Option<String>,

    /// How often to rebuild the /metrics snapshot in the background (seconds).
    #[serde(default = "default_metrics_refresh_secs")]
    pub metrics_refresh_secs: u64,

    /// Maximum concurrent proxy sessions (each uses ~2 TCP sockets). Capped at startup
    /// from the process open-file limit; see `nofile_limit`.
    #[serde(default = "default_max_conn")]
    pub max_connections: usize,

    /// Try to raise RLIMIT_NOFILE (soft limit) to this value at startup. Set to 0 to skip.
    #[serde(default = "default_nofile_limit")]
    pub nofile_limit: u64,

    /// TCP listen backlog per listener (`listen(2)`).
    #[serde(default = "default_listen_backlog")]
    pub listen_backlog: u32,

    /// Which hostnames may use the proxy (allowlist) and optional DNS/IP override.
    /// Add `{ pattern: ".*", address: "*" }` to relay any hostname; otherwise only listed patterns.
    #[serde(default)]
    pub hosts: Vec<crate::hosts::HostsEntry>,

    /// Compiled hosts table (filled by [`AppConfig::finalize`]).
    #[serde(skip)]
    pub hosts_table: Option<Arc<HostsTable>>,

    /// Per-domain daily bandwidth and connection limits.
    /// Keys match the exact SNI/Host or any subdomain (case-insensitive).
    #[serde(default, alias = "limits")]
    pub domain_limits: HashMap<String, DomainLimitConfig>,

    /// Persist daily limit counters to this JSON file (survives restarts).
    /// When `domain_limits` is set and this is omitted, defaults to
    /// `/var/lib/snirelay/domain_limits.json`. Override with `DOMAIN_LIMITS_STATE_FILE`.
    #[serde(default)]
    pub domain_limits_state_file: Option<String>,

    /// How often to flush limit counters to disk (seconds).
    #[serde(default = "default_domain_limits_persist_secs")]
    pub domain_limits_persist_secs: u64,

    /// Embedded admin panel (SQLite + UI). Disabled when `enabled: false`.
    #[serde(default)]
    pub panel: PanelConfig,

    /// Path of the YAML config file that was loaded (filled at runtime; not from YAML).
    #[serde(skip)]
    pub config_path: Option<String>,
}

/// Admin panel bind address, database, and dnsmasq integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelConfig {
    /// Master switch. Default true so Docker images ship with a panel.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Listen address for the panel HTTP server.
    #[serde(default = "default_panel_addr")]
    pub addr: String,
    /// SQLite database path.
    #[serde(default = "default_panel_db")]
    pub db_path: String,
    /// Public/server IP written into dnsmasq `address=/domain/IP` lines.
    #[serde(default)]
    pub relay_ip: Option<String>,
    /// Directory of dnsmasq drop-in configs (e.g. `/etc/dnsmasq.d`). When set,
    /// the Domains tab reads/writes live dnsmasq files instead of SQLite.
    #[serde(default)]
    pub dnsmasq_conf_dir: Option<String>,
    /// File for `address=/…/RELAY_IP` rules. Auto-detected if omitted.
    #[serde(default)]
    pub dnsmasq_relay_file: Option<String>,
    /// File for bypass `server=/…/#` rules. Auto-detected if omitted.
    #[serde(default)]
    pub dnsmasq_bypass_file: Option<String>,
    /// Legacy single-file export path (still used as relay file fallback).
    #[serde(default)]
    pub dnsmasq_conf_path: Option<String>,
    /// Optional absolute path to dnsmasq query log (`log-queries` + `log-facility=/path`).
    #[serde(default)]
    pub dnsmasq_query_log: Option<String>,
    /// How long to keep DNS query log rows in SQLite (hours). Default 72.
    #[serde(default = "default_dns_query_retain_hours")]
    pub dns_query_retain_hours: u64,
    /// Optional shell command after writing dnsmasq config (e.g. `kill -HUP $(pidof dnsmasq)`).
    #[serde(default)]
    pub dnsmasq_reload_cmd: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Runtime upstream health monitor (lightweight SOCKS/HTTP handshake probes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamMonitorConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Seconds between full probe rounds (default 60).
    #[serde(default = "default_monitor_interval_secs")]
    pub interval_secs: u64,
    /// Per-probe timeout (default 10s) — CONNECT + TLS/HTTP reply.
    #[serde(default = "default_monitor_timeout_secs")]
    pub timeout_secs: u64,
    /// Consecutive failures before marking DOWN + notify (default 2).
    #[serde(default = "default_monitor_fail_threshold")]
    pub fail_threshold: u32,
    /// Consecutive successes before marking UP after DOWN (default 2).
    #[serde(default = "default_monitor_recover_threshold")]
    pub recover_threshold: u32,
    /// Send Telegram message when a profile recovers.
    #[serde(default = "default_true")]
    pub notify_recovery: bool,
    /// Min seconds between two similar alerts for the same profile (default 600).
    #[serde(default = "default_monitor_cooldown_secs")]
    pub notify_cooldown_secs: u64,
    /// Profile names to monitor. Empty = all non-`direct` profiles.
    #[serde(default)]
    pub profiles: Vec<String>,
    /// Primary probe host (used when `probe_hosts` is empty).
    /// Default `ifconfig.io` — matches a typical manual `curl --proxy … https://ifconfig.io` check.
    #[serde(default = "default_monitor_probe_host")]
    pub probe_host: String,
    /// Port for `probe_host` / default port for entries in `probe_hosts` (default 443).
    #[serde(default = "default_monitor_probe_port")]
    pub probe_port: u16,
    /// Optional list of `host` or `host:port`. When non-empty, **all** must succeed.
    /// Useful when Cloudflare still answers but general HTTPS is dead.
    #[serde(default)]
    pub probe_hosts: Vec<String>,
}

impl UpstreamMonitorConfig {
    /// Resolved `(host, port)` list for the e2e probe.
    pub fn probe_targets(&self) -> Vec<(String, u16)> {
        if self.probe_hosts.is_empty() {
            return vec![(self.probe_host.clone(), self.probe_port)];
        }
        self.probe_hosts
            .iter()
            .filter(|s| !s.trim().is_empty())
            .map(|s| parse_probe_target(s, self.probe_port))
            .collect()
    }

    pub fn probe_targets_label(&self) -> String {
        self.probe_targets()
            .into_iter()
            .map(|(h, p)| format!("{h}:{p}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl Default for UpstreamMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: default_monitor_interval_secs(),
            timeout_secs: default_monitor_timeout_secs(),
            fail_threshold: default_monitor_fail_threshold(),
            recover_threshold: default_monitor_recover_threshold(),
            notify_recovery: true,
            notify_cooldown_secs: default_monitor_cooldown_secs(),
            profiles: Vec::new(),
            probe_host: default_monitor_probe_host(),
            probe_port: default_monitor_probe_port(),
            probe_hosts: Vec::new(),
        }
    }
}

fn parse_probe_target(raw: &str, default_port: u16) -> (String, u16) {
    let s = raw.trim();
    if let Some((host, port_s)) = s.rsplit_once(':') {
        if !host.is_empty() && !host.contains(']') && port_s.parse::<u16>().is_ok() {
            if let Ok(p) = port_s.parse::<u16>() {
                return (host.to_string(), p);
            }
        }
    }
    // IPv6 in brackets: [2001:db8::1]:443
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((host, port_s)) = rest.split_once("]:") {
            if let Ok(p) = port_s.parse::<u16>() {
                return (host.to_string(), p);
            }
        }
    }
    (s.to_string(), default_port)
}

fn default_monitor_interval_secs() -> u64 {
    60
}
fn default_monitor_timeout_secs() -> u64 {
    10
}
fn default_monitor_fail_threshold() -> u32 {
    2
}
fn default_monitor_recover_threshold() -> u32 {
    2
}
fn default_monitor_cooldown_secs() -> u64 {
    600
}
fn default_monitor_probe_host() -> String {
    // Same target many operators use for `curl --proxy socks5://… https://ifconfig.io`.
    // Cloudflare (one.one.one.one) often still works when the node is "half-dead".
    "ifconfig.io".into()
}
fn default_monitor_probe_port() -> u16 {
    443
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramConfig {
    #[serde(default)]
    pub bot_token: Option<String>,
    #[serde(default)]
    pub chat_id: Option<String>,
    /// Bot API host base, e.g. `https://api.telegram.org` or a local reverse-proxy.
    /// Override with `TELEGRAM_API_BASE`. Trailing slash is stripped.
    #[serde(default = "default_telegram_api_base")]
    pub api_base: String,
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            bot_token: None,
            chat_id: None,
            api_base: default_telegram_api_base(),
        }
    }
}

fn default_telegram_api_base() -> String {
    "https://api.telegram.org".into()
}

impl TelegramConfig {
    pub fn is_configured(&self) -> bool {
        matches!(
            (&self.bot_token, &self.chat_id),
            (Some(t), Some(c)) if !t.is_empty() && !c.is_empty()
        )
    }

    /// Normalized API base without trailing slash.
    pub fn api_base_url(&self) -> &str {
        self.api_base.trim_end_matches('/')
    }
}
fn default_panel_addr() -> String {
    "0.0.0.0:9080".into()
}
fn default_panel_db() -> String {
    "/var/lib/snirelay/panel.db".into()
}
fn default_dns_query_retain_hours() -> u64 {
    72
}

impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            addr: default_panel_addr(),
            db_path: default_panel_db(),
            relay_ip: None,
            dnsmasq_conf_dir: None,
            dnsmasq_relay_file: None,
            dnsmasq_bypass_file: None,
            dnsmasq_conf_path: None,
            dnsmasq_query_log: None,
            dns_query_retain_hours: default_dns_query_retain_hours(),
            dnsmasq_reload_cmd: None,
        }
    }
}

fn default_listeners() -> Vec<ListenerConfig> {
    vec![
        ListenerConfig {
            name: Some("https".to_string()),
            addr: "0.0.0.0:443".to_string(),
            proto: Some("tls".to_string()),
            routes: Vec::new(),
        },
        ListenerConfig {
            name: Some("http".to_string()),
            addr: "0.0.0.0:80".to_string(),
            proto: Some("http".to_string()),
            routes: Vec::new(),
        },
    ]
}

fn default_connect_timeout() -> u64 { 10 }
fn default_upstream_probe_wait_secs() -> u64 { 60 }
fn default_upstream_probe_interval_secs() -> u64 { 2 }
fn default_upstream_probe_required() -> bool { false }
fn default_rw_timeout()     -> u64 { 300 }
fn default_max_conn()        -> usize { 50_000 }
fn default_nofile_limit()   -> u64 { 1_048_576 }
fn default_listen_backlog() -> u32 { 4096 }
fn default_metrics_refresh_secs() -> u64 { 2 }
fn default_domain_limits_persist_secs() -> u64 { 5 }

impl Default for UpstreamProxy {
    fn default() -> Self {
        UpstreamProxy::Socks5 {
            host: "127.0.0.1".to_string(),
            port: 1080,
            username: None,
            password: None,
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            listens: default_listeners(),
            tls_listen: Vec::new(),
            http_listen: Vec::new(),
            upstream_proxy: UpstreamProxy::default(),
            upstreams: HashMap::new(),
            default_upstream: None,
            client_upstreams: HashMap::new(),
            upstream_failover: false,
            client_whitelist: Vec::new(),
            client_whitelist_ufw: true,
            ufw_bin: None,
            upstream_monitor: UpstreamMonitorConfig::default(),
            telegram: TelegramConfig::default(),
            connect_timeout_secs: default_connect_timeout(),
            upstream_probe_wait_secs: default_upstream_probe_wait_secs(),
            upstream_probe_interval_secs: default_upstream_probe_interval_secs(),
            upstream_probe_required: default_upstream_probe_required(),
            rw_timeout_secs: default_rw_timeout(),
            workers: 0,
            metrics_addr: None,
            log_file: None,
            metrics_refresh_secs: default_metrics_refresh_secs(),
            max_connections: default_max_conn(),
            nofile_limit: default_nofile_limit(),
            listen_backlog: default_listen_backlog(),
            hosts: Vec::new(),
            hosts_table: None,
            domain_limits: HashMap::new(),
            domain_limits_state_file: None,
            domain_limits_persist_secs: default_domain_limits_persist_secs(),
            panel: PanelConfig::default(),
            config_path: None,
        }
    }
}

impl AppConfig {
    /// State file path for domain limit counters, if limits are configured.
    pub fn domain_limits_state_path(&self) -> Option<std::path::PathBuf> {
        if self.domain_limits.is_empty() {
            return None;
        }
        if let Some(path) = &self.domain_limits_state_file {
            return Some(std::path::PathBuf::from(path));
        }
        if let Ok(path) = std::env::var("DOMAIN_LIMITS_STATE_FILE") {
            if !path.is_empty() {
                return Some(std::path::PathBuf::from(path));
            }
        }
        Some(std::path::PathBuf::from("/var/lib/snirelay/domain_limits.json"))
    }

    /// Load config from YAML file, falling back to defaults if file not found.
    pub fn load(path: &str) -> Result<Self> {
        // First check environment variables (Docker-friendly)
        let from_env = Self::from_env();

        if Path::new(path).exists() {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read config file: {path}"))?;
            let mut cfg: AppConfig = serde_yaml::from_str(&content)
                .with_context(|| format!("Failed to parse config file: {path}"))?;

            // Env vars take precedence over file (default profile only).
            if let Some(proxy) = from_env.upstream_proxy_override {
                cfg.apply_default_proxy_override(proxy);
            }
            apply_probe_env_overrides(&mut cfg);
            apply_panel_env_overrides(&mut cfg);
            apply_monitor_env_overrides(&mut cfg);
            cfg.config_path = Some(path.to_string());

            cfg.finalize()?;
            Ok(cfg)
        } else {
            tracing::warn!("Config file {path} not found, using defaults + env vars");
            let mut cfg = AppConfig::default();
            if let Some(proxy) = from_env.upstream_proxy_override {
                cfg.apply_default_proxy_override(proxy);
            }
            apply_probe_env_overrides(&mut cfg);
            apply_panel_env_overrides(&mut cfg);
            apply_monitor_env_overrides(&mut cfg);
            cfg.config_path = Some(path.to_string());
            cfg.finalize()?;
            Ok(cfg)
        }
    }

    /// Override the default upstream profile (`PROXY` / `--proxy`).
    pub fn apply_default_proxy_override(&mut self, proxy: UpstreamProxy) {
        self.upstream_proxy = proxy.clone();
        let name = self
            .default_upstream
            .clone()
            .filter(|n| self.upstreams.contains_key(n) || self.upstreams.is_empty())
            .unwrap_or_else(|| {
                if self.upstreams.is_empty() {
                    "default".into()
                } else {
                    self.upstreams
                        .keys()
                        .next()
                        .cloned()
                        .unwrap_or_else(|| "default".into())
                }
            });
        if self.upstreams.is_empty() {
            self.upstreams.insert(name.clone(), proxy);
            self.default_upstream = Some(name);
        } else {
            self.upstreams.insert(name.clone(), proxy);
            self.default_upstream = Some(name);
        }
    }

    /// Parse listeners, normalize multi-upstream maps, compile hosts table.
    pub fn finalize(&mut self) -> Result<()> {
        self.finalize_listeners()?;
        self.normalize_upstreams()?;
        self.normalize_client_whitelist();
        self.hosts_table = crate::hosts::compile_hosts_table(&self.hosts)?;
        Ok(())
    }

    fn normalize_client_whitelist(&mut self) {
        let mut out = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for e in std::mem::take(&mut self.client_whitelist) {
            match normalize_client_ip(&e.ip) {
                Some(n) if seen.insert(n.clone()) => {
                    out.push(WhitelistEntry {
                        ip: n,
                        username: e
                            .username
                            .as_deref()
                            .and_then(sanitize_whitelist_username),
                    });
                }
                Some(_) => {}
                None => tracing::warn!(ip = %e.ip, "dropping invalid client_whitelist entry"),
            }
        }
        self.client_whitelist = out;
    }

    /// Ensure `upstreams` / `default_upstream` / `client_upstreams` are consistent
    /// and keep legacy `upstream_proxy` synced to the default profile.
    pub fn normalize_upstreams(&mut self) -> Result<()> {
        if self.upstreams.is_empty() {
            self.upstreams
                .insert("default".into(), self.upstream_proxy.clone());
            self.default_upstream = Some("default".into());
        }

        let default_name = match &self.default_upstream {
            Some(name) if self.upstreams.contains_key(name) => name.clone(),
            Some(name) => {
                bail!(
                    "default_upstream '{name}' is not in upstreams ({:?})",
                    self.upstreams.keys().collect::<Vec<_>>()
                );
            }
            None => {
                // Prefer a profile literally named "default", else first key (stable-ish).
                if self.upstreams.contains_key("default") {
                    "default".into()
                } else {
                    let mut keys: Vec<_> = self.upstreams.keys().cloned().collect();
                    keys.sort();
                    keys.into_iter()
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("upstreams map is empty"))?
                }
            }
        };
        self.default_upstream = Some(default_name.clone());
        self.upstream_proxy = self
            .upstreams
            .get(&default_name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing default upstream profile"))?;

        // Drop client mappings that point at unknown profiles (warn).
        let unknown: Vec<_> = self
            .client_upstreams
            .iter()
            .filter(|(_, profile)| !self.upstreams.contains_key(*profile))
            .map(|(ip, profile)| (ip.clone(), profile.clone()))
            .collect();
        for (ip, profile) in unknown {
            tracing::warn!(
                client_ip = %ip,
                profile = %profile,
                "client_upstreams entry references unknown profile; removing"
            );
            self.client_upstreams.remove(&ip);
        }

        // Canonicalize IP keys where parseable.
        let raw = std::mem::take(&mut self.client_upstreams);
        for (ip, profile) in raw {
            let key = normalize_client_ip(&ip).unwrap_or(ip);
            self.client_upstreams.insert(key, profile);
        }

        Ok(())
    }

    /// Default profile name after normalize.
    pub fn default_upstream_name(&self) -> &str {
        self.default_upstream.as_deref().unwrap_or("default")
    }

    /// Build the final listener list from `listens` or legacy `tls_listen` + `http_listen`.
    pub fn finalize_listeners(&mut self) -> Result<()> {
        if self.listens.is_empty() {
            self.listens.reserve(self.tls_listen.len() + self.http_listen.len());
            self.listens.append(&mut self.tls_listen);
            self.listens.append(&mut self.http_listen);
        } else if !self.tls_listen.is_empty() || !self.http_listen.is_empty() {
            tracing::warn!(
                "config: `listens` is set; ignoring tls_listen ({}) and http_listen ({})",
                self.tls_listen.len(),
                self.http_listen.len()
            );
            self.tls_listen.clear();
            self.http_listen.clear();
        }

        if self.listens.is_empty() {
            self.listens = default_listeners();
        }

        for (i, listener) in self.listens.iter_mut().enumerate() {
            if !listener.routes.is_empty() {
                tracing::warn!(
                    "listens[{i}] {}: `routes` is deprecated and ignored; use global `hosts` only",
                    listener.addr
                );
                listener.routes.clear();
            }
            listener
                .normalize_proto()
                .with_context(|| format!("listens[{i}] ({})", listener.addr))?;
        }

        Ok(())
    }

    /// Remap loopback upstreams when the gateway resembles a Docker bridge.
    /// Host networking shares the host loopback; gateway detection is heuristic.
    /// Applies to every named profile in `upstreams` (and synced `upstream_proxy`).
    pub fn remap_docker_loopback_upstream(&mut self) {
        if !Path::new("/.dockerenv").exists() {
            return;
        }
        if std::env::var("HOST_PROXY_GATEWAY")
            .map(|v| v.eq_ignore_ascii_case("off"))
            .unwrap_or(false)
        {
            return;
        }

        let any_loopback = self
            .upstreams
            .values()
            .chain(std::iter::once(&self.upstream_proxy))
            .any(|p| p.host_port().map(|(h, _)| is_loopback_host(h)).unwrap_or(false));
        if !any_loopback {
            return;
        }

        let gateway = std::env::var("HOST_PROXY_GATEWAY")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(docker_default_gateway);

        let Some(gw) = gateway else {
            tracing::warn!(
                "Upstream proxy uses loopback but Docker host gateway could not be detected; \
                 use HOST_PROXY_GATEWAY or `docker run --network host`"
            );
            return;
        };

        if !is_docker_bridge_gateway(&gw) {
            tracing::info!(
                "Docker: default gateway {gw} does not match the bridge heuristic; \
                 keeping loopback upstreams (`--network host` shares the host loopback)"
            );
            return;
        }

        for (name, proxy) in self.upstreams.iter_mut() {
            remap_proxy_loopback_host(proxy, &gw, Some(name));
        }
        remap_proxy_loopback_host(&mut self.upstream_proxy, &gw, None);
    }

    fn from_env() -> EnvOverrides {
        let proxy = std::env::var("PROXY").ok()
            .and_then(|s| parse_proxy_string(&s).ok());
        EnvOverrides { upstream_proxy_override: proxy }
    }
}

struct EnvOverrides {
    upstream_proxy_override: Option<UpstreamProxy>,
}

/// Parse "socks5 host port" or "http host port" strings (proxychains format)
pub fn parse_proxy_string(s: &str) -> Result<UpstreamProxy> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.is_empty() || parts[0].eq_ignore_ascii_case("direct") {
        return Ok(UpstreamProxy::Direct);
    }
    if parts.len() < 3 {
        bail!("Invalid proxy string '{}'. Expected: '<type> <host> <port>'", s);
    }
    let host = parts[1].to_string();
    let port: u16 = parts[2].parse()
        .with_context(|| format!("Invalid port in proxy string: '{}'", parts[2]))?;

    match parts[0].to_lowercase().as_str() {
        "socks5" | "socks5h" => {
            let username = parts.get(3).map(|s| s.to_string());
            let password = parts.get(4).map(|s| s.to_string());
            Ok(UpstreamProxy::Socks5 { host, port, username, password })
        }
        "http" | "https" => {
            Ok(UpstreamProxy::Http { host, port, auth: None })
        }
        other => bail!("Unknown proxy type '{}'. Expected socks5 or http", other),
    }
}

fn apply_monitor_env_overrides(cfg: &mut AppConfig) {
    if let Ok(v) = std::env::var("UPSTREAM_MONITOR_ENABLED") {
        cfg.upstream_monitor.enabled = matches!(
            v.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
    if let Ok(v) = std::env::var("UPSTREAM_MONITOR_INTERVAL_SECS") {
        if let Ok(secs) = v.parse::<u64>() {
            cfg.upstream_monitor.interval_secs = secs.max(15);
        }
    }
    if let Ok(v) = std::env::var("UPSTREAM_MONITOR_TIMEOUT_SECS") {
        if let Ok(secs) = v.parse::<u64>() {
            cfg.upstream_monitor.timeout_secs = secs.max(1);
        }
    }
    if let Ok(v) = std::env::var("UPSTREAM_MONITOR_FAIL_THRESHOLD") {
        if let Ok(n) = v.parse::<u32>() {
            cfg.upstream_monitor.fail_threshold = n.max(1);
        }
    }
    if let Ok(v) = std::env::var("UPSTREAM_MONITOR_PROBE_HOST") {
        if !v.is_empty() {
            cfg.upstream_monitor.probe_host = v;
        }
    }
    if let Ok(v) = std::env::var("UPSTREAM_MONITOR_PROBE_PORT") {
        if let Ok(p) = v.parse::<u16>() {
            cfg.upstream_monitor.probe_port = p;
        }
    }
    if let Ok(v) = std::env::var("UPSTREAM_MONITOR_PROBE_HOSTS") {
        let list: Vec<String> = v
            .split(|c| c == ',' || c == ' ')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if !list.is_empty() {
            cfg.upstream_monitor.probe_hosts = list;
        }
    }
    if let Ok(v) = std::env::var("TELEGRAM_BOT_TOKEN") {
        if !v.is_empty() {
            cfg.telegram.bot_token = Some(v);
        }
    }
    if let Ok(v) = std::env::var("TELEGRAM_CHAT_ID") {
        if !v.is_empty() {
            cfg.telegram.chat_id = Some(v);
        }
    }
    if let Ok(v) = std::env::var("TELEGRAM_API_BASE") {
        if !v.is_empty() {
            cfg.telegram.api_base = v.trim_end_matches('/').to_string();
        }
    }
}

fn apply_probe_env_overrides(cfg: &mut AppConfig) {
    if let Ok(v) = std::env::var("UPSTREAM_PROBE_WAIT_SECS") {
        if let Ok(secs) = v.parse::<u64>() {
            cfg.upstream_probe_wait_secs = secs;
        }
    }
    if let Ok(v) = std::env::var("UPSTREAM_PROBE_INTERVAL_SECS") {
        if let Ok(secs) = v.parse::<u64>() {
            cfg.upstream_probe_interval_secs = secs.max(1);
        }
    }
    if let Ok(v) = std::env::var("UPSTREAM_PROBE_REQUIRED") {
        cfg.upstream_probe_required = matches!(
            v.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
}

fn apply_panel_env_overrides(cfg: &mut AppConfig) {
    if let Ok(v) = std::env::var("PANEL_ADDR") {
        if !v.is_empty() {
            cfg.panel.addr = v;
        }
    }
    if let Ok(v) = std::env::var("PANEL_DB") {
        if !v.is_empty() {
            cfg.panel.db_path = v;
        }
    }
    if let Ok(v) = std::env::var("PANEL_ENABLED") {
        cfg.panel.enabled = matches!(
            v.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
    if let Ok(v) = std::env::var("RELAY_IP") {
        if !v.is_empty() {
            cfg.panel.relay_ip = Some(v);
        }
    }
    if let Ok(v) = std::env::var("DNSMASQ_CONF_DIR") {
        if !v.is_empty() {
            cfg.panel.dnsmasq_conf_dir = Some(v);
        }
    }
    if let Ok(v) = std::env::var("DNSMASQ_RELAY_FILE") {
        if !v.is_empty() {
            cfg.panel.dnsmasq_relay_file = Some(v);
        }
    }
    if let Ok(v) = std::env::var("DNSMASQ_BYPASS_FILE") {
        if !v.is_empty() {
            cfg.panel.dnsmasq_bypass_file = Some(v);
        }
    }
    if let Ok(v) = std::env::var("DNSMASQ_CONF_PATH") {
        if !v.is_empty() {
            cfg.panel.dnsmasq_conf_path = Some(v.clone());
            if cfg.panel.dnsmasq_relay_file.is_none() {
                cfg.panel.dnsmasq_relay_file = Some(v);
            }
        }
    }
    if let Ok(v) = std::env::var("DNSMASQ_QUERY_LOG") {
        if !v.is_empty() {
            cfg.panel.dnsmasq_query_log = Some(v);
        }
    }
    if let Ok(v) = std::env::var("DNS_QUERY_RETAIN_HOURS") {
        if let Ok(n) = v.parse::<u64>() {
            cfg.panel.dns_query_retain_hours = n.max(1);
        }
    }
    if let Ok(v) = std::env::var("DNSMASQ_RELOAD_CMD") {
        if !v.is_empty() {
            cfg.panel.dnsmasq_reload_cmd = Some(v);
        }
    }
    if let Ok(v) = std::env::var("CLIENT_WHITELIST_UFW") {
        cfg.client_whitelist_ufw = matches!(
            v.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
    if let Ok(v) = std::env::var("UFW_BIN") {
        if !v.is_empty() {
            cfg.ufw_bin = Some(v);
        }
    }
    // Auto-detect dnsmasq drop-in dir when unset but present (e.g. mounted volume).
    if cfg
        .panel
        .dnsmasq_conf_dir
        .as_ref()
        .map(|s| s.is_empty())
        .unwrap_or(true)
    {
        for candidate in ["/etc/dnsmasq.d", "/usr/local/etc/dnsmasq.d"] {
            if std::path::Path::new(candidate).is_dir() {
                cfg.panel.dnsmasq_conf_dir = Some(candidate.into());
                break;
            }
        }
    }
    // Auto-detect common dnsmasq query log when unset but present (e.g. mounted volume).
    if cfg
        .panel
        .dnsmasq_query_log
        .as_ref()
        .map(|s| s.is_empty())
        .unwrap_or(true)
    {
        for candidate in [
            "/var/log/dnsmasq/queries.log",
            "/var/log/dnsmasq.log",
            "/var/log/dnsmasq/dnsmasq.log",
        ] {
            if std::path::Path::new(candidate).is_file() {
                cfg.panel.dnsmasq_query_log = Some(candidate.into());
                break;
            }
        }
    }
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn remap_proxy_loopback_host(proxy: &mut UpstreamProxy, gateway: &str, profile: Option<&str>) {
    match proxy {
        UpstreamProxy::Socks5 { host, port, .. } | UpstreamProxy::Http { host, port, .. }
            if is_loopback_host(host) =>
        {
            let old = host.clone();
            let port = *port;
            if let Some(name) = profile {
                tracing::info!(
                    "Docker: remapping upstream profile '{name}' {old}:{port} → {gateway}:{port}"
                );
            } else {
                tracing::info!(
                    "Docker: remapping upstream proxy {old}:{port} → {gateway}:{port} \
                     (127.0.0.1 inside a container is not the host)"
                );
            }
            tracing::warn!(
                "Host SOCKS/HTTP proxy must listen on 0.0.0.0:{port} or {gateway}:{port}, \
                 or run sniproxy with `docker run --network host`"
            );
            *host = gateway.to_string();
        }
        _ => {}
    }
}

/// Canonicalize a client IP string for map lookups (IPv4/IPv6).
pub fn normalize_client_ip(ip: &str) -> Option<String> {
    let s = ip.trim();
    if s.is_empty() {
        return None;
    }
    s.parse::<std::net::IpAddr>()
        .ok()
        .map(|a| a.to_string())
}

/// One whitelist row: IP plus optional username (stored in UFW comment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhitelistEntry {
    pub ip: String,
    pub username: Option<String>,
}

impl WhitelistEntry {
    pub fn ip_only(ip: impl Into<String>) -> Self {
        Self {
            ip: ip.into(),
            username: None,
        }
    }
}

impl<'de> Deserialize<'de> for WhitelistEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Ip(String),
            Obj {
                ip: String,
                #[serde(default)]
                username: Option<String>,
            },
        }
        match Raw::deserialize(deserializer)? {
            Raw::Ip(ip) => Ok(Self {
                ip,
                username: None,
            }),
            Raw::Obj { ip, username } => Ok(Self {
                ip,
                username: username.and_then(|u| sanitize_whitelist_username(&u)),
            }),
        }
    }
}

impl Serialize for WhitelistEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        match &self.username {
            Some(u) if !u.is_empty() => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("ip", &self.ip)?;
                map.serialize_entry("username", u)?;
                map.end()
            }
            _ => serializer.serialize_str(&self.ip),
        }
    }
}

/// Sanitize username for UFW comments / API.
/// Allows letters, digits, and `._@+-`. Max 32 chars. Empty → None.
pub fn sanitize_whitelist_username(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '+' | '-'))
        .take(32)
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// True when the default route points at Docker's bridge (not the host's public gateway).
fn is_docker_bridge_gateway(gw: &str) -> bool {
    gw.starts_with("172.17.")
        || gw.starts_with("172.18.")
        || gw.starts_with("172.19.")
        || gw.starts_with("172.20.")
        || gw.starts_with("172.21.")
        || gw.starts_with("172.22.")
        || gw.starts_with("192.168.65.")
}

/// Default route gateway from `/proc/net/route` (Docker bridge → host).
fn docker_default_gateway() -> Option<String> {
    let route = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in route.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[1] == "00000000" {
            return hex_le_ipv4(fields[2]);
        }
    }
    None
}

fn hex_le_ipv4(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let octet = |i: usize| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok();
    // `/proc/net/route` stores the gateway as a little-endian hex uint32.
    Some(format!(
        "{}.{}.{}.{}",
        octet(3)?,
        octet(2)?,
        octet(1)?,
        octet(0)?
    ))
}

#[cfg(test)]
mod byte_size_tests {
    use super::parse_byte_size;

    #[test]
    fn mib_suffix_is_case_insensitive() {
        assert_eq!(parse_byte_size("20MiB").unwrap(), 20 * 1_048_576);
        assert_eq!(parse_byte_size("20Mib").unwrap(), 20 * 1_048_576);
        assert_eq!(parse_byte_size("20mib").unwrap(), 20 * 1_048_576);
    }
}

#[cfg(test)]
mod docker_tests {
    use super::*;

    #[test]
    fn hex_le_ipv4_parses_docker_gateway() {
        assert_eq!(hex_le_ipv4("010011AC").as_deref(), Some("172.17.0.1"));
    }

    #[test]
    fn loopback_hosts() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("localhost"));
        assert!(!is_loopback_host("172.17.0.1"));
    }

    #[test]
    fn docker_bridge_gateway_detection() {
        assert!(is_docker_bridge_gateway("172.17.0.1"));
        assert!(!is_docker_bridge_gateway("31.214.250.65"));
    }

    #[test]
    fn public_socks_yaml_preserves_endpoint_and_routing() {
        let yaml = r#"
upstream_proxy:
  type: socks5
  host: "103.75.197.9"
  port: 1080
listens:
  - name: https
    addr: "0.0.0.0:443"
    proto: tls
  - name: http
    addr: "0.0.0.0:80"
    proto: http
hosts:
  - pattern: ".*"
    address: "*"
"#;
        let mut cfg: AppConfig = serde_yaml::from_str(yaml).unwrap();
        cfg.finalize().unwrap();
        cfg.remap_docker_loopback_upstream();
        assert_eq!(cfg.upstream_proxy.host_port(), Some(("103.75.197.9", 1080)));
        assert_eq!(cfg.listens.len(), 2);
        assert_eq!(cfg.hosts_table.as_ref().unwrap().stats(), (0, 1));
    }

    #[test]
    fn parse_multi_listens_yaml() {
        let yaml = r#"
listens:
  - name: https-main
    addr: "0.0.0.0:443"
    proto: tls
  - name: https-alt
    addr: "0.0.0.0:8443"
    proto: tls
  - name: http-main
    addr: "0.0.0.0:80"
    proto: http
  - addr: "0.0.0.0:8080"
"#;
        let mut cfg: AppConfig = serde_yaml::from_str(yaml).unwrap();
        cfg.finalize().unwrap();
        assert_eq!(cfg.listens.len(), 4);
        assert!(cfg.listens[0].is_tls());
        assert!(cfg.listens[2].is_http());
        assert!(cfg.listens[3].is_http());
        assert_eq!(cfg.listens[3].proto_str(), "http");
    }

    #[test]
    fn legacy_tls_and_http_listen_merge() {
        let yaml = r#"
tls_listen:
  - addr: "0.0.0.0:9443"
    proto: tls
http_listen:
  - addr: "0.0.0.0:8080"
    proto: http
"#;
        let mut cfg: AppConfig = serde_yaml::from_str(yaml).unwrap();
        cfg.finalize().unwrap();
        assert_eq!(cfg.listens.len(), 2);
        assert_eq!(cfg.listens[0].addr, "0.0.0.0:9443");
        assert_eq!(cfg.listens[1].addr, "0.0.0.0:8080");
    }
}
