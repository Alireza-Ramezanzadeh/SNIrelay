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

// ── Routing table entry ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    /// Regex pattern matched against the SNI/Host. Use ".*" for wildcard.
    pub pattern: String,
    /// Target address.  "*" means "same host, same port".
    #[serde(default = "default_target")]
    pub target: String,
}

fn default_target() -> String {
    "*".to_string()
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
    /// Routing table for this listener
    #[serde(default = "default_routes")]
    pub routes: Vec<RouteEntry>,
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

fn default_routes() -> Vec<RouteEntry> {
    vec![RouteEntry { pattern: ".*".to_string(), target: "*".to_string() }]
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

    /// Upstream proxy to tunnel traffic through
    #[serde(default)]
    pub upstream_proxy: UpstreamProxy,

    /// Connection timeout to upstream proxy (seconds)
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,

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

    /// Static hostname → IP map. Checked before per-listener routes.
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
}

fn default_listeners() -> Vec<ListenerConfig> {
    vec![
        ListenerConfig {
            name: Some("https".to_string()),
            addr: "0.0.0.0:443".to_string(),
            proto: Some("tls".to_string()),
            routes: default_routes(),
        },
        ListenerConfig {
            name: Some("http".to_string()),
            addr: "0.0.0.0:80".to_string(),
            proto: Some("http".to_string()),
            routes: default_routes(),
        },
    ]
}

fn default_connect_timeout() -> u64 { 10 }
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
            connect_timeout_secs: default_connect_timeout(),
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

            // Env vars take precedence over file
            if let Some(proxy) = from_env.upstream_proxy_override {
                cfg.upstream_proxy = proxy;
            }

            cfg.finalize()?;
            Ok(cfg)
        } else {
            tracing::warn!("Config file {path} not found, using defaults + env vars");
            let mut cfg = AppConfig::default();
            if let Some(proxy) = from_env.upstream_proxy_override {
                cfg.upstream_proxy = proxy;
            }
            cfg.finalize()?;
            Ok(cfg)
        }
    }

    /// Parse listeners and compile the hosts table.
    pub fn finalize(&mut self) -> Result<()> {
        self.finalize_listeners()?;
        self.hosts_table = crate::hosts::compile_hosts_table(&self.hosts)?;
        Ok(())
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
            listener
                .normalize_proto()
                .with_context(|| format!("listens[{i}] ({})", listener.addr))?;
        }

        Ok(())
    }

    /// When running inside Docker, `127.0.0.1` / `localhost` on the upstream proxy
    /// refer to the container, not the host where v2ray/SOCKS usually listens.
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
                "Docker: default gateway is {gw} (not docker0 bridge); keeping upstream 127.0.0.1 \
                 (`docker run --network host` shares the host loopback)"
            );
            return;
        }

        match &mut self.upstream_proxy {
            UpstreamProxy::Socks5 { host, port, .. } | UpstreamProxy::Http { host, port, .. }
                if is_loopback_host(host) =>
            {
                let old = host.clone();
                let port = *port;
                tracing::info!(
                    "Docker: remapping upstream proxy {old}:{port} → {gw}:{port} \
                     (127.0.0.1 inside a container is not the host)"
                );
                tracing::warn!(
                    "Host SOCKS/HTTP proxy must listen on 0.0.0.0:{port} or {gw}:{port}, \
                     or run sniproxy with `docker run --network host`"
                );
                *host = gw;
            }
            _ => {}
        }
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

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1")
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
    fn parse_multi_listens_yaml() {
        let yaml = r#"
listens:
  - name: https-main
    addr: "0.0.0.0:443"
    proto: tls
    routes:
      - pattern: ".*"
        target: "*"
  - name: https-alt
    addr: "0.0.0.0:8443"
    proto: tls
    routes:
      - pattern: ".*"
        target: "*"
  - name: http-main
    addr: "0.0.0.0:80"
    proto: http
    routes:
      - pattern: ".*"
        target: "*"
  - addr: "0.0.0.0:8080"
    routes:
      - pattern: ".*"
        target: "*"
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
    routes:
      - pattern: ".*"
        target: "*"
http_listen:
  - addr: "0.0.0.0:8080"
    proto: http
    routes:
      - pattern: ".*"
        target: "*"
"#;
        let mut cfg: AppConfig = serde_yaml::from_str(yaml).unwrap();
        cfg.finalize().unwrap();
        assert_eq!(cfg.listens.len(), 2);
        assert_eq!(cfg.listens[0].addr, "0.0.0.0:9443");
        assert_eq!(cfg.listens[1].addr, "0.0.0.0:8080");
    }
}
