// service.rs — Pingora-based SNI proxy service
//
// For each incoming TCP connection we:
//   1. Peek at the first bytes without consuming them
//   2. Extract SNI (TLS) or Host header (HTTP)
//   3. Match against routing table
//   4. Dial the upstream proxy tunnel to the origin
//   5. Splice bytes bidirectionally — zero-copy where possible
//
// Pingora's `ServerApp` trait is used for the raw TCP listener.
// We do NOT use `HttpProxy` because we need raw L4 access to avoid
// TLS termination.

use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use regex::Regex;

use crate::config::{AppConfig, RouteEntry};
use crate::hosts::{HostResolve, HostsTable};
use crate::metrics::{self, TargetLabels};
use crate::proxy_connector;
use crate::sni::{self, PeekResult};

// ── Route table (compiled regexes) ───────────────────────────────────────────

struct CompiledRoute {
    pattern: Regex,
    target: String,
}

struct RouteTable {
    routes: Vec<CompiledRoute>,
}

impl RouteTable {
    fn compile(routes: &[RouteEntry]) -> Result<Self> {
        let compiled = routes.iter().map(|r| {
            let pattern = Regex::new(&r.pattern)
                .with_context(|| format!("Invalid route regex: '{}'", r.pattern))?;
            Ok(CompiledRoute { pattern, target: r.target.clone() })
        }).collect::<Result<Vec<_>>>()?;
        Ok(RouteTable { routes: compiled })
    }

    /// Returns the target for a given hostname.
    /// Target "*" means "use the hostname as-is".
    fn resolve(&self, hostname: &str) -> Option<&str> {
        for route in &self.routes {
            if route.pattern.is_match(hostname) {
                return Some(&route.target);
            }
        }
        None
    }
}

// ── Top-level service ─────────────────────────────────────────────────────────

pub struct SniProxyService {
    cfg: Arc<AppConfig>,
    connection_slots: Arc<Semaphore>,
}

impl SniProxyService {
    pub fn new(cfg: AppConfig, max_connections: usize) -> Self {
        SniProxyService {
            cfg: Arc::new(cfg),
            connection_slots: Arc::new(Semaphore::new(max_connections)),
        }
    }

    /// Spawn all listeners and block until SIGINT/SIGTERM (Ctrl+C / `docker stop`).
    pub async fn run(self) -> Result<()> {
        let cfg = self.cfg.clone();
        let connection_slots = self.connection_slots.clone();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let mut handles = Vec::new();

        for listener_cfg in &cfg.listens {
            let routes = Arc::new(RouteTable::compile(&listener_cfg.routes)?);
            let cfg2 = cfg.clone();
            let laddr = listener_cfg.addr.clone();
            let proto = listener_cfg.proto_str().to_string();
            let label = listener_cfg.label();
            let listen_port = listener_cfg
                .listen_port()
                .with_context(|| format!("listener [{}]", listener_cfg.label()))?;
            let routes2 = routes.clone();
            let shutdown_rx = shutdown_rx.clone();
            let slots = connection_slots.clone();
            let backlog = cfg.listen_backlog;

            let handle = tokio::spawn(async move {
                if let Err(e) = run_listener(
                    laddr,
                    proto,
                    label,
                    listen_port,
                    routes2,
                    cfg2,
                    shutdown_rx,
                    slots,
                    backlog,
                )
                .await
                {
                    error!("Listener error: {e:#}");
                }
            });
            handles.push(handle);
        }

        info!(
            "All {} listener(s) started. Press Ctrl+C or send SIGTERM to stop.",
            cfg.listens.len()
        );

        let shutdown_notify = shutdown_tx.clone();
        let signal_task = tokio::spawn(async move {
            wait_shutdown_signal().await;
            let _ = shutdown_notify.send(true);
        });

        let mut shutdown_rx = shutdown_rx;
        while !*shutdown_rx.borrow_and_update() {
            if shutdown_rx.changed().await.is_err() {
                break;
            }
        }

        info!("Shutdown requested, stopping listeners...");
        signal_task.abort();

        for h in handles {
            let _ = h.await;
        }

        info!("Stopped.");
        Ok(())
    }
}

/// Wait for Ctrl+C (SIGINT) or `docker stop` (SIGTERM).
async fn wait_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                warn!("Could not install SIGTERM handler: {e}; Ctrl+C only");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT (Ctrl+C)");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM");
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        info!("Received Ctrl+C");
    }
}

// ── Listener loop ─────────────────────────────────────────────────────────────

async fn bind_listener(addr: &str, backlog: u32) -> Result<TcpListener> {
    use std::net::SocketAddr;

    let socket_addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid listen address '{addr}'"))?;

    let socket = if socket_addr.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };

    #[cfg(unix)]
    {
        if let Err(e) = socket.set_reuseaddr(true) {
            warn!("Could not set SO_REUSEADDR on {addr}: {e}");
        }
    }

    socket.bind(socket_addr)?;
    let listener = socket.listen(backlog)?;
    Ok(listener)
}

async fn run_listener(
    addr: String,
    proto: String,
    label: String,
    listen_port: u16,
    routes: Arc<RouteTable>,
    cfg: Arc<AppConfig>,
    mut shutdown_rx: watch::Receiver<bool>,
    connection_slots: Arc<Semaphore>,
    backlog: u32,
) -> Result<()> {
    let listener = bind_listener(&addr, backlog)
        .await
        .with_context(|| format!("Failed to bind to {addr}"))?;
    info!("Listening [{label}] on {addr} ({proto}), backlog={backlog}");

    loop {
        if *shutdown_rx.borrow() {
            info!("Listener [{label}] on {addr} stopped");
            break;
        }

        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    info!("Listener [{label}] on {addr} stopped");
                    break;
                }
            }
            permit = connection_slots.clone().acquire_owned() => {
                let permit = match permit {
                    Ok(p) => p,
                    Err(_) => break,
                };

                match listener.accept().await {
                    Ok((stream, peer)) => {
                        debug!("New connection from {peer}");
                        metrics::connection_accepted(&peer.to_string());
                        let routes2 = routes.clone();
                        let cfg2 = cfg.clone();
                        let proto2 = proto.clone();

                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = handle_connection(
                                stream,
                                peer.to_string(),
                                proto2,
                                listen_port,
                                routes2,
                                cfg2,
                            )
                            .await
                            {
                                warn!("Connection from {peer} failed: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        drop(permit);
                        warn!("Accept error on {addr}: {e}");
                    }
                }
            }
        }
    }

    Ok(())
}

// ── Connection handler ────────────────────────────────────────────────────────

async fn handle_connection(
    mut client: TcpStream,
    peer: String,
    proto: String,
    listen_port: u16,
    routes: Arc<RouteTable>,
    cfg: Arc<AppConfig>,
) -> Result<()> {
    let connect_timeout = Duration::from_secs(cfg.connect_timeout_secs);
    let mut labels = TargetLabels::unknown();
    labels.set_client_ip_from_peer(&peer);
    let mut opened = false;

    let result: Result<()> = async {
        // ── Peek to extract hostname ──────────────────────────────────────────
        let (hostname, port, peeked_bytes, client_overflow) = match proto.as_str() {
            "tls" => extract_tls_info(&mut client, &cfg, listen_port).await?,
            "http" => {
                let (h, p, b) = extract_http_info(&mut client, listen_port, &cfg).await?;
                (h, p, b, Vec::new())
            }
            other => {
                let _ = other;
                extract_auto(&mut client, &cfg, listen_port).await?
            }
        };

        labels.set_domain(&hostname);
        debug!("Connection from {peer}: host={hostname} port={port}");

        // ── Hosts table, then per-listener routes ─────────────────────────────
        let (final_host, final_port, mapped_from_hosts) = resolve_destination(
            &hostname,
            port,
            listen_port,
            cfg.hosts_table.as_deref(),
            &routes,
        );

        labels.set_upstream(&final_host);

        if mapped_from_hosts {
            debug!(
                "Hosts map: {hostname} → {final_host}:{final_port} (client SNI/Host preserved in TLS)"
            );
        }

        // ── Connect upstream ──────────────────────────────────────────────────
        let mut upstream = proxy_connector::connect(
            &cfg.upstream_proxy,
            &final_host,
            final_port,
            connect_timeout,
        )
        .await
        .with_context(|| {
            format!(
                "Upstream connect to {final_host}:{final_port} via {} failed",
                cfg.upstream_proxy
            )
        })?;

        metrics::connection_opened(&labels);
        opened = true;

        if mapped_from_hosts && final_host != hostname {
            info!(
                "Proxying {peer} → {final_host}:{final_port} (hosts map for {hostname}) via {}",
                cfg.upstream_proxy
            );
        } else {
            info!(
                "Proxying {peer} → {final_host}:{final_port} via {}",
                cfg.upstream_proxy
            );
        }

        // ── Replay peeked bytes ───────────────────────────────────────────────
        if !peeked_bytes.is_empty() {
            debug!(
                "Replaying {} bytes of ClientHello flight to upstream",
                peeked_bytes.len()
            );
            upstream
                .write_all(&peeked_bytes)
                .await
                .context("Failed to replay ClientHello to upstream")?;
        }
        if !client_overflow.is_empty() {
            debug!(
                "Forwarding {} bytes of post-ClientHello client data to upstream",
                client_overflow.len()
            );
            upstream
                .write_all(&client_overflow)
                .await
                .context("Failed to forward post-ClientHello client data")?;
        }
        if !peeked_bytes.is_empty() || !client_overflow.is_empty() {
            upstream
                .flush()
                .await
                .context("Failed to flush upstream after replay")?;
        }

        // ── Bidirectional splice ────────────────────────────────────────────
        let rw_timeout = Duration::from_secs(cfg.rw_timeout_secs);
        let (c2u, u2c) = splice(client, upstream, rw_timeout).await;

        metrics::connection_closed(&labels, c2u, u2c);
        opened = false;

        debug!("Connection {peer} closed: ↑{c2u}B ↓{u2c}B");
        Ok(())
    }
    .await;

    if let Err(e) = result {
        metrics::connection_failed(&labels, opened);
        return Err(e);
    }

    Ok(())
}

/// Apply sniproxy `table hosts`, then per-listener `routes`.
fn resolve_destination(
    hostname: &str,
    port: u16,
    listen_port: u16,
    hosts: Option<&HostsTable>,
    routes: &RouteTable,
) -> (String, u16, bool) {
    if let Some(table) = hosts {
        if let Some(resolved) = table.resolve(hostname) {
            let (h, p) = apply_host_resolve(hostname, port, listen_port, resolved);
            return (h, p, true);
        }
    }

    let target_host = match routes.resolve(hostname) {
        Some("*") | None => hostname.to_string(),
        Some(target) => target.to_string(),
    };

    let (h, p) = if target_host.contains(':') {
        let mut parts = target_host.splitn(2, ':');
        let h = parts.next().unwrap().to_string();
        let p = parts
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(listen_port);
        (h, p)
    } else {
        (target_host, port)
    };

    (h, p, false)
}

fn apply_host_resolve(
    sni_hostname: &str,
    port: u16,
    listen_port: u16,
    resolved: HostResolve,
) -> (String, u16) {
    match resolved {
        HostResolve::Passthrough => (sni_hostname.to_string(), port),
        HostResolve::Ip(ip) => (ip.to_string(), port),
        HostResolve::Hostname(backend) => {
            if backend.contains(':') {
                parse_host_port(&backend, listen_port)
            } else {
                (backend, port)
            }
        }
    }
}

// ── Protocol detection helpers ────────────────────────────────────────────────

/// Peek bytes from a TLS stream, extract SNI.
/// Returns (hostname, port, client_hello_flight, extra_client_bytes).
async fn extract_tls_info(
    client: &mut TcpStream,
    cfg: &AppConfig,
    listen_port: u16,
) -> Result<(String, u16, Vec<u8>, Vec<u8>)> {
    // We read bytes into this buffer progressively.
    // Unlike peek(), read() consumes bytes — so we accumulate them here and
    // replay the entire buffer to the upstream once we've parsed the SNI.
    // Chrome/Google ClientHellos can exceed 4 KiB; use max TLS plaintext size.
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0;

    loop {
        // Read at least 1 new byte
        let n = timeout(
            Duration::from_secs(cfg.connect_timeout_secs),
            client.read(&mut buf[total..]),
        )
        .await
        .context("TLS peek timeout")?
        .context("TLS read error")?;

        if n == 0 {
            anyhow::bail!("Client closed connection during TLS handshake read");
        }
        total += n;

        let (result, replay_len) = sni::parse_sni_with_replay(&buf[..total]);
        match result {
            PeekResult::Tls(host) => {
                let flight = buf[..replay_len].to_vec();
                let overflow = if total > replay_len {
                    buf[replay_len..total].to_vec()
                } else {
                    Vec::new()
                };
                if !overflow.is_empty() {
                    debug!(
                        "ClientHello flight is {} bytes; {} extra bytes buffered for upstream",
                        flight.len(),
                        overflow.len()
                    );
                }
                return Ok((host, listen_port, flight, overflow));
            }
            PeekResult::NeedMore => {
                if total >= buf.len() {
                    anyhow::bail!("TLS ClientHello too large (>{} bytes)", buf.len());
                }
                // Loop to read more bytes
            }
            PeekResult::TlsNoSni => {
                // Forward the traffic anyway; routing by IP is caller's problem
                anyhow::bail!("TLS ClientHello has no SNI extension — cannot route");
            }
            PeekResult::PlainHttp | PeekResult::Unknown => {
                anyhow::bail!("Non-TLS data received on TLS listener");
            }
        }
    }
}

/// Read a plain HTTP request line to extract Host header.
async fn extract_http_info(
    client: &mut TcpStream,
    listen_port: u16,
    cfg: &AppConfig,
) -> Result<(String, u16, Vec<u8>)> {
    let mut buf = vec![0u8; 8192];
    let mut total = 0;

    let read_timeout = Duration::from_secs(cfg.connect_timeout_secs);

    loop {
        let n = timeout(read_timeout, client.read(&mut buf[total..]))
            .await
            .context("HTTP header read timeout")?
            .context("HTTP read error")?;
        if n == 0 {
            anyhow::bail!("EOF while reading HTTP headers");
        }
        total += n;

        let headers_str = std::str::from_utf8(&buf[..total]).unwrap_or("");

        // Check for CONNECT (HTTPS over HTTP proxy)
        if headers_str.starts_with("CONNECT ") {
            let line = headers_str.lines().next().unwrap_or("");
            // "CONNECT host:port HTTP/1.1"
            let target = line.split_whitespace().nth(1).unwrap_or("");
            let (host, port) = parse_host_port(target, listen_port);
            // Reply 200 Connection Established, then transparent
            let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
            client.write_all(response).await?;
            // The remaining bytes are the TLS ClientHello — extract SNI
            // For simplicity, return the hostname from CONNECT and empty peeked_bytes
            // (the client will send TLS ClientHello which we forward directly)
            return Ok((host, port, vec![]));
        }

        // Look for Host header in regular HTTP
        if headers_str.contains("\r\n\r\n") || headers_str.contains("\n\n") {
            if let Some(host) = extract_host_header(headers_str) {
                let (h, p) = parse_host_port(&host, listen_port);
                return Ok((h, p, buf[..total].to_vec()));
            }
            anyhow::bail!("HTTP request has no Host header");
        }

        if total >= buf.len() {
            anyhow::bail!("HTTP headers too large");
        }
    }
}

/// Auto-detect TLS vs HTTP
async fn extract_auto(
    client: &mut TcpStream,
    cfg: &AppConfig,
    listen_port: u16,
) -> Result<(String, u16, Vec<u8>, Vec<u8>)> {
    let mut peek_buf = vec![0u8; 8];
    let n = client.peek(&mut peek_buf).await?;

    if n >= 3 && peek_buf[0] == 0x16 && peek_buf[1] == 0x03 {
        extract_tls_info(client, cfg, listen_port).await
    } else {
        let (h, p, b) = extract_http_info(client, listen_port, cfg).await?;
        Ok((h, p, b, Vec::new()))
    }
}

fn extract_host_header(headers: &str) -> Option<String> {
    for line in headers.lines() {
        if line.to_lowercase().starts_with("host:") {
            return Some(line[5..].trim().to_string());
        }
    }
    None
}

fn parse_host_port(s: &str, default_port: u16) -> (String, u16) {
    // Handle IPv6 like [::1]:443
    if s.starts_with('[') {
        if let Some(end) = s.find(']') {
            let host = s[1..end].to_string();
            let port = s.get(end + 2..)
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (host, port);
        }
    }
    match s.rfind(':') {
        Some(idx) => {
            let host = s[..idx].to_string();
            let port = s[idx + 1..].parse().unwrap_or(default_port);
            (host, port)
        }
        None => (s.to_string(), default_port),
    }
}

// ── Bidirectional splice ──────────────────────────────────────────────────────

/// Copy bytes between client and upstream in both directions concurrently.
/// Returns (client_to_upstream_bytes, upstream_to_client_bytes).
async fn splice(
    client: TcpStream,
    upstream: TcpStream,
    _rw_timeout: Duration,
) -> (u64, u64) {
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = tokio::io::split(upstream);

    let c2u = tokio::spawn(async move {
        match tokio::io::copy(&mut cr, &mut uw).await {
            Ok(n) => n,
            Err(_) => 0,
        }
    });

    let u2c = tokio::spawn(async move {
        match tokio::io::copy(&mut ur, &mut cw).await {
            Ok(n) => n,
            Err(_) => 0,
        }
    });

    let c2u_bytes = c2u.await.unwrap_or(0);
    let u2c_bytes = u2c.await.unwrap_or(0);

    (c2u_bytes, u2c_bytes)
}
