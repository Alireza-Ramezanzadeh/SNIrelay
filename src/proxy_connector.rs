// proxy_connector.rs — Upstream proxy connection establishment
//
// Provides a unified async interface to connect to a target host:port
// via SOCKS5, HTTP CONNECT, or directly.
//
// Once the tunnel is established the caller gets a plain `TcpStream`
// and blindly splices bytes through it — no TLS termination.

use anyhow::{Context, Result, bail};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

use crate::config::UpstreamProxy;

#[cfg(test)]
mod probe_tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn probe_mock(reply: Option<[u8; 2]>) -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            if let Some(reply) = reply {
                stream.write_all(&reply).await.unwrap();
            }
            std::future::pending::<()>().await;
        });
        let proxy = UpstreamProxy::Socks5 {
            host: "127.0.0.1".into(), port, username: None, password: None,
        };
        let result = timeout(
            Duration::from_secs(2),
            probe_upstream(&proxy, Duration::from_millis(100)),
        ).await;
        server.abort();
        let _ = server.await;
        result.expect("probe exceeded its deadline while waiting for SOCKS greeting")
    }

    #[tokio::test]
    async fn silent_socks_server_times_out() {
        let error = probe_mock(None).await.unwrap_err();
        assert!(format!("{error:#}").contains("timed out"));
    }

    #[tokio::test]
    async fn socks_greeting_success() {
        probe_mock(Some([5, 0])).await.unwrap();
    }

    #[tokio::test]
    async fn socks_greeting_rejection_is_preserved() {
        let error = probe_mock(Some([5, 255])).await.unwrap_err();
        assert!(format!("{error:#}").contains("rejected all auth methods"));
    }

    #[tokio::test]
    async fn ensure_ready_soft_fails_when_not_required() {
        let proxy = UpstreamProxy::Socks5 {
            host: "127.0.0.1".into(),
            port: 1, // nothing listens
            username: None,
            password: None,
        };
        let ok = ensure_upstream_ready(
            &proxy,
            Duration::from_millis(50),
            Duration::from_millis(120),
            Duration::from_millis(40),
            false,
        )
        .await
        .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn ensure_ready_hard_fails_when_required() {
        let proxy = UpstreamProxy::Socks5 {
            host: "127.0.0.1".into(),
            port: 1,
            username: None,
            password: None,
        };
        let err = ensure_upstream_ready(
            &proxy,
            Duration::from_millis(50),
            Duration::from_millis(120),
            Duration::from_millis(40),
            true,
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("still unreachable"));
    }
}

/// Verify the configured upstream proxy is reachable before accepting clients.
pub async fn probe_upstream(proxy: &UpstreamProxy, connect_timeout: Duration) -> Result<()> {
    // TCP may connect successfully while the proxy never answers the greeting.
    // Bound the whole probe, including writes and reads, before listener startup.
    timeout(connect_timeout, probe_upstream_inner(proxy, connect_timeout))
        .await
        .with_context(|| format!(
            "upstream probe timed out after {connect_timeout:?} for {proxy} \
             (TCP connection or proxy handshake); listeners have not started"
        ))?
}

/// Runtime health check against one or more probe targets.
/// **All** targets must succeed (detects partial outages where Cloudflare works
/// but general HTTPS like `ifconfig.io` dies — the common Xray/VLESS failure mode).
pub async fn check_upstream(
    proxy: &UpstreamProxy,
    connect_timeout: Duration,
    probes: &[(String, u16)],
) -> Result<()> {
    if probes.is_empty() {
        bail!("no probe targets configured");
    }
    for (host, port) in probes {
        check_upstream_one(proxy, connect_timeout, host, *port).await?;
    }
    Ok(())
}

async fn check_upstream_one(
    proxy: &UpstreamProxy,
    connect_timeout: Duration,
    probe_host: &str,
    probe_port: u16,
) -> Result<()> {
    let started = Instant::now();
    let mut stream = connect(proxy, probe_host, probe_port, connect_timeout)
        .await
        .with_context(|| {
            format!("upstream tunnel failed for {proxy} → {probe_host}:{probe_port}")
        })?;

    let remaining = connect_timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        bail!(
            "upstream check timed out during CONNECT for {proxy} \
             (tunnel to {probe_host}:{probe_port})"
        );
    }

    verify_tunnel_alive(&mut stream, probe_host, probe_port, remaining)
        .await
        .with_context(|| {
            format!(
                "upstream tunnel opened but probe target did not reply via {proxy} \
                 ({probe_host}:{probe_port})"
            )
        })?;

    drop(stream);
    Ok(())
}

/// Prove the tunneled path can carry a full TLS/HTTP response record
/// (catches mid-handshake EOF — same class of failure as curl's
/// `unexpected eof while reading`).
async fn verify_tunnel_alive(
    stream: &mut TcpStream,
    probe_host: &str,
    probe_port: u16,
    budget: Duration,
) -> Result<()> {
    let deadline = Instant::now() + budget;
    let remaining = || deadline.saturating_duration_since(Instant::now());

    let use_tls = probe_port == 443 || probe_port == 8443 || probe_port == 2053;
    if use_tls {
        let hello = build_minimal_tls_client_hello(probe_host);
        timeout(remaining(), stream.write_all(&hello))
            .await
            .context("timed out writing TLS ClientHello through tunnel")?
            .context("failed writing TLS ClientHello through tunnel")?;

        // Full first TLS record (header + body) — not just 1 byte.
        let mut hdr = [0u8; 5];
        timeout(remaining(), stream.read_exact(&mut hdr))
            .await
            .context("timed out waiting for TLS record header through tunnel")?
            .context("tunnel closed before TLS reply (unexpected EOF)")?;
        if hdr[0] != 0x16 && hdr[0] != 0x15 {
            bail!("unexpected TLS content type 0x{:02x}", hdr[0]);
        }
        let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        if rec_len == 0 || rec_len > 16_384 {
            bail!("invalid TLS record length {rec_len}");
        }
        let mut body = vec![0u8; rec_len];
        timeout(remaining(), stream.read_exact(&mut body))
            .await
            .context("timed out waiting for TLS record body through tunnel")?
            .context("tunnel closed mid-TLS handshake (unexpected EOF)")?;
    } else {
        let req = format!(
            "HEAD / HTTP/1.0\r\nHost: {probe_host}\r\nConnection: close\r\n\r\n"
        );
        timeout(remaining(), stream.write_all(req.as_bytes()))
            .await
            .context("timed out writing HTTP probe through tunnel")?
            .context("failed writing HTTP probe through tunnel")?;
        let mut buf = [0u8; 16];
        let n = timeout(remaining(), stream.read(&mut buf))
            .await
            .context("timed out waiting for HTTP reply through tunnel")?
            .context("tunnel closed before HTTP reply")?;
        if n == 0 {
            bail!("empty HTTP reply through tunnel");
        }
        if !buf[..n].windows(5).any(|w| w == b"HTTP/") && buf[0] != b'H' {
            // Accept partial "HTTP" at start; otherwise still require some data.
            debug!("HTTP probe got {} non-HTTP bytes (still counted alive)", n);
        }
    }
    Ok(())
}

/// Minimal TLS 1.2 ClientHello with SNI — enough for most servers to answer.
fn build_minimal_tls_client_hello(sni_host: &str) -> Vec<u8> {
    let sni_bytes = sni_host.as_bytes();
    // Extension: server_name
    // type(2) + ext_len(2) + list_len(2) + name_type(1) + name_len(2) + name
    let mut extensions = Vec::with_capacity(9 + sni_bytes.len());
    extensions.extend_from_slice(&[0x00, 0x00]); // server_name
    let sni_ext_len = (5 + sni_bytes.len()) as u16;
    extensions.extend_from_slice(&sni_ext_len.to_be_bytes());
    let list_len = (3 + sni_bytes.len()) as u16;
    extensions.extend_from_slice(&list_len.to_be_bytes());
    extensions.push(0x00); // host_name
    let name_len = sni_bytes.len() as u16;
    extensions.extend_from_slice(&name_len.to_be_bytes());
    extensions.extend_from_slice(sni_bytes);

    // supported_versions + signature_algorithms kept tiny via cipher-only hello body
    // ClientHello body: version(2) + random(32) + session_id_len(1) + cipher_len(2)
    // + ciphers + comp_len(1) + comp + ext_len(2) + extensions
    let mut body = Vec::with_capacity(50 + extensions.len());
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session id length
    // A few common suites so modern endpoints still reply (handshake or alert).
    let ciphers: &[u8] = &[
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
    ];
    body.extend_from_slice(&((ciphers.len() as u16).to_be_bytes()));
    body.extend_from_slice(ciphers);
    body.push(1); // compression methods length
    body.push(0); // null compression
    let ext_len = extensions.len() as u16;
    body.extend_from_slice(&ext_len.to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::with_capacity(4 + body.len());
    handshake.push(0x01); // ClientHello
    let hs_len = body.len() as u32;
    handshake.push(((hs_len >> 16) & 0xff) as u8);
    handshake.push(((hs_len >> 8) & 0xff) as u8);
    handshake.push((hs_len & 0xff) as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::with_capacity(5 + handshake.len());
    record.push(0x16); // Handshake
    record.extend_from_slice(&[0x03, 0x01]); // record version TLS 1.0
    let rec_len = handshake.len() as u16;
    record.extend_from_slice(&rec_len.to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Retry [`probe_upstream`] until success, deadline, or optional hard failure.
///
/// Returns `Ok(true)` when the upstream answered, `Ok(false)` when soft-failing
/// after the wait window, and `Err` when `required` and still unreachable.
pub async fn ensure_upstream_ready(
    proxy: &UpstreamProxy,
    connect_timeout: Duration,
    wait: Duration,
    interval: Duration,
    required: bool,
) -> Result<bool> {
    if matches!(proxy, UpstreamProxy::Direct) {
        probe_upstream(proxy, connect_timeout).await?;
        return Ok(true);
    }

    let deadline = Instant::now() + wait;
    let mut attempt: u32 = 0;
    let mut last_err = String::from("unknown error");

    loop {
        attempt += 1;
        match probe_upstream(proxy, connect_timeout).await {
            Ok(()) => {
                if attempt > 1 {
                    info!(
                        attempt,
                        "Upstream proxy became reachable after retries: {proxy}"
                    );
                }
                return Ok(true);
            }
            Err(e) => {
                last_err = format!("{e:#}");
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                warn!(
                    attempt,
                    wait_left_secs = remaining.as_secs(),
                    "Upstream probe failed ({proxy}): {last_err}; retrying in {}s",
                    interval.as_secs().max(1)
                );
                sleep(interval.min(remaining)).await;
            }
        }
    }

    let detail = last_err;
    if required {
        let wait_secs = wait.as_secs();
        bail!(
            "upstream proxy {proxy} still unreachable after {wait_secs}s ({attempt} attempt(s)): {detail}\n\
             Hint: on the host run `ss -lntp | grep -E '1080|10808'` and confirm Xray/SOCKS is up.\n\
             With Docker use `docker run --network host` (or compose `network_mode: host`) so \
             `127.0.0.1` is the host loopback. Set UPSTREAM_PROBE_REQUIRED=false to start anyway."
        );
    }

    warn!(
        attempts = attempt,
        wait_secs = wait.as_secs(),
        "Upstream proxy {proxy} unreachable after startup wait — starting listeners anyway. \
         New connections will fail until SOCKS is available. Last error: {detail}"
    );
    Ok(false)
}

async fn probe_upstream_inner(proxy: &UpstreamProxy, connect_timeout: Duration) -> Result<()> {
    match proxy {
        UpstreamProxy::Direct => {
            debug!("Upstream proxy: direct (no probe)");
            Ok(())
        }
        UpstreamProxy::Socks5 { host, port, username, password: _ } => {
            let mut stream = timeout(
                connect_timeout,
                TcpStream::connect(format!("{host}:{port}")),
            )
            .await
            .with_context(|| format!("timed out connecting to SOCKS5 proxy {host}:{port}"))?
            .with_context(|| {
                format!(
                    "cannot reach SOCKS5 proxy at {host}:{port}; check the effective upstream \
                     configuration, SOCKS listener bind address/port, and firewall. \
                     Docker host networking shares the host loopback; bridge networking does not"
                )
            })?;

            debug!("Connected to SOCKS5 proxy {host}:{port}; waiting for SOCKS5 greeting response");
            let auth_method: u8 = if username.is_some() { 0x02 } else { 0x00 };
            stream.write_all(&[0x05, 0x01, auth_method]).await?;
            let mut resp = [0u8; 2];
            stream
                .read_exact(&mut resp)
                .await
                .context("SOCKS5 proxy closed during handshake probe")?;
            if resp[0] != 0x05 {
                bail!("SOCKS5 probe: unexpected version {}", resp[0]);
            }
            if resp[1] == 0xff {
                bail!("SOCKS5 probe: proxy rejected all auth methods");
            }
            debug!(
                "SOCKS5 proxy at {host}:{port} is reachable (selected auth 0x{:02x})",
                resp[1]
            );
            Ok(())
        }
        UpstreamProxy::Http { host, port, .. } => {
            timeout(connect_timeout, TcpStream::connect(format!("{host}:{port}")))
                .await
                .with_context(|| format!("timed out connecting to HTTP proxy {host}:{port}"))?
                .with_context(|| format!("cannot reach HTTP proxy at {host}:{port}"))?;
            debug!("HTTP proxy at {host}:{port} is reachable");
            Ok(())
        }
    }
}

/// Establish a tunneled TCP connection to `target_host:target_port`
/// through the configured upstream proxy.
///
/// Returns a connected `TcpStream` whose bytes are transparently
/// forwarded to the origin (for TLS the full ClientHello is relayed).
pub async fn connect(
    proxy: &UpstreamProxy,
    target_host: &str,
    target_port: u16,
    connect_timeout: Duration,
) -> Result<TcpStream> {
    match proxy {
        UpstreamProxy::Direct => {
            debug!("Direct connect to {target_host}:{target_port}");
            let stream = timeout(
                connect_timeout,
                TcpStream::connect(format!("{target_host}:{target_port}")),
            )
            .await
            .context("connect timeout")?
            .context("direct TCP connect failed")?;
            stream.set_nodelay(true)?;
            Ok(stream)
        }

        UpstreamProxy::Socks5 { host, port, username, password } => {
            debug!("SOCKS5 connect {target_host}:{target_port} via {host}:{port}");
            socks5_connect(host, *port, target_host, target_port, username.as_deref(), password.as_deref(), connect_timeout).await
        }

        UpstreamProxy::Http { host, port, auth } => {
            debug!("HTTP CONNECT {target_host}:{target_port} via {host}:{port}");
            http_connect(host, *port, target_host, target_port, auth.as_deref(), connect_timeout).await
        }
    }
}

// ── SOCKS5 ────────────────────────────────────────────────────────────────────
//
// RFC 1928 + RFC 1929 (user/pass auth)

fn build_socks5_connect_request(target_host: &str, target_port: u16) -> Result<Vec<u8>> {
    let port_bytes = [(target_port >> 8) as u8, target_port as u8];

    if let Ok(ip) = target_host.parse::<IpAddr>() {
        let mut req = vec![0x05, 0x01, 0x00];
        match ip {
            IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
        }
        req.extend_from_slice(&port_bytes);
        return Ok(req);
    }

    let host_bytes = target_host.as_bytes();
    if host_bytes.len() > 255 {
        bail!("SOCKS5: hostname too long (>255 bytes)");
    }
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port_bytes);
    Ok(req)
}

async fn socks5_connect(
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
    username: Option<&str>,
    password: Option<&str>,
    connect_timeout: Duration,
) -> Result<TcpStream> {
    let mut stream = timeout(
        connect_timeout,
        TcpStream::connect(format!("{proxy_host}:{proxy_port}")),
    )
    .await
    .context("SOCKS5 proxy connect timeout")?
    .context("SOCKS5 proxy TCP connect failed")?;
    stream.set_nodelay(true)?;

    // ── Greeting ─────────────────────────────────────────────────────────────
    // VER=5, NMETHODS=1 or 2, METHOD=0x00 (no auth) or 0x02 (user/pass)
    let auth_method: u8 = if username.is_some() { 0x02 } else { 0x00 };
    stream.write_all(&[0x05, 0x01, auth_method]).await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.context("SOCKS5 greeting response")?;
    if resp[0] != 0x05 {
        bail!("SOCKS5: server replied with unexpected version {}", resp[0]);
    }

    match resp[1] {
        0x00 => {
            // No auth required
        }
        0x02 => {
            // Username/password auth (RFC 1929)
            let user = username.unwrap_or("");
            let pass = password.unwrap_or("");
            let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
            auth_req.push(0x01);                   // VER
            auth_req.push(user.len() as u8);
            auth_req.extend_from_slice(user.as_bytes());
            auth_req.push(pass.len() as u8);
            auth_req.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth_req).await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await.context("SOCKS5 auth response")?;
            if auth_resp[1] != 0x00 {
                bail!("SOCKS5 authentication failed (status {})", auth_resp[1]);
            }
        }
        0xFF => bail!("SOCKS5: no acceptable authentication method"),
        m    => bail!("SOCKS5: unsupported auth method 0x{m:02x}"),
    }

    // ── CONNECT request ───────────────────────────────────────────────────────
    let req = build_socks5_connect_request(target_host, target_port)?;
    stream.write_all(&req).await?;

    // ── Response ──────────────────────────────────────────────────────────────
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await.context("SOCKS5 CONNECT response header")?;
    if hdr[0] != 0x05 {
        bail!("SOCKS5: unexpected version in response");
    }
    if hdr[1] != 0x00 {
        bail!("SOCKS5: CONNECT failed with status {}", socks5_reply_text(hdr[1]));
    }
    // Skip bound address (ATYP in hdr[3])
    skip_socks5_addr(&mut stream, hdr[3]).await?;

    debug!("SOCKS5 tunnel established to {target_host}:{target_port}");
    Ok(stream)
}

async fn skip_socks5_addr(stream: &mut TcpStream, atyp: u8) -> Result<()> {
    match atyp {
        0x01 => {
            // IPv4 (4 bytes) + port (2 bytes)
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
        }
        0x03 => {
            // Domain: length (1 byte) + domain + port (2 bytes)
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut buf).await?;
        }
        0x04 => {
            // IPv6 (16 bytes) + port (2 bytes)
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
        }
        _ => bail!("SOCKS5: unknown address type 0x{atyp:02x}"),
    }
    Ok(())
}

fn socks5_reply_text(code: u8) -> &'static str {
    match code {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "Network unreachable",
        0x04 => "Host unreachable",
        0x05 => "Connection refused",
        0x06 => "TTL expired",
        0x07 => "Command not supported",
        0x08 => "Address type not supported",
        _    => "unknown error",
    }
}

// ── HTTP CONNECT ──────────────────────────────────────────────────────────────

async fn http_connect(
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
    auth: Option<&str>,
    connect_timeout: Duration,
) -> Result<TcpStream> {
    let mut stream = timeout(
        connect_timeout,
        TcpStream::connect(format!("{proxy_host}:{proxy_port}")),
    )
    .await
    .context("HTTP proxy connect timeout")?
    .context("HTTP proxy TCP connect failed")?;
    stream.set_nodelay(true)?;

    // Send CONNECT request
    let mut req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
    );
    if let Some(auth_val) = auth {
        req.push_str(&format!("Proxy-Authorization: Basic {auth_val}\r\n"));
    }
    req.push_str("Proxy-Connection: keep-alive\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;

    // Read response (peek for "200 Connection established")
    let mut response_buf = vec![0u8; 4096];
    let mut total = 0;

    loop {
        let n = stream.read(&mut response_buf[total..]).await?;
        if n == 0 {
            bail!("HTTP proxy closed connection during CONNECT handshake");
        }
        total += n;

        // Look for end of headers
        if let Some(idx) = find_crlfcrlf(&response_buf[..total]) {
            let headers = std::str::from_utf8(&response_buf[..idx])
                .unwrap_or("<invalid utf8>");
            let first_line = headers.lines().next().unwrap_or("");

            // HTTP/1.x 200 ...
            if !first_line.contains("200") {
                bail!("HTTP CONNECT failed: {first_line}");
            }
            break;
        }

        if total >= response_buf.len() {
            bail!("HTTP CONNECT response too large");
        }
    }

    debug!("HTTP CONNECT tunnel established to {target_host}:{target_port}");
    Ok(stream)
}

fn find_crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}
