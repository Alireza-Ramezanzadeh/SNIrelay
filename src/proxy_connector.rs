// proxy_connector.rs — Upstream proxy connection establishment
//
// Provides a unified async interface to connect to a target host:port
// via SOCKS5, HTTP CONNECT, or directly.
//
// Once the tunnel is established the caller gets a plain `TcpStream`
// and blindly splices bytes through it — no TLS termination.

use anyhow::{Context, Result, bail};
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{debug, info};

use crate::config::UpstreamProxy;

/// Verify the configured upstream proxy is reachable before accepting clients.
pub async fn probe_upstream(proxy: &UpstreamProxy, connect_timeout: Duration) -> Result<()> {
    match proxy {
        UpstreamProxy::Direct => {
            info!("Upstream proxy: direct (no probe)");
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
                    "cannot reach SOCKS5 proxy at {host}:{port} from this network namespace \
                     (in Docker, 127.0.0.1 is the container — use 172.17.0.1, --network host, \
                     or enable LAN on the host SOCKS listener)"
                )
            })?;

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
            info!(
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
            info!("HTTP proxy at {host}:{port} is reachable");
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
