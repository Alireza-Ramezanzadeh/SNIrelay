// metrics.rs — Prometheus metrics with per-domain, upstream, and client IP breakdown.
//
// Scrapes are served from a pre-encoded snapshot refreshed on a background task so
// `prometheus::gather()` never runs on the hot path and concurrent scrapes are cheap.

use anyhow::Result;
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, TextEncoder, opts,
    register_int_counter, register_int_counter_vec, register_int_gauge, register_int_gauge_vec,
};
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, error, info};

// ── Global totals ───────────────────────────────────────────────────────────────

pub static ACTIVE_CONNECTIONS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "sniproxy_active_connections",
        "Currently active proxy connections (all)"
    )
    .unwrap()
});

pub static TOTAL_CONNECTIONS: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "sniproxy_connections_total",
        "Successful proxy sessions opened (all)"
    )
    .unwrap()
});

pub static BYTES_PROXIED: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "sniproxy_bytes_proxied_total",
        "Bytes proxied in both directions (all)"
    )
    .unwrap()
});

pub static CONNECTION_ERRORS: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "sniproxy_connection_errors_total",
        "Failed connections (all)"
    )
    .unwrap()
});

static ACCEPTED_CONNECTIONS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "sniproxy_accepted_connections_total",
            "TCP connections accepted on proxy listeners (before TLS/HTTP parsing)"
        ),
        &["client_ip"]
    )
    .unwrap()
});

// ── Per domain, upstream target, and client (input) IP ────────────────────────

static ACTIVE_BY_LABEL: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        opts!(
            "sniproxy_active_connections_by_target",
            "Active connections by client IP, SNI/Host domain, and upstream target"
        ),
        &["client_ip", "domain", "upstream"]
    )
    .unwrap()
});

static CONNECTIONS_BY_LABEL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "sniproxy_connections_by_target_total",
            "Successful proxy sessions by client IP, domain, and upstream target"
        ),
        &["client_ip", "domain", "upstream"]
    )
    .unwrap()
});

static BYTES_BY_LABEL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "sniproxy_bytes_proxied_by_target_total",
            "Bytes proxied by client IP, domain, upstream, and direction"
        ),
        &["client_ip", "domain", "upstream", "direction"]
    )
    .unwrap()
});

static ERRORS_BY_LABEL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        opts!(
            "sniproxy_connection_errors_by_target_total",
            "Failed connections by client IP, domain, and upstream target"
        ),
        &["client_ip", "domain", "upstream"]
    )
    .unwrap()
});

/// Sanitize values for Prometheus labels (safe, bounded length).
pub fn label_value(raw: &str) -> String {
    let s: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.len() > 128 {
        s[..128].to_string()
    } else if s.is_empty() {
        "unknown".to_string()
    } else {
        s
    }
}

/// Extract the client IP from `peer` (`SocketAddr::to_string()`, e.g. `1.2.3.4:12345` or `[::1]:1234`).
pub fn client_ip_from_peer(peer: &str) -> String {
    if let Ok(addr) = peer.parse::<SocketAddr>() {
        return label_value(&addr.ip().to_string());
    }
    label_value(peer)
}

/// Labels for one proxied connection.
#[derive(Debug, Clone)]
pub struct TargetLabels {
    pub client_ip: String,
    pub domain: String,
    pub upstream: String,
}

impl TargetLabels {
    pub fn unknown() -> Self {
        Self {
            client_ip: "unknown".to_string(),
            domain: "unknown".to_string(),
            upstream: "unknown".to_string(),
        }
    }

    pub fn set_client_ip_from_peer(&mut self, peer: &str) {
        self.client_ip = client_ip_from_peer(peer);
    }

    pub fn set_domain(&mut self, domain: &str) {
        self.domain = label_value(domain);
    }

    pub fn set_upstream(&mut self, upstream: &str) {
        self.upstream = label_value(upstream);
    }

    fn as_label_values(&self) -> [&str; 3] {
        [&self.client_ip, &self.domain, &self.upstream]
    }
}

/// Count every accepted TCP connection (includes failures before upstream open).
pub fn connection_accepted(peer: &str) {
    let ip = client_ip_from_peer(peer);
    ACCEPTED_CONNECTIONS.with_label_values(&[&ip]).inc();
}

pub fn connection_opened(labels: &TargetLabels) {
    let lv = labels.as_label_values();
    ACTIVE_CONNECTIONS.inc();
    TOTAL_CONNECTIONS.inc();
    ACTIVE_BY_LABEL.with_label_values(&lv).inc();
    CONNECTIONS_BY_LABEL.with_label_values(&lv).inc();
}

pub fn connection_closed(labels: &TargetLabels, client_to_upstream: u64, upstream_to_client: u64) {
    let lv = labels.as_label_values();
    ACTIVE_CONNECTIONS.dec();
    ACTIVE_BY_LABEL.with_label_values(&lv).dec();

    let total = client_to_upstream + upstream_to_client;
    BYTES_PROXIED.inc_by(total);
    if client_to_upstream > 0 {
        BYTES_BY_LABEL
            .with_label_values(&[&lv[0], &lv[1], &lv[2], "client_to_upstream"])
            .inc_by(client_to_upstream);
    }
    if upstream_to_client > 0 {
        BYTES_BY_LABEL
            .with_label_values(&[&lv[0], &lv[1], &lv[2], "upstream_to_client"])
            .inc_by(upstream_to_client);
    }
}

pub fn connection_failed(labels: &TargetLabels, was_open: bool) {
    let lv = labels.as_label_values();
    CONNECTION_ERRORS.inc();
    ERRORS_BY_LABEL.with_label_values(&lv).inc();
    if was_open {
        ACTIVE_CONNECTIONS.dec();
        ACTIVE_BY_LABEL.with_label_values(&lv).dec();
    }
}

fn encode_metrics_body() -> Result<Vec<u8>, prometheus::Error> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)?;
    Ok(buffer)
}

async fn publish_snapshot(tx: &watch::Sender<Arc<Vec<u8>>>) {
    match tokio::task::spawn_blocking(encode_metrics_body).await {
        Ok(Ok(body)) => {
            let nbytes = body.len();
            if tx.send(Arc::new(body)).is_err() {
                debug!("Metrics snapshot channel closed ({nbytes} bytes not published)");
            }
        }
        Ok(Err(e)) => error!("Metrics encode error: {e}"),
        Err(e) => error!("Metrics encode task failed: {e}"),
    }
}

/// Periodically refresh the exposition snapshot on the blocking thread pool.
async fn metrics_refresh_loop(tx: watch::Sender<Arc<Vec<u8>>>, refresh_secs: u64) {
    let busy = Arc::new(AtomicBool::new(false));
    let mut interval = tokio::time::interval(Duration::from_secs(refresh_secs.max(1)));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        if busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            continue;
        }

        let tx = tx.clone();
        let busy = busy.clone();
        tokio::spawn(async move {
            publish_snapshot(&tx).await;
            busy.store(false, Ordering::Release);
        });
    }
}

async fn write_http_response(stream: &mut TcpStream, status: &str, body: &[u8]) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    if !body.is_empty() {
        let _ = stream.write_all(body).await;
    }
    let _ = stream.shutdown().await;
}

async fn serve_metrics(mut stream: TcpStream, mut snapshot_rx: watch::Receiver<Arc<Vec<u8>>>) {
    let mut request = [0u8; 4096];
    if tokio::time::timeout(Duration::from_secs(5), stream.read(&mut request))
        .await
        .ok()
        .and_then(|r| r.ok())
        .is_none()
    {
        return;
    }

    let body = snapshot_rx.borrow().clone();
    let body = if body.is_empty() {
        match tokio::time::timeout(Duration::from_secs(10), snapshot_rx.changed()).await {
            Ok(Ok(())) => snapshot_rx.borrow().clone(),
            _ => {
                write_http_response(
                    &mut stream,
                    "503 Service Unavailable",
                    b"metrics snapshot not ready yet\n",
                )
                .await;
                return;
            }
        }
    } else {
        body
    };

    write_http_response(&mut stream, "200 OK", body.as_ref()).await;
}

pub async fn start_metrics_server(addr: String, refresh_secs: u64) -> Result<()> {
    let (snapshot_tx, snapshot_rx) = watch::channel(Arc::new(Vec::new()));

    publish_snapshot(&snapshot_tx).await;

    let refresh_tx = snapshot_tx.clone();
    tokio::spawn(metrics_refresh_loop(refresh_tx, refresh_secs));

    let listener = TcpListener::bind(&addr).await?;
    info!(
        "Metrics server listening on http://{addr}/metrics (snapshot refresh every {}s)",
        refresh_secs.max(1)
    );

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let rx = snapshot_rx.clone();
                    tokio::spawn(serve_metrics(stream, rx));
                }
                Err(e) => {
                    error!("Metrics server accept error: {e}");
                }
            }
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_sanitize_and_truncate() {
        assert_eq!(label_value("eu.taline.ir"), "eu.taline.ir");
        assert_eq!(label_value(""), "unknown");
        assert_eq!(label_value("91.107.161.221"), "91.107.161.221");
    }

    #[test]
    fn client_ip_from_peer_parses() {
        assert_eq!(client_ip_from_peer("5.202.52.54:43673"), "5.202.52.54");
        assert_eq!(client_ip_from_peer("[2001:db8::1]:443"), "2001:db8::1");
    }
}
