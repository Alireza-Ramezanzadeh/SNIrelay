//! Batched traffic accounting into SQLite (per client IP + domain).

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::db::PanelDb;

#[derive(Debug, Clone)]
pub struct TrafficSample {
    pub client_ip: String,
    pub domain: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

#[derive(Clone)]
pub struct TrafficAggregator {
    tx: mpsc::Sender<TrafficSample>,
}

impl TrafficAggregator {
    pub fn start(db: Arc<PanelDb>, flush_secs: u64) -> Self {
        let (tx, mut rx) = mpsc::channel::<TrafficSample>(8192);
        let flush = Duration::from_secs(flush_secs.max(1));
        tokio::spawn(async move {
            let mut buf: Vec<(String, String, u64, u64)> = Vec::with_capacity(256);
            let mut ticker = tokio::time::interval(flush);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    sample = rx.recv() => {
                        match sample {
                            Some(s) => {
                                buf.push((s.client_ip, s.domain, s.bytes_up, s.bytes_down));
                                if buf.len() >= 500 {
                                    flush_buf(&db, &mut buf);
                                }
                            }
                            None => {
                                flush_buf(&db, &mut buf);
                                break;
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        flush_buf(&db, &mut buf);
                    }
                }
            }
        });
        Self { tx }
    }

    pub fn record(&self, client_ip: &str, domain: &str, bytes_up: u64, bytes_down: u64) {
        let sample = TrafficSample {
            client_ip: client_ip.to_string(),
            domain: domain.to_string(),
            bytes_up,
            bytes_down,
        };
        if self.tx.try_send(sample).is_err() {
            debug!("traffic aggregator queue full; dropping sample");
        }
    }
}

fn flush_buf(db: &PanelDb, buf: &mut Vec<(String, String, u64, u64)>) {
    if buf.is_empty() {
        return;
    }
    let batch = std::mem::take(buf);
    if let Err(e) = db.apply_traffic_batch(&batch) {
        warn!("Failed to flush traffic batch ({} rows): {e:#}", batch.len());
    }
}
