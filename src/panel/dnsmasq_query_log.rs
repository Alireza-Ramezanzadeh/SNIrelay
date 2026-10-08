//! Tail and parse dnsmasq `log-queries` output into SQLite (AdGuard-style query log).

use anyhow::{Context, Result};
use chrono::{Datelike, Local, NaiveDateTime, TimeZone, Utc};
use regex::Regex;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use super::db::{DnsQueryInsert, PanelDb};

/// Background ingest of a dnsmasq query log file.
pub fn start_query_log_ingest(db: Arc<PanelDb>, path: PathBuf, retain_hours: u64) {
    if path.as_os_str().is_empty() {
        return;
    }
    info!(path = %path.display(), "dnsmasq query log ingest starting");
    tokio::spawn(async move {
        let mut offset = db
            .get_setting("dnsmasq_log_offset")
            .ok()
            .flatten()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let mut pending: HashMap<String, i64> = HashMap::new();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut prune_tick = tokio::time::interval(Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    match ingest_once(&db, &path, &mut offset, &mut pending) {
                        Ok(n) if n > 0 => {
                            let _ = db.set_setting("dnsmasq_log_offset", &offset.to_string());
                        }
                        Ok(_) => {}
                        Err(e) => debug!(error = %e, "dnsmasq log ingest tick"),
                    }
                }
                _ = prune_tick.tick() => {
                    if let Err(e) = db.prune_dns_queries(retain_hours) {
                        warn!("prune dns queries: {e:#}");
                    }
                }
            }
        }
    });
}

fn ingest_once(
    db: &PanelDb,
    path: &Path,
    offset: &mut u64,
    pending: &mut HashMap<String, i64>,
) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }
    let meta = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let len = meta.len();
    if len < *offset {
        *offset = 0;
        pending.clear();
    }
    if len == *offset {
        return Ok(0);
    }

    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    file.seek(SeekFrom::Start(*offset))?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    *offset = len;

    for line in buf.lines() {
        if let Some(ev) = parse_dnsmasq_line(line) {
            match ev.kind.as_str() {
                "query" => {
                    let row = DnsQueryInsert {
                        ts: ev.ts,
                        client_ip: ev.client_ip.clone(),
                        qtype: ev.qtype.clone(),
                        domain: ev.domain.clone(),
                        action: "query".into(),
                        answer: String::new(),
                    };
                    if let Ok(id) = db.insert_dns_query(&row) {
                        pending.insert(
                            format!("{}|{}|{}", ev.client_ip, ev.qtype, ev.domain),
                            id,
                        );
                        pending.insert(ev.domain.clone(), id);
                    }
                }
                other => {
                    let full = format!("{}|{}|{}", ev.client_ip, ev.qtype, ev.domain);
                    let id = pending
                        .remove(&full)
                        .or_else(|| pending.remove(&ev.domain));
                    if let Some(id) = id {
                        pending.retain(|_, v| *v != id);
                        let _ = db.update_dns_query_result(id, other, &ev.answer);
                    } else {
                        let _ = db.insert_dns_query(&DnsQueryInsert {
                            ts: ev.ts,
                            client_ip: ev.client_ip,
                            qtype: ev.qtype,
                            domain: ev.domain,
                            action: other.to_string(),
                            answer: ev.answer,
                        });
                    }
                }
            }
        }
    }
    if pending.len() > 50_000 {
        pending.clear();
    }
    Ok(buf.lines().count())
}

#[derive(Debug)]
struct ParsedEvent {
    ts: String,
    client_ip: String,
    qtype: String,
    domain: String,
    kind: String,
    answer: String,
}

fn parse_dnsmasq_line(line: &str) -> Option<ParsedEvent> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    static RE_QUERY: once_cell::sync::Lazy<Regex> = once_cell::sync::Lazy::new(|| {
        Regex::new(r"(?i)query\[([^\]]+)\]\s+(\S+)\s+from\s+(\S+)").unwrap()
    });
    static RE_CONFIG: once_cell::sync::Lazy<Regex> = once_cell::sync::Lazy::new(|| {
        Regex::new(r"(?i)\bconfig\s+(\S+)\s+is\s+(.+)$").unwrap()
    });
    static RE_REPLY: once_cell::sync::Lazy<Regex> = once_cell::sync::Lazy::new(|| {
        Regex::new(r"(?i)\breply\s+(\S+)\s+is\s+(.+)$").unwrap()
    });
    static RE_FWD: once_cell::sync::Lazy<Regex> = once_cell::sync::Lazy::new(|| {
        Regex::new(r"(?i)\bforwarded\s+(\S+)\s+to\s+(\S+)").unwrap()
    });
    static RE_CACHED: once_cell::sync::Lazy<Regex> = once_cell::sync::Lazy::new(|| {
        Regex::new(r"(?i)\bcached\s+(\S+)\s+is\s+(.+)$").unwrap()
    });

    let ts = extract_timestamp(line).unwrap_or_else(|| Utc::now().to_rfc3339());

    if let Some(c) = RE_QUERY.captures(line) {
        return Some(ParsedEvent {
            ts,
            qtype: c[1].to_uppercase(),
            domain: c[2].trim_end_matches('.').to_lowercase(),
            client_ip: c[3].to_string(),
            kind: "query".into(),
            answer: String::new(),
        });
    }
    if let Some(c) = RE_CONFIG.captures(line) {
        let answer = c[2].trim().to_string();
        let kind = if looks_like_ip(&answer) {
            "relay"
        } else {
            "config"
        };
        return Some(ParsedEvent {
            ts,
            qtype: "A".into(),
            domain: c[1].trim_end_matches('.').to_lowercase(),
            client_ip: String::new(),
            kind: kind.into(),
            answer,
        });
    }
    if let Some(c) = RE_CACHED.captures(line) {
        return Some(ParsedEvent {
            ts,
            qtype: "A".into(),
            domain: c[1].trim_end_matches('.').to_lowercase(),
            client_ip: String::new(),
            kind: "cached".into(),
            answer: c[2].trim().to_string(),
        });
    }
    if let Some(c) = RE_REPLY.captures(line) {
        return Some(ParsedEvent {
            ts,
            qtype: "A".into(),
            domain: c[1].trim_end_matches('.').to_lowercase(),
            client_ip: String::new(),
            kind: "reply".into(),
            answer: c[2].trim().to_string(),
        });
    }
    if let Some(c) = RE_FWD.captures(line) {
        return Some(ParsedEvent {
            ts,
            qtype: "A".into(),
            domain: c[1].trim_end_matches('.').to_lowercase(),
            client_ip: String::new(),
            kind: "forwarded".into(),
            answer: c[2].trim().to_string(),
        });
    }
    None
}

fn looks_like_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

fn extract_timestamp(line: &str) -> Option<String> {
    // "Oct  7 11:20:01 ..." or "2026-10-07T11:20:01 ..."
    if line.len() >= 19 && line.as_bytes().get(4) == Some(&b'-') {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&line[..19]) {
            return Some(dt.with_timezone(&Utc).to_rfc3339());
        }
    }
    // syslog: Mon DD HH:MM:SS
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 3 {
        let stamp = format!("{} {} {}", parts[0], parts[1], parts[2]);
        let year = Local::now().year();
        if let Ok(naive) = NaiveDateTime::parse_from_str(
            &format!("{year} {stamp}"),
            "%Y %b %e %H:%M:%S",
        ) {
            return Some(
                Local
                    .from_local_datetime(&naive)
                    .single()
                    .unwrap_or_else(|| Local.from_utc_datetime(&naive))
                    .with_timezone(&Utc)
                    .to_rfc3339(),
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_query_and_config() {
        let q = parse_dnsmasq_line(
            "Oct  7 11:20:01 box dnsmasq[1]: query[A] steam.com from 10.0.0.5",
        )
        .unwrap();
        assert_eq!(q.kind, "query");
        assert_eq!(q.domain, "steam.com");
        assert_eq!(q.client_ip, "10.0.0.5");
        assert_eq!(q.qtype, "A");

        let c = parse_dnsmasq_line(
            "Oct  7 11:20:01 box dnsmasq[1]: config steam.com is 94.182.174.181",
        )
        .unwrap();
        assert_eq!(c.kind, "relay");
        assert_eq!(c.answer, "94.182.174.181");
    }
}
