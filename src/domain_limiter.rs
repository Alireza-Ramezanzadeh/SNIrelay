// domain_limiter.rs — Per-domain daily bandwidth and connection-count limits.
//
// Limits are keyed by SNI/Host hostname (lowercased). A config key matches the
// exact name or any subdomain (`api.example.com` matches key `example.com`).
// Counters reset at UTC midnight. Optional JSON state file survives restarts.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::config::DomainLimitConfig;

const STATE_VERSION: u8 = 1;

// ── Day index ─────────────────────────────────────────────────────────────────

fn epoch_day_utc() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
        / 86400
}

// ── On-disk format ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct PersistedState {
    version: u8,
    domains: HashMap<String, PersistedDomain>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedDomain {
    day: u32,
    bytes: u64,
    connections: u64,
}

// ── Per-domain counters ───────────────────────────────────────────────────────

struct DomainCounters {
    bytes: AtomicU64,
    connections: AtomicU64,
    day: AtomicU32,
}

impl DomainCounters {
    fn new() -> Self {
        Self {
            bytes: AtomicU64::new(0),
            connections: AtomicU64::new(0),
            day: AtomicU32::new(epoch_day_utc()),
        }
    }

    fn restore(&self, day: u32, bytes: u64, connections: u64) {
        self.day.store(day, Ordering::Release);
        self.bytes.store(bytes, Ordering::Release);
        self.connections.store(connections, Ordering::Release);
    }

    fn refresh_if_new_day(&self) {
        let today = epoch_day_utc();
        let stored = self.day.load(Ordering::Acquire);
        if stored != today {
            if self
                .day
                .compare_exchange(stored, today, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                self.bytes.store(0, Ordering::Release);
                self.connections.store(0, Ordering::Release);
            }
        }
    }

    fn snapshot(&self) -> (u32, u64, u64) {
        self.refresh_if_new_day();
        (
            self.day.load(Ordering::Acquire),
            self.bytes.load(Ordering::Acquire),
            self.connections.load(Ordering::Acquire),
        )
    }
}

// ── Limit exceeded reason ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitReason {
    DailyBandwidth,
    DailyConnections,
}

impl fmt::Display for LimitReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LimitReason::DailyBandwidth => write!(f, "daily_bandwidth"),
            LimitReason::DailyConnections => write!(f, "daily_connections"),
        }
    }
}

// ── DomainLimiter ─────────────────────────────────────────────────────────────

pub struct DomainLimiter {
    limits: HashMap<String, DomainLimitConfig>,
    counters: HashMap<String, DomainCounters>,
    state_file: Option<PathBuf>,
    dirty: AtomicBool,
}

impl DomainLimiter {
    /// Build limiter and restore counters from `state_file` when present.
    pub fn load(
        limits: HashMap<String, DomainLimitConfig>,
        state_file: Option<PathBuf>,
    ) -> Result<Self> {
        let limits: HashMap<String, DomainLimitConfig> = limits
            .into_iter()
            .map(|(k, v)| (k.to_lowercase(), v))
            .collect();

        let counters = limits
            .keys()
            .map(|k| (k.clone(), DomainCounters::new()))
            .collect();

        let mut limiter = Self {
            limits,
            counters,
            state_file,
            dirty: AtomicBool::new(false),
        };

        if let Some(path) = limiter.state_file.clone() {
            limiter.load_from_disk(&path)?;
        }

        Ok(limiter)
    }

    #[cfg(test)]
    fn new(limits: HashMap<String, DomainLimitConfig>) -> Self {
        Self::load(limits, None).expect("in-memory limiter")
    }

    fn load_from_disk(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            debug!(path = %path.display(), "No domain limits state file yet");
            return Ok(());
        }

        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read domain limits state {}", path.display()))?;
        let state: PersistedState = serde_json::from_str(&raw)
            .with_context(|| format!("Failed to parse domain limits state {}", path.display()))?;

        if state.version != STATE_VERSION {
            warn!(
                path = %path.display(),
                version = state.version,
                "Ignoring domain limits state file with unsupported version"
            );
            return Ok(());
        }

        let today = epoch_day_utc();
        let mut restored = 0usize;
        for (domain, saved) in state.domains {
            let key = domain.to_lowercase();
            let Some(counters) = self.counters.get(&key) else {
                continue;
            };
            if saved.day != today {
                debug!(
                    domain = %key,
                    saved_day = saved.day,
                    today,
                    "Skipping stale domain limits state (previous UTC day)"
                );
                continue;
            }
            counters.restore(saved.day, saved.bytes, saved.connections);
            restored += 1;
            info!(
                domain = %key,
                bytes = saved.bytes,
                connections = saved.connections,
                "Restored domain limits usage for today"
            );
        }

        if restored > 0 {
            info!(
                path = %path.display(),
                restored,
                "Loaded domain limits state"
            );
        }

        Ok(())
    }

    fn mark_dirty(&self) {
        if self.state_file.is_some() {
            self.dirty.store(true, Ordering::Release);
        }
    }

    fn build_snapshot(&self) -> PersistedState {
        let mut domains = HashMap::new();
        for (key, counters) in &self.counters {
            let (day, bytes, connections) = counters.snapshot();
            domains.insert(
                key.clone(),
                PersistedDomain {
                    day,
                    bytes,
                    connections,
                },
            );
        }
        PersistedState {
            version: STATE_VERSION,
            domains,
        }
    }

    /// Write counters to disk (atomic rename). No-op when no state file is configured.
    pub fn persist_now(&self) -> Result<()> {
        let path = match &self.state_file {
            Some(p) => p,
            None => return Ok(()),
        };

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("Failed to create domain limits state directory {}", parent.display())
                })?;
            }
        }

        let json = serde_json::to_string_pretty(&self.build_snapshot())
            .context("Failed to serialize domain limits state")?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json)
            .with_context(|| format!("Failed to write {}", tmp.display()))?;
        fs::rename(&tmp, path)
            .with_context(|| format!("Failed to rename {} → {}", tmp.display(), path.display()))?;
        self.dirty.store(false, Ordering::Release);
        debug!(path = %path.display(), "Persisted domain limits state");
        Ok(())
    }

    /// Persist when counters changed since the last flush.
    pub fn flush_if_dirty(&self) -> Result<()> {
        if !self.dirty.load(Ordering::Acquire) {
            return Ok(());
        }
        self.persist_now()
    }

    fn resolve_limit_key<'a>(&'a self, sni: &str) -> Option<&'a str> {
        let sni = sni.to_lowercase();
        if self.limits.contains_key(&sni) {
            return self.limits.get_key_value(&sni).map(|(k, _)| k.as_str());
        }

        let mut best: Option<&str> = None;
        for key in self.limits.keys() {
            let matches = sni == *key || sni.ends_with(&format!(".{key}"));
            if matches && best.map(|b| key.len() > b.len()).unwrap_or(true) {
                best = Some(key.as_str());
            }
        }
        best
    }

    fn counters_for(&self, sni: &str) -> Option<(&DomainLimitConfig, &DomainCounters)> {
        let key = self.resolve_limit_key(sni)?;
        Some((self.limits.get(key)?, self.counters.get(key)?))
    }

    pub fn check_connection(&self, domain: &str) -> Result<(), LimitReason> {
        let Some((limit, counters)) = self.counters_for(domain) else {
            return Ok(());
        };

        counters.refresh_if_new_day();

        if let Some(max_bytes) = limit.daily_bandwidth {
            let used = counters.bytes.load(Ordering::Acquire);
            if used >= max_bytes.0 {
                debug!(
                    domain = %domain,
                    used_bytes = used,
                    limit_bytes = max_bytes.0,
                    "daily bandwidth limit reached"
                );
                return Err(LimitReason::DailyBandwidth);
            }
        }

        if let Some(max_conn) = limit.daily_connections {
            let mut current = counters.connections.load(Ordering::Acquire);
            loop {
                if current >= max_conn {
                    debug!(
                        domain = %domain,
                        used = current,
                        limit = max_conn,
                        "daily connection limit reached"
                    );
                    return Err(LimitReason::DailyConnections);
                }
                match counters.connections.compare_exchange_weak(
                    current,
                    current + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        self.mark_dirty();
                        break;
                    }
                    Err(actual) => current = actual,
                }
            }
        }

        Ok(())
    }

    pub fn account_bytes(&self, domain: &str, bytes: u64) -> Result<(), LimitReason> {
        if bytes == 0 {
            return Ok(());
        }

        let Some((limit, counters)) = self.counters_for(domain) else {
            return Ok(());
        };

        let Some(max_bytes) = limit.daily_bandwidth else {
            return Ok(());
        };

        counters.refresh_if_new_day();
        let new_used = counters.bytes.fetch_add(bytes, Ordering::AcqRel) + bytes;
        self.mark_dirty();

        if new_used > max_bytes.0 {
            debug!(
                domain = %domain,
                used_bytes = new_used,
                limit_bytes = max_bytes.0,
                added = bytes,
                "daily bandwidth limit exceeded during transfer"
            );
            return Err(LimitReason::DailyBandwidth);
        }

        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ByteSize, DomainLimitConfig};
    fn limiter_with(domain: &str, max_conn: Option<u64>, max_bytes: Option<u64>) -> DomainLimiter {
        let mut limits = HashMap::new();
        limits.insert(
            domain.to_string(),
            DomainLimitConfig {
                daily_connections: max_conn,
                daily_bandwidth: max_bytes.map(ByteSize),
            },
        );
        DomainLimiter::new(limits)
    }

    #[test]
    fn unknown_domain_is_allowed() {
        let l = limiter_with("example.com", Some(10), None);
        assert!(l.check_connection("other.com").is_ok());
    }

    #[test]
    fn connection_limit_enforced() {
        let l = limiter_with("example.com", Some(2), None);
        assert!(l.check_connection("example.com").is_ok());
        assert!(l.check_connection("example.com").is_ok());
        assert_eq!(
            l.check_connection("example.com"),
            Err(LimitReason::DailyConnections)
        );
    }

    #[test]
    fn bandwidth_limit_enforced_at_connect() {
        let l = limiter_with("example.com", None, Some(1000));
        assert!(l.check_connection("example.com").is_ok());
        assert!(l.account_bytes("example.com", 1000).is_ok());
        assert_eq!(
            l.check_connection("example.com"),
            Err(LimitReason::DailyBandwidth)
        );
    }

    #[test]
    fn bandwidth_limit_enforced_mid_transfer() {
        let l = limiter_with("example.com", None, Some(1000));
        assert!(l.check_connection("example.com").is_ok());
        assert!(l.account_bytes("example.com", 900).is_ok());
        assert_eq!(
            l.account_bytes("example.com", 200),
            Err(LimitReason::DailyBandwidth)
        );
        assert_eq!(
            l.check_connection("example.com"),
            Err(LimitReason::DailyBandwidth)
        );
    }

    #[test]
    fn case_insensitive_lookup() {
        let l = limiter_with("Example.COM", Some(1), None);
        assert!(l.check_connection("example.com").is_ok());
        assert_eq!(
            l.check_connection("EXAMPLE.COM"),
            Err(LimitReason::DailyConnections)
        );
    }

    #[test]
    fn subdomain_inherits_parent_limit() {
        let l = limiter_with("limoodns.com", None, Some(500));
        assert!(l.check_connection("yooz106.limoodns.com").is_ok());
        assert!(l.account_bytes("yooz106.limoodns.com", 500).is_ok());
        assert_eq!(
            l.check_connection("yooz106.limoodns.com"),
            Err(LimitReason::DailyBandwidth)
        );
    }

    #[test]
    fn more_specific_limit_wins_over_parent() {
        let mut limits = HashMap::new();
        limits.insert(
            "limoodns.com".to_string(),
            DomainLimitConfig {
                daily_connections: None,
                daily_bandwidth: Some(ByteSize(10_000)),
            },
        );
        limits.insert(
            "yooz106.limoodns.com".to_string(),
            DomainLimitConfig {
                daily_connections: None,
                daily_bandwidth: Some(ByteSize(100)),
            },
        );
        let l = DomainLimiter::new(limits);
        assert!(l.check_connection("yooz106.limoodns.com").is_ok());
        assert!(l.account_bytes("yooz106.limoodns.com", 100).is_ok());
        assert_eq!(
            l.check_connection("yooz106.limoodns.com"),
            Err(LimitReason::DailyBandwidth)
        );
        assert!(l.check_connection("other.limoodns.com").is_ok());
    }

    #[test]
    fn unlimited_when_both_none() {
        let l = limiter_with("example.com", None, None);
        for _ in 0..1000 {
            assert!(l.check_connection("example.com").is_ok());
        }
    }

    #[test]
    fn persist_and_restore_same_day() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("limits.json");
        let today = epoch_day_utc();

        let limits = HashMap::from([(
            "example.com".to_string(),
            DomainLimitConfig {
                daily_connections: None,
                daily_bandwidth: Some(ByteSize(50_000)),
            },
        )]);

        {
            let l = DomainLimiter::load(limits.clone(), Some(path.clone())).unwrap();
            assert!(l.check_connection("example.com").is_ok());
            l.account_bytes("example.com", 42_000).unwrap();
            l.persist_now().unwrap();
        }

        let l2 = DomainLimiter::load(limits, Some(path)).unwrap();
        let counters = l2.counters.get("example.com").unwrap();
        assert_eq!(counters.day.load(Ordering::Acquire), today);
        assert_eq!(counters.bytes.load(Ordering::Acquire), 42_000);
        assert!(l2.check_connection("example.com").is_ok());
        assert_eq!(
            l2.account_bytes("example.com", 9_000),
            Err(LimitReason::DailyBandwidth)
        );
    }

    #[test]
    fn stale_day_not_restored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("limits.json");

        let state = PersistedState {
            version: STATE_VERSION,
            domains: HashMap::from([(
                "example.com".to_string(),
                PersistedDomain {
                    day: epoch_day_utc().saturating_sub(1),
                    bytes: 999_999,
                    connections: 99,
                },
            )]),
        };
        fs::write(&path, serde_json::to_string_pretty(&state).unwrap()).unwrap();

        let limits = HashMap::from([(
            "example.com".to_string(),
            DomainLimitConfig {
                daily_connections: None,
                daily_bandwidth: Some(ByteSize(1000)),
            },
        )]);

        let l = DomainLimiter::load(limits, Some(path)).unwrap();
        assert!(l.check_connection("example.com").is_ok());
    }
}
