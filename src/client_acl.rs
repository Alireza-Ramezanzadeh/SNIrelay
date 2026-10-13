//! Client IP whitelist (application-level ACL).

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Result;
use parking_lot::RwLock;

use crate::config::{normalize_client_ip, sanitize_whitelist_username, AppConfig, WhitelistEntry};

/// Live client IP allowlist.
///
/// Empty map → ACL is inactive (all clients allowed).
/// Non-empty → only listed IPs may use the proxy listeners (panel is unaffected).
#[derive(Debug, Clone)]
pub struct ClientAcl {
    /// IP → username (empty string when none / legacy).
    entries: BTreeMap<String, String>,
    /// When true, panel add/remove also syncs UFW rules.
    ufw_sync: bool,
}

impl ClientAcl {
    pub fn from_config(cfg: &AppConfig) -> Self {
        let mut entries = BTreeMap::new();
        for e in &cfg.client_whitelist {
            if let Some(n) = normalize_client_ip(&e.ip) {
                let user = e
                    .username
                    .as_deref()
                    .and_then(sanitize_whitelist_username)
                    .unwrap_or_default();
                entries.insert(n, user);
            } else {
                tracing::warn!(ip = %e.ip, "ignoring invalid client_whitelist entry");
            }
        }
        Self {
            entries,
            ufw_sync: cfg.client_whitelist_ufw,
        }
    }

    pub fn from_parts(entries: Vec<WhitelistEntry>, ufw_sync: bool) -> Result<Self> {
        let mut map = BTreeMap::new();
        for e in entries {
            let n = normalize_client_ip(&e.ip)
                .ok_or_else(|| anyhow::anyhow!("invalid whitelist IP '{}'", e.ip))?;
            let user = e
                .username
                .as_deref()
                .and_then(sanitize_whitelist_username)
                .unwrap_or_default();
            map.insert(n, user);
        }
        Ok(Self {
            entries: map,
            ufw_sync,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn ufw_sync(&self) -> bool {
        self.ufw_sync
    }

    /// True when no whitelist is configured (open proxy ACL).
    pub fn is_open(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn is_allowed(&self, client_ip: &str) -> bool {
        if self.entries.is_empty() {
            return true;
        }
        let key = normalize_client_ip(client_ip).unwrap_or_else(|| client_ip.trim().to_string());
        self.entries.contains_key(&key)
    }

    pub fn username_for(&self, ip: &str) -> Option<&str> {
        let key = normalize_client_ip(ip)?;
        self.entries.get(&key).map(|s| s.as_str())
    }

    /// Insert/update. Returns `(added_new, username)`.
    pub fn add(&mut self, ip: &str, username: &str) -> Result<(bool, String)> {
        let n = normalize_client_ip(ip)
            .ok_or_else(|| anyhow::anyhow!("invalid whitelist IP '{ip}'"))?;
        let user = sanitize_whitelist_username(username)
            .ok_or_else(|| anyhow::anyhow!("invalid or empty username"))?;
        let added = !self.entries.contains_key(&n);
        self.entries.insert(n, user.clone());
        Ok((added, user))
    }

    pub fn remove(&mut self, ip: &str) -> Result<bool> {
        let n = normalize_client_ip(ip)
            .ok_or_else(|| anyhow::anyhow!("invalid whitelist IP '{ip}'"))?;
        Ok(self.entries.remove(&n).is_some())
    }

    pub fn as_vec(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    pub fn as_entries(&self) -> Vec<WhitelistEntry> {
        self.entries
            .iter()
            .map(|(ip, user)| WhitelistEntry {
                ip: ip.clone(),
                username: if user.is_empty() {
                    None
                } else {
                    Some(user.clone())
                },
            })
            .collect()
    }

    pub fn contains_ip(&self, ip: &str) -> bool {
        normalize_client_ip(ip)
            .map(|n| self.entries.contains_key(&n))
            .unwrap_or(false)
    }
}

/// Validate username for API (required, non-empty after sanitize).
pub fn require_username(raw: &str) -> Result<String> {
    sanitize_whitelist_username(raw).ok_or_else(|| {
        anyhow::anyhow!("username required (letters, digits, . _ @ + -; max 32 chars)")
    })
}

pub type SharedClientAcl = Arc<RwLock<ClientAcl>>;

pub fn shared_from_config(cfg: &AppConfig) -> SharedClientAcl {
    Arc::new(RwLock::new(ClientAcl::from_config(cfg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allows_all() {
        let acl = ClientAcl::from_parts(vec![], true).unwrap();
        assert!(acl.is_open());
        assert!(acl.is_allowed("1.2.3.4"));
    }

    #[test]
    fn nonempty_filters() {
        let acl = ClientAcl::from_parts(
            vec![
                WhitelistEntry {
                    ip: "10.0.0.1".into(),
                    username: Some("alice".into()),
                },
                WhitelistEntry {
                    ip: "10.0.0.2".into(),
                    username: None,
                },
            ],
            false,
        )
        .unwrap();
        assert!(!acl.is_open());
        assert!(acl.is_allowed("10.0.0.1"));
        assert!(!acl.is_allowed("10.0.0.9"));
        assert_eq!(acl.username_for("10.0.0.1"), Some("alice"));
    }
}
