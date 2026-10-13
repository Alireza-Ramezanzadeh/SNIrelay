//! Live multi-upstream registry: named SOCKS/HTTP profiles + per-client-IP routing.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use parking_lot::RwLock;

use crate::config::{normalize_client_ip, AppConfig, UpstreamProxy};

/// Snapshot of named upstreams and client IP → profile routing.
#[derive(Debug, Clone)]
pub struct UpstreamRegistry {
    profiles: HashMap<String, UpstreamProxy>,
    default: String,
    by_ip: HashMap<String, String>,
    /// Try other profiles when the preferred one fails to connect.
    failover: bool,
}

impl UpstreamRegistry {
    pub fn from_config(cfg: &AppConfig) -> Self {
        let default = cfg.default_upstream_name().to_string();
        Self {
            profiles: cfg.upstreams.clone(),
            default,
            by_ip: cfg.client_upstreams.clone(),
            failover: cfg.upstream_failover,
        }
    }

    pub fn default_name(&self) -> &str {
        &self.default
    }

    pub fn failover_enabled(&self) -> bool {
        self.failover
    }

    pub fn profiles(&self) -> &HashMap<String, UpstreamProxy> {
        &self.profiles
    }

    pub fn client_upstreams(&self) -> &HashMap<String, String> {
        &self.by_ip
    }

    pub fn profile_name_for_ip(&self, client_ip: &str) -> &str {
        let key = normalize_client_ip(client_ip).unwrap_or_else(|| client_ip.trim().to_string());
        self.by_ip
            .get(&key)
            .map(|s| s.as_str())
            .filter(|name| self.profiles.contains_key(*name))
            .unwrap_or(self.default.as_str())
    }

    /// Resolve `(profile_name, proxy)` for a client IP.
    pub fn resolve(&self, client_ip: &str) -> Result<(&str, &UpstreamProxy)> {
        let name = self.profile_name_for_ip(client_ip);
        let proxy = self
            .profiles
            .get(name)
            .with_context(|| format!("upstream profile '{name}' missing"))?;
        Ok((name, proxy))
    }

    /// Ordered connect candidates for a client IP.
    /// Primary (mapped or default) first. When `failover` is on, appends
    /// `default` (if different) then remaining profile names sorted.
    pub fn connect_candidates(&self, client_ip: &str) -> Result<Vec<(String, UpstreamProxy)>> {
        let primary = self.profile_name_for_ip(client_ip).to_string();
        let primary_proxy = self
            .profiles
            .get(&primary)
            .with_context(|| format!("upstream profile '{primary}' missing"))?
            .clone();

        let mut out = vec![(primary.clone(), primary_proxy)];
        if !self.failover {
            return Ok(out);
        }

        let mut rest: Vec<String> = self
            .profiles
            .keys()
            .filter(|k| *k != &primary)
            .cloned()
            .collect();
        // Prefer default next, then alphabetical for the rest.
        rest.sort_by(|a, b| {
            let a_def = a == &self.default;
            let b_def = b == &self.default;
            match (a_def, b_def) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.cmp(b),
            }
        });
        for name in rest {
            if let Some(proxy) = self.profiles.get(&name) {
                out.push((name, proxy.clone()));
            }
        }
        Ok(out)
    }

    pub fn default_proxy(&self) -> Result<&UpstreamProxy> {
        self.profiles
            .get(&self.default)
            .with_context(|| format!("default upstream '{}' missing", self.default))
    }

    /// Set/replace client IP → profile mapping.
    pub fn set_client_upstream(&mut self, ip: &str, profile: &str) -> Result<()> {
        if !self.profiles.contains_key(profile) {
            bail!("unknown upstream profile '{profile}'");
        }
        let key = normalize_client_ip(ip).ok_or_else(|| {
            anyhow::anyhow!("invalid client IP '{ip}' (need exact IPv4/IPv6, no CIDR)")
        })?;
        self.by_ip.insert(key, profile.to_string());
        Ok(())
    }

    /// Remove per-IP mapping. Returns true if it existed.
    pub fn remove_client_upstream(&mut self, ip: &str) -> Result<bool> {
        let key = normalize_client_ip(ip).ok_or_else(|| {
            anyhow::anyhow!("invalid client IP '{ip}' (need exact IPv4/IPv6, no CIDR)")
        })?;
        Ok(self.by_ip.remove(&key).is_some())
    }

    /// Validate and build a registry from panel/API payload pieces.
    pub fn from_parts(
        profiles: HashMap<String, UpstreamProxy>,
        default: String,
        by_ip: HashMap<String, String>,
        failover: bool,
    ) -> Result<Self> {
        if profiles.is_empty() {
            bail!("at least one upstream profile is required");
        }
        if !profiles.contains_key(&default) {
            bail!("default_upstream '{default}' is not in upstreams");
        }
        let mut by_ip_norm = HashMap::new();
        for (ip, profile) in by_ip {
            if !profiles.contains_key(&profile) {
                bail!("client_upstreams[{ip}] references unknown profile '{profile}'");
            }
            let key = normalize_client_ip(&ip).ok_or_else(|| {
                anyhow::anyhow!("invalid client IP '{ip}' (need exact IPv4/IPv6, no CIDR)")
            })?;
            by_ip_norm.insert(key, profile);
        }
        Ok(Self {
            profiles,
            default,
            by_ip: by_ip_norm,
            failover,
        })
    }
}

pub type SharedUpstreamRegistry = Arc<RwLock<UpstreamRegistry>>;

pub fn shared_from_config(cfg: &AppConfig) -> SharedUpstreamRegistry {
    Arc::new(RwLock::new(UpstreamRegistry::from_config(cfg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socks(host: &str, port: u16) -> UpstreamProxy {
        UpstreamProxy::Socks5 {
            host: host.into(),
            port,
            username: None,
            password: None,
        }
    }

    #[test]
    fn resolves_mapped_and_default() {
        let mut profiles = HashMap::new();
        profiles.insert("me".into(), socks("127.0.0.1", 10808));
        profiles.insert("eu".into(), socks("10.0.0.2", 1080));
        let mut by_ip = HashMap::new();
        by_ip.insert("94.183.122.121".into(), "eu".into());
        let reg = UpstreamRegistry::from_parts(profiles, "me".into(), by_ip, false).unwrap();
        let (name, proxy) = reg.resolve("94.183.122.121").unwrap();
        assert_eq!(name, "eu");
        assert_eq!(proxy.host_port(), Some(("10.0.0.2", 1080)));
        let (name2, _) = reg.resolve("1.2.3.4").unwrap();
        assert_eq!(name2, "me");
    }

    #[test]
    fn failover_candidates_order() {
        let mut profiles = HashMap::new();
        profiles.insert("me".into(), socks("127.0.0.1", 10808));
        profiles.insert("eu".into(), socks("10.0.0.2", 1080));
        profiles.insert("asia".into(), socks("10.0.0.3", 1080));
        let mut by_ip = HashMap::new();
        by_ip.insert("1.2.3.4".into(), "eu".into());

        let no_fo = UpstreamRegistry::from_parts(profiles.clone(), "me".into(), by_ip.clone(), false)
            .unwrap();
        let c0 = no_fo.connect_candidates("1.2.3.4").unwrap();
        assert_eq!(c0.len(), 1);
        assert_eq!(c0[0].0, "eu");

        let fo = UpstreamRegistry::from_parts(profiles, "me".into(), by_ip, true).unwrap();
        let names: Vec<_> = fo
            .connect_candidates("1.2.3.4")
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, vec!["eu", "me", "asia"]);
    }

    #[test]
    fn client_ip_yaml_roundtrip_keeps_string_keys() {
        let mut clients = serde_yaml::Mapping::new();
        clients.insert(
            serde_yaml::Value::String("94.183.122.121".into()),
            serde_yaml::Value::String("europe".into()),
        );
        let mut root = serde_yaml::Mapping::new();
        root.insert(
            serde_yaml::Value::String("client_upstreams".into()),
            serde_yaml::Value::Mapping(clients),
        );
        let yaml = serde_yaml::to_string(&serde_yaml::Value::Mapping(root)).unwrap();
        assert!(yaml.contains("94.183.122.121"));
        #[derive(serde::Deserialize)]
        struct Slice {
            client_upstreams: HashMap<String, String>,
        }
        let parsed: Slice = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            parsed.client_upstreams.get("94.183.122.121").map(String::as_str),
            Some("europe")
        );
    }
}
