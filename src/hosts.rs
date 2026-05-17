// hosts.rs — Static hostname → backend address map (YAML `hosts` in config).

use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::info;

/// One row in the `hosts` list in config.yaml.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct HostsEntry {
    /// Hostname (exact) or regex (e.g. `.*`).
    pub pattern: String,
    /// IPv4/IPv6 address, or `*` to use the client SNI/Host as-is.
    pub address: String,
}

/// Result of a hosts-table lookup.
#[derive(Debug, Clone, PartialEq)]
pub enum HostResolve {
    /// `*` — tunnel to the same hostname the client asked for.
    Passthrough,
    /// Fixed IP backend (DNS override).
    Ip(IpAddr),
    /// Rare: backend hostname string (not an IP).
    Hostname(String),
}

#[derive(Debug)]
pub struct HostsTable {
    exact: HashMap<String, HostResolve>,
    patterns: Vec<(Regex, HostResolve)>,
}

impl HostsTable {
    pub fn compile(entries: &[HostsEntry]) -> Result<Self> {
        let mut exact = HashMap::new();
        let mut patterns = Vec::new();

        for (i, entry) in entries.iter().enumerate() {
            let (is_exact, key, resolve) = compile_entry(&entry.pattern, &entry.address)
                .with_context(|| format!("hosts[{i}]"))?;

            if is_exact {
                if exact.insert(key.clone(), resolve).is_some() {
                    tracing::warn!("hosts: duplicate exact host '{key}', using last entry");
                }
            } else {
                let re = Regex::new(&key)
                    .with_context(|| format!("hosts[{i}]: invalid regex '{key}'"))?;
                patterns.push((re, resolve));
            }
        }

        Ok(HostsTable { exact, patterns })
    }

    /// First-match wins: exact host map, then regex patterns in config order.
    pub fn resolve(&self, hostname: &str) -> Option<HostResolve> {
        let host = hostname.to_lowercase();

        if let Some(r) = self.exact.get(&host) {
            return Some(r.clone());
        }

        for (re, resolve) in &self.patterns {
            if re.is_match(&host) {
                return Some(resolve.clone());
            }
        }

        None
    }

    pub fn stats(&self) -> (usize, usize) {
        (self.exact.len(), self.patterns.len())
    }
}

pub fn compile_hosts_table(entries: &[HostsEntry]) -> Result<Option<Arc<HostsTable>>> {
    if entries.is_empty() {
        return Ok(None);
    }

    let table = HostsTable::compile(entries)?;
    let (exact, patterns) = table.stats();
    info!("Hosts table: {exact} exact + {patterns} pattern rule(s)");
    Ok(Some(Arc::new(table)))
}

fn compile_entry(pattern: &str, address: &str) -> Result<(bool, String, HostResolve)> {
    let resolve = parse_address(address)?;

    let pattern = pattern.trim();
    let is_regex = pattern == ".*"
        || pattern.contains('*')
        || pattern.contains('?')
        || pattern.starts_with('^')
        || pattern.ends_with('$');

    if is_regex {
        Ok((false, pattern.to_string(), resolve))
    } else {
        Ok((true, pattern.to_lowercase(), resolve))
    }
}

fn parse_address(address: &str) -> Result<HostResolve> {
    let address = address.trim();
    if address == "*" {
        return Ok(HostResolve::Passthrough);
    }
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Ok(HostResolve::Ip(ip));
    }
    Ok(HostResolve::Hostname(address.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_exact_and_wildcard() {
        let table = HostsTable::compile(&[
            HostsEntry {
                pattern: "eu.taline.ir".into(),
                address: "91.107.161.221".into(),
            },
            HostsEntry {
                pattern: ".*".into(),
                address: "*".into(),
            },
        ])
        .unwrap();

        assert!(matches!(
            table.resolve("eu.taline.ir"),
            Some(HostResolve::Ip(_))
        ));
        assert!(matches!(
            table.resolve("other.example.com"),
            Some(HostResolve::Passthrough)
        ));
    }
}
