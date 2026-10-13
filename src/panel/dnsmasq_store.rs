//! Read/write dnsmasq `address=` and bypass `server=/domain/#` rules from conf files.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

/// One managed DNS routing rule from dnsmasq.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsDomain {
    /// Domain label as written in dnsmasq (no leading `*.` — wildcards are implicit for address=/).
    pub pattern: String,
    /// `relay` → `address=/pattern/IP` ; `bypass` → `server=/pattern/#`
    pub mode: String,
    /// File this entry was last loaded from (informational).
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct DnsmasqPaths {
    pub conf_dir: PathBuf,
    pub relay_file: PathBuf,
    pub bypass_file: PathBuf,
    pub relay_ip: String,
    pub reload_cmd: Option<String>,
}

impl DnsmasqPaths {
    pub fn from_panel(panel: &crate::config::PanelConfig) -> Option<Self> {
        let dir = panel
            .dnsmasq_conf_dir
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                panel
                    .dnsmasq_conf_path
                    .as_ref()
                    .or(panel.dnsmasq_relay_file.as_ref())
                    .and_then(|p| Path::new(p).parent().map(|d| d.to_path_buf()))
            })?;
        if !dir.is_dir() {
            tracing::warn!(
                path = %dir.display(),
                "dnsmasq_conf_dir is set but not a directory inside the container \
                 (mount host /etc/dnsmasq.d or create the path)"
            );
            return None;
        }
        let relay_ip = panel
            .relay_ip
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "127.0.0.1".into());

        let (auto_relay, auto_bypass) = detect_files(&dir);
        let relay_file = panel
            .dnsmasq_relay_file
            .as_ref()
            .or(panel.dnsmasq_conf_path.as_ref())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or(auto_relay)
            .unwrap_or_else(|| dir.join("snirelay-relay.conf"));
        let bypass_file = panel
            .dnsmasq_bypass_file
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or(auto_bypass)
            .unwrap_or_else(|| dir.join("bypass.conf"));

        Some(Self {
            conf_dir: dir,
            relay_file,
            bypass_file,
            relay_ip,
            reload_cmd: panel.dnsmasq_reload_cmd.clone(),
        })
    }
}

fn detect_files(dir: &Path) -> (Option<PathBuf>, Option<PathBuf>) {
    let mut best_relay: Option<(usize, PathBuf)> = None;
    let mut named_bypass: Option<PathBuf> = None;
    let mut best_bypass: Option<(usize, PathBuf)> = None;
    let Ok(rd) = fs::read_dir(dir) else {
        return (None, None);
    };
    for ent in rd.flatten() {
        let path = ent.path();
        if path.extension().and_then(|e| e.to_str()) != Some("conf") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let mut addr = 0usize;
        let mut bypass = 0usize;
        for line in text.lines() {
            let t = line.trim();
            if t.starts_with("address=/") {
                addr += 1;
            } else if is_bypass_server_line(t) {
                bypass += 1;
            }
        }
        if addr > best_relay.as_ref().map(|(n, _)| *n).unwrap_or(0) {
            best_relay = Some((addr, path.clone()));
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.contains("bypass") {
            named_bypass = Some(path.clone());
        } else if bypass > best_bypass.as_ref().map(|(n, _)| *n).unwrap_or(0) {
            best_bypass = Some((bypass, path));
        }
    }
    (
        best_relay.map(|(_, p)| p),
        named_bypass.or_else(|| best_bypass.map(|(_, p)| p)),
    )
}

fn is_bypass_server_line(line: &str) -> bool {
    // server=/domain/#  → use system upstream (direct / not hijacked)
    let Some(rest) = line.strip_prefix("server=/") else {
        return false;
    };
    rest.ends_with("/#")
}

fn parse_address_line(line: &str) -> Option<(String, String)> {
    // address=/domain/1.2.3.4
    let rest = line.strip_prefix("address=/")?;
    let (domain, ip) = rest.rsplit_once('/')?;
    if domain.is_empty() || ip.is_empty() {
        return None;
    }
    Some((domain.to_lowercase(), ip.to_string()))
}

fn parse_bypass_line(line: &str) -> Option<String> {
    let rest = line.strip_prefix("server=/")?;
    let domain = rest.strip_suffix("/#")?;
    if domain.is_empty() {
        return None;
    }
    Some(domain.to_lowercase())
}

/// Load all relay + bypass domain rules from every `*.conf` under `conf_dir`.
pub fn load_domains(paths: &DnsmasqPaths) -> Result<Vec<DnsDomain>> {
    let mut by_key: BTreeMap<(String, String), DnsDomain> = BTreeMap::new();
    let rd = fs::read_dir(&paths.conf_dir)
        .with_context(|| format!("read dnsmasq dir {}", paths.conf_dir.display()))?;
    for ent in rd.flatten() {
        let path = ent.path();
        if path.extension().and_then(|e| e.to_str()) != Some("conf") {
            continue;
        }
        let text = fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.display()))?;
        let source = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        for line in text.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            if let Some((pattern, ip)) = parse_address_line(t) {
                // Prefer configured relay_ip display; keep pattern unique for relay
                let _ = ip;
                by_key.insert(
                    (pattern.clone(), "relay".into()),
                    DnsDomain {
                        pattern,
                        mode: "relay".into(),
                        source: source.clone(),
                    },
                );
            } else if let Some(pattern) = parse_bypass_line(t) {
                by_key.insert(
                    (pattern.clone(), "bypass".into()),
                    DnsDomain {
                        pattern,
                        mode: "bypass".into(),
                        source: source.clone(),
                    },
                );
            }
        }
    }
    Ok(by_key.into_values().collect())
}

/// Rewrite relay + bypass files from the domain list; strip managed lines from other confs.
pub fn save_domains(paths: &DnsmasqPaths, domains: &[DnsDomain]) -> Result<()> {
    if paths.relay_ip.is_empty() {
        bail!("relay_ip is empty; set panel.relay_ip or RELAY_IP");
    }

    let mut relay: BTreeSet<String> = BTreeSet::new();
    let mut bypass: BTreeSet<String> = BTreeSet::new();
    for d in domains {
        let p = d.pattern.trim().to_lowercase();
        if p.is_empty() {
            continue;
        }
        match d.mode.as_str() {
            "bypass" | "direct" => {
                bypass.insert(p);
            }
            _ => {
                relay.insert(p);
            }
        }
    }
    // If same domain in both, bypass wins (longest-match / explicit exception)
    for b in &bypass {
        relay.remove(b);
    }

    // Strip managed lines from every conf, preserve everything else
    let rd = fs::read_dir(&paths.conf_dir)
        .with_context(|| format!("read {}", paths.conf_dir.display()))?;
    for ent in rd.flatten() {
        let path = ent.path();
        if path.extension().and_then(|e| e.to_str()) != Some("conf") {
            continue;
        }
        // Skip rewriting relay/bypass destinations here; we overwrite them fully below
        if path == paths.relay_file || path == paths.bypass_file {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap_or_default();
        let cleaned = strip_managed_lines(&text);
        if cleaned != text {
            fs::write(&path, cleaned)
                .with_context(|| format!("write cleaned {}", path.display()))?;
        }
    }

    let relay_body = render_relay_lines(&relay, &paths.relay_ip);
    write_managed_file(&paths.relay_file, &relay_body)?;

    let bypass_body = render_bypass_lines(&bypass);
    write_managed_file(&paths.bypass_file, &bypass_body)?;

    Ok(())
}

fn write_managed_file(path: &Path, managed_block: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let existing = fs::read_to_string(path).unwrap_or_default();
    let preserved = strip_managed_lines(&existing);
    let preserved = strip_panel_banners(&preserved);
    let mut out = String::from(
        "# Managed by SNIrelay admin panel — domain rules below are rewritten on Save.\n\
         # Other directives in this file are preserved.\n",
    );
    if !preserved.trim().is_empty() {
        out.push_str(&preserved);
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("# ------------------------------------------------------------\n");
    }
    out.push_str(managed_block);
    fs::write(path, out).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn strip_panel_banners(text: &str) -> String {
    text.lines()
        .filter(|l| {
            let t = l.trim();
            !(t.starts_with("# Managed by SNIrelay")
                || t.starts_with("# Do not edit by hand while the panel")
                || t.starts_with("# Longest-match:")
                || t == "# ------------------------------------------------------------")
        })
        .fold(String::new(), |mut acc, l| {
            acc.push_str(l);
            acc.push('\n');
            acc
        })
}

fn strip_managed_lines(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("address=/") || is_bypass_server_line(t) {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn render_relay_lines(domains: &BTreeSet<String>, relay_ip: &str) -> String {
    let mut out = String::new();
    for d in domains {
        out.push_str(&format!("address=/{d}/{relay_ip}\n"));
    }
    out
}

fn render_bypass_lines(domains: &BTreeSet<String>) -> String {
    let mut out = String::new();
    for d in domains {
        out.push_str(&format!("server=/{d}/#\n"));
    }
    out
}

fn in_docker() -> bool {
    Path::new("/.dockerenv").exists()
}

fn nsenter_bin() -> Option<&'static str> {
    for p in ["/usr/bin/nsenter", "/bin/nsenter"] {
        if Path::new(p).exists() {
            return Some(p);
        }
    }
    None
}

/// Reload host dnsmasq after writing drop-ins.
///
/// Inside Docker, plain `kill -HUP $(pidof dnsmasq)` often fails with
/// `Permission denied` even with `pid: host` — signal the host process via
/// `nsenter -t 1` (same pattern as UFW sync).
pub fn reload(paths: &DnsmasqPaths) -> Result<Option<bool>> {
    let Some(cmd) = &paths.reload_cmd else {
        return Ok(None);
    };

    let output = if in_docker() {
        if let Some(ns) = nsenter_bin() {
            // mount+net only — skip IPC/UTS (some hosts deny /proc/1/ns/ipc)
            Command::new(ns)
                .args(["-t", "1", "-m", "-n", "--", "sh", "-c", cmd])
                .output()
                .with_context(|| {
                    format!(
                        "nsenter -t 1 -m -n -- sh -c {cmd:?} (needs privileged + pid: host)"
                    )
                })?
        } else {
            warn!("Docker detected but nsenter missing; dnsmasq reload may fail (install util-linux)");
            Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .output()
                .with_context(|| format!("run reload cmd: {cmd}"))?
        }
    } else {
        Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .with_context(|| format!("run reload cmd: {cmd}"))?
    };

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if output.status.success() {
        info!(%cmd, "dnsmasq reload ok");
        Ok(Some(true))
    } else {
        let detail = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("exit {}", output.status)
        };
        warn!(%cmd, error = %detail, "dnsmasq reload failed");
        Ok(Some(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn roundtrip_relay_and_bypass() {
        let dir = tempdir().unwrap();
        let conf = dir.path();
        fs::write(
            conf.join("routed.conf"),
            "address=/ea.com/1.2.3.4\naddress=/steam.com/1.2.3.4\n",
        )
        .unwrap();
        fs::write(
            conf.join("bypass.conf"),
            "server=/gosredirector.ea.com/#\nfilter-AAAA\n",
        )
        .unwrap();
        fs::write(conf.join("no-aaaa.conf"), "filter-AAAA\n").unwrap();

        let paths = DnsmasqPaths {
            conf_dir: conf.to_path_buf(),
            relay_file: conf.join("routed.conf"),
            bypass_file: conf.join("bypass.conf"),
            relay_ip: "9.9.9.9".into(),
            reload_cmd: None,
        };
        let loaded = load_domains(&paths).unwrap();
        assert!(loaded.iter().any(|d| d.pattern == "ea.com" && d.mode == "relay"));
        assert!(loaded
            .iter()
            .any(|d| d.pattern == "gosredirector.ea.com" && d.mode == "bypass"));

        let mut next = loaded;
        next.push(DnsDomain {
            pattern: "new.game".into(),
            mode: "relay".into(),
            source: String::new(),
        });
        next.push(DnsDomain {
            pattern: "voice.example".into(),
            mode: "bypass".into(),
            source: String::new(),
        });
        save_domains(&paths, &next).unwrap();

        let routed = fs::read_to_string(conf.join("routed.conf")).unwrap();
        assert!(routed.contains("address=/new.game/9.9.9.9"));
        assert!(routed.contains("address=/ea.com/9.9.9.9"));
        let bypass = fs::read_to_string(conf.join("bypass.conf")).unwrap();
        assert!(bypass.contains("server=/gosredirector.ea.com/#"));
        assert!(bypass.contains("server=/voice.example/#"));
        // no-aaaa untouched domain-wise
        assert_eq!(
            fs::read_to_string(conf.join("no-aaaa.conf")).unwrap().trim(),
            "filter-AAAA"
        );
    }
}
