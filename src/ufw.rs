//! Host UFW sync for client whitelist.
//!
//! Inside Docker we must not run a bind-mounted `/usr/sbin/ufw` (Python script
//! missing host libs). With `pid: host` + `privileged`, we `nsenter` into PID 1
//! (the host init) and run the real host `ufw`.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;
use tracing::{debug, info, warn};

const RULE_COMMENT_PREFIX: &str = "snirelay";

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

fn host_ufw_path(configured: Option<&str>) -> String {
    configured
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "/usr/sbin/ufw".into())
}

/// How we invoke ufw: via host namespaces, or direct binary.
#[derive(Debug, Clone)]
enum UfwInvoke {
    /// `nsenter -t 1 -m -n -- /usr/sbin/ufw …` (mount + net only; IPC/UTS not needed)
    Nsenter { nsenter: String, ufw: String },
    /// Direct `ufw` / path (bare metal or full ufw install in container).
    Direct { ufw: String },
}

/// Host namespaces needed for UFW: mount (host ufw + rules) + net (iptables).
/// Avoid `-i`/`-u` — some hosts deny `/proc/1/ns/ipc` even when privileged.
const NSENTER_HOST_ARGS: &[&str] = &["-t", "1", "-m", "-n", "--"];

fn resolve_invoke(configured: Option<&str>) -> UfwInvoke {
    let ufw = host_ufw_path(configured);
    if in_docker() {
        if let Some(ns) = nsenter_bin() {
            return UfwInvoke::Nsenter {
                nsenter: ns.into(),
                ufw,
            };
        }
        warn!("Docker detected but nsenter missing; ufw sync needs util-linux + pid:host");
    }
    UfwInvoke::Direct { ufw }
}

/// Probe whether host ufw can be driven from this process.
pub fn ufw_available(configured: Option<&str>) -> bool {
    match run_ufw(configured, &["status"]) {
        Ok(_) => true,
        Err(e) => {
            debug!(error = %e, "ufw availability probe failed");
            false
        }
    }
}

/// UFW rule comment: `snirelay:<username>` or `snirelay-whitelist` when no user.
pub fn rule_comment(username: Option<&str>) -> String {
    match username.map(str::trim).filter(|s| !s.is_empty()) {
        Some(u) => format!("{RULE_COMMENT_PREFIX}:{u}"),
        None => format!("{RULE_COMMENT_PREFIX}-whitelist"),
    }
}

fn run_ufw(configured: Option<&str>, args: &[&str]) -> Result<String> {
    let invoke = resolve_invoke(configured);
    let output = match &invoke {
        UfwInvoke::Nsenter { nsenter, ufw } => {
            let mut cmd = Command::new(nsenter);
            // pid:host so PID 1 is host init; privileged (or CAP_SYS_ADMIN) for nsenter.
            cmd.args(NSENTER_HOST_ARGS);
            cmd.arg(ufw);
            cmd.args(args);
            cmd.output().with_context(|| {
                format!(
                    "exec {nsenter} -t 1 -m -n -- {ufw} {}",
                    args.join(" ")
                )
            })?
        }
        UfwInvoke::Direct { ufw } => Command::new(ufw)
            .args(args)
            .output()
            .with_context(|| format!("exec {ufw} {}", args.join(" ")))?,
    };

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() {
        let mut msg = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("exit {}", output.status)
        };
        if msg.contains("Permission denied") || msg.contains("cannot open /proc/1") {
            msg.push_str(
                " — ensure docker-compose has `pid: host` and `privileged: true`, then recreate the container",
            );
        }
        bail!("ufw {}: {msg}", args.join(" "));
    }
    Ok(if stdout.is_empty() { stderr } else { stdout })
}

/// Allow traffic from `ip` (all ports), tagged with username in the UFW comment.
pub fn allow_ip(
    ip: &str,
    username: Option<&str>,
    configured_bin: Option<&str>,
) -> Result<String> {
    let comment = rule_comment(username);
    if rule_exists(configured_bin, ip)? {
        // Refresh comment: delete then re-add.
        let _ = delete_ip(ip, configured_bin);
    }
    let out = run_ufw(
        configured_bin,
        &["allow", "from", ip, "comment", &comment],
    )?;
    info!(%ip, %comment, "ufw: allowed from client (host)");
    Ok(out)
}

/// Remove the allow-from rule for `ip`.
pub fn delete_ip(ip: &str, configured_bin: Option<&str>) -> Result<String> {
    if !rule_exists(configured_bin, ip)? {
        info!(%ip, "ufw: no allow rule to delete");
        return Ok("not present".into());
    }
    let out = run_ufw(configured_bin, &["--force", "delete", "allow", "from", ip])?;
    info!(%ip, "ufw: deleted allow from client (host)");
    Ok(out)
}

fn rule_exists(configured: Option<&str>, ip: &str) -> Result<bool> {
    let status = run_ufw(configured, &["status"])?;
    for line in status.lines() {
        if !line.contains(ip) {
            continue;
        }
        if line.contains("ALLOW") || line.to_ascii_lowercase().contains("allow") {
            return Ok(true);
        }
    }
    Ok(false)
}
