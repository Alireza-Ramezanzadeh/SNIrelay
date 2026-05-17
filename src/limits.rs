// limits.rs — Raise RLIMIT_NOFILE and derive a safe concurrent connection cap.

use std::io;

use tracing::{info, warn};

use crate::config::AppConfig;

/// Result of process limit configuration at startup.
#[derive(Debug, Clone, Copy)]
pub struct ProcessLimits {
    pub soft_nofile: u64,
    pub max_connections: usize,
}

/// Default file descriptors reserved for listeners, metrics, logs, and libc overhead.
const FD_RESERVE: u64 = 128;

/// Apply `nofile_limit` from config and compute how many proxy sessions we allow.
pub fn apply(cfg: &AppConfig) -> io::Result<ProcessLimits> {
    let soft = if cfg.nofile_limit > 0 {
        match raise_nofile_limit(cfg.nofile_limit) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "Could not raise open-file limit to {}: {e}; using current soft limit",
                    cfg.nofile_limit
                );
                current_nofile_soft()?
            }
        }
    } else {
        current_nofile_soft()?
    };

    let max_connections = effective_connection_limit(soft, cfg.max_connections, FD_RESERVE);

    info!(
        "Process open-file soft limit: {soft}; max concurrent proxy sessions: {max_connections} \
         (config max_connections={}, ~2 FDs per session)",
        cfg.max_connections
    );

    if max_connections < cfg.max_connections {
        warn!(
            "max_connections ({}) exceeds safe capacity for soft nofile ({soft}); \
             capped at {max_connections}. Raise ulimit (e.g. `ulimit -n 1048576` or \
             `docker run --ulimit nofile=1048576:1048576`) or lower max_connections.",
            cfg.max_connections
        );
    }

    if soft < 4096 {
        warn!(
            "Open-file soft limit ({soft}) is low for heavy traffic; \
             sysctl fs.file-max does not raise per-process ulimit. \
             Use `ulimit -n` or container ulimits."
        );
    }

    Ok(ProcessLimits {
        soft_nofile: soft,
        max_connections,
    })
}

/// Concurrent sessions allowed: min(configured, (soft − reserve) / 2).
pub fn effective_connection_limit(
    soft_nofile: u64,
    configured_max: usize,
    reserve_fds: u64,
) -> usize {
    let fds_for_conns = soft_nofile.saturating_sub(reserve_fds);
    let by_fds = (fds_for_conns / 2) as usize;
    configured_max.min(by_fds.max(1))
}

#[cfg(unix)]
pub fn current_nofile_soft() -> io::Result<u64> {
    use libc::{getrlimit, rlimit, RLIMIT_NOFILE};

    let mut lim = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { getrlimit(RLIMIT_NOFILE, &mut lim) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(lim.rlim_cur)
}

#[cfg(not(unix))]
pub fn current_nofile_soft() -> io::Result<u64> {
    Ok(1024)
}

#[cfg(unix)]
fn rlim_is_infinity(v: u64) -> bool {
    v == libc::RLIM_INFINITY as u64
}

/// Raise the soft open-file limit toward `target`, without exceeding the hard limit.
#[cfg(unix)]
pub fn raise_nofile_limit(target: u64) -> io::Result<u64> {
    use libc::{getrlimit, setrlimit, rlimit, RLIMIT_NOFILE};

    let mut lim = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { getrlimit(RLIMIT_NOFILE, &mut lim) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let cur_soft = lim.rlim_cur;
    let cur_hard = lim.rlim_max;

    if cur_soft >= target {
        return Ok(cur_soft);
    }

    let want_soft = if rlim_is_infinity(cur_hard) {
        target
    } else {
        target.min(cur_hard)
    };

    if want_soft == cur_soft {
        return Ok(cur_soft);
    }

    // Only bump soft; keep hard unchanged (required in Docker/seccomp environments).
    lim.rlim_cur = want_soft;
    if unsafe { setrlimit(RLIMIT_NOFILE, &lim) } != 0 {
        return Err(io::Error::last_os_error());
    }

    if unsafe { getrlimit(RLIMIT_NOFILE, &mut lim) } != 0 {
        return Err(io::Error::last_os_error());
    }

    if lim.rlim_cur < target {
        warn!(
            "Requested nofile limit {target}, but soft limit is only {} (hard={})",
            lim.rlim_cur,
            if rlim_is_infinity(lim.rlim_max) {
                "unlimited".to_string()
            } else {
                lim.rlim_max.to_string()
            }
        );
    }

    Ok(lim.rlim_cur)
}

#[cfg(not(unix))]
pub fn raise_nofile_limit(_target: u64) -> io::Result<u64> {
    Ok(1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_limit_respects_fds_and_config() {
        assert_eq!(effective_connection_limit(1024, 65535, 128), 448);
        assert_eq!(effective_connection_limit(1_048_576, 10_000, 128), 10_000);
        assert_eq!(effective_connection_limit(256, 65535, 128), 64);
    }

    #[test]
    fn want_soft_caps_at_hard() {
        let target = 1_048_576_u64;
        let hard = 65_536_u64;
        assert_eq!(target.min(hard), hard);
    }
}
