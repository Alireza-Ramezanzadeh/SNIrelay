//! Prevent SOCKS/HTTP hairpin loops back onto this host's own listeners.
//!
//! With an open `hosts` catch-all, a client can send `Host: <this-server-ip>`.
//! SNIrelay then dials that IP via the upstream proxy; the proxy egress connects
//! back to the same listener → connection storm.
//!
//! Catch-all **domains** stay allowed; only destinations that resolve to a local
//! interface IP on a port we listen on are rejected.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::config::AppConfig;

/// Snapshot of local addresses + listen ports used to detect self-proxy loops.
#[derive(Debug, Clone)]
pub struct SelfLoopGuard {
    local_ips: HashSet<IpAddr>,
    listen_ports: HashSet<u16>,
}

impl SelfLoopGuard {
    pub fn from_config(cfg: &AppConfig) -> Self {
        let listen_ports: HashSet<u16> = cfg
            .listens
            .iter()
            .filter_map(|l| l.listen_port().ok())
            .collect();

        let mut local_ips = interface_ips();
        // Also include any explicit bind IPs from listen addrs (non-wildcard).
        for listener in &cfg.listens {
            if let Ok(addr) = listener.addr.parse::<SocketAddr>() {
                let ip = addr.ip();
                if !ip.is_unspecified() {
                    local_ips.insert(ip);
                }
            }
        }

        info!(
            local_ips = local_ips.len(),
            listen_ports = ?listen_ports.iter().copied().collect::<Vec<_>>(),
            "Self-loop guard armed (blocks proxying to local IPs on listen ports)"
        );
        for ip in &local_ips {
            debug!(%ip, "Self-loop guard local address");
        }

        Self {
            local_ips,
            listen_ports,
        }
    }

    /// Whether dialing `host:port` via upstream would hairpin onto our listeners.
    pub async fn would_loop(&self, host: &str, port: u16) -> bool {
        if !self.listen_ports.contains(&port) {
            return false;
        }

        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.is_local_ip(ip);
        }

        // Domain may point at this server; resolve locally with a short bound.
        match tokio::time::timeout(
            Duration::from_millis(500),
            tokio::net::lookup_host((host, port)),
        )
        .await
        {
            Ok(Ok(addrs)) => {
                for addr in addrs {
                    if self.is_local_ip(addr.ip()) {
                        warn!(
                            host,
                            port,
                            resolved = %addr.ip(),
                            "Destination resolves to a local listen address (self-loop)"
                        );
                        return true;
                    }
                }
                false
            }
            Ok(Err(e)) => {
                debug!(host, port, error = %e, "Self-loop DNS lookup failed; allowing");
                false
            }
            Err(_) => {
                debug!(host, port, "Self-loop DNS lookup timed out; allowing");
                false
            }
        }
    }

    fn is_local_ip(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || ip.is_unspecified() || self.local_ips.contains(&ip)
    }
}

/// Collect IPv4/IPv6 addresses assigned to local network interfaces.
fn interface_ips() -> HashSet<IpAddr> {
    let mut set = HashSet::new();
    set.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    set.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));

    #[cfg(unix)]
    {
        unsafe {
            let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifap) != 0 {
                warn!("getifaddrs failed; self-loop guard has only loopback addresses");
                return set;
            }
            let mut cursor = ifap;
            while !cursor.is_null() {
                let ifa = &*cursor;
                let addr = ifa.ifa_addr;
                if !addr.is_null() {
                    match (*addr).sa_family as i32 {
                        libc::AF_INET => {
                            let sin = &*(addr as *const libc::sockaddr_in);
                            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                            if !ip.is_unspecified() {
                                set.insert(IpAddr::V4(ip));
                            }
                        }
                        libc::AF_INET6 => {
                            let sin6 = &*(addr as *const libc::sockaddr_in6);
                            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                            if !ip.is_unspecified() {
                                set.insert(IpAddr::V6(ip));
                            }
                        }
                        _ => {}
                    }
                }
                cursor = ifa.ifa_next;
            }
            libc::freeifaddrs(ifap);
        }
    }

    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;

    fn guard_with(local: &[&str], ports: &[u16]) -> SelfLoopGuard {
        let mut local_ips = HashSet::new();
        for s in local {
            local_ips.insert(s.parse().unwrap());
        }
        local_ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
        SelfLoopGuard {
            local_ips,
            listen_ports: ports.iter().copied().collect(),
        }
    }

    #[test]
    fn blocks_own_public_ip_on_listen_port() {
        let g = guard_with(&["94.182.174.181", "94.182.174.171"], &[80, 443]);
        assert!(g.is_local_ip("94.182.174.181".parse().unwrap()));
        assert!(g.listen_ports.contains(&80));
    }

    #[test]
    fn allows_remote_ip_on_listen_port() {
        let g = guard_with(&["94.182.174.181"], &[80, 443]);
        assert!(!g.is_local_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn allows_own_ip_on_non_listen_port() {
        let g = guard_with(&["94.182.174.181"], &[80, 443]);
        // would_loop checks port membership first
        assert!(!g.listen_ports.contains(&22));
    }

    #[tokio::test]
    async fn would_loop_literal_local_ip() {
        let g = guard_with(&["94.182.174.181"], &[80, 443]);
        assert!(g.would_loop("94.182.174.181", 80).await);
        assert!(!g.would_loop("94.182.174.181", 22).await);
        assert!(!g.would_loop("8.8.8.8", 80).await);
        assert!(g.would_loop("127.0.0.1", 80).await);
    }

    #[test]
    fn from_config_collects_listen_ports() {
        let mut cfg: AppConfig = serde_yaml::from_str(
            r#"
listens:
  - addr: "0.0.0.0:80"
    proto: http
  - addr: "0.0.0.0:443"
    proto: tls
"#,
        )
        .unwrap();
        cfg.finalize().unwrap();
        let g = SelfLoopGuard::from_config(&cfg);
        assert!(g.listen_ports.contains(&80));
        assert!(g.listen_ports.contains(&443));
        assert!(g.is_local_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }
}
