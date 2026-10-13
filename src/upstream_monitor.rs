//! Periodic upstream health checks + Telegram alerts on transitions.
//!
//! Profiles that share the same SOCKS/HTTP endpoint are probed once per tick
//! (avoids duplicate load and flaky double-checks on the same port).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::config::{AppConfig, TelegramConfig, UpstreamMonitorConfig, UpstreamProxy};
use crate::proxy_connector::check_upstream;
use crate::telegram::{self, escape_html};
use crate::upstream_registry::SharedUpstreamRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Up,
    Down,
}

#[derive(Debug, Clone)]
pub(crate) struct ProfileState {
    health: Health,
    consecutive_fails: u32,
    consecutive_oks: u32,
    last_error: Option<String>,
    last_notify: Option<Instant>,
    down_since: Option<Instant>,
}

impl Default for ProfileState {
    fn default() -> Self {
        Self {
            health: Health::Up,
            consecutive_fails: 0,
            consecutive_oks: 0,
            last_error: None,
            last_notify: None,
            down_since: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    WentDown { error: String },
    Recovered { downtime: Duration },
    None,
}

/// One probe target: unique proxy endpoint + all profile names that use it.
#[derive(Debug, Clone)]
struct MonitorTarget {
    /// Stable key e.g. `socks5|127.0.0.1|10809`
    key: String,
    proxy: UpstreamProxy,
    profiles: Vec<String>,
}

/// Pure state update used by the monitor loop (unit-tested).
pub(crate) fn apply_probe_result(
    state: &mut ProfileState,
    ok: bool,
    error: Option<String>,
    fail_threshold: u32,
    recover_threshold: u32,
    now: Instant,
) -> Transition {
    if ok {
        state.consecutive_oks = state.consecutive_oks.saturating_add(1);
        state.consecutive_fails = 0;
        state.last_error = None;
        if state.health == Health::Down && state.consecutive_oks >= recover_threshold.max(1) {
            let downtime = state
                .down_since
                .map(|t| now.saturating_duration_since(t))
                .unwrap_or_default();
            state.health = Health::Up;
            state.down_since = None;
            state.consecutive_oks = 0;
            return Transition::Recovered { downtime };
        }
        Transition::None
    } else {
        state.consecutive_fails = state.consecutive_fails.saturating_add(1);
        state.consecutive_oks = 0;
        if let Some(e) = error {
            state.last_error = Some(e.clone());
        }
        if state.health == Health::Up && state.consecutive_fails >= fail_threshold.max(1) {
            state.health = Health::Down;
            state.down_since = Some(now);
            state.consecutive_fails = 0;
            return Transition::WentDown {
                error: state
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "unknown error".into()),
            };
        }
        Transition::None
    }
}

fn cooldown_ok(state: &ProfileState, cooldown: Duration, now: Instant) -> bool {
    match state.last_notify {
        None => true,
        Some(t) => now.saturating_duration_since(t) >= cooldown,
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

fn endpoint_key(proxy: &UpstreamProxy) -> String {
    match proxy {
        UpstreamProxy::Socks5 { host, port, .. } => format!("socks5|{host}|{port}"),
        UpstreamProxy::Http { host, port, .. } => format!("http|{host}|{port}"),
        UpstreamProxy::Direct => "direct".into(),
    }
}

fn profiles_label(names: &[String]) -> String {
    names.join(", ")
}

fn short_error(error: &str) -> String {
    // Keep Telegram readable: first line / trim nested context noise.
    let line = error.lines().next().unwrap_or(error).trim();
    const MAX: usize = 280;
    if line.chars().count() <= MAX {
        line.to_string()
    } else {
        let trimmed: String = line.chars().take(MAX).collect();
        format!("{trimmed}…")
    }
}

fn down_message(
    profiles: &[String],
    proxy: &UpstreamProxy,
    probe_label: &str,
    error: &str,
) -> String {
    format!(
        "🔴 <b>Upstream DOWN</b>\n\
         \n\
         📍 <b>Profiles</b>\n\
         <code>{profiles}</code>\n\
         \n\
         🔌 <b>Endpoint</b>\n\
         <code>{endpoint}</code>\n\
         \n\
         🎯 <b>Probe</b>\n\
         <code>{probe}</code>\n\
         \n\
         ⚠️ <b>Error</b>\n\
         <pre>{error}</pre>",
        profiles = escape_html(&profiles_label(profiles)),
        endpoint = escape_html(&proxy.to_string()),
        probe = escape_html(probe_label),
        error = escape_html(&short_error(error)),
    )
}

fn up_message(profiles: &[String], proxy: &UpstreamProxy, downtime: Duration) -> String {
    format!(
        "🟢 <b>Upstream RECOVERED</b>\n\
         \n\
         📍 <b>Profiles</b>\n\
         <code>{profiles}</code>\n\
         \n\
         🔌 <b>Endpoint</b>\n\
         <code>{endpoint}</code>\n\
         \n\
         ⏱ <b>Downtime</b>\n\
         <code>{downtime}</code>",
        profiles = escape_html(&profiles_label(profiles)),
        endpoint = escape_html(&proxy.to_string()),
        downtime = escape_html(&format_duration(downtime)),
    )
}

fn startup_message(mon: &UpstreamMonitorConfig, telegram: &TelegramConfig) -> String {
    format!(
        "✅ <b>SNIrelay monitor online</b>\n\
         \n\
         ⏱ interval <code>{interval}s</code> · timeout <code>{timeout}s</code>\n\
         📉 fail after <code>{fail}</code> · recover after <code>{recover}</code>\n\
         🎯 probe <code>{probe}</code>\n\
         🌐 api <code>{api}</code>",
        interval = mon.interval_secs.max(15),
        timeout = mon.timeout_secs.max(1),
        fail = mon.fail_threshold.max(1),
        recover = mon.recover_threshold.max(1),
        probe = escape_html(&mon.probe_targets_label()),
        api = escape_html(&telegram.api_base_url()),
    )
}

fn targets_to_check(
    registry: &SharedUpstreamRegistry,
    mon: &UpstreamMonitorConfig,
) -> Vec<MonitorTarget> {
    let reg = registry.read();
    let mut by_endpoint: HashMap<String, MonitorTarget> = HashMap::new();

    let wanted: Vec<(String, UpstreamProxy)> = if mon.profiles.is_empty() {
        reg.profiles()
            .iter()
            .filter(|(_, p)| !matches!(p, UpstreamProxy::Direct))
            .map(|(n, p)| (n.clone(), p.clone()))
            .collect()
    } else {
        let mut out = Vec::new();
        for name in &mon.profiles {
            if let Some(proxy) = reg.profiles().get(name) {
                if matches!(proxy, UpstreamProxy::Direct) {
                    continue;
                }
                out.push((name.clone(), proxy.clone()));
            } else {
                warn!(profile = %name, "monitor: profile not in registry (skipped)");
            }
        }
        out
    };

    for (name, proxy) in wanted {
        let key = endpoint_key(&proxy);
        by_endpoint
            .entry(key.clone())
            .and_modify(|t| {
                if !t.profiles.contains(&name) {
                    t.profiles.push(name.clone());
                }
            })
            .or_insert_with(|| MonitorTarget {
                key,
                proxy,
                profiles: vec![name],
            });
    }

    let mut out: Vec<MonitorTarget> = by_endpoint.into_values().collect();
    for t in &mut out {
        t.profiles.sort();
    }
    out.sort_by(|a, b| a.profiles[0].cmp(&b.profiles[0]));
    out
}

/// Spawn background monitor. No-op when disabled.
pub fn start(cfg: Arc<AppConfig>, registry: SharedUpstreamRegistry) {
    let mon = cfg.upstream_monitor.clone();
    if !mon.enabled {
        info!("Upstream monitor disabled");
        return;
    }

    let interval = Duration::from_secs(mon.interval_secs.max(15));
    let timeout = Duration::from_secs(mon.timeout_secs.max(1));
    let telegram = cfg.telegram.clone();

    if !telegram.is_configured() {
        warn!(
            "Upstream monitor enabled but Telegram is not configured \
             (set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID); transitions will only be logged"
        );
    }

    info!(
        interval_secs = interval.as_secs(),
        timeout_secs = timeout.as_secs(),
        fail_threshold = mon.fail_threshold,
        recover_threshold = mon.recover_threshold,
        probe = %mon.probe_targets_label(),
        api_base = %telegram.api_base_url(),
        telegram_configured = telegram.is_configured(),
        "Upstream monitor starting (e2e tunnel probe)"
    );

    tokio::spawn(async move {
        if telegram.is_configured() {
            telegram::notify(&telegram, &startup_message(&mon, &telegram)).await;
        }
        run_loop(mon, telegram, registry, interval, timeout).await;
    });
}

async fn run_loop(
    mon: UpstreamMonitorConfig,
    telegram: TelegramConfig,
    registry: SharedUpstreamRegistry,
    interval: Duration,
    timeout: Duration,
) {
    let mut states: HashMap<String, ProfileState> = HashMap::new();
    let cooldown = Duration::from_secs(mon.notify_cooldown_secs);
    // Stagger first round slightly so startup probes settle.
    tokio::time::sleep(Duration::from_secs(5)).await;

    loop {
        let targets = targets_to_check(&registry, &mon);
        if targets.is_empty() {
            warn!("upstream monitor: no profiles to check (only direct, or empty upstreams)");
        } else {
            info!(
                endpoints = targets.len(),
                profiles = targets.iter().map(|t| t.profiles.len()).sum::<usize>(),
                "upstream monitor tick"
            );
        }

        let probes = mon.probe_targets();
        let probe_label = mon.probe_targets_label();
        let mut summary: Vec<String> = Vec::with_capacity(targets.len());
        for target in targets {
            let label = profiles_label(&target.profiles);
            let started = Instant::now();
            let result = check_upstream(&target.proxy, timeout, &probes).await;
            let elapsed_ms = started.elapsed().as_millis();
            let now = Instant::now();
            let state = states.entry(target.key.clone()).or_default();
            let (ok, err) = match result {
                Ok(()) => (true, None),
                Err(e) => (false, Some(format!("{e:#}"))),
            };
            summary.push(if ok {
                format!("{label}=ok({elapsed_ms}ms)")
            } else {
                format!("{label}=FAIL({elapsed_ms}ms)")
            });

            let transition = apply_probe_result(
                state,
                ok,
                err.clone(),
                mon.fail_threshold,
                mon.recover_threshold,
                now,
            );

            match transition {
                Transition::WentDown { error } => {
                    warn!(
                        profiles = %label,
                        proxy = %target.proxy,
                        %error,
                        "upstream monitor: DOWN"
                    );
                    if cooldown_ok(state, cooldown, now) {
                        let msg = down_message(
                            &target.profiles,
                            &target.proxy,
                            &probe_label,
                            &error,
                        );
                        telegram::notify(&telegram, &msg).await;
                        state.last_notify = Some(now);
                    } else {
                        info!(
                            profiles = %label,
                            "upstream monitor: DOWN notify skipped (cooldown)"
                        );
                    }
                }
                Transition::Recovered { downtime } => {
                    info!(
                        profiles = %label,
                        proxy = %target.proxy,
                        downtime = %format_duration(downtime),
                        "upstream monitor: RECOVERED"
                    );
                    if mon.notify_recovery && cooldown_ok(state, cooldown, now) {
                        let msg = up_message(&target.profiles, &target.proxy, downtime);
                        telegram::notify(&telegram, &msg).await;
                        state.last_notify = Some(now);
                    }
                }
                Transition::None => {
                    if ok {
                        debug!(
                            profiles = %label,
                            elapsed_ms,
                            "upstream monitor: ok"
                        );
                    } else {
                        info!(
                            profiles = %label,
                            proxy = %target.proxy,
                            elapsed_ms,
                            fails = state.consecutive_fails,
                            threshold = mon.fail_threshold,
                            error = err.as_deref().unwrap_or("?"),
                            "upstream monitor: probe failed (waiting for threshold)"
                        );
                    }
                }
            }

            // Small gap between endpoints to avoid burst.
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        if !summary.is_empty() {
            info!(results = %summary.join(" · "), "upstream monitor results");
        }

        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_fail_threshold_before_down() {
        let mut s = ProfileState::default();
        let now = Instant::now();
        assert_eq!(
            apply_probe_result(&mut s, false, Some("e1".into()), 3, 2, now),
            Transition::None
        );
        assert_eq!(s.health, Health::Up);
        assert_eq!(
            apply_probe_result(&mut s, false, Some("e2".into()), 3, 2, now),
            Transition::None
        );
        match apply_probe_result(&mut s, false, Some("e3".into()), 3, 2, now) {
            Transition::WentDown { error } => assert_eq!(error, "e3"),
            other => panic!("expected WentDown, got {other:?}"),
        }
        assert_eq!(s.health, Health::Down);
    }

    #[test]
    fn needs_recover_threshold_before_up() {
        let mut s = ProfileState {
            health: Health::Down,
            down_since: Some(Instant::now() - Duration::from_secs(30)),
            ..Default::default()
        };
        let now = Instant::now();
        assert_eq!(
            apply_probe_result(&mut s, true, None, 3, 2, now),
            Transition::None
        );
        match apply_probe_result(&mut s, true, None, 3, 2, now) {
            Transition::Recovered { downtime } => assert!(downtime.as_secs() >= 30),
            other => panic!("expected Recovered, got {other:?}"),
        }
        assert_eq!(s.health, Health::Up);
    }

    #[test]
    fn success_resets_fail_streak() {
        let mut s = ProfileState::default();
        let now = Instant::now();
        apply_probe_result(&mut s, false, Some("x".into()), 3, 2, now);
        apply_probe_result(&mut s, false, Some("x".into()), 3, 2, now);
        assert_eq!(s.consecutive_fails, 2);
        apply_probe_result(&mut s, true, None, 3, 2, now);
        assert_eq!(s.consecutive_fails, 0);
        assert_eq!(s.health, Health::Up);
    }

    #[test]
    fn escape_html_basic() {
        assert_eq!(escape_html("a<b>&c"), "a&lt;b&gt;&amp;c");
    }
}
