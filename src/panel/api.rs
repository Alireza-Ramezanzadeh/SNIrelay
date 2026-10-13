//! REST API for the admin panel.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use chrono::{Duration as ChronoDuration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::db::render_dnsmasq;
use super::dnsmasq_store::{self, DnsDomain, DnsmasqPaths};
use super::{hash_password, session_token_from_headers, verify_password, PanelState};
use crate::client_acl::{require_username, ClientAcl};
use crate::config::WhitelistEntry;
use crate::config::UpstreamProxy;
use crate::hosts::{compile_hosts_table, HostsEntry};
use crate::metrics;
use crate::upstream_registry::UpstreamRegistry;
use crate::ufw;
use std::collections::HashMap;

fn new_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn dnsmasq_paths(state: &PanelState) -> Option<DnsmasqPaths> {
    DnsmasqPaths::from_panel(&state.cfg.panel)
}

fn save_dnsmasq(state: &PanelState, domains: &[DnsDomain]) -> Result<serde_json::Value, String> {
    let paths = dnsmasq_paths(state).ok_or_else(|| {
        "dnsmasq conf dir not available (set DNSMASQ_CONF_DIR=/etc/dnsmasq.d)".to_string()
    })?;
    dnsmasq_store::save_domains(&paths, domains).map_err(|e| e.to_string())?;
    let reload_ok = dnsmasq_store::reload(&paths).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "ok": true,
        "source": "dnsmasq",
        "relay_file": paths.relay_file.display().to_string(),
        "bypass_file": paths.bypass_file.display().to_string(),
        "relay_ip": paths.relay_ip,
        "reload_ok": reload_ok,
        "count": domains.len(),
    }))
}

pub fn api_router() -> Router<PanelState> {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/me", get(me))
        .route("/api/auth/password", post(change_password))
        .route("/api/stats", get(stats))
        .route("/api/traffic/ips", get(traffic_ips))
        .route("/api/traffic/ips/{ip}", get(traffic_ip_detail))
        .route("/api/traffic/daily", get(traffic_daily))
        .route("/api/domains", get(list_domains).post(create_domain).put(replace_domains))
        .route("/api/domains/import", post(import_domains))
        .route(
            "/api/domains/{pattern}",
            put(update_domain).delete(delete_domain),
        )
        .route("/api/dnsmasq/export", get(dnsmasq_export))
        .route("/api/dnsmasq/apply", post(dnsmasq_apply))
        .route("/api/dnsmasq/reload", post(dnsmasq_reload))
        .route("/api/dns/queries", get(list_dns_queries).delete(clear_dns_queries))
        .route("/api/dns/queries/top", get(dns_queries_top))
        .route("/api/config/summary", get(config_summary))
        .route("/api/hosts", get(get_hosts).put(put_hosts))
        .route("/api/upstreams", get(get_upstreams).put(put_upstreams))
        .route("/api/upstreams/client", post(add_client_upstream))
        .route(
            "/api/upstreams/client/{ip}",
            delete(delete_client_upstream),
        )
        .route("/api/whitelist", get(get_whitelist).put(put_whitelist))
        .route("/api/whitelist/{ip}", delete(delete_whitelist_ip))
        .route("/api/whitelist/add", post(add_whitelist_ip))
}

fn unauthorized() -> impl IntoResponse {
    (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"unauthorized"})))
}

async fn require_auth(state: &PanelState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let Some(token) = session_token_from_headers(headers) else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    match state.db.session_valid(&token) {
        Ok(true) => Ok(()),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"ok": true, "service": "snirelay-panel"}))
}

#[derive(Deserialize)]
struct LoginReq {
    password: String,
}

async fn login(State(state): State<PanelState>, Json(body): Json<LoginReq>) -> impl IntoResponse {
    let hash = match state.db.get_setting("admin_password_hash") {
        Ok(Some(h)) => h,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error":"password not configured"})),
            )
                .into_response();
        }
    };
    if !verify_password(&body.password, &hash) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error":"invalid password"})),
        )
            .into_response();
    }
    let token = new_session_token();
    if let Err(e) = state.db.create_session(&token, 24 * 7) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }
    let cookie = format!(
        "snirelay_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        7 * 24 * 3600
    );
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({"ok": true})),
    )
        .into_response()
}

async fn logout(State(state): State<PanelState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(token) = session_token_from_headers(&headers) {
        let _ = state.db.delete_session(&token);
    }
    let cookie = "snirelay_session=; Path=/; HttpOnly; Max-Age=0";
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({"ok": true})),
    )
}

async fn me(State(state): State<PanelState>, headers: HeaderMap) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    Json(serde_json::json!({"ok": true, "user": "admin"})).into_response()
}

#[derive(Deserialize)]
struct PasswordReq {
    current: String,
    new_password: String,
}

async fn change_password(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Json(body): Json<PasswordReq>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    if body.new_password.len() < 6 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":"password too short"})),
        )
            .into_response();
    }
    let hash = state
        .db
        .get_setting("admin_password_hash")
        .ok()
        .flatten()
        .unwrap_or_default();
    if !verify_password(&body.current, &hash) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error":"current password incorrect"})),
        )
            .into_response();
    }
    match hash_password(&body.new_password) {
        Ok(h) => {
            let _ = state.db.set_setting("admin_password_hash", &h);
            Json(serde_json::json!({"ok": true})).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn stats(State(state): State<PanelState>, headers: HeaderMap) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    Json(serde_json::json!({
        "active_connections": metrics::ACTIVE_CONNECTIONS.get(),
        "total_connections": metrics::TOTAL_CONNECTIONS.get(),
        "bytes_proxied": metrics::BYTES_PROXIED.get(),
        "connection_errors": metrics::CONNECTION_ERRORS.get(),
        "upstream_ok": state.upstream_ok.load(std::sync::atomic::Ordering::Relaxed),
        "upstream": state.cfg.upstream_proxy.to_string(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct RangeQuery {
    #[serde(default = "default_range")]
    range: String,
    from: Option<String>,
    to: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_range() -> String {
    "7d".into()
}
fn default_limit() -> i64 {
    100
}

fn resolve_range(q: &RangeQuery) -> (String, String) {
    let today = Utc::now().date_naive();
    if let (Some(f), Some(t)) = (&q.from, &q.to) {
        return (f.clone(), t.clone());
    }
    let days = match q.range.as_str() {
        "1d" | "today" => 0,
        "30d" => 29,
        _ => 6,
    };
    let from = (today - ChronoDuration::days(days)).format("%Y-%m-%d").to_string();
    let to = today.format("%Y-%m-%d").to_string();
    (from, to)
}

async fn traffic_ips(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Query(q): Query<RangeQuery>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let (from, to) = resolve_range(&q);
    match state.db.traffic_by_ip(&from, &to, q.limit.max(1).min(1000)) {
        Ok(rows) => Json(serde_json::json!({"from": from, "to": to, "items": rows})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn traffic_ip_detail(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Path(ip): Path<String>,
    Query(q): Query<RangeQuery>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let (from, to) = resolve_range(&q);
    match state
        .db
        .traffic_for_ip_domains(&ip, &from, &to, q.limit.max(1).min(500))
    {
        Ok(rows) => Json(serde_json::json!({
            "client_ip": ip, "from": from, "to": to, "domains": rows
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn traffic_daily(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Query(q): Query<RangeQuery>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let (from, to) = resolve_range(&q);
    match state.db.daily_totals(&from, &to) {
        Ok(rows) => Json(serde_json::json!({"from": from, "to": to, "items": rows})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn list_domains(State(state): State<PanelState>, headers: HeaderMap) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    if let Some(paths) = dnsmasq_paths(&state) {
        return match dnsmasq_store::load_domains(&paths) {
            Ok(items) => Json(serde_json::json!({
                "source": "dnsmasq",
                "relay_ip": paths.relay_ip,
                "relay_file": paths.relay_file.display().to_string(),
                "bypass_file": paths.bypass_file.display().to_string(),
                "conf_dir": paths.conf_dir.display().to_string(),
                "items": items,
            }))
            .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response(),
        };
    }
    let configured = state.cfg.panel.dnsmasq_conf_dir.clone();
    let hint = match configured.as_deref() {
        Some(p) if !p.is_empty() => format!(
            "Configured dnsmasq_conf_dir={p} but it is missing inside the container. \
             Mount host path: -v /etc/dnsmasq.d:/etc/dnsmasq.d"
        ),
        _ => "Set panel.dnsmasq_conf_dir: \"/etc/dnsmasq.d\" in snirelay.yaml \
              (or DNSMASQ_CONF_DIR=/etc/dnsmasq.d) and mount /etc/dnsmasq.d into the container."
            .into(),
    };
    match state.db.list_domains() {
        Ok(items) => Json(serde_json::json!({
            "source": "sqlite",
            "items": items,
            "dnsmasq_hint": hint,
            "dnsmasq_conf_dir": configured,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct DomainReq {
    pattern: String,
    #[serde(default = "exact_kind")]
    kind: String,
    #[serde(default = "relay_mode")]
    mode: String,
    #[serde(default)]
    note: String,
}
fn exact_kind() -> String {
    "exact".into()
}
fn relay_mode() -> String {
    "relay".into()
}

fn normalize_mode(mode: &str) -> String {
    match mode {
        "bypass" | "direct" => "bypass".into(),
        _ => "relay".into(),
    }
}

async fn create_domain(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Json(body): Json<DomainReq>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let mode = normalize_mode(&body.mode);
    if let Some(paths) = dnsmasq_paths(&state) {
        let mut items = match dnsmasq_store::load_domains(&paths) {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        };
        let pattern = body.pattern.trim().to_lowercase();
        if pattern.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "empty pattern"})),
            )
                .into_response();
        }
        items.retain(|d| !(d.pattern == pattern && d.mode == mode));
        items.push(DnsDomain {
            pattern,
            mode,
            source: String::new(),
        });
        return match save_dnsmasq(&state, &items) {
            Ok(v) => Json(v).into_response(),
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e})),
            )
                .into_response(),
        };
    }
    match state
        .db
        .add_domain(&body.pattern, &body.kind, &mode, &body.note)
    {
        Ok(id) => Json(serde_json::json!({"ok": true, "id": id})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct ReplaceReq {
    items: Vec<DnsDomain>,
}

async fn replace_domains(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Json(body): Json<ReplaceReq>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    if dnsmasq_paths(&state).is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "bulk replace requires DNSMASQ_CONF_DIR"
            })),
        )
            .into_response();
    }
    match save_dnsmasq(&state, &body.items) {
        Ok(v) => Json(v).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

async fn update_domain(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Path(pattern): Path<String>,
    Json(body): Json<DomainReq>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let mode = normalize_mode(&body.mode);
    if let Some(paths) = dnsmasq_paths(&state) {
        let mut items = match dnsmasq_store::load_domains(&paths) {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        };
        let old = pattern.to_lowercase();
        let new_pat = body.pattern.trim().to_lowercase();
        let before = items.len();
        items.retain(|d| d.pattern != old);
        if items.len() == before {
            // also try matching any mode
        }
        if new_pat.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "empty pattern"})),
            )
                .into_response();
        }
        items.retain(|d| !(d.pattern == new_pat && d.mode == mode));
        items.push(DnsDomain {
            pattern: new_pat,
            mode,
            source: String::new(),
        });
        return match save_dnsmasq(&state, &items) {
            Ok(v) => Json(v).into_response(),
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e})),
            )
                .into_response(),
        };
    }
    // sqlite path: pattern is numeric id
    let Ok(id) = pattern.parse::<i64>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid id"})),
        )
            .into_response();
    };
    match state
        .db
        .update_domain(id, &body.pattern, &body.kind, &mode, &body.note)
    {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct DeleteQuery {
    #[serde(default = "relay_mode")]
    mode: String,
}

async fn delete_domain(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Path(pattern): Path<String>,
    Query(q): Query<DeleteQuery>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let mode = normalize_mode(&q.mode);
    if let Some(paths) = dnsmasq_paths(&state) {
        let mut items = match dnsmasq_store::load_domains(&paths) {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        };
        let pat = pattern.to_lowercase();
        let before = items.len();
        items.retain(|d| !(d.pattern == pat && d.mode == mode));
        if items.len() == before {
            items.retain(|d| d.pattern != pat);
        }
        return match save_dnsmasq(&state, &items) {
            Ok(v) => Json(v).into_response(),
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e})),
            )
                .into_response(),
        };
    }
    let Ok(id) = pattern.parse::<i64>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid id"})),
        )
            .into_response();
    };
    match state.db.delete_domain(id) {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct ImportReq {
    text: String,
    #[serde(default = "relay_mode")]
    mode: String,
}

async fn import_domains(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Json(body): Json<ImportReq>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let mode = normalize_mode(&body.mode);
    if let Some(paths) = dnsmasq_paths(&state) {
        let mut items = match dnsmasq_store::load_domains(&paths) {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        };
        let mut n = 0usize;
        for raw in body.text.lines() {
            let line = raw.trim().to_lowercase();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // accept raw dnsmasq lines or bare domains
            let (pat, line_mode) = if let Some((p, _)) = line
                .strip_prefix("address=/")
                .and_then(|r| r.rsplit_once('/').map(|(d, ip)| (d, ip)))
            {
                (p.to_string(), "relay".to_string())
            } else if let Some(p) = line
                .strip_prefix("server=/")
                .and_then(|r| r.strip_suffix("/#"))
            {
                (p.to_string(), "bypass".to_string())
            } else if let Some(rest) = line.strip_prefix("*.") {
                (rest.to_string(), mode.clone())
            } else {
                (line, mode.clone())
            };
            if pat.is_empty() {
                continue;
            }
            items.retain(|d| !(d.pattern == pat && d.mode == line_mode));
            items.push(DnsDomain {
                pattern: pat,
                mode: line_mode,
                source: String::new(),
            });
            n += 1;
        }
        return match save_dnsmasq(&state, &items) {
            Ok(mut v) => {
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("imported".into(), serde_json::json!(n));
                }
                Json(v).into_response()
            }
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e})),
            )
                .into_response(),
        };
    }
    match state.db.import_domains(&body.text, &mode) {
        Ok(n) => Json(serde_json::json!({"ok": true, "imported": n})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn dnsmasq_export(State(state): State<PanelState>, headers: HeaderMap) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    if let Some(paths) = dnsmasq_paths(&state) {
        return match dnsmasq_store::load_domains(&paths) {
            Ok(items) => {
                let mut relay = String::new();
                let mut bypass = String::new();
                for d in &items {
                    if d.mode == "bypass" {
                        bypass.push_str(&format!("server=/{}/#\n", d.pattern));
                    } else {
                        relay.push_str(&format!("address=/{}/{}\n", d.pattern, paths.relay_ip));
                    }
                }
                Json(serde_json::json!({
                    "relay_ip": paths.relay_ip,
                    "relay_file": paths.relay_file.display().to_string(),
                    "bypass_file": paths.bypass_file.display().to_string(),
                    "content": format!("# relay\n{relay}\n# bypass\n{bypass}"),
                    "relay": relay,
                    "bypass": bypass,
                }))
                .into_response()
            }
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response(),
        };
    }
    let relay_ip = match state
        .cfg
        .panel
        .relay_ip
        .clone()
        .filter(|s| !s.is_empty())
    {
        Some(ip) => ip,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "relay_ip not configured"})),
            )
                .into_response();
        }
    };
    match state.db.relay_domains_for_dnsmasq() {
        Ok(domains) => Json(serde_json::json!({
            "relay_ip": relay_ip,
            "content": render_dnsmasq(&domains, &relay_ip),
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn dnsmasq_apply(State(state): State<PanelState>, headers: HeaderMap) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    // Re-save current on-disk list (normalize + reload)
    if let Some(paths) = dnsmasq_paths(&state) {
        return match dnsmasq_store::load_domains(&paths) {
            Ok(items) => match save_dnsmasq(&state, &items) {
                Ok(v) => Json(v).into_response(),
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": e})),
                )
                    .into_response(),
            },
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response(),
        };
    }
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": "configure DNSMASQ_CONF_DIR to apply to live dnsmasq files"
        })),
    )
        .into_response()
}

async fn dnsmasq_reload(State(state): State<PanelState>, headers: HeaderMap) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let Some(paths) = dnsmasq_paths(&state) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "dnsmasq not configured"})),
        )
            .into_response();
    };
    match dnsmasq_store::reload(&paths) {
        Ok(reload_ok) => Json(serde_json::json!({"ok": true, "reload_ok": reload_ok})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct DnsQueriesQuery {
    #[serde(default = "default_dns_limit")]
    limit: i64,
    domain: Option<String>,
    client: Option<String>,
    action: Option<String>,
}

fn default_dns_limit() -> i64 {
    200
}

async fn list_dns_queries(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Query(q): Query<DnsQueriesQuery>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let enabled = state
        .cfg
        .panel
        .dnsmasq_query_log
        .as_ref()
        .map(|p| !p.is_empty())
        .unwrap_or(false);
    match state.db.list_dns_queries(
        q.limit,
        q.domain.as_deref(),
        q.client.as_deref(),
        q.action.as_deref(),
    ) {
        Ok(items) => {
            let total = state.db.dns_queries_count().unwrap_or(items.len() as i64);
            Json(serde_json::json!({
                "enabled": enabled,
                "log_path": state.cfg.panel.dnsmasq_query_log,
                "retain_hours": state.cfg.panel.dns_query_retain_hours,
                "total": total,
                "items": items,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn dns_queries_top(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Query(q): Query<DnsQueriesQuery>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    match state.db.dns_query_top_domains(q.limit.max(1).min(100)) {
        Ok(rows) => {
            let items: Vec<_> = rows
                .into_iter()
                .map(|(domain, count)| serde_json::json!({"domain": domain, "count": count}))
                .collect();
            Json(serde_json::json!({"items": items})).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn clear_dns_queries(
    State(state): State<PanelState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    match state.db.clear_dns_queries() {
        Ok(n) => Json(serde_json::json!({"ok": true, "deleted": n})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn config_summary(State(state): State<PanelState>, headers: HeaderMap) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let listens: Vec<_> = state
        .cfg
        .listens
        .iter()
        .map(|l| {
            serde_json::json!({
                "name": l.label(),
                "addr": l.addr,
                "proto": l.proto_str()
            })
        })
        .collect();
    let reg = state.upstream_registry.read();
    let upstream_profiles: serde_json::Map<String, serde_json::Value> = reg
        .profiles()
        .iter()
        .map(|(k, v)| (k.clone(), proxy_public_json(v)))
        .collect();
    Json(serde_json::json!({
        "upstream": state.cfg.upstream_proxy.to_string(),
        "default_upstream": reg.default_name(),
        "upstream_failover": reg.failover_enabled(),
        "upstreams": upstream_profiles,
        "client_upstreams": reg.client_upstreams().clone(),
        "listens": listens,
        "hosts": state.hosts_entries.read().clone(),
        "panel": {
            "addr": state.cfg.panel.addr,
            "db_path": state.cfg.panel.db_path,
            "relay_ip": state.cfg.panel.relay_ip,
            "dnsmasq_conf_dir": state.cfg.panel.dnsmasq_conf_dir,
            "dnsmasq_relay_file": state.cfg.panel.dnsmasq_relay_file,
            "dnsmasq_bypass_file": state.cfg.panel.dnsmasq_bypass_file,
            "dnsmasq_conf_path": state.cfg.panel.dnsmasq_conf_path,
            "dnsmasq_query_log": state.cfg.panel.dnsmasq_query_log,
            "dns_query_retain_hours": state.cfg.panel.dns_query_retain_hours,
            "dns_queries_count": state.db.dns_queries_count().unwrap_or(0),
            "dnsmasq_reload_cmd": state.cfg.panel.dnsmasq_reload_cmd,
            "dnsmasq_live": dnsmasq_paths(&state).map(|p| serde_json::json!({
                "conf_dir": p.conf_dir.display().to_string(),
                "relay_file": p.relay_file.display().to_string(),
                "bypass_file": p.bypass_file.display().to_string(),
                "relay_ip": p.relay_ip,
            })),
        },
        "config_path": state.config_path.display().to_string(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
    .into_response()
}

#[derive(Serialize, Deserialize)]
struct HostsPayload {
    hosts: Vec<HostsEntry>,
}

async fn get_hosts(State(state): State<PanelState>, headers: HeaderMap) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    Json(serde_json::json!({"hosts": state.hosts_entries.read().clone()})).into_response()
}

async fn put_hosts(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Json(body): Json<HostsPayload>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let compiled = match compile_hosts_table(&body.hosts) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    // Hot-reload in-memory table
    *state.hosts_live.write() = compiled;
    *state.hosts_entries.write() = body.hosts.clone();

    // Persist into YAML if possible (best-effort merge of hosts key)
    let persist_msg = match persist_hosts_yaml(&state.config_path, &body.hosts) {
        Ok(()) => "saved".to_string(),
        Err(e) => format!("hot-reloaded; YAML save failed: {e}"),
    };

    Json(serde_json::json!({
        "ok": true,
        "persist": persist_msg,
        "note": "hosts table hot-reloaded for new connections"
    }))
    .into_response()
}

fn persist_hosts_yaml(path: &std::path::Path, hosts: &[HostsEntry]) -> anyhow::Result<()> {
    use anyhow::Context;
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(&content).context("parse yaml")?;
    let hosts_val = serde_yaml::to_value(hosts).context("serialize hosts")?;
    if let serde_yaml::Value::Mapping(ref mut map) = value {
        map.insert(serde_yaml::Value::String("hosts".into()), hosts_val);
    } else {
        anyhow::bail!("config root is not a mapping");
    }
    let out = serde_yaml::to_string(&value)?;
    std::fs::write(path, out).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn proxy_public_json(proxy: &UpstreamProxy) -> serde_json::Value {
    match proxy {
        UpstreamProxy::Socks5 {
            host,
            port,
            username,
            password,
        } => serde_json::json!({
            "type": "socks5",
            "host": host,
            "port": port,
            "username": username,
            "has_password": password.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
        }),
        UpstreamProxy::Http { host, port, auth } => serde_json::json!({
            "type": "http",
            "host": host,
            "port": port,
            "has_auth": auth.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
        }),
        UpstreamProxy::Direct => serde_json::json!({ "type": "direct" }),
    }
}

#[derive(Deserialize)]
struct UpstreamsPayload {
    upstreams: HashMap<String, UpstreamProxy>,
    default_upstream: String,
    #[serde(default)]
    client_upstreams: HashMap<String, String>,
    #[serde(default)]
    upstream_failover: bool,
}

async fn get_upstreams(State(state): State<PanelState>, headers: HeaderMap) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let reg = state.upstream_registry.read();
    let profiles: serde_json::Map<String, serde_json::Value> = reg
        .profiles()
        .iter()
        .map(|(k, v)| (k.clone(), proxy_public_json(v)))
        .collect();
    Json(serde_json::json!({
        "upstreams": profiles,
        "default_upstream": reg.default_name(),
        "client_upstreams": reg.client_upstreams().clone(),
        "upstream_failover": reg.failover_enabled(),
    }))
    .into_response()
}

async fn put_upstreams(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Json(body): Json<UpstreamsPayload>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }

    // Preserve secrets when the client omits password/auth (UI send without secrets).
    let mut profiles = body.upstreams;
    {
        let current = state.upstream_registry.read();
        for (name, proxy) in profiles.iter_mut() {
            if let Some(old) = current.profiles().get(name) {
                merge_proxy_secrets(proxy, old);
            }
        }
    }

    let registry = match UpstreamRegistry::from_parts(
        profiles,
        body.default_upstream.clone(),
        body.client_upstreams.clone(),
        body.upstream_failover,
    ) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    *state.upstream_registry.write() = registry.clone();

    let persist_msg = match persist_upstreams_yaml(&state.config_path, &registry) {
        Ok(()) => "saved".to_string(),
        Err(e) => format!("hot-reloaded; YAML save failed: {e}"),
    };

    Json(serde_json::json!({
        "ok": true,
        "persist": persist_msg,
        "default_upstream": registry.default_name(),
        "upstream_failover": registry.failover_enabled(),
        "profiles": registry.profiles().len(),
        "client_routes": registry.client_upstreams().len(),
        "client_upstreams": registry.client_upstreams().clone(),
        "note": "upstream routing hot-reloaded for new connections"
    }))
    .into_response()
}

#[derive(Deserialize)]
struct ClientUpstreamBody {
    ip: String,
    profile: String,
}

async fn add_client_upstream(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Json(body): Json<ClientUpstreamBody>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let mut reg = state.upstream_registry.read().clone();
    if let Err(e) = reg.set_client_upstream(&body.ip, body.profile.trim()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }
    *state.upstream_registry.write() = reg.clone();
    let persist_msg = match persist_upstreams_yaml(&state.config_path, &reg) {
        Ok(()) => "saved".to_string(),
        Err(e) => format!("hot-reloaded; YAML save failed: {e}"),
    };
    Json(serde_json::json!({
        "ok": true,
        "persist": persist_msg,
        "ip": crate::config::normalize_client_ip(&body.ip).unwrap_or(body.ip),
        "profile": body.profile.trim(),
        "client_upstreams": reg.client_upstreams().clone(),
        "default_upstream": reg.default_name(),
    }))
    .into_response()
}

async fn delete_client_upstream(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let mut reg = state.upstream_registry.read().clone();
    let removed = match reg.remove_client_upstream(&ip) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    *state.upstream_registry.write() = reg.clone();
    let persist_msg = match persist_upstreams_yaml(&state.config_path, &reg) {
        Ok(()) => "saved".to_string(),
        Err(e) => format!("hot-reloaded; YAML save failed: {e}"),
    };
    Json(serde_json::json!({
        "ok": true,
        "removed": removed,
        "persist": persist_msg,
        "client_upstreams": reg.client_upstreams().clone(),
        "default_upstream": reg.default_name(),
    }))
    .into_response()
}

fn merge_proxy_secrets(new: &mut UpstreamProxy, old: &UpstreamProxy) {
    match (new, old) {
        (
            UpstreamProxy::Socks5 {
                password: new_pw, ..
            },
            UpstreamProxy::Socks5 {
                password: old_pw, ..
            },
        ) => {
            if new_pw.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                *new_pw = old_pw.clone();
            }
        }
        (
            UpstreamProxy::Http { auth: new_auth, .. },
            UpstreamProxy::Http { auth: old_auth, .. },
        ) => {
            if new_auth.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                *new_auth = old_auth.clone();
            }
        }
        _ => {}
    }
}

fn persist_upstreams_yaml(
    path: &std::path::Path,
    registry: &UpstreamRegistry,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(&content).context("parse yaml")?;
    let upstreams_val = serde_yaml::to_value(registry.profiles()).context("serialize upstreams")?;
    let default_val = serde_yaml::Value::String(registry.default_name().to_string());
    // Force string keys so IPs like 94.183.122.121 are never written/parsed as floats.
    let mut clients_map = serde_yaml::Mapping::new();
    for (ip, profile) in registry.client_upstreams() {
        clients_map.insert(
            serde_yaml::Value::String(ip.clone()),
            serde_yaml::Value::String(profile.clone()),
        );
    }
    let clients_val = serde_yaml::Value::Mapping(clients_map);
    let failover_val = serde_yaml::Value::Bool(registry.failover_enabled());
    let default_proxy = registry
        .default_proxy()
        .map(|p| p.clone())
        .unwrap_or(UpstreamProxy::Direct);
    let upstream_proxy_val =
        serde_yaml::to_value(&default_proxy).context("serialize upstream_proxy")?;

    if let serde_yaml::Value::Mapping(ref mut map) = value {
        map.insert(
            serde_yaml::Value::String("upstreams".into()),
            upstreams_val,
        );
        map.insert(
            serde_yaml::Value::String("default_upstream".into()),
            default_val,
        );
        map.insert(
            serde_yaml::Value::String("client_upstreams".into()),
            clients_val,
        );
        map.insert(
            serde_yaml::Value::String("upstream_failover".into()),
            failover_val,
        );
        // Keep legacy single-upstream key in sync with default profile.
        map.insert(
            serde_yaml::Value::String("upstream_proxy".into()),
            upstream_proxy_val,
        );
    } else {
        anyhow::bail!("config root is not a mapping");
    }
    let out = serde_yaml::to_string(&value)?;
    std::fs::write(path, out).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[derive(Deserialize)]
struct WhitelistEntryBody {
    ip: String,
    #[serde(default)]
    username: Option<String>,
}

#[derive(Deserialize)]
struct WhitelistPayload {
    /// Legacy: IP-only list (no usernames).
    #[serde(default)]
    ips: Vec<String>,
    /// Preferred: IP + username rows.
    #[serde(default)]
    entries: Vec<WhitelistEntryBody>,
    #[serde(default)]
    ufw_sync: Option<bool>,
}

#[derive(Deserialize)]
struct WhitelistIpBody {
    ip: String,
    username: String,
}

fn whitelist_entries_json(acl: &ClientAcl) -> Vec<serde_json::Value> {
    acl.as_entries()
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "ip": e.ip,
                "username": e.username.unwrap_or_default(),
            })
        })
        .collect()
}

async fn get_whitelist(State(state): State<PanelState>, headers: HeaderMap) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let acl = state.client_acl.read();
    let ufw_bin = state.cfg.ufw_bin.as_deref();
    Json(serde_json::json!({
        "ips": acl.as_vec(),
        "entries": whitelist_entries_json(&acl),
        "open": acl.is_open(),
        "ufw_sync": acl.ufw_sync(),
        "ufw_available": ufw::ufw_available(ufw_bin),
        "ufw_bin": state.cfg.ufw_bin,
        "note": "Empty list = allow all (ACL off). Panel itself is never filtered. UFW comment = snirelay:<username>.",
    }))
    .into_response()
}

async fn put_whitelist(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Json(body): Json<WhitelistPayload>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }

    let mut rows: Vec<WhitelistEntry> = body
        .entries
        .into_iter()
        .map(|e| WhitelistEntry {
            ip: e.ip,
            username: e.username,
        })
        .collect();
    if rows.is_empty() {
        rows = body
            .ips
            .into_iter()
            .map(WhitelistEntry::ip_only)
            .collect();
    }

    let acl = match ClientAcl::from_parts(
        rows,
        body.ufw_sync
            .unwrap_or_else(|| state.client_acl.read().ufw_sync()),
    ) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    let prev = state.client_acl.read().clone();
    let ufw_bin = state.cfg.ufw_bin.clone();
    let do_ufw = acl.ufw_sync();

    let mut ufw_notes = Vec::new();
    if do_ufw {
        for e in acl.as_entries() {
            let user = e.username.as_deref();
            let was = prev.contains_ip(&e.ip);
            let same_user = prev.username_for(&e.ip) == user;
            if !was || !same_user {
                match ufw::allow_ip(&e.ip, user, ufw_bin.as_deref()) {
                    Ok(m) => ufw_notes.push(format!("+ {}: {m}", e.ip)),
                    Err(err) => ufw_notes.push(format!("+ {}: ERROR {err}", e.ip)),
                }
            }
        }
        for ip in prev.as_vec() {
            if !acl.contains_ip(&ip) {
                match ufw::delete_ip(&ip, ufw_bin.as_deref()) {
                    Ok(m) => ufw_notes.push(format!("- {ip}: {m}")),
                    Err(e) => ufw_notes.push(format!("- {ip}: ERROR {e}")),
                }
            }
        }
    }

    let persist_msg = match persist_whitelist_yaml(&state.config_path, &acl) {
        Ok(()) => "saved".to_string(),
        Err(e) => format!("hot-reloaded; YAML save failed: {e}"),
    };
    *state.client_acl.write() = acl.clone();

    Json(serde_json::json!({
        "ok": true,
        "persist": persist_msg,
        "ips": acl.as_vec(),
        "entries": whitelist_entries_json(&acl),
        "open": acl.is_open(),
        "ufw_sync": acl.ufw_sync(),
        "ufw": ufw_notes,
    }))
    .into_response()
}

async fn add_whitelist_ip(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Json(body): Json<WhitelistIpBody>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let username = match require_username(&body.username) {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    let mut acl = state.client_acl.read().clone();
    let (added, user) = match acl.add(&body.ip, &username) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    let mut ufw_note = None;
    if acl.ufw_sync() {
        match ufw::allow_ip(&body.ip, Some(&user), state.cfg.ufw_bin.as_deref()) {
            Ok(m) => ufw_note = Some(m),
            Err(e) => ufw_note = Some(format!("ERROR: {e}")),
        }
    }

    let persist_msg = match persist_whitelist_yaml(&state.config_path, &acl) {
        Ok(()) => "saved".to_string(),
        Err(e) => format!("hot-reloaded; YAML save failed: {e}"),
    };
    *state.client_acl.write() = acl.clone();

    Json(serde_json::json!({
        "ok": true,
        "added": added,
        "username": user,
        "ufw_comment": ufw::rule_comment(Some(&user)),
        "persist": persist_msg,
        "ips": acl.as_vec(),
        "entries": whitelist_entries_json(&acl),
        "open": acl.is_open(),
        "ufw": ufw_note,
    }))
    .into_response()
}

async fn delete_whitelist_ip(
    State(state): State<PanelState>,
    headers: HeaderMap,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized().into_response();
    }
    let mut acl = state.client_acl.read().clone();
    let removed = match acl.remove(&ip) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    let mut ufw_note = None;
    if removed && acl.ufw_sync() {
        match ufw::delete_ip(&ip, state.cfg.ufw_bin.as_deref()) {
            Ok(m) => ufw_note = Some(m),
            Err(e) => ufw_note = Some(format!("ERROR: {e}")),
        }
    }

    let persist_msg = match persist_whitelist_yaml(&state.config_path, &acl) {
        Ok(()) => "saved".to_string(),
        Err(e) => format!("hot-reloaded; YAML save failed: {e}"),
    };
    *state.client_acl.write() = acl.clone();

    Json(serde_json::json!({
        "ok": true,
        "removed": removed,
        "persist": persist_msg,
        "ips": acl.as_vec(),
        "entries": whitelist_entries_json(&acl),
        "open": acl.is_open(),
        "ufw": ufw_note,
    }))
    .into_response()
}

fn persist_whitelist_yaml(path: &std::path::Path, acl: &ClientAcl) -> anyhow::Result<()> {
    use anyhow::Context;
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(&content).context("parse yaml")?;

    let entries_val = serde_yaml::to_value(acl.as_entries()).context("serialize whitelist")?;

    if let serde_yaml::Value::Mapping(ref mut map) = value {
        map.insert(
            serde_yaml::Value::String("client_whitelist".into()),
            entries_val,
        );
        map.insert(
            serde_yaml::Value::String("client_whitelist_ufw".into()),
            serde_yaml::Value::Bool(acl.ufw_sync()),
        );
    } else {
        anyhow::bail!("config root is not a mapping");
    }
    let out = serde_yaml::to_string(&value)?;
    std::fs::write(path, out).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}
