//! Admin panel HTTP server (axum) + embedded static UI.

mod api;
mod db;
mod dnsmasq_query_log;
mod dnsmasq_store;
mod traffic;

pub use db::PanelDb;
pub use traffic::TrafficAggregator;

use anyhow::{Context, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use rand::rngs::OsRng;
use rust_embed::Embed;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};

use crate::config::AppConfig;
use crate::hosts::HostsTable;

use api::api_router;

#[derive(Embed)]
#[folder = "panel/dist/"]
struct PanelAssets;

#[derive(Clone)]
pub struct PanelState {
    pub db: Arc<PanelDb>,
    pub cfg: Arc<AppConfig>,
    #[allow(dead_code)]
    pub traffic: TrafficAggregator,
    pub upstream_ok: Arc<AtomicBool>,
    pub hosts_live: Arc<parking_lot::RwLock<Option<Arc<HostsTable>>>>,
    pub hosts_entries: Arc<parking_lot::RwLock<Vec<crate::hosts::HostsEntry>>>,
    pub config_path: PathBuf,
}

pub async fn start_panel(
    cfg: Arc<AppConfig>,
    upstream_ok: Arc<AtomicBool>,
) -> Result<(TrafficAggregator, Arc<parking_lot::RwLock<Option<Arc<HostsTable>>>>)> {
    let panel = &cfg.panel;
    if !panel.enabled {
        info!("Admin panel disabled");
        let dummy_db = Arc::new(PanelDb::open(&panel.db_path)?);
        let traffic = TrafficAggregator::start(dummy_db, 5);
        let hosts_live = Arc::new(parking_lot::RwLock::new(cfg.hosts_table.clone()));
        return Ok((traffic, hosts_live));
    }

    let db = Arc::new(PanelDb::open(&panel.db_path)?);
    ensure_admin_password(&db)?;

    let traffic = TrafficAggregator::start(db.clone(), 2);
    let hosts_live = Arc::new(parking_lot::RwLock::new(cfg.hosts_table.clone()));
    let hosts_entries = Arc::new(parking_lot::RwLock::new(cfg.hosts.clone()));
    let config_path = PathBuf::from(
        cfg.config_path
            .clone()
            .unwrap_or_else(|| "/etc/sniproxy/config.yaml".into()),
    );

    let state = PanelState {
        db: db.clone(),
        cfg: cfg.clone(),
        traffic: traffic.clone(),
        upstream_ok,
        hosts_live: hosts_live.clone(),
        hosts_entries: hosts_entries.clone(),
        config_path,
    };

    let app = Router::new()
        .merge(api_router())
        .route("/", get(index_handler))
        .route("/{*path}", get(static_handler))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state);

    let addr: SocketAddr = panel
        .addr
        .parse()
        .with_context(|| format!("invalid panel.addr '{}'", panel.addr))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind admin panel on {addr}"))?;
    info!("Admin panel listening on http://{addr}/");

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            warn!("Admin panel server stopped: {e}");
        }
    });

    // periodic session cleanup
    let db_cleanup = db.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tick.tick().await;
            let _ = db_cleanup.cleanup_sessions();
        }
    });

    if let Some(ref log_path) = panel.dnsmasq_query_log {
        if !log_path.is_empty() {
            dnsmasq_query_log::start_query_log_ingest(
                db.clone(),
                PathBuf::from(log_path),
                panel.dns_query_retain_hours.max(1),
            );
        }
    }

    Ok((traffic, hosts_live))
}

fn ensure_admin_password(db: &PanelDb) -> Result<()> {
    if db.get_setting("admin_password_hash")?.is_some() {
        return Ok(());
    }
    let plain = std::env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "snirelay".into());
    let hash = hash_password(&plain)?;
    db.set_setting("admin_password_hash", &hash)?;
    if std::env::var("ADMIN_PASSWORD").is_err() {
        warn!(
            "Admin panel password not set; using default 'snirelay'. \
             Set ADMIN_PASSWORD env var and change it in the panel."
        );
    } else {
        info!("Admin panel password initialized from ADMIN_PASSWORD");
    }
    Ok(())
}

pub fn hash_password(plain: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?
        .to_string();
    Ok(hash)
}

pub fn verify_password(plain: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(plain.as_bytes(), &parsed)
        .is_ok()
}

async fn index_handler(State(state): State<PanelState>) -> impl IntoResponse {
    serve_asset(&state, "index.html")
}

async fn static_handler(
    State(state): State<PanelState>,
    axum::extract::Path(path): axum::extract::Path<String>,
) -> impl IntoResponse {
    let path = path.trim_start_matches('/');
    if path.is_empty() || path == "index.html" {
        return serve_asset(&state, "index.html");
    }
    // Don't hijack API
    if path.starts_with("api/") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    serve_asset(&state, path)
}

fn serve_asset(_state: &PanelState, path: &str) -> Response<Body> {
    match PanelAssets::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime)
                .header(header::CACHE_CONTROL, "no-cache")
                .body(Body::from(file.data.into_owned()))
                .unwrap()
        }
        None => {
            // SPA fallback
            if let Some(file) = PanelAssets::get("index.html") {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .body(Body::from(file.data.into_owned()))
                    .unwrap()
            } else {
                (StatusCode::NOT_FOUND, "panel assets missing").into_response()
            }
        }
    }
}

pub fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                let c = c.trim();
                c.strip_prefix("snirelay_session=")
                    .map(|v| v.to_string())
            })
        })
}
