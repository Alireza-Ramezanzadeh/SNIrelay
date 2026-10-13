//! Minimal Telegram Bot API helper via host/`curl` (no extra Rust TLS deps).

use anyhow::{bail, Context, Result};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, warn};

use crate::config::TelegramConfig;

fn curl_bin() -> &'static str {
    for p in ["/usr/bin/curl", "/bin/curl"] {
        if std::path::Path::new(p).exists() {
            return p;
        }
    }
    "curl"
}

/// Escape text for Telegram `parse_mode=HTML`.
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

/// Send an HTML-formatted message. Failures are returned to the caller.
pub async fn send_message(cfg: &TelegramConfig, text: &str) -> Result<()> {
    let token = cfg
        .bot_token
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("telegram bot_token not set"))?;
    let chat_id = cfg
        .chat_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("telegram chat_id not set"))?;

    let base = cfg.api_base_url();
    let url = format!("{base}/bot{token}/sendMessage");
    let output = Command::new(curl_bin())
        .args([
            "-sS",
            "--max-time",
            "8",
            "-X",
            "POST",
            &url,
            "-d",
            &format!("chat_id={chat_id}"),
            "--data-urlencode",
            &format!("text={text}"),
            "-d",
            "parse_mode=HTML",
            "-d",
            "disable_web_page_preview=true",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("exec curl for telegram sendMessage (is curl installed?)")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        bail!(
            "curl failed ({}): {}",
            output.status,
            if !stderr.is_empty() {
                stderr.trim()
            } else {
                stdout.trim()
            }
        );
    }

    if let Ok(v) = serde_json::from_str::<serde_json::Value>(stdout.trim()) {
        if v.get("ok").and_then(|o| o.as_bool()) == Some(false) {
            let desc = v
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("unknown");
            bail!("telegram api error: {desc}");
        }
    }

    debug!(chat_id, "telegram message sent");
    Ok(())
}

/// Best-effort notify; logs on failure and never panics.
pub async fn notify(cfg: &TelegramConfig, text: &str) {
    if !cfg.is_configured() {
        warn!("telegram not configured; alert skipped");
        return;
    }
    match send_message(cfg, text).await {
        Ok(()) => {
            tracing::info!(
                api_base = %cfg.api_base_url(),
                chat_id = cfg.chat_id.as_deref().unwrap_or("?"),
                "telegram notify ok"
            );
        }
        Err(e) => {
            warn!(
                error = %e,
                api_base = %cfg.api_base_url(),
                "telegram notify failed"
            );
        }
    }
}
