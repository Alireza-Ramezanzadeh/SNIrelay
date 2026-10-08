//! SQLite persistence for the admin panel (traffic, domains, settings, sessions).

use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;

pub struct PanelDb {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DomainRow {
    pub id: i64,
    pub pattern: String,
    pub kind: String,
    pub mode: String,
    pub note: String,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IpTrafficRow {
    pub client_ip: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub sessions: u64,
    pub last_seen: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IpDomainTrafficRow {
    pub domain: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub sessions: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DailyTrafficRow {
    pub day: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub sessions: u64,
}

impl PanelDb {
    pub fn open(path: &str) -> Result<Self> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create panel db dir {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("open panel sqlite db at {path}"))?;
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL DEFAULT 'exact',
                mode TEXT NOT NULL DEFAULT 'relay',
                note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS traffic_by_ip (
                day TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                bytes_up INTEGER NOT NULL DEFAULT 0,
                bytes_down INTEGER NOT NULL DEFAULT 0,
                sessions INTEGER NOT NULL DEFAULT 0,
                last_seen TEXT NOT NULL,
                PRIMARY KEY (day, client_ip)
            );
            CREATE TABLE IF NOT EXISTS traffic_by_ip_domain (
                day TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                domain TEXT NOT NULL,
                bytes_up INTEGER NOT NULL DEFAULT 0,
                bytes_down INTEGER NOT NULL DEFAULT 0,
                sessions INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (day, client_ip, domain)
            );
            CREATE INDEX IF NOT EXISTS idx_traffic_ip_last ON traffic_by_ip(last_seen);
            CREATE INDEX IF NOT EXISTS idx_domains_mode ON domains(mode);
            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                client_ip TEXT NOT NULL DEFAULT '',
                qtype TEXT NOT NULL DEFAULT 'A',
                domain TEXT NOT NULL,
                action TEXT NOT NULL DEFAULT 'query',
                answer TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_dns_queries_ts ON dns_queries(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_dns_queries_domain ON dns_queries(domain);
            CREATE INDEX IF NOT EXISTS idx_dns_queries_client ON dns_queries(client_ip);
            ",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |r| r.get(0),
        )
        .optional()
        .context("get_setting")
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn create_session(&self, token: &str, ttl_hours: i64) -> Result<()> {
        let now = Utc::now();
        let exp = now + chrono::Duration::hours(ttl_hours);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sessions(token, created_at, expires_at) VALUES(?1, ?2, ?3)",
            params![token, now.to_rfc3339(), exp.to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn session_valid(&self, token: &str) -> Result<bool> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        let found: Option<String> = conn
            .query_row(
                "SELECT token FROM sessions WHERE token = ?1 AND expires_at > ?2",
                params![token, now],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    pub fn delete_session(&self, token: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sessions WHERE token = ?1", params![token])?;
        Ok(())
    }

    pub fn cleanup_sessions(&self) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", params![now])?;
        Ok(())
    }

    pub fn apply_traffic_batch(
        &self,
        rows: &[(String, String, u64, u64)],
    ) -> Result<()> {
        // (client_ip, domain, up, down)
        if rows.is_empty() {
            return Ok(());
        }
        let day = Utc::now().format("%Y-%m-%d").to_string();
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt_ip = tx.prepare(
                "INSERT INTO traffic_by_ip(day, client_ip, bytes_up, bytes_down, sessions, last_seen)
                 VALUES(?1, ?2, ?3, ?4, 1, ?5)
                 ON CONFLICT(day, client_ip) DO UPDATE SET
                   bytes_up = bytes_up + excluded.bytes_up,
                   bytes_down = bytes_down + excluded.bytes_down,
                   sessions = sessions + 1,
                   last_seen = excluded.last_seen",
            )?;
            let mut stmt_dom = tx.prepare(
                "INSERT INTO traffic_by_ip_domain(day, client_ip, domain, bytes_up, bytes_down, sessions)
                 VALUES(?1, ?2, ?3, ?4, ?5, 1)
                 ON CONFLICT(day, client_ip, domain) DO UPDATE SET
                   bytes_up = bytes_up + excluded.bytes_up,
                   bytes_down = bytes_down + excluded.bytes_down,
                   sessions = sessions + 1",
            )?;
            for (ip, domain, up, down) in rows {
                stmt_ip.execute(params![day, ip, *up as i64, *down as i64, now])?;
                stmt_dom.execute(params![day, ip, domain, *up as i64, *down as i64])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn traffic_by_ip(&self, from_day: &str, to_day: &str, limit: i64) -> Result<Vec<IpTrafficRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT client_ip,
                    SUM(bytes_up), SUM(bytes_down), SUM(sessions), MAX(last_seen)
             FROM traffic_by_ip
             WHERE day >= ?1 AND day <= ?2
             GROUP BY client_ip
             ORDER BY (SUM(bytes_up) + SUM(bytes_down)) DESC
             LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![from_day, to_day, limit], |r| {
                Ok(IpTrafficRow {
                    client_ip: r.get(0)?,
                    bytes_up: r.get::<_, i64>(1)? as u64,
                    bytes_down: r.get::<_, i64>(2)? as u64,
                    sessions: r.get::<_, i64>(3)? as u64,
                    last_seen: r.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn traffic_for_ip_domains(
        &self,
        client_ip: &str,
        from_day: &str,
        to_day: &str,
        limit: i64,
    ) -> Result<Vec<IpDomainTrafficRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT domain, SUM(bytes_up), SUM(bytes_down), SUM(sessions)
             FROM traffic_by_ip_domain
             WHERE client_ip = ?1 AND day >= ?2 AND day <= ?3
             GROUP BY domain
             ORDER BY (SUM(bytes_up) + SUM(bytes_down)) DESC
             LIMIT ?4",
        )?;
        let rows = stmt
            .query_map(params![client_ip, from_day, to_day, limit], |r| {
                Ok(IpDomainTrafficRow {
                    domain: r.get(0)?,
                    bytes_up: r.get::<_, i64>(1)? as u64,
                    bytes_down: r.get::<_, i64>(2)? as u64,
                    sessions: r.get::<_, i64>(3)? as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn daily_totals(&self, from_day: &str, to_day: &str) -> Result<Vec<DailyTrafficRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT day, SUM(bytes_up), SUM(bytes_down), SUM(sessions)
             FROM traffic_by_ip
             WHERE day >= ?1 AND day <= ?2
             GROUP BY day
             ORDER BY day ASC",
        )?;
        let rows = stmt
            .query_map(params![from_day, to_day], |r| {
                Ok(DailyTrafficRow {
                    day: r.get(0)?,
                    bytes_up: r.get::<_, i64>(1)? as u64,
                    bytes_down: r.get::<_, i64>(2)? as u64,
                    sessions: r.get::<_, i64>(3)? as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_domains(&self) -> Result<Vec<DomainRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, pattern, kind, mode, note, created_at FROM domains ORDER BY pattern ASC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(DomainRow {
                    id: r.get(0)?,
                    pattern: r.get(1)?,
                    kind: r.get(2)?,
                    mode: r.get(3)?,
                    note: r.get(4)?,
                    created_at: r.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn add_domain(&self, pattern: &str, kind: &str, mode: &str, note: &str) -> Result<i64> {
        let pattern = pattern.trim().to_lowercase();
        if pattern.is_empty() {
            bail!("empty domain pattern");
        }
        let kind = if kind == "wildcard" { "wildcard" } else { "exact" };
        let mode = if mode == "direct" { "direct" } else { "relay" };
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO domains(pattern, kind, mode, note, created_at) VALUES(?1, ?2, ?3, ?4, ?5)",
            params![pattern, kind, mode, note, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_domain(
        &self,
        id: i64,
        pattern: &str,
        kind: &str,
        mode: &str,
        note: &str,
    ) -> Result<()> {
        let pattern = pattern.trim().to_lowercase();
        let kind = if kind == "wildcard" { "wildcard" } else { "exact" };
        let mode = if mode == "direct" { "direct" } else { "relay" };
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE domains SET pattern=?1, kind=?2, mode=?3, note=?4 WHERE id=?5",
            params![pattern, kind, mode, note, id],
        )?;
        if n == 0 {
            bail!("domain id {id} not found");
        }
        Ok(())
    }

    pub fn delete_domain(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute("DELETE FROM domains WHERE id = ?1", params![id])?;
        if n == 0 {
            bail!("domain id {id} not found");
        }
        Ok(())
    }

    pub fn import_domains(&self, lines: &str, mode: &str) -> Result<usize> {
        let mode = if mode == "direct" { "direct" } else { "relay" };
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        let mut count = 0usize;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO domains(pattern, kind, mode, note, created_at) VALUES(?1, ?2, ?3, '', ?4)
                 ON CONFLICT(pattern) DO UPDATE SET mode = excluded.mode",
            )?;
            for raw in lines.lines() {
                let line = raw.trim().to_lowercase();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let (kind, pattern) = if let Some(rest) = line.strip_prefix("*.") {
                    ("wildcard", rest.to_string())
                } else {
                    ("exact", line)
                };
                if pattern.is_empty() {
                    continue;
                }
                stmt.execute(params![pattern, kind, mode, now])?;
                count += 1;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    pub fn relay_domains_for_dnsmasq(&self) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT pattern, kind FROM domains WHERE mode = 'relay' ORDER BY pattern ASC",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn insert_dns_query(&self, row: &DnsQueryInsert) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO dns_queries(ts, client_ip, qtype, domain, action, answer)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                row.ts,
                row.client_ip,
                row.qtype,
                row.domain,
                row.action,
                row.answer
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn insert_dns_queries_batch(&self, rows: &[DnsQueryInsert]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO dns_queries(ts, client_ip, qtype, domain, action, answer)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for row in rows {
                stmt.execute(params![
                    row.ts,
                    row.client_ip,
                    row.qtype,
                    row.domain,
                    row.action,
                    row.answer
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn update_dns_query_result(&self, id: i64, action: &str, answer: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE dns_queries SET action = ?1, answer = ?2 WHERE id = ?3",
            params![action, answer, id],
        )?;
        Ok(())
    }

    pub fn list_dns_queries(
        &self,
        limit: i64,
        domain_q: Option<&str>,
        client_q: Option<&str>,
        action_q: Option<&str>,
    ) -> Result<Vec<DnsQueryRow>> {
        let conn = self.conn.lock().unwrap();
        let mut sql = String::from(
            "SELECT id, ts, client_ip, qtype, domain, action, answer FROM dns_queries WHERE 1=1",
        );
        let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(d) = domain_q.filter(|s| !s.is_empty()) {
            sql.push_str(" AND domain LIKE ?");
            params_vec.push(Box::new(format!("%{d}%")));
        }
        if let Some(c) = client_q.filter(|s| !s.is_empty()) {
            sql.push_str(" AND client_ip LIKE ?");
            params_vec.push(Box::new(format!("%{c}%")));
        }
        if let Some(a) = action_q.filter(|s| !s.is_empty()) {
            sql.push_str(" AND action = ?");
            params_vec.push(Box::new(a.to_string()));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        params_vec.push(Box::new(limit.max(1).min(2000)));

        let mut stmt = conn.prepare(&sql)?;
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(params_refs.as_slice(), |r| {
                Ok(DnsQueryRow {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    client_ip: r.get(2)?,
                    qtype: r.get(3)?,
                    domain: r.get(4)?,
                    action: r.get(5)?,
                    answer: r.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn dns_query_top_domains(&self, limit: i64) -> Result<Vec<(String, i64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT domain, COUNT(*) AS c FROM dns_queries
             WHERE action = 'query' OR action IN ('relay','reply','forwarded','cached','config')
             GROUP BY domain ORDER BY c DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit.max(1).min(100)], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn clear_dns_queries(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute("DELETE FROM dns_queries", [])?;
        Ok(n)
    }

    pub fn prune_dns_queries(&self, retain_hours: u64) -> Result<usize> {
        let cutoff = (Utc::now() - chrono::Duration::hours(retain_hours as i64)).to_rfc3339();
        let conn = self.conn.lock().unwrap();
        let n = conn.execute("DELETE FROM dns_queries WHERE ts < ?1", params![cutoff])?;
        Ok(n)
    }

    pub fn dns_queries_count(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM dns_queries", [], |r| r.get(0))?;
        Ok(n)
    }
}

#[derive(Debug, Clone)]
pub struct DnsQueryInsert {
    pub ts: String,
    pub client_ip: String,
    pub qtype: String,
    pub domain: String,
    pub action: String,
    pub answer: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DnsQueryRow {
    pub id: i64,
    pub ts: String,
    pub client_ip: String,
    pub qtype: String,
    pub domain: String,
    pub action: String,
    pub answer: String,
}

pub fn render_dnsmasq(domains: &[(String, String)], relay_ip: &str) -> String {
    let mut out = String::from("# Generated by SNIrelay admin panel\n");
    out.push_str(&format!("# relay_ip={relay_ip}\n"));
    for (pattern, kind) in domains {
        if kind == "wildcard" {
            out.push_str(&format!("address=/{pattern}/{relay_ip}\n"));
        } else {
            out.push_str(&format!("address=/{pattern}/{relay_ip}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn traffic_and_domains_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("panel.db");
        let db = PanelDb::open(path.to_str().unwrap()).unwrap();
        db.apply_traffic_batch(&[
            ("1.2.3.4".into(), "game.example.com".into(), 100, 200),
            ("1.2.3.4".into(), "cdn.example.com".into(), 50, 10),
            ("5.6.7.8".into(), "game.example.com".into(), 1, 2),
        ])
        .unwrap();
        let day = Utc::now().format("%Y-%m-%d").to_string();
        let ips = db.traffic_by_ip(&day, &day, 10).unwrap();
        assert_eq!(ips[0].client_ip, "1.2.3.4");
        assert_eq!(ips[0].bytes_up, 150);
        assert_eq!(ips[0].bytes_down, 210);
        assert_eq!(ips[0].sessions, 2);

        db.add_domain("play.example.com", "exact", "relay", "").unwrap();
        db.import_domains("*.cdn.example.com\nother.com\n", "relay")
            .unwrap();
        let list = db.list_domains().unwrap();
        assert!(list.len() >= 3);
        let dnsmasq = render_dnsmasq(&db.relay_domains_for_dnsmasq().unwrap(), "10.0.0.1");
        assert!(dnsmasq.contains("address=/play.example.com/10.0.0.1"));
    }
}
