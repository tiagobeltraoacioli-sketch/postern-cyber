//! SQLite storage. Rows are returned as JSON objects so the API layer does
//! not need one struct per table.

use rusqlite::types::{Value as SqlV, ValueRef};
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

pub fn random_token(prefix: &str) -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!("{prefix}_{}", hex::encode(b))
}

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
CREATE TABLE IF NOT EXISTS endpoints (
  id TEXT PRIMARY KEY, hostname TEXT NOT NULL, os TEXT, arch TEXT, version TEXT,
  key_hash TEXT NOT NULL UNIQUE, enrolled_at INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  heartbeat TEXT, isolated INTEGER NOT NULL DEFAULT 0, mode TEXT NOT NULL DEFAULT 'detect',
  inventory TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, endpoint_id TEXT NOT NULL,
  kind TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'sensor', fields TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_ep ON events(endpoint_id, ts);
CREATE INDEX IF NOT EXISTS events_kind ON events(kind, ts);
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY, endpoint_id TEXT NOT NULL, title TEXT NOT NULL,
  severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  alert_count INTEGER NOT NULL DEFAULT 0, ai_verdict TEXT, ai_model TEXT, ai_at INTEGER
);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, endpoint_id TEXT NOT NULL,
  rule_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
  mitre TEXT NOT NULL DEFAULT '[]', event_id INTEGER, incident_id INTEGER
);
CREATE INDEX IF NOT EXISTS alerts_inc ON alerts(incident_id);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY, endpoint_id TEXT NOT NULL, kind TEXT NOT NULL, params TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', requested_by TEXT NOT NULL,
  created_at INTEGER NOT NULL, completed_at INTEGER, output TEXT
);
CREATE TABLE IF NOT EXISTS rules (
  id TEXT PRIMARY KEY, yaml TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
  source TEXT NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS iocs (
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL, note TEXT,
  created_at INTEGER NOT NULL, UNIQUE(kind, value)
);
CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, email TEXT NOT NULL, role TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS endpoint_vulns (
  endpoint_id TEXT NOT NULL, vuln_id TEXT NOT NULL, package TEXT NOT NULL, installed TEXT NOT NULL,
  fixed TEXT, severity TEXT NOT NULL, summary TEXT, published TEXT,
  PRIMARY KEY (endpoint_id, vuln_id, package)
);
UPDATE api_keys SET role = 'analyst' WHERE role = 'operator';
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, actor TEXT NOT NULL,
  action TEXT NOT NULL, detail TEXT
);
"#;

pub fn open(path: &std::path::Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

/// Run a SELECT and return each row as a JSON object. Text columns holding a
/// JSON object or array are returned parsed.
pub fn query(conn: &Connection, sql: &str, args: Vec<SqlV>) -> rusqlite::Result<Vec<Value>> {
    let mut st = conn.prepare(sql)?;
    let names: Vec<String> = st.column_names().iter().map(|s| s.to_string()).collect();
    let rows = st.query_map(params_from_iter(args), |r| {
        let mut m = Map::new();
        for (i, name) in names.iter().enumerate() {
            let v = match r.get_ref(i)? {
                ValueRef::Null | ValueRef::Blob(_) => Value::Null,
                ValueRef::Integer(n) => n.into(),
                ValueRef::Real(f) => serde_json::json!(f),
                ValueRef::Text(t) => {
                    let s = String::from_utf8_lossy(t).into_owned();
                    let structured = matches!(name.as_str(), "fields" | "heartbeat" | "inventory" | "mitre" | "params" | "ai_verdict");
                    if structured {
                        serde_json::from_str(&s).unwrap_or(Value::String(s))
                    } else {
                        Value::String(s)
                    }
                }
            };
            m.insert(name.clone(), v);
        }
        Ok(Value::Object(m))
    })?;
    rows.collect()
}

pub fn get_setting(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get(0))
        .optional()
        .ok()
        .flatten()
}

pub fn set_setting(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO settings(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub fn audit(conn: &Connection, actor: &str, action: &str, detail: &str) {
    let _ = conn.execute(
        "INSERT INTO audit(ts, actor, action, detail) VALUES (?1, ?2, ?3, ?4)",
        params![postern_proto::now_ms(), actor, action, detail],
    );
}

pub fn severity_rank(s: &str) -> i32 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}
