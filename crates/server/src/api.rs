//! HTTP API: sensor plane (enroll, telemetry, action results) and console
//! plane (everything an operator or an integration calls).

use crate::{ai, db, detect, AppState};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use postern_proto::{now_ms, Action, ActionResult, BatchResponse, EnrollRequest, EnrollResponse, Event, EventBatch};
use rusqlite::types::Value as SqlV;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

type St = State<Arc<AppState>>;
type Q = Query<HashMap<String, String>>;

pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}
impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("database error: {e}"))
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::BAD_GATEWAY, e.to_string())
    }
}
fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}
type R = Result<Json<Value>, ApiError>;

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.trim().to_string())
}

/// Authenticate a console / integration caller. Returns the key name.
fn operator(conn: &Connection, headers: &HeaderMap) -> Result<String, ApiError> {
    let token = bearer(headers).ok_or(ApiError(StatusCode::UNAUTHORIZED, "missing bearer token".into()))?;
    conn.query_row("SELECT name FROM api_keys WHERE key_hash = ?1", [db::sha256_hex(&token)], |r| r.get(0))
        .optional()?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid token".into()))
}

/// Authenticate a sensor. Returns (endpoint id, protection mode).
fn sensor(conn: &Connection, headers: &HeaderMap) -> Result<(String, String), ApiError> {
    let token = bearer(headers).ok_or(ApiError(StatusCode::UNAUTHORIZED, "missing agent key".into()))?;
    conn.query_row(
        "SELECT id, mode FROM endpoints WHERE key_hash = ?1",
        [db::sha256_hex(&token)],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()?
    .ok_or(ApiError(StatusCode::UNAUTHORIZED, "unknown agent key".into()))
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(|| async { Html(include_str!("../../../console/index.html")) }))
        .route("/healthz", get(|| async { "ok" }))
        // sensor plane
        .route("/api/v1/sensor/enroll", post(enroll))
        .route("/api/v1/sensor/events", post(sensor_events))
        .route("/api/v1/sensor/actions/:id/result", post(action_result))
        // console plane
        .route("/api/v1/overview", get(overview))
        .route("/api/v1/endpoints", get(endpoints))
        .route("/api/v1/endpoints/:id", get(endpoint_detail))
        .route("/api/v1/endpoints/:id/actions", post(request_action))
        .route("/api/v1/endpoints/:id/mode", post(set_mode))
        .route("/api/v1/incidents", get(incidents))
        .route("/api/v1/incidents/:id", get(incident_detail))
        .route("/api/v1/incidents/:id/status", post(incident_status))
        .route("/api/v1/alerts", get(alerts))
        .route("/api/v1/events", get(events))
        .route("/api/v1/actions", get(actions))
        .route("/api/v1/rules", get(rules).post(save_rule))
        .route("/api/v1/rules/:id/toggle", post(toggle_rule))
        .route("/api/v1/rules/:id/delete", post(delete_rule))
        .route("/api/v1/iocs", get(iocs).post(add_ioc))
        .route("/api/v1/iocs/:id/delete", post(delete_ioc))
        .route("/api/v1/ingest", post(ingest_external))
        .route("/api/v1/audit", get(audit_log))
        .route("/api/v1/settings", get(settings))
        .route("/api/v1/settings/ai", post(set_ai))
        .route("/api/v1/settings/ai/test", post(test_ai))
        .route("/api/v1/keys", post(create_key))
        .route("/api/v1/ai/triage/:id", post(ai_triage))
        .route("/api/v1/ai/hunt", post(ai_hunt))
        .route("/api/v1/ai/rule", post(ai_rule))
        .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024))
        .with_state(state)
}

// ---------------------------------------------------------------- ingestion

struct AlertSpec<'a> {
    rule_id: &'a str,
    title: &'a str,
    severity: &'a str,
    mitre: &'a [String],
    response: &'a [String],
}

fn raise_alert(conn: &Connection, endpoint_id: &str, mode: &str, ev: &Event, event_id: i64, a: AlertSpec) -> rusqlite::Result<()> {
    // Storyline: alerts on one endpoint within 30 minutes join one incident.
    let open: Option<(i64, String)> = conn
        .query_row(
            "SELECT id, severity FROM incidents WHERE endpoint_id = ?1 AND status IN ('open','investigating') \
             AND updated_at >= ?2 ORDER BY updated_at DESC LIMIT 1",
            params![endpoint_id, ev.ts - 30 * 60_000],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let incident_id = match open {
        Some((id, sev)) => {
            let sev = if db::severity_rank(a.severity) > db::severity_rank(&sev) { a.severity.to_string() } else { sev };
            conn.execute(
                "UPDATE incidents SET updated_at = ?1, severity = ?2, alert_count = alert_count + 1 WHERE id = ?3",
                params![ev.ts.max(now_ms()), sev, id],
            )?;
            id
        }
        None => {
            conn.execute(
                "INSERT INTO incidents(endpoint_id, title, severity, created_at, updated_at, alert_count) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
                params![endpoint_id, a.title, a.severity, ev.ts, ev.ts.max(now_ms())],
            )?;
            conn.last_insert_rowid()
        }
    };
    conn.execute(
        "INSERT INTO alerts(ts, endpoint_id, rule_id, title, severity, mitre, event_id, incident_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![ev.ts, endpoint_id, a.rule_id, a.title, a.severity, json!(a.mitre).to_string(), event_id, incident_id],
    )?;
    if mode == "protect" {
        for kind in a.response {
            let p = match kind.as_str() {
                "kill_process" => ev.fields.get("process.pid").map(|pid| json!({"pid": pid})),
                "quarantine_file" => ev.text("process.exe").or_else(|| ev.text("file.path")).map(|path| json!({"path": path})),
                "isolate_host" => Some(json!({})),
                _ => None,
            };
            if let Some(p) = p {
                queue_action(conn, endpoint_id, kind, &p, &format!("policy:{}", a.rule_id))?;
            }
        }
    }
    Ok(())
}

fn queue_action(conn: &Connection, endpoint_id: &str, kind: &str, p: &Value, by: &str) -> rusqlite::Result<String> {
    let id = db::random_token("act");
    conn.execute(
        "INSERT INTO actions(id, endpoint_id, kind, params, requested_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, endpoint_id, kind, p.to_string(), by, now_ms()],
    )?;
    db::audit(conn, by, "action.queue", &format!("{kind} on {endpoint_id} {p}"));
    Ok(id)
}

/// Store events, run detections, raise alerts. Returns the number of alerts.
fn ingest(state: &AppState, conn: &Connection, endpoint_id: &str, mode: &str, source: &str, events: &[Event]) -> rusqlite::Result<usize> {
    let mut engine = state.engine.lock().unwrap();
    let mut raised = 0;
    for ev in events {
        if ev.kind == "inventory" {
            conn.execute(
                "UPDATE endpoints SET inventory = ?1 WHERE id = ?2",
                params![Value::Object(ev.fields.clone()).to_string(), endpoint_id],
            )?;
            continue;
        }
        conn.execute(
            "INSERT INTO events(ts, endpoint_id, kind, source, fields) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ev.ts, endpoint_id, ev.kind, source, Value::Object(ev.fields.clone()).to_string()],
        )?;
        let event_id = conn.last_insert_rowid();

        // Indicator matching: file hashes and remote addresses.
        for (ioc_kind, field) in [("sha256", "process.sha256"), ("sha256", "file.sha256"), ("ip", "net.remote_ip"), ("ip", "auth.source_ip")] {
            let Some(v) = ev.text(field) else { continue };
            let note: Option<Option<String>> = conn
                .query_row("SELECT note FROM iocs WHERE kind = ?1 AND value = ?2", params![ioc_kind, v.to_lowercase()], |r| r.get(0))
                .optional()?;
            if let Some(note) = note {
                let title = format!("Indicator match: {ioc_kind} {v}{}", note.map(|n| format!(" ({n})")).unwrap_or_default());
                let response: Vec<String> = if ioc_kind == "sha256" && field == "process.sha256" {
                    vec!["kill_process".into(), "quarantine_file".into()]
                } else {
                    vec![]
                };
                raise_alert(conn, endpoint_id, mode, ev, event_id, AlertSpec {
                    rule_id: "PC-IOC", title: &title, severity: "high", mitre: &[], response: &response,
                })?;
                raised += 1;
            }
        }

        for rule in engine.evaluate(endpoint_id, ev) {
            raise_alert(conn, endpoint_id, mode, ev, event_id, AlertSpec {
                rule_id: &rule.id, title: &rule.title, severity: &rule.severity, mitre: &rule.mitre, response: &rule.response,
            })?;
            raised += 1;
        }
    }
    Ok(raised)
}

// ------------------------------------------------------------- sensor plane

async fn enroll(State(s): St, Json(req): Json<EnrollRequest>) -> Result<Json<EnrollResponse>, ApiError> {
    let conn = s.db.lock().unwrap();
    let expected = db::get_setting(&conn, "enroll_token").unwrap_or_default();
    if expected.is_empty() || db::sha256_hex(&req.enroll_token) != db::sha256_hex(&expected) {
        db::audit(&conn, "sensor", "enroll.denied", &req.hostname);
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid enrollment token".into()));
    }
    let agent_id = db::random_token("ep")[..19].to_string();
    let agent_key = db::random_token("pcs");
    let now = now_ms();
    conn.execute(
        "INSERT INTO endpoints(id, hostname, os, arch, version, key_hash, enrolled_at, last_seen) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
        params![agent_id, req.hostname, req.os, req.arch, req.version, db::sha256_hex(&agent_key), now],
    )?;
    db::audit(&conn, "sensor", "enroll.ok", &format!("{} as {agent_id}", req.hostname));
    Ok(Json(EnrollResponse { agent_id, agent_key }))
}

async fn sensor_events(State(s): St, headers: HeaderMap, Json(batch): Json<EventBatch>) -> Result<Json<BatchResponse>, ApiError> {
    let conn = s.db.lock().unwrap();
    let (id, mode) = sensor(&conn, &headers)?;
    conn.execute(
        "UPDATE endpoints SET last_seen = ?1, heartbeat = ?2, isolated = ?3, version = ?4 WHERE id = ?5",
        params![now_ms(), json!(batch.heartbeat).to_string(), batch.heartbeat.isolated as i64, batch.heartbeat.version, id],
    )?;
    ingest(&s, &conn, &id, &mode, "sensor", &batch.events)?;
    let pending = db::query(
        &conn,
        "SELECT id, kind, params FROM actions WHERE endpoint_id = ?1 AND status = 'pending' ORDER BY created_at LIMIT 20",
        vec![SqlV::Text(id.clone())],
    )?;
    let mut actions = Vec::new();
    for a in pending {
        let aid = a["id"].as_str().unwrap_or_default().to_string();
        conn.execute("UPDATE actions SET status = 'sent' WHERE id = ?1", [&aid])?;
        actions.push(Action { id: aid, kind: a["kind"].as_str().unwrap_or_default().to_string(), params: a["params"].clone() });
    }
    Ok(Json(BatchResponse { actions, mode }))
}

async fn action_result(State(s): St, headers: HeaderMap, Path(aid): Path<String>, Json(res): Json<ActionResult>) -> R {
    let conn = s.db.lock().unwrap();
    let (id, _) = sensor(&conn, &headers)?;
    let n = conn.execute(
        "UPDATE actions SET status = ?1, output = ?2, completed_at = ?3 WHERE id = ?4 AND endpoint_id = ?5",
        params![if res.ok { "done" } else { "failed" }, res.output.chars().take(8000).collect::<String>(), now_ms(), aid, id],
    )?;
    db::audit(&conn, &id, "action.result", &format!("{aid} ok={}", res.ok));
    Ok(Json(json!({"updated": n})))
}

// ------------------------------------------------------------ console plane

async fn overview(State(s): St, headers: HeaderMap) -> R {
    let conn = s.db.lock().unwrap();
    operator(&conn, &headers)?;
    let now = now_ms();
    let day = now - 24 * 3_600_000;
    let one = |sql: &str, args: Vec<SqlV>| -> rusqlite::Result<i64> {
        conn.query_row(sql, rusqlite::params_from_iter(args), |r| r.get(0))
    };
    let recent_alerts = db::query(&conn, "SELECT ts, rule_id, title, severity, mitre FROM alerts WHERE ts >= ?1", vec![SqlV::Integer(day)])?;
    let mut by_hour = vec![0i64; 24];
    let mut techniques: HashMap<String, i64> = HashMap::new();
    let mut top_rules: HashMap<String, i64> = HashMap::new();
    for a in &recent_alerts {
        let h = ((a["ts"].as_i64().unwrap_or(day) - day) / 3_600_000).clamp(0, 23) as usize;
        by_hour[h] += 1;
        for t in a["mitre"].as_array().into_iter().flatten().filter_map(|t| t.as_str()) {
            *techniques.entry(t.to_string()).or_default() += 1;
        }
        *top_rules.entry(format!("{} {}", a["rule_id"].as_str().unwrap_or(""), a["title"].as_str().unwrap_or(""))).or_default() += 1;
    }
    let ranked = |m: HashMap<String, i64>| {
        let mut v: Vec<_> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.into_iter().take(8).map(|(k, n)| json!({"name": k, "count": n})).collect::<Vec<_>>()
    };
    let mut out = json!({
        "endpoints_total": one("SELECT COUNT(*) FROM endpoints WHERE os != 'external'", vec![])?,
        "endpoints_online": one("SELECT COUNT(*) FROM endpoints WHERE os != 'external' AND last_seen >= ?1", vec![SqlV::Integer(now - 90_000)])?,
        "endpoints_isolated": one("SELECT COUNT(*) FROM endpoints WHERE isolated = 1", vec![])?,
        "incidents_open": db::query(&conn, "SELECT severity, COUNT(*) AS n FROM incidents WHERE status IN ('open','investigating') GROUP BY severity", vec![])?,
        "alerts_24h": recent_alerts.len(),
        "events_24h": one("SELECT COUNT(*) FROM events WHERE ts >= ?1", vec![SqlV::Integer(day)])?,
        "alerts_by_hour": by_hour,
        "top_techniques": ranked(techniques),
        "top_rules": ranked(top_rules),
        "rules_loaded": s.engine.lock().unwrap().rule_count(),
    });
    drop(conn);
    out["ai_configured"] = json!(ai::config(&s).is_some());
    Ok(Json(out))
}

async fn endpoints(State(s): St, headers: HeaderMap) -> R {
    let conn = s.db.lock().unwrap();
    operator(&conn, &headers)?;
    Ok(Json(json!(db::query(
        &conn,
        "SELECT e.id, e.hostname, e.os, e.arch, e.version, e.enrolled_at, e.last_seen, e.heartbeat, e.isolated, e.mode, \
         (SELECT COUNT(*) FROM incidents i WHERE i.endpoint_id = e.id AND i.status IN ('open','investigating')) AS open_incidents \
         FROM endpoints e ORDER BY e.hostname",
        vec![],
    )?)))
}

async fn endpoint_detail(State(s): St, headers: HeaderMap, Path(id): Path<String>) -> R {
    let conn = s.db.lock().unwrap();
    operator(&conn, &headers)?;
    let ep = db::query(
        &conn,
        "SELECT id, hostname, os, arch, version, enrolled_at, last_seen, heartbeat, isolated, mode, inventory FROM endpoints WHERE id = ?1",
        vec![SqlV::Text(id.clone())],
    )?
    .into_iter()
    .next()
    .ok_or(ApiError(StatusCode::NOT_FOUND, "endpoint not found".into()))?;
    // Latest result per posture check.
    let posture = db::query(
        &conn,
        "SELECT fields, MAX(ts) AS ts FROM events WHERE endpoint_id = ?1 AND kind = 'posture' \
         GROUP BY json_extract(fields, '$.\"posture.check\"') ORDER BY ts DESC LIMIT 60",
        vec![SqlV::Text(id.clone())],
    )?;
    let listeners = db::query(
        &conn,
        "SELECT fields, MAX(ts) AS ts FROM events WHERE endpoint_id = ?1 AND kind = 'listen_port' \
         GROUP BY json_extract(fields, '$.\"net.local_port\"') ORDER BY ts DESC LIMIT 100",
        vec![SqlV::Text(id)],
    )?;
    Ok(Json(json!({"endpoint": ep, "posture": posture, "listeners": listeners})))
}

async fn request_action(State(s): St, headers: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> R {
    let conn = s.db.lock().unwrap();
    let who = operator(&conn, &headers)?;
    let kind = b["kind"].as_str().unwrap_or_default();
    let p = b.get("params").cloned().unwrap_or(json!({}));
    match kind {
        "kill_process" if p["pid"].as_i64().is_some() => {}
        "quarantine_file" if p["path"].as_str().is_some_and(|x| x.starts_with('/')) => {}
        "isolate_host" | "unisolate_host" | "collect_triage" => {}
        "kill_process" => return Err(bad("kill_process needs params.pid")),
        "quarantine_file" => return Err(bad("quarantine_file needs an absolute params.path")),
        _ => return Err(bad("unknown action kind")),
    }
    let exists: Option<i64> = conn.query_row("SELECT 1 FROM endpoints WHERE id = ?1", [&id], |r| r.get(0)).optional()?;
    if exists.is_none() {
        return Err(ApiError(StatusCode::NOT_FOUND, "endpoint not found".into()));
    }
    let aid = queue_action(&conn, &id, kind, &p, &who)?;
    Ok(Json(json!({"id": aid, "status": "pending"})))
}

async fn set_mode(State(s): St, headers: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> R {
    let conn = s.db.lock().unwrap();
    let who = operator(&conn, &headers)?;
    let mode = b["mode"].as_str().unwrap_or_default();
    if !["detect", "protect"].contains(&mode) {
        return Err(bad("mode must be detect or protect"));
    }
    let n = conn.execute("UPDATE endpoints SET mode = ?1 WHERE id = ?2", params![mode, id])?;
    db::audit(&conn, &who, "endpoint.mode", &format!("{id} -> {mode}"));
    Ok(Json(json!({"updated": n})))
}

async fn incidents(State(s): St, headers: HeaderMap, Query(q): Q) -> R {
    let conn = s.db.lock().unwrap();
    operator(&conn, &headers)?;
    let mut sql = String::from(
        "SELECT i.id, i.endpoint_id, p.hostname, i.title, i.severity, i.status, i.created_at, i.updated_at, i.alert_count, \
         json_extract(i.ai_verdict, '$.verdict') AS verdict FROM incidents i LEFT JOIN endpoints p ON p.id = i.endpoint_id",
    );
    let mut args = vec![];
    if let Some(st) = q.get("status").filter(|x| !x.is_empty() && *x != "all") {
        if st == "active" {
            sql.push_str(" WHERE i.status IN ('open','investigating')");
        } else {
            args.push(SqlV::Text(st.clone()));
            sql.push_str(" WHERE i.status = ?1");
        }
    }
    sql.push_str(" ORDER BY i.updated_at DESC LIMIT 200");
    Ok(Json(json!(db::query(&conn, &sql, args)?)))
}

async fn incident_detail(State(s): St, headers: HeaderMap, Path(id): Path<i64>) -> R {
    let conn = s.db.lock().unwrap();
    operator(&conn, &headers)?;
    let inc = db::query(
        &conn,
        "SELECT i.*, p.hostname FROM incidents i LEFT JOIN endpoints p ON p.id = i.endpoint_id WHERE i.id = ?1",
        vec![SqlV::Integer(id)],
    )?
    .into_iter()
    .next()
    .ok_or(ApiError(StatusCode::NOT_FOUND, "incident not found".into()))?;
    let alerts = db::query(
        &conn,
        "SELECT a.id, a.ts, a.rule_id, a.title, a.severity, a.mitre, a.event_id, e.kind, e.fields \
         FROM alerts a LEFT JOIN events e ON e.id = a.event_id WHERE a.incident_id = ?1 ORDER BY a.ts LIMIT 300",
        vec![SqlV::Integer(id)],
    )?;
    let ep = inc["endpoint_id"].as_str().unwrap_or_default().to_string();
    let acts = db::query(
        &conn,
        "SELECT id, kind, params, status, requested_by, created_at, completed_at, output FROM actions \
         WHERE endpoint_id = ?1 AND created_at >= ?2 ORDER BY created_at DESC LIMIT 50",
        vec![SqlV::Text(ep), SqlV::Integer(inc["created_at"].as_i64().unwrap_or(0))],
    )?;
    Ok(Json(json!({"incident": inc, "alerts": alerts, "actions": acts})))
}

async fn incident_status(State(s): St, headers: HeaderMap, Path(id): Path<i64>, Json(b): Json<Value>) -> R {
    let conn = s.db.lock().unwrap();
    let who = operator(&conn, &headers)?;
    let status = b["status"].as_str().unwrap_or_default();
    if !["open", "investigating", "resolved", "false_positive"].contains(&status) {
        return Err(bad("status must be open, investigating, resolved or false_positive"));
    }
    let n = conn.execute("UPDATE incidents SET status = ?1 WHERE id = ?2", params![status, id])?;
    db::audit(&conn, &who, "incident.status", &format!("#{id} -> {status}"));
    Ok(Json(json!({"updated": n})))
}

async fn alerts(State(s): St, headers: HeaderMap) -> R {
    let conn = s.db.lock().unwrap();
    operator(&conn, &headers)?;
    Ok(Json(json!(db::query(
        &conn,
        "SELECT a.id, a.ts, p.hostname, a.rule_id, a.title, a.severity, a.mitre, a.event_id, a.incident_id \
         FROM alerts a LEFT JOIN endpoints p ON p.id = a.endpoint_id ORDER BY a.ts DESC LIMIT 300",
        vec![],
    )?)))
}

async fn events(State(s): St, headers: HeaderMap, Query(q): Q) -> R {
    let conn = s.db.lock().unwrap();
    operator(&conn, &headers)?;
    let mins: i64 = q.get("since_minutes").and_then(|v| v.parse().ok()).unwrap_or(60);
    let mut sql = String::from(
        "SELECT e.id, e.ts, e.endpoint_id, p.hostname, e.kind, e.source, e.fields FROM events e \
         LEFT JOIN endpoints p ON p.id = e.endpoint_id WHERE e.ts >= ?1",
    );
    let mut args = vec![SqlV::Integer(now_ms() - mins.clamp(1, 60 * 24 * 365) * 60_000)];
    if let Some(t) = q.get("q").filter(|t| !t.is_empty()) {
        args.push(SqlV::Text(format!("%{}%", t.replace('%', ""))));
        sql.push_str(&format!(" AND e.fields LIKE ?{}", args.len()));
    }
    if let Some(k) = q.get("kind").filter(|k| !k.is_empty()) {
        args.push(SqlV::Text(k.clone()));
        sql.push_str(&format!(" AND e.kind = ?{}", args.len()));
    }
    if let Some(e) = q.get("endpoint").filter(|e| !e.is_empty()) {
        args.push(SqlV::Text(e.clone()));
        sql.push_str(&format!(" AND (e.endpoint_id = ?{0} OR p.hostname = ?{0})", args.len()));
    }
    let limit: i64 = q.get("limit").and_then(|v| v.parse().ok()).unwrap_or(200);
    sql.push_str(&format!(" ORDER BY e.ts DESC LIMIT {}", limit.clamp(1, 1000)));
    Ok(Json(json!(db::query(&conn, &sql, args)?)))
}

async fn actions(State(s): St, headers: HeaderMap) -> R {
    let conn = s.db.lock().unwrap();
    operator(&conn, &headers)?;
    Ok(Json(json!(db::query(
        &conn,
        "SELECT a.id, p.hostname, a.kind, a.params, a.status, a.requested_by, a.created_at, a.completed_at, a.output \
         FROM actions a LEFT JOIN endpoints p ON p.id = a.endpoint_id ORDER BY a.created_at DESC LIMIT 200",
        vec![],
    )?)))
}

async fn rules(State(s): St, headers: HeaderMap) -> R {
    let conn = s.db.lock().unwrap();
    operator(&conn, &headers)?;
    let rows = db::query(&conn, "SELECT id, yaml, enabled, source, updated_at FROM rules ORDER BY id", vec![])?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|mut r| {
            if let Ok(parsed) = detect::parse_rules(r["yaml"].as_str().unwrap_or_default()) {
                if let Some(p) = parsed.first() {
                    r["title"] = json!(p.title);
                    r["severity"] = json!(p.severity);
                    r["mitre"] = json!(p.mitre);
                    r["kind"] = json!(p.kind);
                    r["response"] = json!(p.response);
                }
            }
            r
        })
        .collect();
    Ok(Json(json!(out)))
}

async fn save_rule(State(s): St, headers: HeaderMap, Json(b): Json<Value>) -> R {
    let saved = {
        let conn = s.db.lock().unwrap();
        let who = operator(&conn, &headers)?;
        let parsed = detect::parse_rules(b["yaml"].as_str().unwrap_or_default()).map_err(|e| bad(e.to_string()))?;
        let source = if b["source"] == "ai" { "ai" } else { "custom" };
        let mut ids = Vec::new();
        for r in &parsed {
            let builtin: Option<String> = conn
                .query_row("SELECT source FROM rules WHERE id = ?1", [&r.id], |x| x.get(0))
                .optional()?;
            if builtin.as_deref() == Some("builtin") {
                return Err(bad(format!("{} is a built-in rule id; choose another id", r.id)));
            }
            let yaml = serde_yaml::to_string(r).map_err(|e| bad(e.to_string()))?;
            conn.execute(
                "INSERT INTO rules(id, yaml, enabled, source, updated_at) VALUES (?1, ?2, 1, ?3, ?4) \
                 ON CONFLICT(id) DO UPDATE SET yaml = excluded.yaml, updated_at = excluded.updated_at",
                params![r.id, yaml, source, now_ms()],
            )?;
            db::audit(&conn, &who, "rule.save", &r.id);
            ids.push(r.id.clone());
        }
        ids
    };
    crate::reload_rules(&s)?;
    Ok(Json(json!({"saved": saved})))
}

async fn toggle_rule(State(s): St, headers: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> R {
    {
        let conn = s.db.lock().unwrap();
        let who = operator(&conn, &headers)?;
        let on = b["enabled"].as_bool().unwrap_or(true);
        conn.execute("UPDATE rules SET enabled = ?1 WHERE id = ?2", params![on as i64, id])?;
        db::audit(&conn, &who, "rule.toggle", &format!("{id} enabled={on}"));
    }
    crate::reload_rules(&s)?;
    Ok(Json(json!({"ok": true})))
}

async fn delete_rule(State(s): St, headers: HeaderMap, Path(id): Path<String>) -> R {
    let n = {
        let conn = s.db.lock().unwrap();
        let who = operator(&conn, &headers)?;
        let n = conn.execute("DELETE FROM rules WHERE id = ?1 AND source != 'builtin'", [&id])?;
        db::audit(&conn, &who, "rule.delete", &id);
        n
    };
    if n == 0 {
        return Err(bad("built-in rules cannot be deleted; disable them instead"));
    }
    crate::reload_rules(&s)?;
    Ok(Json(json!({"deleted": n})))
}

async fn iocs(State(s): St, headers: HeaderMap) -> R {
    let conn = s.db.lock().unwrap();
    operator(&conn, &headers)?;
    Ok(Json(json!(db::query(&conn, "SELECT id, kind, value, note, created_at FROM iocs ORDER BY created_at DESC LIMIT 2000", vec![])?)))
}

async fn add_ioc(State(s): St, headers: HeaderMap, Json(b): Json<Value>) -> R {
    let conn = s.db.lock().unwrap();
    let who = operator(&conn, &headers)?;
    let kind = b["kind"].as_str().unwrap_or_default();
    let value = b["value"].as_str().unwrap_or_default().trim().to_lowercase();
    let ok = match kind {
        "sha256" => value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()),
        "ip" => value.parse::<std::net::IpAddr>().is_ok(),
        _ => false,
    };
    if !ok {
        return Err(bad("kind must be sha256 (64 hex chars) or ip (a valid address)"));
    }
    conn.execute(
        "INSERT OR IGNORE INTO iocs(kind, value, note, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![kind, value, b["note"].as_str(), now_ms()],
    )?;
    db::audit(&conn, &who, "ioc.add", &format!("{kind} {value}"));
    Ok(Json(json!({"ok": true})))
}

async fn delete_ioc(State(s): St, headers: HeaderMap, Path(id): Path<i64>) -> R {
    let conn = s.db.lock().unwrap();
    let who = operator(&conn, &headers)?;
    let n = conn.execute("DELETE FROM iocs WHERE id = ?1", [id])?;
    db::audit(&conn, &who, "ioc.delete", &id.to_string());
    Ok(Json(json!({"deleted": n})))
}

/// XDR ingestion: third-party logs (firewall, cloud, identity provider, ...)
/// posted as events and run through the same detections.
async fn ingest_external(State(s): St, headers: HeaderMap, Json(b): Json<Value>) -> R {
    let conn = s.db.lock().unwrap();
    let who = operator(&conn, &headers)?;
    let source: String = b["source"]
        .as_str()
        .unwrap_or("external")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .take(48)
        .collect();
    if source.is_empty() {
        return Err(bad("source must contain letters, digits, '-', '_' or '.'"));
    }
    let evs: Vec<Event> = b["events"]
        .as_array()
        .ok_or_else(|| bad("events must be an array"))?
        .iter()
        .filter_map(|e| {
            Some(Event {
                ts: e["ts"].as_i64().unwrap_or_else(now_ms),
                kind: e["kind"].as_str().unwrap_or("external").to_string(),
                fields: e["fields"].as_object()?.clone(),
            })
        })
        .collect();
    let id = format!("ext-{source}");
    conn.execute(
        "INSERT INTO endpoints(id, hostname, os, arch, version, key_hash, enrolled_at, last_seen) VALUES (?1, ?2, 'external', '', '', ?3, ?4, ?4) \
         ON CONFLICT(id) DO UPDATE SET last_seen = excluded.last_seen",
        params![id, source, db::sha256_hex(&db::random_token("x")), now_ms()],
    )?;
    let raised = ingest(&s, &conn, &id, "detect", &format!("api:{who}"), &evs)?;
    Ok(Json(json!({"accepted": evs.len(), "alerts": raised})))
}

async fn audit_log(State(s): St, headers: HeaderMap) -> R {
    let conn = s.db.lock().unwrap();
    operator(&conn, &headers)?;
    Ok(Json(json!(db::query(&conn, "SELECT ts, actor, action, detail FROM audit ORDER BY id DESC LIMIT 300", vec![])?)))
}

async fn settings(State(s): St, headers: HeaderMap) -> R {
    let (enroll, stored_key, keys) = {
        let conn = s.db.lock().unwrap();
        operator(&conn, &headers)?;
        (
            db::get_setting(&conn, "enroll_token").unwrap_or_default(),
            db::get_setting(&conn, "ai_api_key").is_some_and(|k| !k.is_empty()),
            db::query(&conn, "SELECT id, name, role, created_at FROM api_keys ORDER BY id", vec![])?,
        )
    };
    let cfg = ai::config(&s);
    Ok(Json(json!({
        "version": postern_proto::VERSION,
        "enroll_token": enroll,
        "api_keys": keys,
        "ai": {
            "configured": cfg.is_some(),
            "key_source": if stored_key { "console" } else if cfg.is_some() { "environment" } else { "none" },
            "model": cfg.as_ref().map(|c| c.model.clone()).unwrap_or_else(|| ai::DEFAULT_MODEL.to_string()),
            "effort": cfg.as_ref().map(|c| c.effort.clone()).unwrap_or_else(|| "high".into()),
            "fallbacks": cfg.as_ref().map(|c| c.fallbacks).unwrap_or(true),
        }
    })))
}

async fn set_ai(State(s): St, headers: HeaderMap, Json(b): Json<Value>) -> R {
    let conn = s.db.lock().unwrap();
    let who = operator(&conn, &headers)?;
    if let Some(k) = b["api_key"].as_str() {
        db::set_setting(&conn, "ai_api_key", k.trim())?;
        db::audit(&conn, &who, "settings.ai_key", if k.trim().is_empty() { "cleared" } else { "updated" });
    }
    if let Some(m) = b["model"].as_str() {
        let m = m.trim();
        if !m.is_empty() && !m.chars().all(|c| c.is_ascii_alphanumeric() || "-._".contains(c)) {
            return Err(bad("model id has invalid characters"));
        }
        db::set_setting(&conn, "ai_model", m)?;
    }
    if let Some(e) = b["effort"].as_str() {
        if !["low", "medium", "high", "xhigh", "max"].contains(&e) {
            return Err(bad("effort must be low, medium, high, xhigh or max"));
        }
        db::set_setting(&conn, "ai_effort", e)?;
    }
    if let Some(f) = b["fallbacks"].as_bool() {
        db::set_setting(&conn, "ai_fallbacks", if f { "default" } else { "off" })?;
    }
    Ok(Json(json!({"ok": true})))
}

async fn create_key(State(s): St, headers: HeaderMap, Json(b): Json<Value>) -> R {
    let conn = s.db.lock().unwrap();
    let who = operator(&conn, &headers)?;
    let name: String = b["name"].as_str().unwrap_or("integration").chars().take(64).collect();
    let key = db::random_token("pck");
    conn.execute(
        "INSERT INTO api_keys(name, key_hash, role, created_at) VALUES (?1, ?2, 'operator', ?3)",
        params![name, db::sha256_hex(&key), now_ms()],
    )?;
    db::audit(&conn, &who, "key.create", &name);
    Ok(Json(json!({"name": name, "key": key, "note": "shown once; store it now"})))
}

fn check_operator(s: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let conn = s.db.lock().unwrap();
    operator(&conn, headers)
}

fn log_ai(s: &AppState, who: &str, what: &str) {
    let conn = s.db.lock().unwrap();
    db::audit(&conn, who, "ai", what);
}

async fn test_ai(State(s): St, headers: HeaderMap) -> R {
    check_operator(&s, &headers)?;
    Ok(Json(ai::ping(&s).await?))
}

async fn ai_triage(State(s): St, headers: HeaderMap, Path(id): Path<i64>) -> R {
    let who = check_operator(&s, &headers)?;
    log_ai(&s, &who, &format!("triage incident #{id}"));
    Ok(Json(ai::triage(&s, id).await?))
}

async fn ai_hunt(State(s): St, headers: HeaderMap, Json(b): Json<Value>) -> R {
    let who = check_operator(&s, &headers)?;
    let q = b["question"].as_str().unwrap_or_default().trim();
    if q.is_empty() {
        return Err(bad("question is required"));
    }
    log_ai(&s, &who, &format!("hunt: {}", q.chars().take(200).collect::<String>()));
    Ok(Json(ai::hunt(&s, q).await?))
}

async fn ai_rule(State(s): St, headers: HeaderMap, Json(b): Json<Value>) -> R {
    let who = check_operator(&s, &headers)?;
    let d = b["description"].as_str().unwrap_or_default().trim();
    if d.is_empty() {
        return Err(bad("description is required"));
    }
    log_ai(&s, &who, &format!("draft rule: {}", d.chars().take(200).collect::<String>()));
    Ok(Json(ai::draft_rule(&s, d).await?))
}
