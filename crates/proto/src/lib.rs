//! Wire types shared by the Postern sensor and the Postern server.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::time::{SystemTime, UNIX_EPOCH};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// One telemetry record. `fields` is a flat map with dotted keys
/// (`process.cmdline`, `file.path`, `net.remote_ip`, ...) so detection rules
/// can address any field without a schema change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ts: i64,
    pub kind: String,
    #[serde(default)]
    pub fields: Map<String, Value>,
}

impl Event {
    pub fn new(kind: &str) -> Self {
        Event { ts: now_ms(), kind: kind.to_string(), fields: Map::new() }
    }

    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.fields.insert(key.to_string(), value.into());
        self
    }

    /// Field rendered as text: strings as-is, numbers and booleans formatted.
    pub fn text(&self, key: &str) -> Option<String> {
        match self.fields.get(key)? {
            Value::String(s) => Some(s.clone()),
            Value::Null => None,
            other => Some(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub enroll_token: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub agent_id: String,
    pub agent_key: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Heartbeat {
    pub version: String,
    pub uptime_secs: u64,
    pub cpu_pct: f32,
    pub mem_used_mb: u64,
    pub mem_total_mb: u64,
    pub isolated: bool,
    /// Response actions this sensor was started with permission to execute.
    pub response_caps: Vec<String>,
    /// How process starts are observed: `kernel` (pushed by the kernel) or `poll`.
    #[serde(default)]
    pub process_source: String,
    /// `enforce` (execution can be denied), `observe` or `off`.
    #[serde(default)]
    pub exec_guard: String,
    #[serde(default)]
    pub vault: Option<VaultStatus>,
}

/// State of the ransomware-rollback vault on a sensor.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultStatus {
    pub protected: Vec<String>,
    pub snapshots: u32,
    pub last_snapshot: i64,
    pub files: u64,
    pub stored_mb: u64,
    /// The last pass saw mass modification consistent with encryption;
    /// older snapshots are being retained.
    pub suspect: bool,
}

/// Execution-prevention policy pushed from the server to sensors.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// SHA-256 of binaries that must not run.
    #[serde(default)]
    pub block_hashes: Vec<String>,
    /// Path prefixes binaries must not run from (for example `/dev/shm/`).
    #[serde(default)]
    pub block_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBatch {
    pub heartbeat: Heartbeat,
    pub events: Vec<Event>,
}

/// A response action queued by the console (or by policy) for a sensor.
/// Kinds: `kill_process`, `quarantine_file`, `isolate_host`, `unisolate_host`,
/// `collect_triage`, `rollback_files`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResponse {
    pub actions: Vec<Action>,
    /// `detect` or `protect`.
    pub mode: String,
    #[serde(default)]
    pub policy: Policy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub ok: bool,
    pub output: String,
}
