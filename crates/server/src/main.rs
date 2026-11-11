//! Postern Cyber management server: telemetry ingestion, detection,
//! incident correlation, response orchestration, AI analyst and console.

mod ai;
mod api;
mod db;
mod detect;

use clap::Parser;
use rusqlite::{params, Connection};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
#[command(name = "postern-server", version, about = "Postern Cyber management server")]
struct Args {
    /// Address to listen on. Plain HTTP: bind to loopback and put a TLS
    /// terminator (Caddy, nginx, cloudflared) in front for remote access.
    #[arg(long, env = "POSTERN_LISTEN", default_value = "127.0.0.1:8460")]
    listen: String,
    /// Directory for the database and the admin token file.
    #[arg(long, env = "POSTERN_DATA_DIR", default_value = "./data")]
    data_dir: PathBuf,
    /// Days of raw telemetry to keep.
    #[arg(long, env = "POSTERN_RETENTION_DAYS", default_value_t = 30)]
    retention_days: i64,
}

pub struct AppState {
    pub db: Mutex<Connection>,
    pub engine: Mutex<detect::Engine>,
    pub http: reqwest::Client,
}

/// Rebuild the in-memory engine from the enabled rules in the database.
pub fn reload_rules(state: &AppState) -> anyhow::Result<()> {
    let rules = {
        let conn = state.db.lock().unwrap();
        let mut st = conn.prepare("SELECT yaml FROM rules WHERE enabled = 1")?;
        let yamls: Vec<String> = st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
        yamls.iter().filter_map(|y| detect::parse_rules(y).ok()).flatten().collect::<Vec<_>>()
    };
    state.engine.lock().unwrap().load(rules);
    Ok(())
}

fn bootstrap(conn: &Connection, data_dir: &std::path::Path) -> anyhow::Result<()> {
    // Built-in rules: refresh the definition, keep the operator's enabled flag.
    for rule in detect::parse_rules(detect::BUILTIN_RULES)? {
        conn.execute(
            "INSERT INTO rules(id, yaml, enabled, source, updated_at) VALUES (?1, ?2, 1, 'builtin', ?3) \
             ON CONFLICT(id) DO UPDATE SET yaml = excluded.yaml, updated_at = excluded.updated_at WHERE rules.source = 'builtin'",
            params![rule.id, serde_yaml::to_string(&rule)?, postern_proto::now_ms()],
        )?;
    }
    if db::get_setting(conn, "enroll_token").is_none() {
        db::set_setting(conn, "enroll_token", &db::random_token("pce"))?;
    }
    let admins: i64 = conn.query_row("SELECT COUNT(*) FROM api_keys WHERE role = 'admin'", [], |r| r.get(0))?;
    if admins == 0 {
        let token = db::random_token("pca");
        conn.execute(
            "INSERT INTO api_keys(name, key_hash, role, created_at) VALUES ('admin', ?1, 'admin', ?2)",
            params![db::sha256_hex(&token), postern_proto::now_ms()],
        )?;
        let path = data_dir.join("admin.token");
        std::fs::write(&path, format!("{token}\n"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        println!("admin token written to {} (shown here once): {token}", path.display());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    std::fs::create_dir_all(&args.data_dir)?;
    let conn = db::open(&args.data_dir.join("postern.db"))?;
    bootstrap(&conn, &args.data_dir)?;

    let state = Arc::new(AppState {
        db: Mutex::new(conn),
        engine: Mutex::new(detect::Engine::default()),
        // Triage on a hard incident can run for minutes on the largest models.
        http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(900)).build()?,
    });
    reload_rules(&state)?;

    let retention = state.clone();
    let days = args.retention_days.max(1);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tick.tick().await;
            let cutoff = postern_proto::now_ms() - days * 86_400_000;
            let conn = retention.db.lock().unwrap();
            // Events referenced by an alert are evidence; keep them.
            let _ = conn.execute(
                "DELETE FROM events WHERE ts < ?1 AND id NOT IN (SELECT event_id FROM alerts WHERE event_id IS NOT NULL)",
                [cutoff],
            );
        }
    });

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    println!(
        "postern-server {} listening on http://{} ({} rules loaded)",
        postern_proto::VERSION,
        args.listen,
        state.engine.lock().unwrap().rule_count()
    );
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
