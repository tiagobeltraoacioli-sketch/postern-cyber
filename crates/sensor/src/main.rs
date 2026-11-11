//! Postern sensor: endpoint telemetry collection and response execution for
//! Linux and macOS.

mod collect;
mod respond;

use clap::Parser;
use postern_proto::{ActionResult, BatchResponse, EnrollRequest, EnrollResponse, Event, EventBatch, Heartbeat, VERSION};
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use sysinfo::System;

#[derive(Parser)]
#[command(name = "postern-sensor", version, about = "Postern Cyber endpoint sensor")]
struct Args {
    /// Management server base URL, e.g. https://console.example.com
    #[arg(long, env = "POSTERN_SERVER")]
    server: String,
    /// Enrollment token (needed on first start only).
    #[arg(long, env = "POSTERN_ENROLL_TOKEN")]
    enroll_token: Option<String>,
    /// Where the sensor keeps its identity and quarantined files.
    #[arg(long, env = "POSTERN_STATE_DIR")]
    state_dir: Option<PathBuf>,
    /// Response actions this sensor may execute, comma separated:
    /// kill, quarantine, isolate. Empty (the default) means observe only.
    #[arg(long, env = "POSTERN_RESPONSE", default_value = "")]
    response: String,
    /// Extra addresses or CIDRs that stay reachable during isolation
    /// (for example your admin jump host), comma separated.
    #[arg(long, env = "POSTERN_ISOLATE_ALLOW", default_value = "")]
    isolate_allow: String,
    /// Additional files or directories for integrity monitoring.
    #[arg(long = "watch")]
    watch: Vec<PathBuf>,
    /// Seconds between uploads.
    #[arg(long, default_value_t = 5)]
    flush_secs: u64,
}

const MAX_BUFFER: usize = 20_000;

struct Identity {
    agent_id: String,
    agent_key: String,
}

fn load_or_enroll(args: &Args, state_dir: &std::path::Path, http: &ureq::Agent) -> anyhow::Result<Identity> {
    let path = state_dir.join("agent.json");
    if let Ok(text) = std::fs::read_to_string(&path) {
        let r: EnrollResponse = serde_json::from_str(&text)?;
        return Ok(Identity { agent_id: r.agent_id, agent_key: r.agent_key });
    }
    let token = args
        .enroll_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("not enrolled yet: pass --enroll-token (find it in the console under Settings)"))?;
    let req = EnrollRequest {
        enroll_token: token,
        hostname: System::host_name().unwrap_or_else(|| "unknown".into()),
        os: System::long_os_version().unwrap_or_else(|| std::env::consts::OS.into()),
        arch: std::env::consts::ARCH.into(),
        version: VERSION.into(),
    };
    let resp: EnrollResponse = http
        .post(&format!("{}/api/v1/sensor/enroll", args.server.trim_end_matches('/')))
        .send_json(serde_json::to_value(&req)?)
        .map_err(|e| anyhow::anyhow!("enrollment failed: {e}"))?
        .into_json()?;
    std::fs::write(&path, serde_json::to_string(&resp)?)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("enrolled as {}", resp.agent_id);
    Ok(Identity { agent_id: resp.agent_id, agent_key: resp.agent_key })
}

/// Resolve the management server to the addresses isolation must keep open.
fn server_addresses(url: &str) -> Vec<String> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    let default_port = if url.starts_with("https") { 443 } else { 80 };
    let target = if authority.rsplit_once(':').is_some_and(|(_, p)| p.parse::<u16>().is_ok()) {
        authority.to_string()
    } else {
        format!("{authority}:{default_port}")
    };
    target.to_socket_addrs().map(|a| a.map(|s| s.ip().to_string()).collect()).unwrap_or_default()
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let root = unsafe { libc::geteuid() } == 0;
    let state_dir = args.state_dir.clone().unwrap_or_else(|| {
        if root {
            PathBuf::from("/var/lib/postern-sensor")
        } else {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".postern-sensor")
        }
    });
    std::fs::create_dir_all(&state_dir)?;

    let http = ureq::AgentBuilder::new().timeout(Duration::from_secs(20)).build();
    let id = load_or_enroll(&args, &state_dir, &http)?;
    let base = args.server.trim_end_matches('/').to_string();

    let caps: Vec<String> = args.response.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    for c in &caps {
        if !["kill", "quarantine", "isolate"].contains(&c.as_str()) {
            anyhow::bail!("unknown response capability `{c}` (use kill, quarantine, isolate)");
        }
    }
    let mut allow = server_addresses(&base);
    allow.extend(args.isolate_allow.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    let responder = respond::Responder { caps: caps.clone(), quarantine_dir: state_dir.join("quarantine"), allow };

    let mut procs = collect::ProcMon::new();
    let mut net = collect::NetMon::new();
    let mut watch = collect::default_fim_paths();
    watch.extend(args.watch.clone());
    let mut fim = collect::Fim::new(watch);
    let mut auth = collect::AuthLog::new();

    println!(
        "postern-sensor {VERSION} agent={} server={base} root={root} response=[{}] auth_log={}",
        id.agent_id,
        caps.join(","),
        auth.available()
    );
    if !root {
        println!("note: running without root - other users' process details, the auth log and the firewall may not be visible");
    }

    let mut buffer: Vec<Event> = Vec::new();
    let started = Instant::now();
    let every = |secs: u64, tick: u64| tick % secs == 0;
    let mut tick: u64 = 0;
    let mut isolated = respond::is_isolated();
    let mut failures = 0u32;

    loop {
        if every(2, tick) {
            procs.poll(&mut buffer);
        }
        if every(5, tick) {
            auth.poll(&mut buffer);
        }
        if every(10, tick) {
            net.poll(&mut buffer);
        }
        if every(30, tick) {
            fim.poll(&mut buffer);
        }
        if every(6 * 3600, tick) {
            buffer.push(collect::inventory());
            collect::posture(&mut buffer);
        }
        if buffer.len() > MAX_BUFFER {
            let drop = buffer.len() - MAX_BUFFER;
            buffer.drain(..drop);
        }

        if every(args.flush_secs.max(1), tick) {
            procs.sys.refresh_cpu();
            procs.sys.refresh_memory();
            let heartbeat = Heartbeat {
                version: VERSION.into(),
                uptime_secs: started.elapsed().as_secs(),
                cpu_pct: procs.sys.global_cpu_info().cpu_usage(),
                mem_used_mb: procs.sys.used_memory() / 1_048_576,
                mem_total_mb: procs.sys.total_memory() / 1_048_576,
                isolated,
                response_caps: caps.clone(),
            };
            let batch = EventBatch { heartbeat, events: std::mem::take(&mut buffer) };
            let sent = http
                .post(&format!("{base}/api/v1/sensor/events"))
                .set("Authorization", &format!("Bearer {}", id.agent_key))
                .send_json(serde_json::to_value(&batch)?);
            match sent.map_err(anyhow::Error::from).and_then(|r| Ok(r.into_json::<BatchResponse>()?)) {
                Ok(resp) => {
                    failures = 0;
                    for action in resp.actions {
                        let result: ActionResult = responder.execute(&action);
                        println!("action {} {} -> ok={} {}", action.kind, action.id, result.ok, result.output.lines().next().unwrap_or(""));
                        if result.ok && action.kind == "isolate_host" {
                            isolated = true;
                        }
                        if result.ok && action.kind == "unisolate_host" {
                            isolated = false;
                        }
                        let _ = http
                            .post(&format!("{base}/api/v1/sensor/actions/{}/result", action.id))
                            .set("Authorization", &format!("Bearer {}", id.agent_key))
                            .send_json(serde_json::to_value(&result)?);
                    }
                }
                Err(e) => {
                    // Keep the telemetry and retry on the next flush.
                    buffer = batch.events;
                    failures += 1;
                    if failures == 1 || failures % 60 == 0 {
                        eprintln!("upload failed ({failures}x): {e}");
                    }
                }
            }
        }

        tick += 1;
        std::thread::sleep(Duration::from_secs(1));
    }
}
