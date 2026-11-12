//! Postern sensor: endpoint telemetry collection, execution prevention,
//! ransomware rollback and response execution for Linux, macOS and Windows.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod collect;
#[cfg(target_os = "linux")]
mod kernel;
#[cfg(unix)]
mod platform_unix;
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod platform_windows;
mod respond;
mod vault;

#[cfg(unix)]
use platform_unix as platform;
#[cfg(windows)]
use platform_windows as platform;

use clap::Parser;
use postern_proto::{ActionResult, BatchResponse, EnrollRequest, EnrollResponse, Event, EventBatch, Heartbeat, Policy, VERSION};
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
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
    /// Where the sensor keeps its identity, quarantine and vault.
    #[arg(long, env = "POSTERN_STATE_DIR")]
    state_dir: Option<PathBuf>,
    /// What this sensor may do beyond observing, comma separated:
    /// kill, quarantine, isolate, prevent (deny execution, Linux), rollback.
    #[arg(long, env = "POSTERN_RESPONSE", default_value = "")]
    response: String,
    /// Extra addresses or CIDRs that stay reachable during isolation
    /// (for example your admin jump host), comma separated.
    #[arg(long, env = "POSTERN_ISOLATE_ALLOW", default_value = "")]
    isolate_allow: String,
    /// Additional files or directories for integrity monitoring.
    #[arg(long = "watch", env = "POSTERN_WATCH", value_delimiter = ',')]
    watch: Vec<PathBuf>,
    /// Directories to keep versioned copies of for ransomware rollback.
    #[arg(long = "protect", env = "POSTERN_PROTECT", value_delimiter = ',')]
    protect: Vec<PathBuf>,
    /// Seconds between vault snapshots.
    #[arg(long, env = "POSTERN_VAULT_INTERVAL", default_value_t = 900)]
    vault_interval_secs: u64,
    /// Upper bound for the vault's stored file versions, in GiB.
    #[arg(long, env = "POSTERN_VAULT_MAX_GB", default_value_t = 20)]
    vault_max_gb: u64,
    /// Seconds between uploads.
    #[arg(long, default_value_t = 5)]
    flush_secs: u64,
}

const MAX_BUFFER: usize = 20_000;

struct Identity {
    agent_id: String,
    agent_key: String,
}

fn http_agent() -> anyhow::Result<ureq::Agent> {
    let b = ureq::AgentBuilder::new().timeout(Duration::from_secs(20));
    // Windows uses the system TLS stack (SChannel) and certificate store.
    #[cfg(windows)]
    let b = b.tls_connector(Arc::new(native_tls::TlsConnector::new()?));
    Ok(b.build())
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
        .filter(|t| !t.is_empty())
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
    #[cfg(unix)]
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
    let admin = platform::is_admin();
    let state_dir = args.state_dir.clone().unwrap_or_else(platform::default_state_dir);
    std::fs::create_dir_all(&state_dir)?;

    let http = http_agent()?;
    let id = load_or_enroll(&args, &state_dir, &http)?;
    let base = args.server.trim_end_matches('/').to_string();

    let caps: Vec<String> = args.response.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    for c in &caps {
        if !respond::CAPABILITIES.contains(&c.as_str()) {
            anyhow::bail!("unknown response capability `{c}` (use {})", respond::CAPABILITIES.join(", "));
        }
    }
    let mut allow = server_addresses(&base);
    allow.extend(args.isolate_allow.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    let responder = respond::Responder { caps: caps.clone(), quarantine_dir: state_dir.join("quarantine"), allow };

    let mut procs = collect::ProcMon::new();
    let mut net = collect::NetMon::new();
    let mut watch = platform::default_fim_paths();
    watch.extend(args.watch.clone());
    let mut fim = collect::Fim::new(watch);
    let mut auth = platform::AuthLog::new();
    let mut vault = if args.protect.is_empty() {
        None
    } else {
        Some(vault::Vault::open(state_dir.join("vault"), args.protect.clone(), args.vault_max_gb)?)
    };

    // Execution policy: the last one the server sent, kept across restarts.
    let policy_path = state_dir.join("policy.json");
    let policy = Arc::new(RwLock::new(
        std::fs::read(&policy_path).ok().and_then(|b| serde_json::from_slice::<Policy>(&b).ok()).unwrap_or_default(),
    ));
    let protect = Arc::new(AtomicBool::new(false));
    #[allow(unused_mut)]
    let (mut process_source, mut exec_guard) = ("poll", "off");

    #[cfg(target_os = "linux")]
    let (proc_rx, blocked_rx) = {
        let (ptx, prx) = std::sync::mpsc::channel();
        let (btx, brx) = std::sync::mpsc::channel();
        if admin {
            let cache: kernel::ExecCache = Default::default();
            match kernel::start_proc_connector(ptx, cache.clone()) {
                Ok(()) => process_source = "kernel",
                Err(e) => eprintln!("kernel process events unavailable ({e}); falling back to polling"),
            }
            let enforce = responder.has("prevent");
            let cfg = kernel::GuardConfig { enforce, policy: policy.clone(), protect: protect.clone(), cache, blocked: btx };
            match kernel::start_exec_guard(cfg) {
                Ok(()) => exec_guard = if enforce { "enforce" } else { "observe" },
                Err(e) => eprintln!("exec guard unavailable ({e})"),
            }
        }
        (prx, brx)
    };

    println!(
        "postern-sensor {VERSION} agent={} server={base} admin={admin} response=[{}] processes={process_source} exec_guard={exec_guard} auth_log={} vault={}",
        id.agent_id,
        caps.join(","),
        auth.available(),
        vault.as_ref().map(|v| v.status().protected.join(",")).unwrap_or_else(|| "off".into()),
    );
    if !admin {
        println!("note: running unprivileged - other users' processes, the auth log, kernel events and the firewall may not be visible");
    }
    if responder.has("prevent") && exec_guard != "enforce" {
        println!("note: `prevent` was granted but execution blocking is only available on Linux as root");
    }

    let mut buffer: Vec<Event> = Vec::new();
    let started = Instant::now();
    let every = |secs: u64, tick: u64| tick % secs == 0;
    let mut tick: u64 = 0;
    let mut isolated = respond::is_isolated();
    let mut failures = 0u32;

    loop {
        #[cfg(target_os = "linux")]
        {
            for r in proc_rx.try_iter() {
                procs.mark_reported(r.pid);
                let mut ev = Event::new("process_start")
                    .with("process.pid", r.pid)
                    .with("process.name", r.name)
                    .with("process.cmdline", r.cmdline)
                    .with("process.source", "kernel");
                if r.short_lived {
                    ev = ev.with("process.short_lived", true);
                }
                if let Some(ppid) = r.ppid {
                    ev = ev.with("process.ppid", ppid);
                }
                if let Some(n) = r.parent_name {
                    ev = ev.with("process.parent_name", n);
                }
                if let Some(uid) = r.uid {
                    ev = ev.with("process.user", procs.user_name(&uid)).with("process.uid", uid);
                }
                let sha = r.sha256.or_else(|| r.exe.as_ref().and_then(|e| procs.exe_hash(std::path::Path::new(e))));
                if let Some(exe) = r.exe {
                    ev = ev.with("process.exe", exe);
                }
                if let Some(h) = sha {
                    ev = ev.with("process.sha256", h);
                }
                buffer.push(ev);
            }
            buffer.extend(blocked_rx.try_iter());
        }
        // With kernel events the poller only reconciles what the kernel
        // dropped under load, so it can run less often.
        if every(if process_source == "kernel" { 10 } else { 2 }, tick) {
            procs.poll(&mut buffer);
        }
        if every(5, tick) {
            auth.poll(&mut buffer);
            if let Some(v) = vault.as_mut() {
                v.check_canaries(&mut buffer);
            }
        }
        if every(10, tick) {
            net.poll(&procs, &mut buffer);
        }
        if every(30, tick) {
            fim.poll(&mut buffer);
        }
        if every(args.vault_interval_secs.max(30), tick) {
            if let Some(v) = vault.as_mut() {
                v.snapshot(&mut buffer);
            }
        }
        if every(6 * 3600, tick) {
            buffer.push(platform::inventory());
            platform::posture(&mut buffer);
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
                process_source: process_source.into(),
                exec_guard: exec_guard.into(),
                vault: vault.as_ref().map(|v| v.status()),
            };
            let batch = EventBatch { heartbeat, events: std::mem::take(&mut buffer) };
            let sent = http
                .post(&format!("{base}/api/v1/sensor/events"))
                .set("Authorization", &format!("Bearer {}", id.agent_key))
                .send_json(serde_json::to_value(&batch)?);
            match sent.map_err(anyhow::Error::from).and_then(|r| Ok(r.into_json::<BatchResponse>()?)) {
                Ok(resp) => {
                    failures = 0;
                    protect.store(resp.mode == "protect", Ordering::Relaxed);
                    if *policy.read().unwrap() != resp.policy {
                        let _ = std::fs::write(&policy_path, serde_json::to_vec(&resp.policy)?);
                        *policy.write().unwrap() = resp.policy;
                    }
                    for action in resp.actions {
                        let result: ActionResult = match (action.kind.as_str(), vault.as_mut()) {
                            ("rollback_files" | "vault_accept", None) => ActionResult { ok: false, output: "this sensor has no protected directories (--protect)".into() },
                            ("rollback_files", Some(v)) => match responder.need("rollback").and_then(|_| v.rollback(action.params["path"].as_str(), action.params["snapshot"].as_i64())) {
                                Ok(output) => ActionResult { ok: true, output },
                                Err(output) => ActionResult { ok: false, output },
                            },
                            ("vault_accept", Some(v)) => match responder.need("rollback") {
                                Ok(()) => ActionResult { ok: true, output: v.accept() },
                                Err(output) => ActionResult { ok: false, output },
                            },
                            _ => responder.execute(&action),
                        };
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
