//! Response actions. Each one is gated by a capability the operator grants
//! when starting the sensor (`--response kill,quarantine,isolate,...`);
//! without it the sensor only observes.

use crate::collect::run;
use postern_proto::{Action, ActionResult};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const CAPABILITIES: &[&str] = &["kill", "quarantine", "isolate", "prevent", "rollback"];

pub struct Responder {
    pub caps: Vec<String>,
    pub quarantine_dir: PathBuf,
    /// Addresses that stay reachable while the host is isolated: the
    /// management server plus anything passed with `--isolate-allow`.
    pub allow: Vec<String>,
}

#[allow(dead_code)]
fn sh(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(cmd).args(args).output().map_err(|e| format!("{cmd}: {e}"))?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if out.status.success() { Ok(text) } else { Err(format!("{cmd} failed: {}", text.trim())) }
}

#[cfg(target_os = "linux")]
const TABLE: &str = "postern_isolate";
#[cfg(windows)]
const RULE: &str = "PosternIsolate";

pub fn is_isolated() -> bool {
    #[cfg(target_os = "linux")]
    return sh("nft", &["list", "table", "inet", TABLE]).is_ok();
    #[cfg(windows)]
    return run("netsh", &["advfirewall", "firewall", "show", "rule", &format!("name={RULE}-out")]).is_some();
    #[cfg(not(any(target_os = "linux", windows)))]
    return false;
}

impl Responder {
    pub fn has(&self, cap: &str) -> bool {
        self.caps.iter().any(|c| c == cap)
    }

    pub fn need(&self, cap: &str) -> Result<(), String> {
        if self.has(cap) {
            Ok(())
        } else {
            Err(format!("this sensor was not started with the `{cap}` response capability"))
        }
    }

    pub fn execute(&self, a: &Action) -> ActionResult {
        let r = match a.kind.as_str() {
            "kill_process" => self.need("kill").and_then(|_| kill(&a.params)),
            "quarantine_file" => self.need("quarantine").and_then(|_| self.quarantine(&a.params)),
            "isolate_host" => self.need("isolate").and_then(|_| self.isolate()),
            "unisolate_host" => self.need("isolate").and_then(|_| unisolate()),
            "collect_triage" => Ok(triage()),
            other => Err(format!("unknown action `{other}`")),
        };
        match r {
            Ok(output) => ActionResult { ok: true, output },
            Err(output) => ActionResult { ok: false, output },
        }
    }

    fn quarantine(&self, p: &serde_json::Value) -> Result<String, String> {
        let src = Path::new(p["path"].as_str().ok_or("missing path")?);
        let meta = fs::symlink_metadata(src).map_err(|e| format!("{}: {e}", src.display()))?;
        if !meta.is_file() {
            return Err(format!("{} is not a regular file", src.display()));
        }
        let lower = src.to_string_lossy().to_lowercase();
        let protected = ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/lib/", "/lib64/", "/boot/", "/system/", "c:\\windows\\", "c:\\program files"];
        if protected.iter().any(|d| lower.starts_with(d)) {
            return Err(format!("{} is in a system directory; quarantine it manually after review", src.display()));
        }
        fs::create_dir_all(&self.quarantine_dir).map_err(|e| e.to_string())?;
        let hash = crate::collect::sha256_file(src).unwrap_or_else(|| "nohash".into());
        let name = src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let dst = self.quarantine_dir.join(format!("{}_{}", &hash[..hash.len().min(16)], name));
        if fs::rename(src, &dst).is_err() {
            fs::copy(src, &dst).map_err(|e| format!("copy to quarantine: {e}"))?;
            fs::remove_file(src).map_err(|e| format!("remove original: {e}"))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.quarantine_dir, fs::Permissions::from_mode(0o700));
            let _ = fs::set_permissions(&dst, fs::Permissions::from_mode(0o000));
        }
        let _ = fs::write(dst.with_extension("origin"), format!("{}\nsha256 {hash}\n", src.display()));
        Ok(format!("moved {} to {} (sha256 {hash})", src.display(), dst.display()))
    }

    fn allowed(&self) -> Result<(Vec<String>, Vec<String>), String> {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for a in &self.allow {
            match a.split('/').next().unwrap_or(a).parse::<IpAddr>() {
                Ok(IpAddr::V4(_)) => v4.push(a.clone()),
                Ok(IpAddr::V6(_)) => v6.push(a.clone()),
                Err(_) => {}
            }
        }
        if v4.is_empty() && v6.is_empty() {
            return Err("no management address resolved; refusing to isolate (the host would be unreachable)".into());
        }
        Ok((v4, v6))
    }

    #[cfg(target_os = "linux")]
    fn isolate(&self) -> Result<String, String> {
        use std::io::Write;
        let (v4, v6) = self.allowed()?;
        let mut rules = String::new();
        for (fam, set) in [("ip", &v4), ("ip6", &v6)] {
            if !set.is_empty() {
                let list = set.join(", ");
                rules.push_str(&format!("    {fam} saddr {{ {list} }} accept\n    {fam} daddr {{ {list} }} accept\n"));
            }
        }
        let script = format!(
            "table inet {TABLE}\ndelete table inet {TABLE}\ntable inet {TABLE} {{\n  chain filter_in {{\n    type filter hook input priority -200; policy drop;\n    iif lo accept\n{rules}  }}\n  chain filter_out {{\n    type filter hook output priority -200; policy drop;\n    oif lo accept\n{rules}  }}\n}}\n"
        );
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("nft: {e}"))?;
        child.stdin.take().unwrap().write_all(script.as_bytes()).map_err(|e| e.to_string())?;
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!("nft failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(format!("host isolated; still reachable: {}", self.allow.join(", ")))
    }

    #[cfg(windows)]
    fn isolate(&self) -> Result<String, String> {
        let (v4, v6) = self.allowed()?;
        let ips = [v4, v6].concat().join(",");
        for dir in ["in", "out"] {
            let _ = sh("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name={RULE}-{dir}")]);
            sh("netsh", &["advfirewall", "firewall", "add", "rule", &format!("name={RULE}-{dir}"), &format!("dir={dir}"), "action=allow", &format!("remoteip={ips}")])?;
        }
        sh("netsh", &["advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"])?;
        Ok(format!("host isolated; still reachable: {ips}"))
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    fn isolate(&self) -> Result<String, String> {
        Err("network isolation is implemented for Linux (nftables) and Windows (Windows Firewall)".into())
    }
}

fn unisolate() -> Result<String, String> {
    #[cfg(target_os = "linux")]
    return sh("nft", &["delete", "table", "inet", TABLE]).map(|_| "network isolation lifted".into());
    #[cfg(windows)]
    {
        sh("netsh", &["advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"])?;
        for dir in ["in", "out"] {
            let _ = sh("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name={RULE}-{dir}")]);
        }
        return Ok("network isolation lifted (firewall policy reset to block inbound, allow outbound)".into());
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    return Err("network isolation is not available on this platform".into());
}

fn kill(p: &serde_json::Value) -> Result<String, String> {
    let pid = p["pid"].as_i64().ok_or("missing pid")?;
    if pid <= 4 || pid == std::process::id() as i64 || pid > i32::MAX as i64 {
        return Err(format!("refusing to kill pid {pid}"));
    }
    kill_pid(pid)
}

#[cfg(unix)]
fn kill_pid(pid: i64) -> Result<String, String> {
    // SAFETY: kill(2) with a validated positive pid and a constant signal.
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    if rc == 0 {
        Ok(format!("sent SIGKILL to pid {pid}"))
    } else {
        Err(format!("kill {pid}: {}", std::io::Error::last_os_error()))
    }
}

#[cfg(windows)]
fn kill_pid(pid: i64) -> Result<String, String> {
    sh("taskkill", &["/F", "/PID", &pid.to_string()]).map(|o| o.trim().to_string())
}

/// Read-only forensic snapshot, capped so it fits in one result.
fn triage() -> String {
    #[cfg(unix)]
    let sections: &[(&str, &str, &[&str])] = &[
        ("logged-in users", "who", &[]),
        ("recent logins", "last", &["-n", "15"]),
        ("processes (by start time)", "ps", &["-eo", "pid,ppid,user,lstart,args", "--sort=-start_time"]),
        ("listening sockets", "ss", &["-tulnp"]),
        ("established connections", "ss", &["-tnp"]),
        ("loaded kernel modules", "lsmod", &[]),
    ];
    #[cfg(windows)]
    let sections: &[(&str, &str, &[&str])] = &[
        ("logged-in users", "query", &["user"]),
        ("processes", "tasklist", &["/v", "/fo", "csv"]),
        ("sockets", "netstat", &["-ano"]),
        ("scheduled tasks", "schtasks", &["/query", "/fo", "csv"]),
        ("services running", "net", &["start"]),
    ];
    let mut out = String::new();
    for (title, cmd, args) in sections {
        let body = run(cmd, args).unwrap_or_else(|| format!("{cmd}: not available"));
        let body: String = body.lines().take(40).collect::<Vec<_>>().join("\n");
        out.push_str(&format!("## {title}\n{body}\n\n"));
    }
    out.chars().take(7500).collect()
}
