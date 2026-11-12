//! Portable telemetry collectors. Platform-specific sources (sockets, auth
//! log, posture, inventory) live in `platform`.

use crate::platform;
use postern_proto::Event;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, UNIX_EPOCH};
use sysinfo::System;

const HASH_LIMIT: u64 = 64 * 1024 * 1024;

pub fn sha256_reader(mut r: impl Read) -> Option<String> {
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = r.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex::encode(h.finalize()))
}

pub fn sha256_file(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > HASH_LIMIT {
        return None;
    }
    sha256_reader(fs::File::open(path).ok()?)
}

pub fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Modification time in nanoseconds since the epoch.
pub fn mtime_ns(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

// ------------------------------------------------------------------ process

pub struct ProcMon {
    pub sys: System,
    known: HashMap<u32, u64>,
    hashes: HashMap<PathBuf, (i64, u64, Option<String>)>,
    users: HashMap<String, String>,
    /// Pids already reported by the kernel event source; the poller skips them.
    reported: HashSet<u32>,
    primed: bool,
}

impl ProcMon {
    pub fn new() -> Self {
        // Do not hold one /proc/<pid>/stat descriptor per process on Linux.
        #[cfg(target_os = "linux")]
        sysinfo::set_open_files_limit(0);
        ProcMon {
            sys: System::new(),
            known: HashMap::new(),
            hashes: HashMap::new(),
            users: platform::users_by_uid(),
            reported: HashSet::new(),
            primed: false,
        }
    }

    pub fn exe_hash(&mut self, exe: &Path) -> Option<String> {
        let meta = fs::metadata(exe).ok()?;
        let key = (mtime_ns(&meta), meta.len());
        if let Some((m, l, h)) = self.hashes.get(exe) {
            if (*m, *l) == key {
                return h.clone();
            }
        }
        let h = sha256_file(exe);
        if self.hashes.len() > 4096 {
            self.hashes.clear();
        }
        self.hashes.insert(exe.to_path_buf(), (key.0, key.1, h.clone()));
        h
    }

    pub fn user_name(&self, uid: &str) -> String {
        self.users.get(uid).cloned().unwrap_or_else(|| uid.to_string())
    }

    pub fn mark_reported(&mut self, pid: u32) {
        self.reported.insert(pid);
    }

    pub fn process_name(&self, pid: u32) -> Option<String> {
        self.sys.process(sysinfo::Pid::from_u32(pid)).map(|p| p.name().to_string())
    }

    pub fn poll(&mut self, out: &mut Vec<Event>) {
        let once = sysinfo::UpdateKind::OnlyIfNotSet;
        self.sys.refresh_processes_specifics(sysinfo::ProcessRefreshKind::new().with_cmd(once).with_exe(once).with_user(once));
        let me = std::process::id();
        let mut current = HashMap::with_capacity(self.known.len());
        let mut fresh = Vec::new();
        for (pid, p) in self.sys.processes() {
            let pid = pid.as_u32();
            current.insert(pid, p.start_time());
            if self.primed && self.known.get(&pid) != Some(&p.start_time()) && pid != me && !self.reported.contains(&pid) {
                fresh.push(pid);
            }
        }
        for pid in fresh {
            let Some(p) = self.sys.process(sysinfo::Pid::from_u32(pid)) else { continue };
            // Threads show up as processes on Linux; only report the leader.
            #[cfg(target_os = "linux")]
            if p.thread_kind().is_some() {
                continue;
            }
            let exe = p.exe().map(Path::to_path_buf);
            let cmdline = if p.cmd().is_empty() { p.name().to_string() } else { p.cmd().join(" ") };
            let ppid = p.parent().map(|x| x.as_u32());
            let parent_name = p.parent().and_then(|pp| self.sys.process(pp)).map(|pp| pp.name().to_string());
            let uid = p.user_id().map(|u| u.to_string());
            let mut ev = Event::new("process_start")
                .with("process.pid", pid)
                .with("process.name", p.name())
                .with("process.cmdline", cmdline.chars().take(4096).collect::<String>())
                .with("process.start_time", p.start_time())
                .with("process.source", "poll");
            if let Some(ppid) = ppid {
                ev = ev.with("process.ppid", ppid);
            }
            if let Some(n) = parent_name {
                ev = ev.with("process.parent_name", n);
            }
            if let Some(uid) = uid {
                ev = ev.with("process.user", self.user_name(&uid)).with("process.uid", uid);
            }
            if let Some(exe) = exe {
                ev = ev.with("process.exe", exe.to_string_lossy().into_owned());
                if let Some(h) = self.exe_hash(&exe) {
                    ev = ev.with("process.sha256", h);
                }
            }
            out.push(ev);
        }
        self.reported.retain(|pid| current.contains_key(pid));
        self.known = current;
        self.primed = true;
    }
}

// ------------------------------------------------------------------ network

#[derive(Debug)]
pub struct Sock {
    pub listen: bool,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub pname: String,
    pub pid: Option<u32>,
}

pub fn split_addr(s: &str) -> Option<(String, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    let host = host.trim_matches(|c| c == '[' || c == ']');
    let host = host.split('%').next().unwrap_or(host);
    Some((host.to_string(), port.parse().unwrap_or(0)))
}

fn is_local(ip: &str) -> bool {
    ip.starts_with("127.") || ip == "::1" || ip == "*" || ip == "0.0.0.0" || ip == "::" || ip.is_empty()
}

pub struct NetMon {
    listeners: HashSet<(u16, String)>,
    conns: HashMap<(String, u16, String), Instant>,
    primed: bool,
}

impl NetMon {
    pub fn new() -> Self {
        NetMon { listeners: HashSet::new(), conns: HashMap::new(), primed: false }
    }

    pub fn poll(&mut self, procs: &ProcMon, out: &mut Vec<Event>) {
        let mut socks = platform::sockets();
        for s in &mut socks {
            if s.pname.is_empty() {
                if let Some(n) = s.pid.and_then(|pid| procs.process_name(pid)) {
                    s.pname = n;
                }
            }
        }
        let listening: HashSet<u16> = socks.iter().filter(|s| s.listen).map(|s| s.local_port).collect();
        let now = Instant::now();
        self.conns.retain(|_, seen| now.duration_since(*seen) < Duration::from_secs(600));
        for s in &socks {
            if s.listen {
                if self.listeners.insert((s.local_port, s.pname.clone())) {
                    let mut ev = Event::new("listen_port")
                        .with("net.local_port", s.local_port)
                        .with("net.protocol", "tcp")
                        .with("process.name", s.pname.clone());
                    if let Some(pid) = s.pid {
                        ev = ev.with("process.pid", pid);
                    }
                    if !self.primed {
                        ev = ev.with("net.baseline", true);
                    }
                    out.push(ev);
                }
            } else if !is_local(&s.remote_ip) {
                let key = (s.remote_ip.clone(), s.remote_port, s.pname.clone());
                let first = self.conns.insert(key, now).is_none();
                if first && self.primed {
                    let inbound = listening.contains(&s.local_port);
                    let mut ev = Event::new("net_conn")
                        .with("net.direction", if inbound { "inbound" } else { "outbound" })
                        .with("net.remote_ip", s.remote_ip.clone())
                        .with("net.remote_port", s.remote_port)
                        .with("net.local_port", s.local_port)
                        .with("net.protocol", "tcp")
                        .with("process.name", s.pname.clone());
                    if let Some(pid) = s.pid {
                        ev = ev.with("process.pid", pid);
                    }
                    out.push(ev);
                }
            }
        }
        self.primed = true;
    }
}

// ----------------------------------------------------------- file integrity

pub struct Fim {
    roots: Vec<PathBuf>,
    state: HashMap<PathBuf, (i64, u64)>,
    primed: bool,
}

impl Fim {
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Fim { roots, state: HashMap::new(), primed: false }
    }

    fn walk(path: &Path, depth: u8, acc: &mut HashMap<PathBuf, (i64, u64)>) {
        if acc.len() >= 8000 {
            return;
        }
        let Ok(meta) = fs::symlink_metadata(path) else { return };
        if meta.is_file() {
            acc.insert(path.to_path_buf(), (mtime_ns(&meta), meta.len()));
        } else if meta.is_dir() && depth > 0 {
            for e in fs::read_dir(path).into_iter().flatten().flatten() {
                Self::walk(&e.path(), depth - 1, acc);
            }
        }
    }

    pub fn poll(&mut self, out: &mut Vec<Event>) {
        let mut now = HashMap::new();
        for r in &self.roots {
            Self::walk(r, 2, &mut now);
        }
        if self.primed {
            for (path, sig) in &now {
                let action = match self.state.get(path) {
                    None => "created",
                    Some(old) if old != sig => "modified",
                    _ => continue,
                };
                let mut ev = Event::new("file_change")
                    .with("file.path", path.to_string_lossy().into_owned())
                    .with("file.action", action)
                    .with("file.size", sig.1);
                if let Some(h) = sha256_file(path) {
                    ev = ev.with("file.sha256", h);
                }
                #[cfg(unix)]
                if let Ok(m) = fs::metadata(path) {
                    use std::os::unix::fs::{MetadataExt, PermissionsExt};
                    ev = ev.with("file.mode", format!("{:o}", m.permissions().mode() & 0o7777)).with("file.uid", m.uid());
                }
                out.push(ev);
            }
            for path in self.state.keys().filter(|p| !now.contains_key(*p)) {
                out.push(Event::new("file_change").with("file.path", path.to_string_lossy().into_owned()).with("file.action", "deleted"));
            }
        }
        self.state = now;
        self.primed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_addresses() {
        assert_eq!(split_addr("10.0.0.1:22").unwrap(), ("10.0.0.1".to_string(), 22));
        assert_eq!(split_addr("[::1]:8080").unwrap(), ("::1".to_string(), 8080));
        assert_eq!(split_addr("0.0.0.0:*").unwrap().1, 0);
    }
}
