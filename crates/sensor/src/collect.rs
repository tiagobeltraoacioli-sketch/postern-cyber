//! Telemetry collectors. Every collector is poll-based and keeps its own
//! baseline so the first pass does not flood the server with existing state.

use postern_proto::Event;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use sysinfo::System;

const HASH_LIMIT: u64 = 64 * 1024 * 1024;

pub fn sha256_file(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > HASH_LIMIT {
        return None;
    }
    let mut f = fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex::encode(h.finalize()))
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn users_by_uid() -> HashMap<String, String> {
    fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut p = l.split(':');
            let name = p.next()?;
            let uid = p.nth(1)?;
            Some((uid.to_string(), name.to_string()))
        })
        .collect()
}

// ------------------------------------------------------------------ process

pub struct ProcMon {
    pub sys: System,
    known: HashMap<u32, u64>,
    hashes: HashMap<PathBuf, (i64, u64, Option<String>)>,
    users: HashMap<String, String>,
    primed: bool,
}

impl ProcMon {
    pub fn new() -> Self {
        // Do not hold one /proc/<pid>/stat descriptor per process on Linux.
        sysinfo::set_open_files_limit(0);
        ProcMon { sys: System::new(), known: HashMap::new(), hashes: HashMap::new(), users: users_by_uid(), primed: false }
    }

    fn exe_hash(&mut self, exe: &Path) -> Option<String> {
        let meta = fs::metadata(exe).ok()?;
        let key = (meta.mtime(), meta.len());
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

    pub fn poll(&mut self, out: &mut Vec<Event>) {
        let once = sysinfo::UpdateKind::OnlyIfNotSet;
        self.sys.refresh_processes_specifics(
            sysinfo::ProcessRefreshKind::new().with_cmd(once).with_exe(once).with_user(once),
        );
        let me = std::process::id();
        let mut current = HashMap::with_capacity(self.known.len());
        let mut fresh = Vec::new();
        for (pid, p) in self.sys.processes() {
            let pid = pid.as_u32();
            current.insert(pid, p.start_time());
            if self.primed && self.known.get(&pid) != Some(&p.start_time()) && pid != me {
                fresh.push(pid);
            }
        }
        for pid in fresh {
            let Some(p) = self.sys.process(sysinfo::Pid::from_u32(pid)) else { continue };
            let exe = p.exe().map(Path::to_path_buf);
            let cmdline = if p.cmd().is_empty() { p.name().to_string() } else { p.cmd().join(" ") };
            let ppid = p.parent().map(|x| x.as_u32());
            let parent_name = p.parent().and_then(|pp| self.sys.process(pp)).map(|pp| pp.name().to_string());
            let uid = p.user_id().map(|u| u.to_string());
            let mut ev = Event::new("process_start")
                .with("process.pid", pid)
                .with("process.name", p.name())
                .with("process.cmdline", cmdline.chars().take(4096).collect::<String>())
                .with("process.start_time", p.start_time());
            if let Some(ppid) = ppid {
                ev = ev.with("process.ppid", ppid);
            }
            if let Some(n) = parent_name {
                ev = ev.with("process.parent_name", n);
            }
            if let Some(uid) = uid {
                let name = self.users.get(&uid).cloned().unwrap_or_else(|| uid.clone());
                ev = ev.with("process.user", name).with("process.uid", uid);
            }
            if let Some(exe) = exe {
                ev = ev.with("process.exe", exe.to_string_lossy().into_owned());
                if let Some(h) = self.exe_hash(&exe) {
                    ev = ev.with("process.sha256", h);
                }
            }
            out.push(ev);
        }
        self.known = current;
        self.primed = true;
    }
}

// ------------------------------------------------------------------ network

#[derive(Debug)]
struct Sock {
    listen: bool,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    pname: String,
    pid: Option<u32>,
}

fn split_addr(s: &str) -> Option<(String, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    let host = host.trim_matches(|c| c == '[' || c == ']');
    let host = host.split('%').next().unwrap_or(host);
    Some((host.to_string(), port.parse().unwrap_or(0)))
}

fn sockets_linux() -> Vec<Sock> {
    let mut v = Vec::new();
    for (args, listen) in [(["-H", "-tnp"], false), (["-H", "-tlnp"], true)] {
        let Some(out) = run("ss", &args) else { continue };
        for line in out.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 5 {
                continue;
            }
            let (Some((_, lport)), Some((rip, rport))) = (split_addr(f[3]), split_addr(f[4])) else { continue };
            let proc_info = f.get(5).copied().unwrap_or("");
            let pname = proc_info.split('"').nth(1).unwrap_or("").to_string();
            let pid = proc_info.split("pid=").nth(1).and_then(|x| x.split(',').next()).and_then(|x| x.parse().ok());
            v.push(Sock { listen, local_port: lport, remote_ip: rip, remote_port: rport, pname, pid });
        }
    }
    v
}

fn sockets_macos() -> Vec<Sock> {
    let mut v = Vec::new();
    let Some(out) = run("lsof", &["-nP", "-iTCP"]) else { return v };
    for line in out.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let state = f[f.len() - 1];
        let name = f[f.len() - 2];
        let pid = f[1].parse().ok();
        let pname = f[0].to_string();
        if state == "(LISTEN)" {
            if let Some((_, lport)) = split_addr(name) {
                v.push(Sock { listen: true, local_port: lport, remote_ip: String::new(), remote_port: 0, pname, pid });
            }
        } else if state == "(ESTABLISHED)" {
            let Some((l, r)) = name.split_once("->") else { continue };
            if let (Some((_, lport)), Some((rip, rport))) = (split_addr(l), split_addr(r)) {
                v.push(Sock { listen: false, local_port: lport, remote_ip: rip, remote_port: rport, pname, pid });
            }
        }
    }
    v
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

    pub fn poll(&mut self, out: &mut Vec<Event>) {
        let socks = if cfg!(target_os = "macos") { sockets_macos() } else { sockets_linux() };
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

pub fn default_fim_paths() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = [
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d", "/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/var/spool/cron", "/etc/systemd/system", "/etc/ld.so.preload", "/etc/ld.so.conf.d", "/etc/pam.d",
        "/etc/hosts", "/etc/resolv.conf", "/etc/profile.d", "/root/.ssh/authorized_keys", "/root/.bashrc",
        "/Library/LaunchDaemons", "/Library/LaunchAgents",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    for base in ["/home", "/Users"] {
        for e in fs::read_dir(base).into_iter().flatten().flatten() {
            v.push(e.path().join(".ssh/authorized_keys"));
        }
    }
    v
}

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
            acc.insert(path.to_path_buf(), (meta.mtime() * 1_000_000_000 + meta.mtime_nsec(), meta.len()));
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
                if let Ok(m) = fs::metadata(path) {
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

// ------------------------------------------------------------ authentication

pub struct AuthLog {
    path: Option<PathBuf>,
    offset: u64,
}

fn word_after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.split_once(marker)?.1.split_whitespace().next()
}

pub fn parse_auth_line(line: &str) -> Option<Event> {
    let base = |result: &str, service: &str| Event::new("auth").with("auth.result", result).with("auth.service", service);
    if line.contains("sshd") {
        if let Some(rest) = line.split_once("Failed password for ").or_else(|| line.split_once("Failed publickey for ")).map(|x| x.1) {
            let rest = rest.strip_prefix("invalid user ").unwrap_or(rest);
            let user = rest.split_whitespace().next()?;
            let mut ev = base("failure", "sshd").with("auth.user", user).with("auth.method", if line.contains("password") { "password" } else { "publickey" });
            if let Some(ip) = word_after(rest, " from ") {
                ev = ev.with("auth.source_ip", ip);
            }
            return Some(ev);
        }
        for method in ["password", "publickey", "keyboard-interactive/pam"] {
            if let Some(rest) = line.split_once(&format!("Accepted {method} for ")).map(|x| x.1) {
                let user = rest.split_whitespace().next()?;
                let mut ev = base("success", "sshd").with("auth.user", user).with("auth.method", method);
                if let Some(ip) = word_after(rest, " from ") {
                    ev = ev.with("auth.source_ip", ip);
                }
                return Some(ev);
            }
        }
    }
    if line.contains("sudo:") && line.contains("COMMAND=") {
        let after = line.split_once("sudo:")?.1;
        let user = after.split(':').next()?.trim();
        let command = line.split_once("COMMAND=")?.1.trim();
        let target = word_after(line, "USER=").map(|u| u.trim_end_matches(';')).unwrap_or("root");
        let failed = line.contains("incorrect password") || line.contains("NOT in sudoers");
        return Some(
            base(if failed { "failure" } else { "success" }, "sudo")
                .with("auth.user", user)
                .with("auth.target_user", target)
                .with("auth.command", command.chars().take(1024).collect::<String>()),
        );
    }
    None
}

impl AuthLog {
    pub fn new() -> Self {
        let path = ["/var/log/auth.log", "/var/log/secure"].iter().map(PathBuf::from).find(|p| fs::File::open(p).is_ok());
        let offset = path.as_ref().and_then(|p| fs::metadata(p).ok()).map(|m| m.len()).unwrap_or(0);
        AuthLog { path, offset }
    }

    pub fn available(&self) -> bool {
        self.path.is_some()
    }

    pub fn poll(&mut self, out: &mut Vec<Event>) {
        let Some(path) = &self.path else { return };
        let Ok(mut f) = fs::File::open(path) else { return };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if len < self.offset {
            self.offset = 0; // rotated
        }
        if len == self.offset || f.seek(SeekFrom::Start(self.offset)).is_err() {
            return;
        }
        let mut buf = Vec::new();
        if f.take(4 * 1024 * 1024).read_to_end(&mut buf).is_err() {
            return;
        }
        // Consume whole lines only; a partial last line is read next time.
        let end = buf.iter().rposition(|b| *b == b'\n').map(|i| i + 1).unwrap_or(0);
        self.offset += end as u64;
        for line in String::from_utf8_lossy(&buf[..end]).lines() {
            if let Some(ev) = parse_auth_line(line) {
                out.push(ev);
            }
        }
    }
}

// ------------------------------------------------------ inventory & posture

fn sshd_setting(key: &str) -> Option<String> {
    let mut files = vec![PathBuf::from("/etc/ssh/sshd_config")];
    files.extend(fs::read_dir("/etc/ssh/sshd_config.d").into_iter().flatten().flatten().map(|e| e.path()));
    // sshd uses the first value it reads; drop-ins are included at the top of
    // the stock config, so check them first.
    files.rotate_left(1);
    for f in files {
        for line in fs::read_to_string(f).unwrap_or_default().lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let mut p = line.split_whitespace();
            if p.next().is_some_and(|k| k.eq_ignore_ascii_case(key)) {
                return p.next().map(|v| v.to_lowercase());
            }
        }
    }
    None
}

pub fn posture(out: &mut Vec<Event>) {
    let mut check = |id: &str, status: &str, detail: String| {
        out.push(Event::new("posture").with("posture.check", id).with("posture.status", status).with("posture.detail", detail));
    };
    let status = |ok: bool| if ok { "pass" } else { "fail" };

    if Path::new("/etc/ssh/sshd_config").exists() {
        let root = sshd_setting("PermitRootLogin").unwrap_or_else(|| "prohibit-password (default)".into());
        check("ssh.root_login", status(root != "yes"), format!("PermitRootLogin {root}"));
        let pw = sshd_setting("PasswordAuthentication").unwrap_or_else(|| "yes (default)".into());
        check("ssh.password_auth", status(pw == "no"), format!("PasswordAuthentication {pw}"));
    }
    if let Ok(v) = fs::read_to_string("/proc/sys/kernel/randomize_va_space") {
        check("kernel.aslr", status(v.trim() == "2"), format!("randomize_va_space={}", v.trim()));
    }
    if Path::new("/etc/apt").exists() {
        let auto = fs::read_to_string("/etc/apt/apt.conf.d/20auto-upgrades").unwrap_or_default();
        check("updates.automatic", status(auto.contains("Unattended-Upgrade \"1\"")), "unattended-upgrades".into());
        let reboot = Path::new("/var/run/reboot-required").exists();
        check("updates.reboot_pending", status(!reboot), if reboot { "a reboot is required to finish updates".into() } else { "no reboot pending".into() });
    }
    if let Ok(m) = fs::metadata("/etc/shadow") {
        let mode = m.permissions().mode() & 0o777;
        check("fs.shadow_permissions", status(mode & 0o007 == 0), format!("/etc/shadow mode {mode:o}"));
    }
    let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
    let uid0: Vec<&str> = passwd.lines().filter(|l| l.split(':').nth(2) == Some("0")).filter_map(|l| l.split(':').next()).collect();
    if !uid0.is_empty() {
        check("accounts.single_uid0", status(uid0 == ["root"]), format!("uid 0 accounts: {}", uid0.join(", ")));
    }
    if cfg!(target_os = "linux") {
        let fw = run("ufw", &["status"]).map(|s| s.contains("Status: active"))
            .or_else(|| run("nft", &["list", "ruleset"]).map(|s| s.contains("chain")))
            .or_else(|| run("iptables", &["-S"]).map(|s| s.lines().count() > 3));
        match fw {
            Some(active) => check("firewall.active", status(active), "host firewall rules present".into()),
            None => check("firewall.active", "unknown", "needs root to inspect the firewall".into()),
        }
    }
    if cfg!(target_os = "macos") {
        if let Some(s) = run("/usr/libexec/ApplicationFirewall/socketfilterfw", &["--getglobalstate"]) {
            check("firewall.active", status(s.contains("enabled")), s.trim().to_string());
        }
        if let Some(s) = run("csrutil", &["status"]) {
            check("macos.sip", status(s.contains("enabled")), s.trim().to_string());
        }
        if let Some(s) = run("fdesetup", &["status"]) {
            check("disk.encryption", status(s.contains("FileVault is On")), s.trim().to_string());
        }
    }
}

pub fn inventory() -> Event {
    let mut ev = Event::new("inventory")
        .with("os", System::long_os_version().unwrap_or_default())
        .with("kernel", System::kernel_version().unwrap_or_default());
    if let Some(list) = run("dpkg-query", &["-W", "-f=${Package} ${Version}\n"]) {
        let pkgs: Vec<String> = list.lines().take(4000).map(str::to_string).collect();
        ev = ev.with("package_count", pkgs.len()).with("packages", pkgs);
    } else if let Some(list) = run("rpm", &["-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"]) {
        let pkgs: Vec<String> = list.lines().take(4000).map(str::to_string).collect();
        ev = ev.with("package_count", pkgs.len()).with("packages", pkgs);
    }
    let shells: Vec<String> = fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.ends_with("nologin") && !l.ends_with("/false") && !l.starts_with('#'))
        .filter_map(|l| l.split(':').next().map(str::to_string))
        .collect();
    ev.with("login_users", shells)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ssh_failure_and_success() {
        let ev = parse_auth_line("Nov 11 10:00:01 h sshd[99]: Failed password for invalid user admin from 198.51.100.7 port 4022 ssh2").unwrap();
        assert_eq!(ev.text("auth.result").unwrap(), "failure");
        assert_eq!(ev.text("auth.user").unwrap(), "admin");
        assert_eq!(ev.text("auth.source_ip").unwrap(), "198.51.100.7");
        let ev = parse_auth_line("Nov 11 10:00:09 h sshd[99]: Accepted publickey for ubuntu from 203.0.113.4 port 5 ssh2: ED25519 SHA256:x").unwrap();
        assert_eq!(ev.text("auth.result").unwrap(), "success");
        assert_eq!(ev.text("auth.method").unwrap(), "publickey");
    }

    #[test]
    fn parses_sudo() {
        let ev = parse_auth_line("Nov 11 10:01:00 h sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash").unwrap();
        assert_eq!(ev.text("auth.user").unwrap(), "ubuntu");
        assert_eq!(ev.text("auth.target_user").unwrap(), "root");
        assert_eq!(ev.text("auth.command").unwrap(), "/bin/bash");
    }

    #[test]
    fn splits_addresses() {
        assert_eq!(split_addr("10.0.0.1:22").unwrap(), ("10.0.0.1".to_string(), 22));
        assert_eq!(split_addr("[::1]:8080").unwrap(), ("::1".to_string(), 8080));
        assert_eq!(split_addr("0.0.0.0:*").unwrap().1, 0);
    }
}
