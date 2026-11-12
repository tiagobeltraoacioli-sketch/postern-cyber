//! Linux and macOS sources: sockets, auth log, posture, inventory.

use crate::collect::{run, split_addr, Sock};
use postern_proto::Event;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use sysinfo::System;

pub fn is_admin() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

pub fn default_state_dir() -> PathBuf {
    if is_admin() {
        PathBuf::from("/var/lib/postern-sensor")
    } else {
        PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".postern-sensor")
    }
}

pub fn users_by_uid() -> HashMap<String, String> {
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

pub fn sockets() -> Vec<Sock> {
    if cfg!(target_os = "macos") {
        sockets_macos()
    } else {
        sockets_linux()
    }
}

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
    // os-release identifies the distribution for vulnerability matching.
    for line in fs::read_to_string("/etc/os-release").unwrap_or_default().lines() {
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim_matches('"');
            match k {
                "ID" => ev = ev.with("os_id", v),
                "VERSION_ID" => ev = ev.with("os_version_id", v),
                _ => {}
            }
        }
    }
    // "<binary> <version> <source package> <source version>"
    if let Some(list) = run("dpkg-query", &["-W", "-f=${Package} ${Version} ${source:Package} ${source:Version}\n"]) {
        let pkgs: Vec<String> = list.lines().take(6000).map(str::to_string).collect();
        ev = ev.with("package_count", pkgs.len()).with("packages", pkgs);
    } else if let Some(list) = run("rpm", &["-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE} %{SOURCERPM} -\n"]) {
        let pkgs: Vec<String> = list.lines().take(6000).map(str::to_string).collect();
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
}
