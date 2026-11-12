//! Windows sources: sockets (netstat), logon events (Security log through
//! wevtutil), posture and installed software. Everything here shells out to
//! tools that ship with Windows, so the sensor stays a single executable.

use crate::collect::{run, split_addr, Sock};
use postern_proto::Event;
use std::collections::HashMap;
use std::path::PathBuf;
use sysinfo::System;

pub fn is_admin() -> bool {
    // `net session` succeeds only in an elevated process.
    run("net", &["session"]).is_some()
}

pub fn default_state_dir() -> PathBuf {
    PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into())).join("PosternSensor")
}

pub fn users_by_uid() -> HashMap<String, String> {
    HashMap::new()
}

pub fn parse_netstat(out: &str) -> Vec<Sock> {
    let mut v = Vec::new();
    for line in out.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 || f[0] != "TCP" {
            continue;
        }
        let (Some((_, lport)), Some((rip, rport))) = (split_addr(f[1]), split_addr(f[2])) else { continue };
        let pid = f[4].parse().ok();
        match f[3] {
            "LISTENING" => v.push(Sock { listen: true, local_port: lport, remote_ip: String::new(), remote_port: 0, pname: String::new(), pid }),
            "ESTABLISHED" => v.push(Sock { listen: false, local_port: lport, remote_ip: rip, remote_port: rport, pname: String::new(), pid }),
            _ => {}
        }
    }
    v
}

pub fn sockets() -> Vec<Sock> {
    run("netstat", &["-ano", "-p", "TCP"]).map(|o| parse_netstat(&o)).unwrap_or_default()
}

pub fn default_fim_paths() -> Vec<PathBuf> {
    let win = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
    let mut v = vec![
        PathBuf::from(format!("{win}\\System32\\drivers\\etc\\hosts")),
        PathBuf::from(format!("{win}\\System32\\Tasks")),
        PathBuf::from(format!("{win}\\System32\\GroupPolicy\\Machine\\Scripts")),
        PathBuf::from(format!("{data}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")),
        PathBuf::from(format!("{data}\\ssh\\administrators_authorized_keys")),
    ];
    for e in std::fs::read_dir("C:\\Users").into_iter().flatten().flatten() {
        v.push(e.path().join("AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
        v.push(e.path().join(".ssh\\authorized_keys"));
    }
    v
}

// ------------------------------------------------------------ authentication

fn between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let i = s.find(start)? + start.len();
    let j = s[i..].find(end)? + i;
    Some(&s[i..j])
}

fn data_field<'a>(event: &'a str, name: &str) -> Option<&'a str> {
    between(event, &format!("<Data Name='{name}'>"), "</Data>")
}

/// Parse the XML that `wevtutil qe Security /f:xml` prints into auth events.
/// Returns the events and the highest record id seen.
pub fn parse_logon_events(xml: &str) -> (Vec<Event>, u64) {
    let mut out = Vec::new();
    let mut last = 0;
    for ev in xml.split("<Event ").skip(1) {
        let record: u64 = between(ev, "<EventRecordID>", "</EventRecordID>").and_then(|r| r.parse().ok()).unwrap_or(0);
        last = last.max(record);
        let id = between(ev, "<EventID", "</EventID>").and_then(|s| s.rsplit('>').next()).unwrap_or("");
        let user = data_field(ev, "TargetUserName").unwrap_or("");
        let logon_type = data_field(ev, "LogonType").unwrap_or("");
        // Skip service, batch and machine-account logons: they are constant noise.
        if user.is_empty() || user.ends_with('$') || !matches!(logon_type, "2" | "3" | "7" | "8" | "10" | "11") {
            continue;
        }
        let method = match logon_type {
            "2" => "interactive",
            "3" => "network",
            "7" => "unlock",
            "8" => "network-cleartext",
            "10" => "remote-desktop",
            _ => "cached",
        };
        let mut e = Event::new("auth")
            .with("auth.result", if id == "4624" { "success" } else { "failure" })
            .with("auth.service", "windows-logon")
            .with("auth.user", user)
            .with("auth.method", method)
            .with("auth.event_id", id);
        if let Some(ip) = data_field(ev, "IpAddress").filter(|ip| !ip.is_empty() && *ip != "-") {
            e = e.with("auth.source_ip", ip);
        }
        out.push(e);
    }
    (out, last)
}

pub struct AuthLog {
    last_record: Option<u64>,
}

impl AuthLog {
    pub fn new() -> Self {
        // Start after the newest record so history is not replayed.
        let last_record = run("wevtutil", &["qe", "Security", "/c:1", "/rd:true", "/f:xml"])
            .and_then(|x| between(&x, "<EventRecordID>", "</EventRecordID>").and_then(|r| r.parse().ok()));
        AuthLog { last_record }
    }

    pub fn available(&self) -> bool {
        self.last_record.is_some()
    }

    pub fn poll(&mut self, out: &mut Vec<Event>) {
        let Some(last) = self.last_record else { return };
        let query = format!("/q:*[System[(EventID=4624 or EventID=4625) and EventRecordID>{last}]]");
        let Some(xml) = run("wevtutil", &["qe", "Security", &query, "/c:500", "/f:xml"]) else { return };
        let (events, newest) = parse_logon_events(&xml);
        out.extend(events);
        self.last_record = Some(last.max(newest));
    }
}

// ------------------------------------------------------ inventory & posture

fn ps(script: &str) -> Option<String> {
    run("powershell", &["-NoProfile", "-NonInteractive", "-Command", script]).map(|s| s.trim().to_string())
}

pub fn posture(out: &mut Vec<Event>) {
    let mut check = |id: &str, ok: Option<bool>, detail: String| {
        let status = match ok {
            Some(true) => "pass",
            Some(false) => "fail",
            None => "unknown",
        };
        out.push(Event::new("posture").with("posture.check", id).with("posture.status", status).with("posture.detail", detail));
    };
    let rtp = ps("(Get-MpComputerStatus).RealTimeProtectionEnabled");
    check("defender.realtime", rtp.as_deref().map(|s| s == "True"), format!("RealTimeProtectionEnabled={}", rtp.unwrap_or_else(|| "unavailable".into())));
    let fw = run("netsh", &["advfirewall", "show", "allprofiles", "state"]);
    check("firewall.active", fw.as_ref().map(|s| s.matches("ON").count() >= 3), "Windows Firewall on for domain, private and public profiles".into());
    let bl = run("manage-bde", &["-status", "C:"]);
    check("disk.encryption", bl.as_ref().map(|s| s.contains("Protection On")), "BitLocker protection on C:".into());
    let uac = run("reg", &["query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "EnableLUA"]);
    check("uac.enabled", uac.as_ref().map(|s| s.contains("0x1")), "User Account Control".into());
    let smb1 = ps("(Get-SmbServerConfiguration).EnableSMB1Protocol");
    check("smb.v1_disabled", smb1.as_deref().map(|s| s == "False"), format!("EnableSMB1Protocol={}", smb1.unwrap_or_else(|| "unavailable".into())));
    let guest = run("net", &["user", "guest"]);
    check("accounts.guest_disabled", guest.as_ref().map(|s| s.lines().any(|l| l.starts_with("Account active") && l.trim_end().ends_with("No"))), "built-in Guest account".into());
    let nla = run("reg", &["query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "/v", "UserAuthentication"]);
    check("rdp.network_level_auth", nla.as_ref().map(|s| s.contains("0x1")), "Remote Desktop requires Network Level Authentication".into());
}

pub fn inventory() -> Event {
    let mut ev = Event::new("inventory")
        .with("os", System::long_os_version().unwrap_or_default())
        .with("kernel", System::kernel_version().unwrap_or_default())
        .with("os_id", "windows")
        .with("os_version_id", System::os_version().unwrap_or_default());
    let script = "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, \
                  HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | \
                  Where-Object DisplayName | ForEach-Object { $_.DisplayName + '|' + $_.DisplayVersion }";
    if let Some(list) = ps(script) {
        let pkgs: Vec<String> = list.lines().take(6000).map(|l| l.trim().to_string()).collect();
        ev = ev.with("package_count", pkgs.len()).with("packages", pkgs);
    }
    if let Some(users) = ps("(Get-LocalUser | Where-Object Enabled).Name") {
        ev = ev.with("login_users", users.lines().map(|l| l.trim().to_string()).collect::<Vec<_>>());
    }
    ev
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_netstat() {
        let out = "\nActive Connections\n\n  Proto  Local Address          Foreign Address        State           PID\n  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1204\n  TCP    10.0.0.5:50122         203.0.113.9:443        ESTABLISHED     4488\n  TCP    [::]:445               [::]:0                 LISTENING       4\n";
        let s = parse_netstat(out);
        assert_eq!(s.len(), 3);
        assert!(s[0].listen && s[0].local_port == 3389 && s[0].pid == Some(1204));
        assert_eq!((s[1].remote_ip.as_str(), s[1].remote_port), ("203.0.113.9", 443));
        assert_eq!(s[2].local_port, 445);
    }

    #[test]
    fn parses_logon_events() {
        let xml = "<Event xmlns='x'><System><EventID>4625</EventID><EventRecordID>901</EventRecordID></System><EventData>\
<Data Name='TargetUserName'>administrator</Data><Data Name='LogonType'>10</Data><Data Name='IpAddress'>198.51.100.7</Data></EventData></Event>\
<Event xmlns='x'><System><EventID Qualifiers='0'>4624</EventID><EventRecordID>902</EventRecordID></System><EventData>\
<Data Name='TargetUserName'>WEB01$</Data><Data Name='LogonType'>3</Data><Data Name='IpAddress'>-</Data></EventData></Event>\
<Event xmlns='x'><System><EventID>4624</EventID><EventRecordID>903</EventRecordID></System><EventData>\
<Data Name='TargetUserName'>alice</Data><Data Name='LogonType'>2</Data><Data Name='IpAddress'>-</Data></EventData></Event>";
        let (evs, last) = parse_logon_events(xml);
        assert_eq!(last, 903);
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].text("auth.result").unwrap(), "failure");
        assert_eq!(evs[0].text("auth.method").unwrap(), "remote-desktop");
        assert_eq!(evs[0].text("auth.source_ip").unwrap(), "198.51.100.7");
        assert_eq!(evs[1].text("auth.user").unwrap(), "alice");
        assert!(evs[1].text("auth.source_ip").is_none());
    }
}
