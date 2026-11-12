//! Vulnerability matching: installed packages against the public OSV
//! database for the endpoint's distribution.
//!
//! The whole database for a distribution is downloaded and matched locally,
//! so no inventory leaves the server. Feeds:
//! https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip

use crate::{db, AppState};
use rusqlite::params;
use serde_json::{json, Value};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const FEED_BASE: &str = "https://osv-vulnerabilities.storage.googleapis.com";
const FEED_MAX_AGE_MS: i64 = 20 * 3_600_000;

/// OSV ecosystem name for an endpoint, from the os-release fields in its
/// inventory. None means no feed is wired for that distribution.
pub fn ecosystem(inv: &Value) -> Option<String> {
    let id = inv["os_id"].as_str()?;
    let ver = inv["os_version_id"].as_str()?;
    match id {
        "ubuntu" => {
            let (major, minor) = ver.split_once('.')?;
            let lts = minor == "04" && major.parse::<u32>().ok()? % 2 == 0;
            Some(if lts { format!("Ubuntu:{ver}:LTS") } else { format!("Ubuntu:{ver}") })
        }
        "debian" => Some(format!("Debian:{}", ver.split('.').next()?)),
        _ => None,
    }
}

// ---- Debian version comparison (Debian Policy 5.6.12) ----

fn order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(b'~') => -1,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => c as i32,
        Some(c) => c as i32 + 256,
    }
}

fn cmp_part(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        // Non-digit run.
        while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
            let (x, y) = (order(a.get(i).copied()), order(b.get(j).copied()));
            if x != y {
                return x.cmp(&y);
            }
            i += 1;
            j += 1;
        }
        // Digit run, compared numerically without overflow.
        while i < a.len() && a[i] == b'0' {
            i += 1;
        }
        while j < b.len() && b[j] == b'0' {
            j += 1;
        }
        let (si, sj) = (i, j);
        while i < a.len() && a[i].is_ascii_digit() {
            i += 1;
        }
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        let (da, db) = (&a[si..i], &b[sj..j]);
        match da.len().cmp(&db.len()).then_with(|| da.cmp(db)) {
            Ordering::Equal => {}
            o => return o,
        }
    }
    Ordering::Equal
}

pub fn dpkg_cmp(a: &str, b: &str) -> Ordering {
    let split = |v: &str| -> (u64, String, String) {
        let (epoch, rest) = match v.split_once(':') {
            Some((e, r)) if e.chars().all(|c| c.is_ascii_digit()) && !e.is_empty() => (e.parse().unwrap_or(0), r),
            _ => (0, v),
        };
        match rest.rsplit_once('-') {
            Some((up, rev)) => (epoch, up.to_string(), rev.to_string()),
            None => (epoch, rest.to_string(), String::new()),
        }
    };
    let (ea, ua, ra) = split(a);
    let (eb, ub, rb) = split(b);
    ea.cmp(&eb).then_with(|| cmp_part(&ua, &ub)).then_with(|| cmp_part(&ra, &rb))
}

/// Is `installed` affected by this OSV `affected` entry? Returns the fixed
/// version when one exists.
fn affected(entry: &Value, installed: &str) -> Option<Option<String>> {
    let fixed = entry["ranges"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|r| r["events"].as_array().into_iter().flatten())
        .find_map(|e| e["fixed"].as_str())
        .map(str::to_string);
    match &fixed {
        Some(f) => (dpkg_cmp(installed, f) == Ordering::Less).then_some(fixed),
        None => {
            // No fix published: trust the explicit list of affected versions
            // when the record carries one.
            let versions = entry["versions"].as_array();
            match versions {
                Some(vs) if !vs.is_empty() => vs.iter().any(|v| v.as_str() == Some(installed)).then_some(None),
                _ => Some(None),
            }
        }
    }
}

struct Installed {
    endpoint_id: String,
    version: String,
}

struct Finding {
    endpoint_id: String,
    vuln_id: String,
    package: String,
    installed: String,
    fixed: Option<String>,
    severity: String,
    summary: String,
    published: String,
}

fn scan_feed(zip_path: &Path, eco: &str, installed: &HashMap<String, Vec<Installed>>) -> anyhow::Result<(Vec<Finding>, usize)> {
    let mut archive = zip::ZipArchive::new(std::fs::File::open(zip_path)?)?;
    let mut out = Vec::new();
    let mut records = 0;
    let mut buf = String::new();
    for i in 0..archive.len() {
        let mut f = archive.by_index(i)?;
        let name = f.name().to_string();
        // Advisories (USN, DSA, DLA) repeat what the per-CVE records say.
        if !name.ends_with(".json") || !name.contains("CVE-") {
            continue;
        }
        buf.clear();
        if f.read_to_string(&mut buf).is_err() {
            continue;
        }
        let Ok(rec) = serde_json::from_str::<Value>(&buf) else { continue };
        records += 1;
        for entry in rec["affected"].as_array().into_iter().flatten() {
            if entry["package"]["ecosystem"].as_str() != Some(eco) {
                continue;
            }
            let Some(pkg) = entry["package"]["name"].as_str() else { continue };
            let Some(hosts) = installed.get(pkg) else { continue };
            for h in hosts {
                let Some(fixed) = affected(entry, &h.version) else { continue };
                let spec = &entry["ecosystem_specific"];
                let severity = spec["ubuntu_priority"].as_str().or(spec["urgency"].as_str()).unwrap_or("unknown");
                let id = rec["id"].as_str().unwrap_or(&name);
                out.push(Finding {
                    endpoint_id: h.endpoint_id.clone(),
                    vuln_id: id.trim_start_matches("UBUNTU-").trim_start_matches("DEBIAN-").to_string(),
                    package: pkg.to_string(),
                    installed: h.version.clone(),
                    fixed,
                    severity: severity.to_string(),
                    summary: rec["summary"].as_str().filter(|s| !s.is_empty()).or(rec["details"].as_str()).unwrap_or("").chars().take(280).collect(),
                    published: rec["published"].as_str().unwrap_or("").chars().take(10).collect(),
                });
            }
        }
    }
    Ok((out, records))
}

async fn download(state: &AppState, eco: &str, dest: &Path) -> anyhow::Result<()> {
    let url = format!("{FEED_BASE}/{eco}/all.zip");
    let mut resp = state.http.get(&url).send().await?.error_for_status()?;
    let tmp = dest.with_extension("part");
    {
        use std::io::Write;
        let mut file = std::fs::File::create(&tmp)?;
        while let Some(chunk) = resp.chunk().await? {
            file.write_all(&chunk)?;
        }
    }
    std::fs::rename(&tmp, dest)?;
    Ok(())
}

fn feed_path(dir: &Path, eco: &str) -> PathBuf {
    let safe: String = eco.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' { c } else { '_' }).collect();
    dir.join(format!("{safe}.zip"))
}

/// Download stale feeds and recompute the findings of every endpoint that
/// reported an inventory for a supported distribution.
pub async fn refresh(state: &Arc<AppState>, force_download: bool) -> anyhow::Result<Value> {
    // ecosystem -> source package -> installations
    let mut by_eco: HashMap<String, HashMap<String, Vec<Installed>>> = HashMap::new();
    let mut unsupported = Vec::new();
    {
        let conn = state.db.lock().unwrap();
        for row in db::query(&conn, "SELECT id, hostname, inventory FROM endpoints WHERE inventory IS NOT NULL", vec![])? {
            let inv = &row["inventory"];
            let Some(eco) = ecosystem(inv) else {
                unsupported.push(row["hostname"].clone());
                continue;
            };
            let map = by_eco.entry(eco).or_default();
            for p in inv["packages"].as_array().into_iter().flatten().filter_map(|p| p.as_str()) {
                // "<binary> <version> <source> <source version>"
                let f: Vec<&str> = p.split(' ').collect();
                if f.len() < 4 {
                    continue;
                }
                let list = map.entry(f[2].to_string()).or_default();
                let ep = row["id"].as_str().unwrap_or_default();
                if !list.iter().any(|x| x.endpoint_id == ep && x.version == f[3]) {
                    list.push(Installed { endpoint_id: ep.to_string(), version: f[3].to_string() });
                }
            }
        }
    }
    let dir = state.data_dir.join("feeds");
    std::fs::create_dir_all(&dir)?;
    let mut report = Vec::new();
    for (eco, installed) in by_eco {
        let path = feed_path(&dir, &eco);
        let age = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_millis() as i64);
        if force_download || age.is_none_or(|a| a > FEED_MAX_AGE_MS) {
            if let Err(e) = download(state, &eco, &path).await {
                if !path.exists() {
                    report.push(json!({"ecosystem": eco, "error": format!("feed download failed: {e}")}));
                    continue;
                }
            }
        }
        let (eco2, path2) = (eco.clone(), path.clone());
        let endpoints: Vec<String> = {
            let mut v: Vec<String> = installed.values().flatten().map(|i| i.endpoint_id.clone()).collect();
            v.sort();
            v.dedup();
            v
        };
        let (findings, records) = tokio::task::spawn_blocking(move || scan_feed(&path2, &eco2, &installed)).await??;
        let conn = state.db.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        for ep in &endpoints {
            tx.execute("DELETE FROM endpoint_vulns WHERE endpoint_id = ?1", [ep])?;
        }
        for f in &findings {
            tx.execute(
                "INSERT OR REPLACE INTO endpoint_vulns(endpoint_id, vuln_id, package, installed, fixed, severity, summary, published) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![f.endpoint_id, f.vuln_id, f.package, f.installed, f.fixed, f.severity, f.summary, f.published],
            )?;
        }
        tx.commit()?;
        report.push(json!({"ecosystem": eco, "records": records, "endpoints": endpoints.len(), "findings": findings.len()}));
    }
    let conn = state.db.lock().unwrap();
    db::set_setting(&conn, "vuln_last_run", &postern_proto::now_ms().to_string())?;
    Ok(json!({"feeds": report, "unsupported_hosts": unsupported}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debian_version_ordering() {
        let lt = |a, b| assert_eq!(dpkg_cmp(a, b), Ordering::Less, "{a} < {b}");
        lt("1.0", "1.1");
        lt("1.9", "1.10");
        lt("1.0~rc1", "1.0");
        lt("1.0", "1.0-1");
        lt("1.0-1", "1.0-1ubuntu0.1");
        lt("1.0-1ubuntu0.1", "1.0-1ubuntu0.2");
        lt("2.0", "1:1.0");
        lt("1.8.1-1", "1.8.1-1ubuntu0.1");
        lt("3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3.6");
        lt("1.0a", "1.0b");
        lt("1.0", "1.0+dfsg");
        assert_eq!(dpkg_cmp("1.0-1", "1.0-1"), Ordering::Equal);
        assert_eq!(dpkg_cmp("1.00", "1.0"), Ordering::Equal);
    }

    #[test]
    fn ecosystem_names() {
        let inv = |id: &str, v: &str| json!({"os_id": id, "os_version_id": v});
        assert_eq!(ecosystem(&inv("ubuntu", "24.04")).as_deref(), Some("Ubuntu:24.04:LTS"));
        assert_eq!(ecosystem(&inv("ubuntu", "25.10")).as_deref(), Some("Ubuntu:25.10"));
        assert_eq!(ecosystem(&inv("debian", "12")).as_deref(), Some("Debian:12"));
        assert_eq!(ecosystem(&inv("fedora", "41")), None);
    }

    #[test]
    fn affected_logic() {
        let fixed = json!({"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.8.1-1ubuntu0.1"}]}]});
        assert_eq!(affected(&fixed, "1.8.1-1"), Some(Some("1.8.1-1ubuntu0.1".to_string())));
        assert_eq!(affected(&fixed, "1.8.1-1ubuntu0.1"), None);
        let unfixed = json!({"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}], "versions": ["10.2-1", "10.2-2"]});
        assert_eq!(affected(&unfixed, "10.2-2"), Some(None));
        assert_eq!(affected(&unfixed, "11.0-1"), None);
    }
}
