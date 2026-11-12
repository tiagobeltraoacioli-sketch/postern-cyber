//! Ransomware rollback: a versioned, content-addressed copy of the
//! directories passed with `--protect`, plus two tripwires.
//!
//! * A snapshot pass stores every changed file once (by SHA-256) and writes a
//!   manifest. A pass that looks like mass encryption is refused, so good
//!   versions are never rotated out by encrypted ones.
//! * Canary files in each protected directory are checked every few seconds;
//!   touching one raises an alert long before the next snapshot.
//! * `rollback` restores a manifest and sets aside whatever was not in it.

use crate::collect::{mtime_ns, sha256_file};
use postern_proto::{now_ms, Event, VaultStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const CANARY_PREFIX: &str = ".postern-canary-";
const MAX_FILES: usize = 200_000;

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
struct Entry {
    sha256: String,
    size: u64,
    mtime_ns: i64,
    /// Shannon entropy of the first 64 KiB, in tenths of a bit per byte.
    entropy: u8,
    #[serde(default)]
    mode: u32,
    #[serde(default)]
    uid: u32,
    #[serde(default)]
    gid: u32,
}

#[derive(Serialize, Deserialize, Default)]
struct Manifest {
    ts: i64,
    files: BTreeMap<String, Entry>,
}

pub struct Vault {
    dir: PathBuf,
    roots: Vec<PathBuf>,
    last: Manifest,
    snapshots: Vec<i64>,
    suspect: bool,
    accept_next: bool,
    canaries: Vec<(PathBuf, String, bool)>,
    max_file: u64,
    max_total: u64,
    stored: u64,
    keep: usize,
    warned_full: bool,
}

fn entropy_tenths(path: &Path) -> u8 {
    let mut buf = vec![0u8; 65536];
    let n = fs::File::open(path).and_then(|mut f| f.read(&mut buf)).unwrap_or(0);
    if n == 0 {
        return 0;
    }
    let mut counts = [0u32; 256];
    for b in &buf[..n] {
        counts[*b as usize] += 1;
    }
    let h: f64 = counts.iter().filter(|c| **c > 0).map(|c| {
        let p = *c as f64 / n as f64;
        -p * p.log2()
    }).sum();
    (h * 10.0).round() as u8
}

/// Encrypted and compressed data sits above 7.5 bits per byte.
fn high(e: u8) -> bool {
    e >= 75
}

fn canary_body(i: usize) -> Vec<u8> {
    // Plausible low-entropy document text, so encryption changes it visibly.
    format!("Quarterly account reconciliation - working copy {i}\n").repeat(80).into_bytes()
}

impl Vault {
    pub fn open(dir: PathBuf, roots: Vec<PathBuf>, max_total_gb: u64) -> std::io::Result<Vault> {
        fs::create_dir_all(dir.join("objects"))?;
        fs::create_dir_all(dir.join("snapshots"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        let mut snapshots: Vec<i64> = fs::read_dir(dir.join("snapshots"))?
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().strip_suffix(".json")?.parse().ok())
            .collect();
        snapshots.sort();
        let last = snapshots.last().and_then(|ts| Self::load(&dir, *ts)).unwrap_or_default();
        let mut v = Vault {
            stored: dir_size(&dir.join("objects")),
            dir,
            roots: roots.into_iter().filter_map(|r| fs::canonicalize(r).ok()).collect(),
            last,
            snapshots,
            suspect: false,
            accept_next: false,
            canaries: Vec::new(),
            max_file: 256 * 1024 * 1024,
            max_total: max_total_gb.max(1) * 1024 * 1024 * 1024,
            keep: 48,
            warned_full: false,
        };
        v.plant_canaries();
        Ok(v)
    }

    fn load(dir: &Path, ts: i64) -> Option<Manifest> {
        serde_json::from_slice(&fs::read(dir.join("snapshots").join(format!("{ts}.json"))).ok()?).ok()
    }

    fn object(&self, sha: &str) -> PathBuf {
        self.dir.join("objects").join(&sha[..2]).join(sha)
    }

    fn plant_canaries(&mut self) {
        self.canaries.clear();
        for root in &self.roots {
            for (i, ext) in ["docx", "xlsx"].iter().enumerate() {
                let path = root.join(format!("{CANARY_PREFIX}{i}.{ext}"));
                let body = canary_body(i);
                if fs::read(&path).ok().as_deref() != Some(&body[..]) {
                    let _ = fs::write(&path, &body);
                }
                if let Some(h) = sha256_file(&path) {
                    self.canaries.push((path, h, false));
                }
            }
        }
    }

    /// Cheap tripwire, run every few seconds.
    pub fn check_canaries(&mut self, out: &mut Vec<Event>) {
        for (path, hash, tripped) in &mut self.canaries {
            if *tripped {
                continue;
            }
            let action = match sha256_file(path) {
                None => "deleted",
                Some(h) if &h != hash => "modified",
                _ => continue,
            };
            *tripped = true;
            out.push(
                Event::new("ransomware_canary")
                    .with("file.path", path.to_string_lossy().into_owned())
                    .with("file.action", action)
                    .with("ransomware.signal", "canary file touched"),
            );
        }
    }

    fn walk(&self, path: &Path, acc: &mut Vec<(PathBuf, fs::Metadata)>) {
        if acc.len() >= MAX_FILES {
            return;
        }
        let Ok(meta) = fs::symlink_metadata(path) else { return };
        if meta.is_dir() {
            for e in fs::read_dir(path).into_iter().flatten().flatten() {
                self.walk(&e.path(), acc);
            }
        } else if meta.is_file() && meta.len() <= self.max_file {
            let canary = path.file_name().is_some_and(|n| n.to_string_lossy().starts_with(CANARY_PREFIX));
            if !canary {
                acc.push((path.to_path_buf(), meta));
            }
        }
    }

    /// Take a snapshot. Emits `ransomware_suspected` and stores nothing when
    /// the changes since the last snapshot look like mass encryption.
    pub fn snapshot(&mut self, out: &mut Vec<Event>) {
        let mut found = Vec::new();
        for r in &self.roots {
            self.walk(r, &mut found);
        }
        let mut next = BTreeMap::new();
        let mut pending: Vec<(String, PathBuf)> = Vec::new();
        let (mut changed, mut changed_high, mut created, mut created_high) = (0u32, 0u32, 0u32, 0u32);
        let mut sample = String::new();
        for (path, meta) in &found {
            let key = path.to_string_lossy().into_owned();
            let sig = (mtime_ns(meta), meta.len());
            let prev = self.last.files.get(&key);
            if let Some(p) = prev.filter(|p| (p.mtime_ns, p.size) == sig) {
                next.insert(key, p.clone());
                continue;
            }
            let Some(sha256) = sha256_file(path) else { continue };
            let entropy = entropy_tenths(path);
            match prev {
                Some(p) if p.sha256 != sha256 => {
                    changed += 1;
                    if high(entropy) && !high(p.entropy) {
                        changed_high += 1;
                        sample = key.clone();
                    }
                }
                None => {
                    created += 1;
                    if high(entropy) {
                        created_high += 1;
                    }
                }
                _ => {}
            }
            #[cfg(unix)]
            let (mode, uid, gid) = {
                use std::os::unix::fs::MetadataExt;
                (meta.mode() & 0o7777, meta.uid(), meta.gid())
            };
            #[cfg(not(unix))]
            let (mode, uid, gid) = (0, 0, 0);
            pending.push((sha256.clone(), path.clone()));
            next.insert(key, Entry { sha256, size: sig.1, mtime_ns: sig.0, entropy, mode, uid, gid });
        }
        let vanished = self.last.files.keys().filter(|k| !next.contains_key(*k)).count() as u32;
        let known = self.last.files.len() as u32;

        // Two shapes of mass encryption: files rewritten in place with random
        // content, or files replaced by renamed encrypted copies.
        let in_place = changed >= 20 && changed_high * 10 >= changed * 6;
        let renamed = vanished >= 20 && vanished * 10 >= known * 3 && created >= 10 && created_high * 10 >= created * 6;
        if (in_place || renamed) && !self.accept_next {
            if !self.suspect {
                out.push(
                    Event::new("ransomware_suspected")
                        .with("ransomware.signal", if in_place { "files rewritten with high-entropy content" } else { "files replaced by high-entropy copies" })
                        .with("ransomware.changed", changed)
                        .with("ransomware.vanished", vanished)
                        .with("ransomware.created", created)
                        .with("ransomware.known_files", known)
                        .with("file.path", sample)
                        .with("vault.last_good_snapshot", self.last.ts),
                );
            }
            self.suspect = true;
            return;
        }
        self.accept_next = false;
        self.suspect = false;
        if pending.is_empty() && vanished == 0 && self.last.ts != 0 {
            return; // nothing changed
        }

        for (sha, src) in &pending {
            let dst = self.object(sha);
            if dst.exists() {
                continue;
            }
            let size = fs::metadata(src).map(|m| m.len()).unwrap_or(0);
            if self.stored + size > self.max_total {
                if !self.warned_full {
                    self.warned_full = true;
                    out.push(Event::new("vault_warning").with("vault.detail", "vault size limit reached; new file versions are not being stored"));
                }
                next.retain(|_, e| &e.sha256 != sha);
                continue;
            }
            let tmp = dst.with_extension("part");
            let stored = fs::create_dir_all(dst.parent().unwrap()).and_then(|_| fs::copy(src, &tmp)).and_then(|_| fs::rename(&tmp, &dst));
            match stored {
                // The file may have changed between hashing and copying.
                Ok(()) if sha256_file(&dst).as_deref() == Some(sha.as_str()) => self.stored += size,
                _ => {
                    let _ = fs::remove_file(&dst);
                    next.retain(|_, e| &e.sha256 != sha);
                }
            }
        }
        let manifest = Manifest { ts: now_ms(), files: next };
        if let Ok(json) = serde_json::to_vec(&manifest) {
            if fs::write(self.dir.join("snapshots").join(format!("{}.json", manifest.ts)), json).is_ok() {
                self.snapshots.push(manifest.ts);
                self.last = manifest;
                self.prune();
            }
        }
    }

    /// Drop the oldest manifests and the objects only they referenced.
    fn prune(&mut self) {
        if self.snapshots.len() <= self.keep {
            return;
        }
        let drop = self.snapshots.len() - self.keep;
        for ts in self.snapshots.drain(..drop) {
            let _ = fs::remove_file(self.dir.join("snapshots").join(format!("{ts}.json")));
        }
        let mut live = std::collections::HashSet::new();
        for ts in &self.snapshots {
            if let Some(m) = Self::load(&self.dir, *ts) {
                live.extend(m.files.into_values().map(|e| e.sha256));
            }
        }
        for shard in fs::read_dir(self.dir.join("objects")).into_iter().flatten().flatten() {
            for obj in fs::read_dir(shard.path()).into_iter().flatten().flatten() {
                if !live.contains(obj.file_name().to_string_lossy().as_ref()) {
                    let _ = fs::remove_file(obj.path());
                }
            }
        }
        self.stored = dir_size(&self.dir.join("objects"));
    }

    pub fn status(&self) -> VaultStatus {
        VaultStatus {
            protected: self.roots.iter().map(|r| r.to_string_lossy().into_owned()).collect(),
            snapshots: self.snapshots.len() as u32,
            last_snapshot: self.last.ts,
            files: self.last.files.len() as u64,
            stored_mb: self.stored / 1_048_576,
            suspect: self.suspect,
        }
    }

    /// Accept the current state of the protected directories as legitimate
    /// (after a bulk re-encode or migration that tripped the detector).
    pub fn accept(&mut self) -> String {
        self.accept_next = true;
        self.plant_canaries();
        "the next snapshot will be stored even if it looks like mass change".into()
    }

    /// Restore files from a snapshot (the latest by default). Files that are
    /// not in the snapshot are moved aside, never deleted.
    pub fn rollback(&mut self, only_under: Option<&str>, snapshot: Option<i64>) -> Result<String, String> {
        let owned;
        let manifest = match snapshot {
            Some(ts) if ts != self.last.ts => {
                owned = Self::load(&self.dir, ts).ok_or_else(|| format!("no snapshot {ts}; available: {:?}", self.snapshots))?;
                &owned
            }
            _ => &self.last,
        };
        if manifest.ts == 0 {
            return Err("the vault holds no snapshot yet".into());
        }
        let scope: Vec<PathBuf> = match only_under {
            Some(p) => {
                let p = fs::canonicalize(p).map_err(|e| format!("{p}: {e}"))?;
                if !self.roots.iter().any(|r| p.starts_with(r)) {
                    return Err(format!("{} is not inside a protected directory", p.display()));
                }
                vec![p]
            }
            None => self.roots.clone(),
        };
        let in_scope = |p: &Path| scope.iter().any(|s| p.starts_with(s));
        let aside = self.dir.join(format!("rollback-{}", now_ms()));
        let (mut restored, mut unchanged, mut failed, mut moved) = (0u32, 0u32, 0u32, 0u32);

        // 1. Set aside what the snapshot does not know (ransom notes, *.locked).
        let mut present = Vec::new();
        for s in &scope {
            self.walk(s, &mut present);
        }
        for (path, _) in &present {
            if manifest.files.contains_key(path.to_string_lossy().as_ref()) {
                continue;
            }
            let rel: PathBuf = path.components().filter(|c| matches!(c, std::path::Component::Normal(_))).collect();
            let dst = aside.join(rel);
            let ok = fs::create_dir_all(dst.parent().unwrap()).is_ok()
                && (fs::rename(path, &dst).is_ok() || (fs::copy(path, &dst).is_ok() && fs::remove_file(path).is_ok()));
            if ok {
                moved += 1;
            } else {
                failed += 1;
            }
        }

        // 2. Restore every file whose content differs from the snapshot.
        for (key, entry) in &manifest.files {
            let path = Path::new(key);
            if !in_scope(path) {
                continue;
            }
            if sha256_file(path).as_deref() == Some(entry.sha256.as_str()) {
                unchanged += 1;
                continue;
            }
            let tmp = path.with_file_name(format!(".postern-restore-{}", &entry.sha256[..12]));
            let ok = path.parent().is_some_and(|d| fs::create_dir_all(d).is_ok())
                && fs::copy(self.object(&entry.sha256), &tmp).is_ok()
                && fs::rename(&tmp, path).is_ok();
            if !ok {
                let _ = fs::remove_file(&tmp);
                failed += 1;
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(entry.mode));
                let _ = std::os::unix::fs::chown(path, Some(entry.uid), Some(entry.gid));
            }
            restored += 1;
        }
        let ts = manifest.ts;
        self.suspect = false;
        self.accept_next = true; // the restore itself is a mass change
        self.plant_canaries();
        Ok(format!(
            "rolled back to snapshot {ts}: {restored} restored, {unchanged} already intact, {moved} unknown files moved to {}, {failed} failed",
            aside.display()
        ))
    }
}

fn dir_size(dir: &Path) -> u64 {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| match e.metadata() {
            Ok(m) if m.is_dir() => dir_size(&e.path()),
            Ok(m) => m.len(),
            Err(_) => 0,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("postern-vault-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("data")).unwrap();
        d
    }

    /// Deterministic bytes that look encrypted (about 8 bits of entropy per byte).
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    fn fill(d: &Path, n: usize) {
        for i in 0..n {
            fs::write(d.join("data").join(format!("report-{i}.txt")), format!("invoice {i}: total due 1200.00\n").repeat(200)).unwrap();
        }
    }

    #[test]
    fn in_place_encryption_is_refused_and_rolled_back() {
        let d = scratch("inplace");
        fill(&d, 40);
        let original = fs::read(d.join("data/report-7.txt")).unwrap();
        let mut v = Vault::open(d.join("vault"), vec![d.join("data")], 1).unwrap();
        let mut ev = Vec::new();
        v.snapshot(&mut ev);
        assert!(ev.is_empty());
        assert_eq!(v.status().files, 40);

        for i in 0..40 {
            fs::write(d.join("data").join(format!("report-{i}.txt")), noise(i as u64 + 1, 6000)).unwrap();
        }
        fs::write(d.join("data/README-DECRYPT.txt"), "pay us").unwrap();
        v.snapshot(&mut ev);
        assert_eq!(ev.iter().filter(|e| e.kind == "ransomware_suspected").count(), 1, "{ev:?}");
        assert!(v.status().suspect);
        assert_eq!(v.status().snapshots, 1, "the encrypted state must not be stored");

        let report = v.rollback(None, None).unwrap();
        assert!(report.contains("40 restored"), "{report}");
        assert_eq!(fs::read(d.join("data/report-7.txt")).unwrap(), original);
        assert!(!d.join("data/README-DECRYPT.txt").exists(), "ransom note is moved aside");
        assert!(!v.status().suspect);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn renamed_encrypted_copies_are_refused() {
        let d = scratch("renamed");
        fill(&d, 40);
        let mut v = Vault::open(d.join("vault"), vec![d.join("data")], 1).unwrap();
        let mut ev = Vec::new();
        v.snapshot(&mut ev);
        for i in 0..40 {
            fs::remove_file(d.join("data").join(format!("report-{i}.txt"))).unwrap();
            fs::write(d.join("data").join(format!("report-{i}.txt.locked")), noise(i as u64 + 100, 6000)).unwrap();
        }
        v.snapshot(&mut ev);
        assert_eq!(ev.iter().filter(|e| e.kind == "ransomware_suspected").count(), 1);
        v.rollback(None, None).unwrap();
        assert!(d.join("data/report-0.txt").exists());
        assert!(!d.join("data/report-0.txt.locked").exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn ordinary_edits_are_stored_and_canaries_trip() {
        let d = scratch("edits");
        fill(&d, 30);
        let mut v = Vault::open(d.join("vault"), vec![d.join("data")], 1).unwrap();
        let mut ev = Vec::new();
        v.snapshot(&mut ev);
        for i in 0..25 {
            fs::write(d.join("data").join(format!("report-{i}.txt")), format!("invoice {i}: revised total 900.00\n").repeat(210)).unwrap();
        }
        v.snapshot(&mut ev);
        assert!(ev.is_empty(), "plain-text edits are not ransomware: {ev:?}");
        assert_eq!(v.status().snapshots, 2);

        v.check_canaries(&mut ev);
        assert!(ev.is_empty());
        fs::write(d.join("data/.postern-canary-0.docx"), noise(9, 4000)).unwrap();
        v.check_canaries(&mut ev);
        v.check_canaries(&mut ev);
        assert_eq!(ev.iter().filter(|e| e.kind == "ransomware_canary").count(), 1, "reported once");
        let _ = fs::remove_dir_all(&d);
    }
}
