//! Linux kernel event sources. Both need root.
//!
//! * **Process connector** (netlink `cn_proc`): the kernel pushes an event
//!   for every exec, so process starts are no longer found by polling.
//! * **Exec guard** (fanotify): the kernel reports every file opened for
//!   execution. In `enforce` mode it waits for the sensor's verdict before
//!   letting the program run, which is what makes pre-execution blocking
//!   possible.
//!
//! No kernel module and no eBPF toolchain: both interfaces are stable kernel
//! ABI (process connector since 2.6.15, FAN_OPEN_EXEC_PERM since 5.0).

use crate::collect::sha256_reader;
use postern_proto::{Event, Policy};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};

/// What the exec guard last saw each pid open for execution: (path, sha256).
/// Lets the process connector describe a process that already exited.
pub type ExecCache = Arc<Mutex<HashMap<i32, (String, Option<String>)>>>;

#[derive(Debug)]
pub struct ProcRecord {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub cmdline: String,
    pub exe: Option<String>,
    pub uid: Option<String>,
    pub parent_name: Option<String>,
    pub sha256: Option<String>,
    /// The process was gone before /proc could be read; the record comes from
    /// the exec guard and has no command line.
    pub short_lived: bool,
}

fn read_proc(pid: u32) -> Option<ProcRecord> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let cmdline = raw.split(|b| *b == 0).filter(|a| !a.is_empty()).map(|a| String::from_utf8_lossy(a).into_owned()).collect::<Vec<_>>().join(" ");
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let field = |name: &str| status.lines().find_map(|l| l.strip_prefix(name)).and_then(|v| v.split_whitespace().next()).map(str::to_string);
    let ppid: Option<u32> = field("PPid:").and_then(|v| v.parse().ok());
    let name = fs::read_to_string(format!("/proc/{pid}/comm")).map(|s| s.trim().to_string()).unwrap_or_default();
    let exe = fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| p.to_string_lossy().into_owned());
    Some(ProcRecord {
        pid,
        ppid,
        parent_name: ppid.and_then(|pp| fs::read_to_string(format!("/proc/{pp}/comm").as_str()).ok()).map(|s| s.trim().to_string()),
        cmdline: if cmdline.is_empty() { name.clone() } else { cmdline.chars().take(4096).collect() },
        name,
        exe,
        uid: field("Uid:"),
        sha256: None,
        short_lived: false,
    })
}

fn debug() -> bool {
    std::env::var_os("POSTERN_DEBUG").is_some()
}

const NETLINK_CONNECTOR: libc::c_int = 11;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const NLMSG_HDR: usize = 16;
const CN_MSG_HDR: usize = 20;

fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap())
}

/// Subscribe to kernel process events and forward every exec on `tx`.
pub fn start_proc_connector(tx: Sender<ProcRecord>, cache: ExecCache) -> io::Result<()> {
    // SAFETY: plain socket(2)/bind(2)/send(2) calls with correctly sized,
    // zero-initialised structures; the fd is owned by OwnedFd afterwards.
    let fd = unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, NETLINK_CONNECTOR);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = OwnedFd::from_raw_fd(fd);
        let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);
        let mut addr: libc::sockaddr_nl = std::mem::zeroed();
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = CN_IDX_PROC;
        addr.nl_pid = std::process::id();
        if libc::bind(raw, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32) < 0 {
            return Err(io::Error::last_os_error());
        }
        let rcvbuf: libc::c_int = 4 * 1024 * 1024;
        libc::setsockopt(raw, libc::SOL_SOCKET, libc::SO_RCVBUF, &rcvbuf as *const _ as *const libc::c_void, 4);

        // nlmsghdr + cn_msg + u32 op
        let mut msg = Vec::with_capacity(NLMSG_HDR + CN_MSG_HDR + 4);
        msg.extend_from_slice(&((NLMSG_HDR + CN_MSG_HDR + 4) as u32).to_ne_bytes());
        msg.extend_from_slice(&(libc::NLMSG_DONE as u16).to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(&std::process::id().to_ne_bytes());
        msg.extend_from_slice(&CN_IDX_PROC.to_ne_bytes());
        msg.extend_from_slice(&CN_VAL_PROC.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes()); // seq
        msg.extend_from_slice(&0u32.to_ne_bytes()); // ack
        msg.extend_from_slice(&4u16.to_ne_bytes()); // len
        msg.extend_from_slice(&0u16.to_ne_bytes()); // flags
        msg.extend_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());
        if libc::send(raw, msg.as_ptr() as *const libc::c_void, msg.len(), 0) < 0 {
            return Err(io::Error::last_os_error());
        }
        fd
    };

    std::thread::Builder::new().name("proc-connector".into()).spawn(move || {
        let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);
        let me = std::process::id();
        let mut buf = vec![0u8; 16384];
        loop {
            // SAFETY: recv into a buffer we own, bounded by its length.
            let n = unsafe { libc::recv(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                // ENOBUFS: the kernel dropped events under load; the poller
                // in the main loop reconciles what was missed.
                if matches!(err.raw_os_error(), Some(libc::ENOBUFS) | Some(libc::EINTR)) {
                    continue;
                }
                eprintln!("process connector stopped: {err}");
                return;
            }
            let data = &buf[..n as usize];
            let mut off = 0;
            while off + NLMSG_HDR + CN_MSG_HDR + 24 <= data.len() {
                let len = u32_at(data, off) as usize;
                if len < NLMSG_HDR || off + len > data.len() {
                    break;
                }
                let ev = off + NLMSG_HDR + CN_MSG_HDR;
                // proc_event: what u32, cpu u32, timestamp u64, then the payload.
                if u32_at(data, ev) == PROC_EVENT_EXEC {
                    let pid = u32_at(data, ev + 16);
                    let tgid = u32_at(data, ev + 20);
                    if pid == tgid && pid != me {
                        let rec = read_proc(pid).or_else(|| {
                            let (path, sha256) = cache.lock().ok()?.get(&(pid as i32)).cloned()?;
                            Some(ProcRecord {
                                pid,
                                ppid: None,
                                name: path.rsplit('/').next().unwrap_or("").to_string(),
                                cmdline: path.clone(),
                                exe: Some(path),
                                uid: None,
                                parent_name: None,
                                sha256,
                                short_lived: true,
                            })
                        });
                        // Skip the helpers this sensor runs itself.
                        if let Some(rec) = rec.filter(|r| r.ppid != Some(me)) {
                            if tx.send(rec).is_err() {
                                return;
                            }
                        }
                    }
                }
                off += (len + 3) & !3;
            }
        }
    })?;
    Ok(())
}

// ------------------------------------------------------------- exec guard

const PSEUDO_FS: &[&str] = &[
    "proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue", "debugfs", "tracefs", "securityfs", "bpf", "pstore",
    "configfs", "fusectl", "hugetlbfs", "nsfs", "autofs", "binfmt_misc", "efivarfs", "rpc_pipefs", "selinuxfs",
];

fn mount_points() -> Vec<String> {
    fs::read_to_string("/proc/self/mounts")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut f = l.split(' ');
            let (_, path, fstype) = (f.next()?, f.next()?, f.next()?);
            (!PSEUDO_FS.contains(&fstype)).then(|| path.replace("\\040", " "))
        })
        .collect()
}

pub struct GuardConfig {
    /// Hold each exec until a verdict is written (needs the `prevent`
    /// capability). Otherwise the guard only observes.
    pub enforce: bool,
    pub policy: Arc<RwLock<Policy>>,
    /// True while the server has this host in protect mode.
    pub protect: Arc<AtomicBool>,
    pub cache: ExecCache,
    pub blocked: Sender<Event>,
}

fn decide(cfg: &GuardConfig, path: &str, hash: &mut dyn FnMut() -> Option<String>) -> Option<(&'static str, Option<String>)> {
    if !cfg.enforce || !cfg.protect.load(Ordering::Relaxed) {
        return None;
    }
    let policy = cfg.policy.read().ok()?;
    if policy.block_paths.iter().any(|p| path.starts_with(p.as_str())) {
        return Some(("blocked path", None));
    }
    if policy.block_hashes.is_empty() {
        return None;
    }
    let h = hash()?;
    policy.block_hashes.iter().any(|b| b.eq_ignore_ascii_case(&h)).then_some(("blocked hash", Some(h)))
}

/// Start the fanotify exec guard. Returns once the first marks are placed.
pub fn start_exec_guard(cfg: GuardConfig) -> io::Result<()> {
    let class = if cfg.enforce { libc::FAN_CLASS_CONTENT } else { libc::FAN_CLASS_NOTIF };
    let mask = if cfg.enforce { libc::FAN_OPEN_EXEC_PERM } else { libc::FAN_OPEN_EXEC };
    // SAFETY: fanotify_init has no pointer arguments.
    let fan = unsafe { libc::fanotify_init(libc::FAN_CLOEXEC | class, (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32) };
    if fan < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fan is a valid descriptor we just created.
    let fan = unsafe { OwnedFd::from_raw_fd(fan) };
    let raw = std::os::fd::AsRawFd::as_raw_fd(&fan);

    // Marks are per mount, never per filesystem, so a sensor running inside a
    // container can never affect execution on the host.
    let mark = move |marked: &mut Vec<String>| {
        let mut added = 0;
        for m in mount_points() {
            if marked.contains(&m) {
                continue;
            }
            let Ok(c) = CString::new(m.as_str()) else { continue };
            // SAFETY: c is a valid NUL-terminated path for the duration of the call.
            let rc = unsafe { libc::fanotify_mark(raw, libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT, mask, libc::AT_FDCWD, c.as_ptr()) };
            if rc == 0 {
                added += 1;
            } else if debug() {
                eprintln!("exec guard: cannot mark {m}: {}", io::Error::last_os_error());
            }
            marked.push(m);
        }
        added
    };
    let mut marked = Vec::new();
    if mark(&mut marked) == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "could not place a fanotify mark on any mount"));
    }

    std::thread::Builder::new().name("exec-guard".into()).spawn(move || {
        // The thread owns the fanotify descriptor. If it were dropped while
        // `raw` is still in use, the number would be reused by another file.
        let _fan = fan;
        let mut hashes: HashMap<(u64, u64, i64, u64), Option<String>> = HashMap::new();
        let mut buf = vec![0u8; 8192];
        let meta_len = std::mem::size_of::<libc::fanotify_event_metadata>();
        let mut last_scan = std::time::Instant::now();
        loop {
            let mut pfd = libc::pollfd { fd: raw, events: libc::POLLIN, revents: 0 };
            // SAFETY: pfd is a valid pollfd for one descriptor.
            let ready = unsafe { libc::poll(&mut pfd, 1, 5000) };
            if last_scan.elapsed().as_secs() >= 60 {
                mark(&mut marked); // pick up filesystems mounted after start
                last_scan = std::time::Instant::now();
            }
            if ready <= 0 {
                continue;
            }
            if pfd.revents & (libc::POLLNVAL | libc::POLLERR | libc::POLLHUP) != 0 {
                eprintln!("exec guard stopped: fanotify descriptor is no longer valid");
                return;
            }
            // SAFETY: read into a buffer we own, bounded by its length.
            let n = unsafe { libc::read(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            let mut off = 0usize;
            while off + meta_len <= n as usize {
                // SAFETY: the kernel wrote a complete fanotify_event_metadata at this offset.
                let meta: libc::fanotify_event_metadata = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off) as *const _) };
                // Never act on anything that is not a well-formed event.
                if (meta.event_len as usize) < meta_len || meta.vers != libc::FANOTIFY_METADATA_VERSION || meta.metadata_len as usize != meta_len {
                    break;
                }
                off += meta.event_len as usize;
                if meta.fd < 0 {
                    continue;
                }
                // SAFETY: the kernel handed us this descriptor; we own it now.
                let file = fs::File::from(unsafe { OwnedFd::from_raw_fd(meta.fd) });
                // Everything below is fail-open: any error allows the exec.
                let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let path = fs::read_link(format!("/proc/self/fd/{}", meta.fd)).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
                    let mut computed: Option<String> = None;
                    let mut hash = || {
                        let m = file.metadata().ok()?;
                        if m.len() > 64 * 1024 * 1024 {
                            return None;
                        }
                        let key = (m.dev(), m.ino(), m.mtime(), m.len());
                        if hashes.len() > 8192 {
                            hashes.clear();
                        }
                        let h = hashes.entry(key).or_insert_with(|| sha256_reader(&file)).clone();
                        computed = h.clone();
                        h
                    };
                    let denied = decide(&cfg, &path, &mut hash);
                    if debug() {
                        eprintln!("exec guard: pid {} opens {path} -> {}", meta.pid, if denied.is_some() { "deny" } else { "allow" });
                    }
                    if let Ok(mut c) = cfg.cache.lock() {
                        if c.len() > 8192 {
                            c.clear();
                        }
                        // The first exec-open per pid is the program itself;
                        // later ones are its interpreter and loader.
                        c.entry(meta.pid).or_insert((path.clone(), computed.clone()));
                    }
                    denied.map(|(reason, h)| (reason, h.or(computed), path))
                }))
                .unwrap_or(None);

                if meta.mask & libc::FAN_OPEN_EXEC_PERM != 0 {
                    let resp = libc::fanotify_response { fd: meta.fd, response: if verdict.is_some() { libc::FAN_DENY } else { libc::FAN_ALLOW } };
                    // SAFETY: resp is a complete fanotify_response for an event we were sent.
                    unsafe { libc::write(raw, &resp as *const _ as *const libc::c_void, std::mem::size_of::<libc::fanotify_response>()) };
                }
                if let Some((reason, h, path)) = verdict {
                    let by = fs::read_to_string(format!("/proc/{}/comm", meta.pid)).map(|s| s.trim().to_string()).unwrap_or_default();
                    let mut ev = Event::new("exec_blocked")
                        .with("file.path", path)
                        .with("prevention.reason", reason)
                        .with("process.pid", meta.pid)
                        .with("process.name", by);
                    if let Some(h) = h {
                        ev = ev.with("file.sha256", h);
                    }
                    let _ = cfg.blocked.send(ev);
                }
            }
        }
    })?;
    Ok(())
}
