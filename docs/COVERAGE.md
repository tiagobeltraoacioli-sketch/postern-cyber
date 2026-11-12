# Coverage

What commercial endpoint platforms (EPP/EDR/XDR suites) offer, and where
Postern Cyber 0.2 stands on each. "Partial" and "No" rows are the roadmap.

| Capability | 0.2 | Notes |
|---|---|---|
| Endpoint sensor, Linux | Yes | Static binary, runs as root or unprivileged (reduced visibility) |
| Endpoint sensor, macOS | Yes | Polling only; no auth-log collection, no network isolation |
| Endpoint sensor, Windows | Partial | Builds to a single `.exe`; enrollment, posture, vault and rollback verified under Wine. Process and network telemetry not yet verified on a real Windows host |
| Kernel-pushed process telemetry | Yes (Linux) | Netlink process connector: every exec is pushed by the kernel. The command line is read right after the exec; a process that exits within microseconds can still lose it, in which case the exec guard supplies path and hash |
| eBPF sensor | No | Would make the command line guaranteed too |
| Network telemetry | Partial | New TCP connections and listeners every 10 s; no DNS, no UDP flows |
| File integrity monitoring | Yes | Critical system paths plus `--watch`; polled every 30 s |
| Authentication telemetry | Partial | SSH and sudo (Linux), logon events 4624/4625 (Windows, unverified) |
| Behavioral detections, ATT&CK mapped | Yes | 48 built-in rules (Linux, macOS, Windows); custom YAML rules |
| Pre-execution blocking | Yes (Linux) | fanotify permission events: a binary on the hash block list, or under a blocked path prefix, is denied before it runs. Needs root and `--response prevent`. Scripts run through an interpreter (`bash x.sh`) are not covered; Windows and macOS need a kernel driver / system extension |
| Machine-learning static analysis | No | Blocking is by hash and path policy |
| Indicator matching (hash, IP) | Yes | No bundled threat-intel feed; bring your own |
| Incident correlation (storyline) | Partial | Groups by host and 30-minute window, not by process tree |
| Response: kill, quarantine, isolate | Yes | Isolation on Linux (nftables) and Windows (Windows Firewall, unverified) |
| Automatic response policy | Yes | Per-host `protect` mode |
| Ransomware detection | Yes | Canary files (5 s), mass-encryption heuristic on protected directories, backup-destruction commands |
| Ransomware rollback | Yes | Versioned content-addressed vault of `--protect` directories; restore to the last good snapshot. Only protected directories, only up to the last snapshot (default every 15 min), and the vault lives on the same host |
| Remote shell to endpoint | No | `collect_triage` returns a read-only snapshot instead |
| AI analyst: triage, natural-language hunting, rule drafting | Yes | Claude via your API key |
| Threat hunting query language | Partial | Text, kind, host and time filters; no joins or aggregations |
| XDR ingestion of third-party logs | Partial | Generic JSON API; no native connectors |
| Vulnerability (CVE) matching | Yes (Ubuntu, Debian) | Installed packages matched locally against the public OSV database; no inventory leaves the server. Other distributions, Windows and macOS software are inventoried but not matched |
| Security posture checks | Yes | SSH, firewall, ASLR, updates, disk encryption, Defender, UAC, SMBv1 |
| Cloud workload / container / Kubernetes security | No | One container-escape rule only |
| Identity threat detection | Partial | Brute force and root logins |
| Single sign-on | Yes | OpenID Connect with PKCE; ID token signature, issuer, audience, expiry and nonce verified |
| Role-based access control | Yes | viewer / analyst / admin on SSO sessions and API keys |
| Multi-tenancy | No | Single tenant |
| Sensor tamper protection | No | One rule alerts when the sensor service is stopped |
| Mutual TLS between sensor and server | No | Bearer agent keys over the TLS you terminate |
| Managed detection and response service | No | Software only |
| Independent audit, certifications | No | |

## Verified in this repository

- `cargo test` (19 tests): rule validity, Linux and Windows detections,
  thresholds, auth-log and netstat/event-log parsers, Debian version
  ordering, role mapping, vault snapshots and two ransomware scenarios.
- `scripts/test-sso.sh` (18 checks) against a mock OpenID Connect provider:
  role mapping by email, group and domain; role enforcement; CSRF header;
  logout; forged signature, wrong nonce and replayed state all refused.
- On Linux 6.8 as root in a container (kernel process events and exec guard
  restricted to the container's mounts):
  - a binary on the hash block list was denied, including a renamed copy;
    a binary under a blocked path was denied; other binaries ran;
  - 300 of 300 back-to-back `/bin/true` runs were captured with their full
    command line while the host was under load;
  - 40 files overwritten with random data raised the mass-encryption alert,
    the encrypted state was not stored, and rollback restored them
    byte for byte and moved the ransom note aside.
- Windows `.exe` under Wine: enrollment, heartbeat, posture, vault,
  mass-encryption alert and rollback.
- Vulnerability matching against the live Ubuntu OSV feed: an inventory of
  Ubuntu 24.04 release-day versions of openssl, openssh, sudo and curl was
  flagged with the right fixed versions (including CVE-2024-6387 and
  CVE-2025-32463), and a package already at its fixed version was not.

## Not yet verified

- The AI analyst against a live API key. Request construction follows the
  Messages API reference and authentication errors are handled, but triage,
  hunting and rule drafting have not run against a real model response.
- The Windows sensor on real Windows: process, network and logon telemetry,
  kill, quarantine and firewall isolation.
- `isolate_host`, `quarantine_file` and `kill_process` on a real target.
- SSO against a commercial provider (only the mock provider was used).
- Behaviour under load beyond a single sensor.

## Known hazards

- With `--response prevent` the kernel waits for the sensor before every
  exec on the host. The guard fails open on every error and allows
  everything if the sensor exits, but a sensor that is stopped (SIGSTOP) or
  starved will stall process starts. Enable it on one host first.
- A path block on `/tmp/` breaks installers and build tools.
