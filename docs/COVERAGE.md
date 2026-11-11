# Coverage

What commercial endpoint platforms (EPP/EDR/XDR suites) offer, and where
Postern Cyber 0.1 stands on each. "Partial" and "No" rows are the roadmap.

| Capability | 0.1 | Notes |
|---|---|---|
| Endpoint sensor, Linux | Yes | Static binary, runs as root or unprivileged (reduced visibility) |
| Endpoint sensor, macOS | Yes | No auth-log collection, no network isolation |
| Endpoint sensor, Windows | No | Planned |
| Process telemetry with lineage and hashes | Yes | Polled every 2 s; a process that starts and exits between polls is missed |
| Kernel-level telemetry (eBPF, Endpoint Security) | No | Planned; removes the polling gap |
| Network telemetry | Partial | New TCP connections and listeners every 10 s; no DNS, no UDP flows |
| File integrity monitoring | Yes | Critical system paths plus `--watch`; polled every 30 s |
| Authentication telemetry | Partial | SSH and sudo from the auth log on Linux |
| Behavioral detections, ATT&CK mapped | Yes | 31 built-in rules; custom YAML rules |
| Static / ML malware prevention before execution | No | Detection happens after the process starts |
| Indicator matching (hash, IP) | Yes | No bundled threat-intel feed; bring your own |
| Incident correlation (storyline) | Partial | Groups by host and 30-minute window, not by process tree |
| Response: kill, quarantine, isolate | Yes | Isolation is Linux/nftables only |
| Automatic response policy | Yes | Per-host `protect` mode |
| Ransomware rollback | No | Detects bulk encryption commands only |
| Remote shell to endpoint | No | `collect_triage` returns a read-only snapshot instead |
| AI analyst: triage, natural-language hunting, rule drafting | Yes | Claude via your API key |
| Threat hunting query language | Partial | Text, kind, host and time filters; no joins or aggregations |
| XDR ingestion of third-party logs | Partial | Generic JSON API; no native connectors |
| Vulnerability management | Partial | Package inventory collected; no CVE matching yet |
| Security posture checks | Yes | SSH, firewall, ASLR, updates, disk encryption, uid 0 accounts |
| Cloud workload / container / Kubernetes security | No | One container-escape rule only |
| Identity threat detection | Partial | SSH brute force and root logins |
| Multi-tenancy, SSO, RBAC | No | Single tenant; bearer tokens |
| Sensor tamper protection | No | One rule alerts when the sensor service is stopped |
| Mutual TLS between sensor and server | No | Bearer agent keys over the TLS you terminate |
| Managed detection and response service | No | Software only |
| Independent audit, certifications | No | |

## Verified in this repository

- `cargo test`: rule file validity, detection matching, threshold and
  de-duplication logic, auth-log parsing.
- End to end on macOS: sensor enrollment, live process detection, posture
  checks, `collect_triage`, capability gating of `kill_process`.
- `scripts/simulate-attack.sh`: nine events produce ten alerts in one
  critical incident.

## Not yet verified

- The AI analyst against a live API key. Request construction follows the
  Messages API reference and authentication errors are handled, but triage,
  hunting and rule drafting have not run against a real model response.
- `isolate_host`, `quarantine_file` and `kill_process` on a real target
  (they need root and a disposable host).
- Behaviour under load beyond a single sensor.
