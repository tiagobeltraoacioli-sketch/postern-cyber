# Architecture

```
 endpoint                         management server                    operator
┌────────────────┐  HTTPS POST   ┌──────────────────────────────┐    ┌──────────┐
│ postern-sensor │ ────────────► │ ingest → detect → correlate  │◄───│ console  │
│  collectors    │  events +     │   │         │         │      │    │ REST API │
│  responder     │  heartbeat    │ SQLite   rules     incidents │    └──────────┘
│                │ ◄──────────── │                              │
└────────────────┘  actions      │ AI analyst ─► api.anthropic  │
                                 └──────────────────────────────┘
```

## Sensor

One process, one loop. Collectors poll and diff against their own baseline:

| Collector | Interval | Event kind |
|---|---|---|
| Processes: kernel process connector (Linux, root) | pushed | `process_start` |
| Processes: poll (other platforms, and reconciliation) | 2 s / 10 s | `process_start` |
| Exec guard: fanotify (Linux, root) | pushed | `exec_blocked` |
| Vault canaries / snapshots (`--protect`) | 5 s / 15 min | `ransomware_canary`, `ransomware_suspected` |
| Auth log | 5 s | `auth` |
| Sockets (`ss` / `lsof`) | 10 s | `net_conn`, `listen_port` |
| File integrity | 30 s | `file_change` |
| Posture and inventory | start, then 6 h | `posture`, `inventory` |

Events are buffered (20,000 max) and uploaded every 5 s. A failed upload keeps
the batch for the next attempt. The upload response carries pending response
actions; the sensor executes those it has the capability for and reports the
result.

## Kernel sources (Linux)

Two stable kernel interfaces, no module and no eBPF toolchain:

- **Process connector** (netlink `cn_proc`). The kernel sends an event per
  exec. The sensor reads `/proc/<pid>` at once. If the process is already
  gone, the record is completed from the exec guard's cache (path and hash,
  `process.short_lived`).
- **Exec guard** (fanotify, `FAN_OPEN_EXEC` or `FAN_OPEN_EXEC_PERM`). Marks
  are placed per mount, never per filesystem, so a sensor in a container
  cannot affect the host. Without the `prevent` capability the guard only
  observes. With it, each exec waits for a verdict: deny when the host is in
  `protect` mode and the file's SHA-256 is on the block list or its path is
  under a blocked prefix. Every error path allows.

The execution policy (`block_hashes`, `block_paths`) comes back with every
upload and is kept on disk for the next start.

## Ransomware vault

`--protect <dir>` keeps a content-addressed store (`vault/objects/<sha256>`)
and one manifest per snapshot. A pass is refused, and
`ransomware_suspected` raised, when at least 20 known files changed and 60 %
of them went from low to high entropy, or when 30 % of known files vanished
while mostly high-entropy files appeared. `rollback_files` restores a
manifest and moves unknown files to `vault/rollback-<ts>/`. `vault_accept`
tells the sensor the mass change was legitimate.

## Event model

`{ts, kind, fields}` where `fields` is a flat map with dotted keys:
`process.name`, `process.exe`, `process.cmdline`, `process.pid`,
`process.ppid`, `process.parent_name`, `process.user`, `process.sha256`,
`file.path`, `file.action`, `file.sha256`, `net.direction`, `net.remote_ip`,
`net.remote_port`, `net.local_port`, `auth.user`, `auth.result`,
`auth.service`, `auth.source_ip`, `posture.check`, `posture.status`.

## Server

- **Ingest**: stores each event, matches indicators, evaluates rules.
- **Detect** (`detect.rs`): compiled YAML rules, sliding-window thresholds,
  60-second de-duplication per rule, endpoint and subject.
- **Correlate**: an alert joins the open incident on the same endpoint if it
  was updated in the last 30 minutes, otherwise opens one. Severity is the
  maximum of its alerts.
- **Respond**: actions are rows in a queue (`pending → sent → done|failed`).
  Sources are an operator or, in `protect` mode, the rule's `response` list.
- **Vulnerabilities** (`vuln.rs`): when an inventory changes, and daily, the
  OSV feed for each distribution in use is downloaded to
  `<data-dir>/feeds/` and scanned; findings land in `endpoint_vulns`.
- **Identity** (`sso.rs`): OpenID Connect authorization-code flow with PKCE;
  sessions are an HttpOnly, SameSite=Lax cookie and every cookie-authenticated
  request must carry `X-Postern-CSRF`.
- **Retention**: events older than `--retention-days` are deleted hourly,
  except those referenced by an alert.

## API

Sensor plane (agent key):

- `POST /api/v1/sensor/enroll`
- `POST /api/v1/sensor/events`
- `POST /api/v1/sensor/actions/{id}/result`

Console plane (admin token or API key, `Authorization: Bearer`):

- `GET /api/v1/overview | endpoints | endpoints/{id} | incidents | incidents/{id} | alerts | events | actions | rules | iocs | audit | settings`
- `POST /api/v1/endpoints/{id}/actions | endpoints/{id}/mode | incidents/{id}/status`
- `POST /api/v1/rules | rules/{id}/toggle | rules/{id}/delete | iocs | iocs/{id}/delete | keys`
- `POST /api/v1/ingest` for third-party events: `{"source": "fw-1", "events": [{"kind": "...", "fields": {...}}]}`
- `POST /api/v1/ai/triage/{id} | ai/hunt | ai/rule | settings/ai | settings/ai/test`
- `GET /api/v1/me | vulns`, `POST /api/v1/vulns/refresh | settings/sso | settings/prevention | keys/{id}/delete`
- `GET /auth/config | /auth/oidc/login | /auth/oidc/callback`, `POST /auth/logout`

Minimum role: `GET` routes viewer; actions, incidents, rules, indicators,
ingest and AI analyst; endpoint mode, settings, keys and feed refresh admin.

## AI analyst

Raw HTTPS to `POST https://api.anthropic.com/v1/messages` (there is no official
Rust SDK), `anthropic-version: 2026-10-21`.

- Model defaults to `claude-mythos-5-2`. Thinking is always on for this model;
  depth is set with `output_config.effort`. No sampling parameters are sent.
- Triage and rule drafting use structured outputs
  (`output_config.format` with a JSON schema).
- Hunting is a manual tool-use loop (12 turns max) over three read-only tools
  with `strict: true`. Assistant turns are replayed unchanged.
- `fallbacks: "default"` with the `server-side-fallback-2026-07-01` beta is on
  by default: security telemetry can trip the cyber safety classifier, and the
  API then re-runs the request on Anthropic's recommended substitute.
  `stop_reason: "refusal"` is surfaced as an error and never parsed.

## Security model

- Tokens (admin, API keys, agent keys, SSO sessions) are stored as SHA-256 hashes. The
  enrollment token and an API key saved through the console are stored in
  clear text in the database; protect the data directory.
- Telemetry is attacker-influenced. The console escapes every rendered value.
  The AI prompts wrap telemetry in tagged blocks and the system prompt tells
  the model to treat it as evidence.
- The AI has no write tools. Response actions require an operator, or an
  explicit per-host `protect` policy.
- A sensor ignores actions it was not started with (`--response`), so a
  compromised server cannot do more than the endpoint owner allowed.
- `quarantine_file` refuses system directories; `kill_process` refuses pid 1
  and the sensor itself; `isolate_host` refuses to run when it cannot resolve
  an address to keep open.
- The server has no TLS of its own. Bind to loopback and terminate TLS in
  front of it.
