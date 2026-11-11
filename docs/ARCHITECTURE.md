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
| Processes (sysinfo) | 2 s | `process_start` |
| Auth log | 5 s | `auth` |
| Sockets (`ss` / `lsof`) | 10 s | `net_conn`, `listen_port` |
| File integrity | 30 s | `file_change` |
| Posture and inventory | start, then 6 h | `posture`, `inventory` |

Events are buffered (20,000 max) and uploaded every 5 s. A failed upload keeps
the batch for the next attempt. The upload response carries pending response
actions; the sensor executes those it has the capability for and reports the
result.

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

- Tokens (admin, API keys, agent keys) are stored as SHA-256 hashes. The
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
