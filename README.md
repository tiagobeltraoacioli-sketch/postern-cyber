# Postern Cyber

Self-hosted endpoint detection and response (EDR/XDR) with an AI analyst that
runs on Claude through your own Anthropic API key. The default model is Claude
Mythos 5.2 (`claude-mythos-5-2`).

Status: **0.2, private preview.** Read [docs/COVERAGE.md](docs/COVERAGE.md)
before relying on it: it lists what works today and what does not.

## What is in the box

| Component | Path | What it does |
|---|---|---|
| `postern-sensor` | `crates/sensor` | Linux/macOS/Windows agent: kernel-pushed process events and pre-execution blocking (Linux), network, file-integrity, authentication, posture and inventory telemetry, ransomware vault and rollback; executes response actions it was granted |
| `postern-server` | `crates/server` | Ingestion, detection engine, incident correlation, response queue, CVE matching, AI analyst, SSO and roles, REST API, embedded console |
| Detections | `rules/builtin.yml` | 48 behavioral rules (Linux, macOS, Windows) mapped to MITRE ATT&CK |
| Console | `console/index.html` | Operator UI, embedded in the server binary |
| Website | `site/` | posterncyber.com landing page |

## Quick start

```sh
cargo build --release

# 1. Server. Prints an admin token once and writes it to data/admin.token.
./target/release/postern-server --listen 127.0.0.1:8460 --data-dir ./data

# 2. Console: open http://127.0.0.1:8460 and sign in with the admin token.
#    Settings shows the enrollment token.

# 3. Sensor (as root for full visibility). Observe-only unless --response is set.
sudo ./target/release/postern-sensor --server http://127.0.0.1:8460 --enroll-token pce_...

# 4. Demo data: replays a synthetic intrusion through the ingest API.
POSTERN_TOKEN=$(cat data/admin.token) scripts/simulate-attack.sh
```

The server speaks plain HTTP. Keep it on loopback and put a TLS terminator in
front for anything remote (`deploy/Caddyfile.example`).

## AI analyst

Set the key in the console (Settings) or through the environment:

```sh
export ANTHROPIC_API_KEY=sk-ant-...
export POSTERN_AI_MODEL=claude-mythos-5-2   # default; any Claude model id works
export POSTERN_AI_EFFORT=high               # low | medium | high | xhigh | max
export POSTERN_AI_FALLBACKS=default         # "off" to disable refusal fallbacks
```

Claude Mythos 5.2 is available to verified organizations only. If your key's
organization does not have it, set another model id (for example
`claude-opus-5-5`).

Three functions, all in `crates/server/src/ai.rs`:

- **Triage** (`POST /api/v1/ai/triage/{incident}`): verdict, confidence,
  narrative with event ids, ATT&CK techniques, recommended actions.
- **Hunt** (`POST /api/v1/ai/hunt`): a tool-use loop over read-only queries of
  the event store.
- **Rule drafting** (`POST /api/v1/ai/rule`): a validated YAML rule from a
  description; nothing is installed until an operator saves it.

The model never executes a response action. It recommends, and an operator
approves each action in the console.

## Response actions

`kill_process`, `quarantine_file`, `isolate_host` / `unisolate_host`,
`rollback_files`, `collect_triage`. A sensor executes only what it was
started with:

```sh
postern-sensor ... --response kill,quarantine,isolate,prevent,rollback \
  --isolate-allow 198.51.100.10 --protect /srv/data,/home
```

- `prevent` (Linux, root): deny a program before it runs when its SHA-256 is
  on the indicator list or its path is under a blocked prefix (Settings).
- `rollback` with `--protect`: keep versioned copies of those directories,
  refuse snapshots that look like mass encryption, restore on demand.

Hosts run in `detect` mode by default. In `protect` mode, rules that declare a
`response` queue those actions automatically.

## Access control

API keys and SSO sessions carry a role: `viewer` (read), `analyst` (also
triage, respond, edit detections) or `admin` (also settings, keys, protect
mode). Single sign-on is OpenID Connect; configure it under Settings and map
emails, groups or domains to roles.

## Vulnerabilities

Sensors report installed packages; the server downloads the public OSV
database for the distribution (Ubuntu, Debian) and matches locally. See the
Exposure tab.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): data flow, API, security model
- [docs/RULES.md](docs/RULES.md): writing detections
- [docs/COVERAGE.md](docs/COVERAGE.md): capability matrix and known gaps
- [docs/DEPLOY.md](docs/DEPLOY.md): systemd units, TLS, the website

## Development

```sh
cargo test              # rules, detections, parsers, vault, version ordering
scripts/test-sso.sh     # SSO and role enforcement against a mock provider
scripts/build-windows.sh  # cross-compile postern-sensor.exe (needs mingw-w64)
scripts/build-site.sh   # regenerates site/index.html from site/page.html
```

Proprietary. All rights reserved.
