# Postern Cyber

Self-hosted endpoint detection and response (EDR/XDR) with an AI analyst that
runs on Claude through your own Anthropic API key. The default model is Claude
Mythos 5.2 (`claude-mythos-5-2`).

Status: **0.1, private preview.** Read [docs/COVERAGE.md](docs/COVERAGE.md)
before relying on it: it lists what works today and what does not.

## What is in the box

| Component | Path | What it does |
|---|---|---|
| `postern-sensor` | `crates/sensor` | Linux/macOS agent: process, network, file-integrity, authentication, posture and inventory telemetry; executes response actions it was granted |
| `postern-server` | `crates/server` | Ingestion, detection engine, incident correlation, response queue, AI analyst, REST API, embedded console |
| Detections | `rules/builtin.yml` | 31 behavioral rules mapped to MITRE ATT&CK |
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

`kill_process`, `quarantine_file`, `isolate_host` / `unisolate_host` (Linux,
nftables), `collect_triage`. A sensor executes only what it was started with:

```sh
postern-sensor ... --response kill,quarantine,isolate --isolate-allow 198.51.100.10
```

Hosts run in `detect` mode by default. In `protect` mode, rules that declare a
`response` queue those actions automatically.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): data flow, API, security model
- [docs/RULES.md](docs/RULES.md): writing detections
- [docs/COVERAGE.md](docs/COVERAGE.md): capability matrix and known gaps
- [docs/DEPLOY.md](docs/DEPLOY.md): systemd units, TLS, the website

## Development

```sh
cargo test          # rule validation, detection and parser tests
scripts/build-site.sh   # regenerates site/index.html from site/page.html
```

Proprietary. All rights reserved.
