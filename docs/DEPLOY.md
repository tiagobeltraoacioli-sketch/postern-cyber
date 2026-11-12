# Deployment

## Server

```sh
cargo build --release
sudo useradd --system --home /var/lib/postern --shell /usr/sbin/nologin postern
sudo install -d -o postern -g postern /var/lib/postern
sudo install -d /opt/postern/bin /etc/postern
sudo install target/release/postern-server target/release/postern-sensor /opt/postern/bin/
sudo install -m 644 deploy/postern-server.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now postern-server
sudo cat /var/lib/postern/admin.token
```

Optional `/etc/postern/server.env` (mode 600):

```
ANTHROPIC_API_KEY=sk-ant-...
POSTERN_AI_MODEL=claude-mythos-5-2
```

The server listens on `127.0.0.1:8460`. For remote sensors and operators, put
Caddy (or nginx, or a Cloudflare tunnel) in front: `deploy/Caddyfile.example`.
Until then, reach the console through an SSH tunnel:

```sh
ssh -N -L 8460:127.0.0.1:8460 user@server
```

## Sensor

```sh
sudo install -m 600 deploy/sensor.env.example /etc/postern/sensor.env   # then edit
sudo install -m 644 deploy/postern-sensor.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now postern-sensor
```

Start every new host in observe-only mode (`POSTERN_RESPONSE=` empty) and
`detect` mode. Grant response capabilities and switch to `protect` once the
detections have run quietly on that host.

Before granting `isolate`, set `POSTERN_ISOLATE_ALLOW` to your admin address.
An isolated host accepts traffic only from the management server and that
list.

## Kernel features and prevention (Linux)

As root the sensor uses kernel process events and the exec guard
automatically (`processes=kernel exec_guard=observe` in its start line).
To let it deny execution:

```
POSTERN_RESPONSE=prevent
```

then put the host in `protect` mode and set the policy under Settings.
Read "Known hazards" in COVERAGE.md first.

## Ransomware rollback

```
POSTERN_PROTECT=/srv/data,/home
POSTERN_RESPONSE=rollback
```

The vault is at `<state-dir>/vault` (root only). Size it with
`POSTERN_VAULT_MAX_GB` (default 20) and `POSTERN_VAULT_INTERVAL` (seconds,
default 900).

## Windows sensor

```sh
scripts/build-windows.sh        # produces target/x86_64-pc-windows-gnu/release/postern-sensor.exe
```

On the Windows host, from an elevated prompt:

```
postern-sensor.exe --server https://console.example.com --enroll-token pce_...
sc create PosternSensor binPath= "C:\Program Files\Postern\postern-sensor.exe --server https://console.example.com" start= auto
```

State lives in `%ProgramData%\PosternSensor`. The executable is not yet a
native service (it does not answer the service control manager), so run it
from Task Scheduler at startup or under a service wrapper.

## Single sign-on

Create an OpenID Connect "web application" client at your provider with the
redirect URI `https://<console>/auth/oidc/callback`, then fill Issuer, Client
ID, Client secret and the role mapping under Settings. Keep at least one
admin API key as a break-glass credential.

## Vulnerability feeds

The server downloads one archive per distribution in use into
`<data-dir>/feeds/` once a day (Ubuntu: about 815 MB, Debian: about 80 MB)
and scans it in roughly a minute and a half. It needs outbound HTTPS to
`osv-vulnerabilities.storage.googleapis.com`; nothing is uploaded.

## Website

`site/index.html` is a static file (`scripts/build-site.sh` regenerates it
from `site/page.html`). Serve it from any static host and point
`posterncyber.com` at it.
