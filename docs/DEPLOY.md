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

## Website

`site/index.html` is a static file (`scripts/build-site.sh` regenerates it
from `site/page.html`). Serve it from any static host and point
`posterncyber.com` at it.
