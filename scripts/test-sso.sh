#!/usr/bin/env bash
# End-to-end test of single sign-on and role enforcement against the mock
# OIDC provider (crates/server/examples/mock_oidc.rs). Needs openssl and curl.
set -euo pipefail
cd "$(dirname "$0")/.."
W=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$W"' EXIT
openssl genrsa -out "$W/key.pem" 2048 2>/dev/null
openssl genrsa -out "$W/forge.pem" 2048 2>/dev/null
MOD=$(openssl rsa -in "$W/key.pem" -noout -modulus | cut -d= -f2)
cargo build -q -p postern-server --example mock_oidc && cargo build -q -p postern-server
S=http://127.0.0.1:8493
./target/debug/postern-server --listen 127.0.0.1:8493 --data-dir "$W/data" >"$W/server.log" 2>&1 &
for _ in $(seq 1 60); do curl -fsS "$S/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
ADMIN="Authorization: Bearer $(cat "$W/data/admin.token")"
curl -fsS -H "$ADMIN" -H 'Content-Type: application/json' "$S/api/v1/settings/sso" -d '{
  "issuer": "http://127.0.0.1:8490", "client_id": "postern-console", "client_secret": "mock-secret", "base_url": "http://127.0.0.1:8493",
  "role_map": {"emails": {"boss@corp.example": "admin"}, "groups": {"soc": "analyst"}, "domains": {"corp.example": "viewer"}, "default": ""}}' >/dev/null

IDP=""
idp() { if [ -n "$IDP" ]; then kill "$IDP" 2>/dev/null || true; wait "$IDP" 2>/dev/null || true; fi; env MOCK_KEY_PEM="$W/key.pem" MOCK_FORGE_KEY_PEM="$W/forge.pem" MOCK_MODULUS_HEX="$MOD" "$@" ./target/debug/examples/mock_oidc >/dev/null 2>&1 & IDP=$!
  for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:8490/jwks >/dev/null 2>&1 && break; sleep 0.5; done; }
login() { rm -f "$W/jar"; curl -sS -L -c "$W/jar" -b "$W/jar" -o /dev/null -w '%{url_effective}' "$S/auth/oidc/login"; }
me() { curl -sS -b "$W/jar" -H 'X-Postern-CSRF: 1' "$S/api/v1/me"; }
code() { curl -sS -o /dev/null -w '%{http_code}' -b "$W/jar" "$@"; }
pass=0; fail=0
check() { if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "ok   $1"; else fail=$((fail+1)); echo "FAIL $1: expected [$3], got [$2]"; fi; }

idp MOCK_EMAIL=viewer@corp.example
login >/dev/null
check "domain mapping gives viewer"            "$(me)" '{"name":"viewer@corp.example","role":"viewer","via":"sso"}'
check "viewer can read"                        "$(code -H 'X-Postern-CSRF: 1' "$S/api/v1/incidents")" 200
check "viewer cannot change a rule"            "$(code -H 'X-Postern-CSRF: 1' -H 'Content-Type: application/json' -d '{"enabled":false}' "$S/api/v1/rules/PC-EXE-001/toggle")" 403
check "viewer cannot read settings secrets"    "$(curl -sS -b "$W/jar" -H 'X-Postern-CSRF: 1' "$S/api/v1/settings" | grep -c 'pce_' || true)" 0
check "cookie without CSRF header is refused"  "$(code "$S/api/v1/incidents")" 403

idp MOCK_EMAIL=someone@corp.example MOCK_GROUPS=soc
login >/dev/null
check "group mapping gives analyst"            "$(me)" '{"name":"someone@corp.example","role":"analyst","via":"sso"}'
check "analyst can change a rule"              "$(code -H 'X-Postern-CSRF: 1' -H 'Content-Type: application/json' -d '{"enabled":true}' "$S/api/v1/rules/PC-EXE-001/toggle")" 200
check "analyst cannot change SSO settings"     "$(code -H 'X-Postern-CSRF: 1' -H 'Content-Type: application/json' -d '{"issuer":"https://evil.example"}' "$S/api/v1/settings/sso")" 403
check "analyst cannot create API keys"         "$(code -H 'X-Postern-CSRF: 1' -H 'Content-Type: application/json' -d '{"name":"x","role":"admin"}' "$S/api/v1/keys")" 403

idp MOCK_EMAIL=boss@corp.example
login >/dev/null
check "email mapping gives admin"              "$(me)" '{"name":"boss@corp.example","role":"admin","via":"sso"}'
curl -sS -o /dev/null -b "$W/jar" -c "$W/jar" -X POST "$S/auth/logout"
check "session is gone after logout"           "$(code -H 'X-Postern-CSRF: 1' "$S/api/v1/incidents")" 401

idp MOCK_EMAIL=stranger@elsewhere.example
check "unmapped account is refused"            "$(login | grep -c 'login_error=.*not+assigned+a+role' || true)" 1
check "refused account has no session"         "$(code -H 'X-Postern-CSRF: 1' "$S/api/v1/incidents")" 401

idp MOCK_EMAIL=boss@corp.example MOCK_FORGE=1
check "token signed by another key is refused" "$(login | grep -c 'login_error=' || true)" 1
check "forged token opens no session"          "$(code -H 'X-Postern-CSRF: 1' "$S/api/v1/incidents")" 401

idp MOCK_EMAIL=boss@corp.example MOCK_BAD_NONCE=1
check "wrong nonce is refused"                 "$(login | grep -c 'login_error=.*nonce' || true)" 1

check "replayed callback state is refused"     "$(curl -sS -o /dev/null -w '%{redirect_url}' "$S/auth/oidc/callback?code=code-1&state=st_deadbeef" | grep -c 'login_error=' || true)" 1
check "API-key roles: viewer key is read-only" "$(K=$(curl -sS -H "$ADMIN" -H 'Content-Type: application/json' -d '{"name":"ro","role":"viewer"}' "$S/api/v1/keys" | sed -E 's/.*"key":"([^"]+)".*/\1/'); curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $K" -H 'Content-Type: application/json' -d '{"kind":"ip","value":"203.0.113.9"}' "$S/api/v1/iocs")" 403

echo; echo "$pass passed, $fail failed"; [ "$fail" = 0 ]
