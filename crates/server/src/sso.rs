//! Single sign-on through OpenID Connect (authorization code flow with PKCE).
//! Works with any standards-compliant provider: Google Workspace, Microsoft
//! Entra ID, Okta, Keycloak, Authentik.
//!
//! The ID token's signature, issuer, audience, expiry and nonce are all
//! verified. Only asymmetric algorithms are accepted, so a token cannot be
//! forged with the client secret as an HMAC key.

use crate::{db, AppState};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use rusqlite::params;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const SESSION_COOKIE: &str = "postern_session";
const SESSION_SECS: i64 = 12 * 3600;
const PENDING_SECS: i64 = 600;

pub struct Pending {
    nonce: String,
    verifier: String,
    redirect_uri: String,
    created: i64,
}

pub struct SsoConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// Public base URL of the console, e.g. https://console.example.com
    pub base_url: String,
    pub role_map: Value,
}

pub fn config(conn: &rusqlite::Connection) -> Option<SsoConfig> {
    let get = |k: &str| db::get_setting(conn, k).filter(|v| !v.is_empty());
    Some(SsoConfig {
        issuer: get("sso_issuer")?.trim_end_matches('/').to_string(),
        client_id: get("sso_client_id")?,
        client_secret: get("sso_client_secret").unwrap_or_default(),
        base_url: get("sso_base_url")?.trim_end_matches('/').to_string(),
        role_map: get("sso_role_map").and_then(|m| serde_json::from_str(&m).ok()).unwrap_or(Value::Null),
    })
}

pub fn valid_role(r: &str) -> bool {
    matches!(r, "viewer" | "analyst" | "admin")
}

pub fn role_rank(r: &str) -> u8 {
    match r {
        "admin" => 3,
        "analyst" => 2,
        "viewer" => 1,
        _ => 0,
    }
}

/// Resolve a signed-in identity to a console role. Precedence: exact email,
/// then the highest-ranked matching group, then the email domain, then the
/// default. No match means the sign-in is refused.
pub fn role_for(map: &Value, email: &str, groups: &[String]) -> Option<String> {
    let email = email.to_lowercase();
    let pick = |section: &str, key: &str| {
        map[section]
            .as_object()
            .and_then(|o| o.iter().find(|(k, _)| k.to_lowercase() == key))
            .and_then(|(_, v)| v.as_str())
            .filter(|r| valid_role(r))
            .map(str::to_string)
    };
    if let Some(r) = pick("emails", &email) {
        return Some(r);
    }
    let by_group = groups.iter().filter_map(|g| pick("groups", &g.to_lowercase())).max_by_key(|r| role_rank(r));
    if by_group.is_some() {
        return by_group;
    }
    if let Some(r) = email.rsplit_once('@').and_then(|(_, d)| pick("domains", d)) {
        return Some(r);
    }
    map["default"].as_str().filter(|r| valid_role(r)).map(str::to_string)
}

async fn discovery(state: &AppState, issuer: &str) -> anyhow::Result<Value> {
    let doc: Value = state
        .http
        .get(format!("{issuer}/.well-known/openid-configuration"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let declared = doc["issuer"].as_str().unwrap_or_default().trim_end_matches('/');
    if declared != issuer {
        anyhow::bail!("provider declares issuer `{declared}`, expected `{issuer}`");
    }
    Ok(doc)
}

/// Start a sign-in: returns the provider URL to redirect the browser to.
pub async fn begin(state: &AppState) -> anyhow::Result<String> {
    let cfg = config(&state.db.lock().unwrap()).ok_or_else(|| anyhow::anyhow!("single sign-on is not configured"))?;
    let doc = discovery(state, &cfg.issuer).await?;
    let auth = doc["authorization_endpoint"].as_str().ok_or_else(|| anyhow::anyhow!("provider has no authorization_endpoint"))?;
    let st = db::random_token("st");
    let nonce = db::random_token("n");
    let verifier = db::random_token("v");
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let redirect_uri = format!("{}/auth/oidc/callback", cfg.base_url);
    let url = reqwest::Url::parse_with_params(
        auth,
        &[
            ("response_type", "code"),
            ("client_id", cfg.client_id.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("scope", "openid email profile"),
            ("state", st.as_str()),
            ("nonce", nonce.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ],
    )?;
    let now = postern_proto::now_ms();
    let mut pending = state.sso_pending.lock().unwrap();
    pending.retain(|_, p| now - p.created < PENDING_SECS * 1000);
    if pending.len() > 5000 {
        anyhow::bail!("too many sign-ins in progress; retry in a few minutes");
    }
    pending.insert(st, Pending { nonce, verifier, redirect_uri, created: now });
    Ok(url.to_string())
}

fn verify_id_token(token: &str, jwks: &Value, issuer: &str, client_id: &str) -> anyhow::Result<Value> {
    let header = decode_header(token)?;
    let asymmetric = matches!(
        header.alg,
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 | Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 | Algorithm::ES256 | Algorithm::ES384
    );
    if !asymmetric {
        anyhow::bail!("ID token uses an algorithm that is not accepted ({:?})", header.alg);
    }
    let keys = jwks["keys"].as_array().ok_or_else(|| anyhow::anyhow!("provider key set has no keys"))?;
    let jwk = keys
        .iter()
        .find(|k| match &header.kid {
            Some(kid) => k["kid"].as_str() == Some(kid),
            None => keys.len() == 1,
        })
        .ok_or_else(|| anyhow::anyhow!("no provider key matches the ID token's key id"))?;
    let field = |f: &str| jwk[f].as_str().ok_or_else(|| anyhow::anyhow!("provider key is missing `{f}`"));
    let key = match jwk["kty"].as_str() {
        Some("RSA") => DecodingKey::from_rsa_components(field("n")?, field("e")?)?,
        Some("EC") => DecodingKey::from_ec_components(field("x")?, field("y")?)?,
        other => anyhow::bail!("unsupported provider key type {other:?}"),
    };
    let mut v = Validation::new(header.alg);
    v.set_audience(&[client_id]);
    v.set_issuer(&[issuer]);
    Ok(decode::<Value>(token, &key, &v)?.claims)
}

pub struct Session {
    pub token: String,
    pub secure: bool,
}

/// Finish a sign-in: exchange the code, verify the ID token, open a session.
pub async fn finish(state: &AppState, code: &str, st: &str) -> anyhow::Result<Session> {
    let pending = state
        .sso_pending
        .lock()
        .unwrap()
        .remove(st)
        .filter(|p| postern_proto::now_ms() - p.created < PENDING_SECS * 1000)
        .ok_or_else(|| anyhow::anyhow!("this sign-in link expired or was already used; start again"))?;
    let cfg = config(&state.db.lock().unwrap()).ok_or_else(|| anyhow::anyhow!("single sign-on is not configured"))?;
    let doc = discovery(state, &cfg.issuer).await?;
    let token_endpoint = doc["token_endpoint"].as_str().ok_or_else(|| anyhow::anyhow!("provider has no token_endpoint"))?;
    let jwks_uri = doc["jwks_uri"].as_str().ok_or_else(|| anyhow::anyhow!("provider has no jwks_uri"))?;

    let resp = state
        .http
        .post(token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", pending.redirect_uri.as_str()),
            ("client_id", cfg.client_id.as_str()),
            ("client_secret", cfg.client_secret.as_str()),
            ("code_verifier", pending.verifier.as_str()),
        ])
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        anyhow::bail!("provider rejected the code exchange ({status}): {}", body["error_description"].as_str().or(body["error"].as_str()).unwrap_or("no detail"));
    }
    let id_token = body["id_token"].as_str().ok_or_else(|| anyhow::anyhow!("provider returned no id_token"))?;
    let jwks: Value = state.http.get(jwks_uri).send().await?.error_for_status()?.json().await?;
    let claims = verify_id_token(id_token, &jwks, doc["issuer"].as_str().unwrap_or(&cfg.issuer), &cfg.client_id)?;

    if claims["nonce"].as_str() != Some(pending.nonce.as_str()) {
        anyhow::bail!("ID token nonce does not match this sign-in");
    }
    if claims["email_verified"].as_bool() == Some(false) {
        anyhow::bail!("the provider reports this email address as unverified");
    }
    let email = claims["email"]
        .as_str()
        .or(claims["preferred_username"].as_str())
        .or(claims["upn"].as_str())
        .ok_or_else(|| anyhow::anyhow!("ID token carries no email; add the `email` claim at the provider"))?
        .to_lowercase();
    let groups: Vec<String> = claims["groups"].as_array().map(|g| g.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();

    let conn = state.db.lock().unwrap();
    let Some(role) = role_for(&cfg.role_map, &email, &groups) else {
        db::audit(&conn, &email, "sso.denied", "no role mapping matches this account");
        anyhow::bail!("{email} is not assigned a role in this console; ask an administrator");
    };
    let token = db::random_token("pss");
    let now = postern_proto::now_ms();
    conn.execute("DELETE FROM sessions WHERE expires_at < ?1", [now])?;
    conn.execute(
        "INSERT INTO sessions(token_hash, email, role, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![db::sha256_hex(&token), email, role, now, now + SESSION_SECS * 1000],
    )?;
    db::audit(&conn, &email, "sso.login", &role);
    Ok(Session { token, secure: cfg.base_url.starts_with("https://") })
}

pub fn cookie(token: &str, secure: bool, max_age: i64) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

pub fn session_max_age() -> i64 {
    SESSION_SECS
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn role_mapping_precedence() {
        let map = json!({
            "emails": {"Root@Corp.com": "admin"},
            "groups": {"soc": "analyst", "everyone": "viewer"},
            "domains": {"corp.com": "viewer"},
            "default": ""
        });
        assert_eq!(role_for(&map, "root@corp.com", &[]).as_deref(), Some("admin"));
        assert_eq!(role_for(&map, "a@corp.com", &["everyone".into(), "SOC".into()]).as_deref(), Some("analyst"));
        assert_eq!(role_for(&map, "a@corp.com", &[]).as_deref(), Some("viewer"));
        assert_eq!(role_for(&map, "a@other.com", &[]), None);
        assert_eq!(role_for(&json!({"default": "viewer"}), "a@other.com", &[]).as_deref(), Some("viewer"));
        assert_eq!(role_for(&json!({"default": "superuser"}), "a@other.com", &[]), None);
    }

    #[test]
    fn rejects_symmetric_tokens() {
        // {"alg":"HS256","typ":"JWT"} . {} . sig
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.c2ln";
        let err = verify_id_token(token, &json!({"keys": []}), "https://idp", "client").unwrap_err();
        assert!(err.to_string().contains("not accepted"), "{err}");
    }
}
