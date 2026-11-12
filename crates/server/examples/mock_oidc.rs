//! Minimal OpenID Connect provider for testing the console's SSO flow.
//! Development tool only: it signs in whoever MOCK_EMAIL names, no password.
//!
//!   MOCK_KEY_PEM=key.pem MOCK_MODULUS_HEX=... MOCK_EMAIL=a@corp.example \
//!     cargo run -p postern-server --example mock_oidc
//!
//! MOCK_FORGE=1 signs tokens with a different key than the one published.

use axum::extract::{Form, Query, State};
use axum::response::Redirect;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const ISSUER: &str = "http://127.0.0.1:8490";

struct Idp {
    key: EncodingKey,
    modulus: String,
    codes: Mutex<HashMap<String, (String, String, String)>>, // code -> (nonce, challenge, client_id)
}

type Q = Query<HashMap<String, String>>;

#[tokio::main]
async fn main() {
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("set {k}"));
    let sign_with = if std::env::var("MOCK_FORGE").is_ok() { env("MOCK_FORGE_KEY_PEM") } else { env("MOCK_KEY_PEM") };
    let pem = std::fs::read(sign_with).expect("read signing key");
    let modulus = URL_SAFE_NO_PAD.encode(hex::decode(env("MOCK_MODULUS_HEX").trim()).expect("modulus hex"));
    let idp = Arc::new(Idp { key: EncodingKey::from_rsa_pem(&pem).expect("rsa pem"), modulus, codes: Mutex::new(HashMap::new()) });

    let app = Router::new()
        .route("/.well-known/openid-configuration", get(|| async {
            Json(json!({
                "issuer": ISSUER,
                "authorization_endpoint": format!("{ISSUER}/authorize"),
                "token_endpoint": format!("{ISSUER}/token"),
                "jwks_uri": format!("{ISSUER}/jwks"),
            }))
        }))
        .route("/jwks", get(|State(idp): State<Arc<Idp>>| async move {
            Json(json!({"keys": [
                {"kty": "RSA", "use": "enc", "alg": "RSA-OAEP", "kid": "enc-1", "n": idp.modulus, "e": "AQAB"},
                {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "sig-1", "n": idp.modulus, "e": "AQAB"}
            ]}))
        }))
        .route("/authorize", get(|State(idp): State<Arc<Idp>>, Query(q): Q| async move {
            let code = format!("code-{}", idp.codes.lock().unwrap().len() + 1);
            let get = |k: &str| q.get(k).cloned().unwrap_or_default();
            idp.codes.lock().unwrap().insert(code.clone(), (get("nonce"), get("code_challenge"), get("client_id")));
            Redirect::to(&format!("{}?code={code}&state={}", get("redirect_uri"), get("state")))
        }))
        .route("/token", post(|State(idp): State<Arc<Idp>>, Form(f): Form<HashMap<String, String>>| async move {
            let get = |k: &str| f.get(k).cloned().unwrap_or_default();
            let Some((nonce, challenge, client_id)) = idp.codes.lock().unwrap().remove(&get("code")) else {
                return Json(json!({"error": "invalid_grant"}));
            };
            if URL_SAFE_NO_PAD.encode(Sha256::digest(get("code_verifier").as_bytes())) != challenge || get("client_secret") != "mock-secret" {
                return Json(json!({"error": "invalid_grant", "error_description": "PKCE or client secret mismatch"}));
            }
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let claims: Value = json!({
                "iss": ISSUER, "aud": client_id, "sub": "user-1", "iat": now, "exp": now + 300,
                "nonce": if std::env::var("MOCK_BAD_NONCE").is_ok() { "wrong".to_string() } else { nonce },
                "email": std::env::var("MOCK_EMAIL").unwrap_or_else(|_| "analyst@corp.example".into()),
                "email_verified": true,
                "groups": std::env::var("MOCK_GROUPS").unwrap_or_default().split(',').filter(|g| !g.is_empty()).collect::<Vec<_>>(),
            });
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some("sig-1".into());
            Json(json!({"access_token": "unused", "token_type": "Bearer", "id_token": encode(&header, &claims, &idp.key).unwrap()}))
        }))
        .with_state(idp);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8490").await.unwrap();
    println!("mock OIDC provider on {ISSUER}");
    axum::serve(listener, app).await.unwrap();
}
