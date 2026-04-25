//! OAuth 2.1 server-side state and Bearer/JWT validation middleware.

pub mod consent;
pub mod handlers;
pub mod store;

use anyhow::Result;
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tauri::AppHandle;

use crate::mcp::McpAppState;

/// Audience claim for access tokens we issue.
pub const AUDIENCE: &str = "mcp";

/// Held inside `McpServerHandle`. Survives across server restarts so the
/// signing key + registered clients persist when the user toggles the server.
pub struct OAuthState {
    pub store: store::OAuthStore,
    pub consent: consent::ConsentRegistry,
    pub signing_key: Vec<u8>,
    /// Last bound port — set on `start`, used to compose absolute URLs in
    /// metadata documents and JWT issuer claims.
    pub bound_port: std::sync::atomic::AtomicU16,
}

impl OAuthState {
    pub fn initialise(app: &AppHandle) -> Result<Self> {
        let store = store::OAuthStore::open(app)?;
        let signing_key = store.get_or_create_signing_key()?;
        Ok(Self {
            store,
            consent: consent::ConsentRegistry::default(),
            signing_key,
            bound_port: std::sync::atomic::AtomicU16::new(0),
        })
    }

    pub fn set_port(&self, port: u16) {
        self.bound_port
            .store(port, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn base_url(&self) -> String {
        let port = self.bound_port.load(std::sync::atomic::Ordering::Relaxed);
        crate::mcp::public_url(port)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
}

/// Middleware that gates `/mcp` on a valid Bearer access token. On failure,
/// returns 401 with `WWW-Authenticate` pointing at the protected-resource
/// metadata so MCP clients can discover the auth server (per the MCP spec).
pub async fn require_bearer(
    State(state): State<McpAppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let token = match req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        Some(t) => t.trim().to_string(),
        None => return unauthorized(&state, "missing Bearer token"),
    };

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_audience(&[AUDIENCE]);
    let decoded = match jsonwebtoken::decode::<AccessClaims>(
        &token,
        &jsonwebtoken::DecodingKey::from_secret(&state.oauth.signing_key),
        &validation,
    ) {
        Ok(d) => d,
        Err(e) => return unauthorized(&state, &format!("invalid token: {e}")),
    };

    let claims = decoded.claims;
    match state.oauth.store.is_access_jti_revoked(&claims.jti) {
        Ok(true) => return unauthorized(&state, "token revoked"),
        Err(e) => return unauthorized(&state, &format!("server error: {e}")),
        Ok(false) => {}
    }
    match state.oauth.store.get_client(&claims.sub) {
        Ok(Some(_)) => {}
        Ok(None) => return unauthorized(&state, "client revoked"),
        Err(e) => return unauthorized(&state, &format!("server error: {e}")),
    }
    let _ = state.oauth.store.touch_client(&claims.sub);

    next.run(req).await
}

fn unauthorized(state: &McpAppState, why: &str) -> Response {
    let metadata = format!(
        "Bearer realm=\"mcp\", resource_metadata=\"{}/.well-known/oauth-protected-resource\", error=\"invalid_token\", error_description=\"{}\"",
        state.oauth.base_url(),
        why.replace('"', "'")
    );
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({
            "error": "invalid_token",
            "error_description": why,
        })),
    )
        .into_response();
    if let Ok(v) = metadata.parse() {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    resp
}
