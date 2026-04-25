//! HTTP handlers for the OAuth 2.1 + PKCE + DCR endpoints we expose to MCP
//! clients on loopback.
//!
//! Endpoints:
//!   GET  /.well-known/oauth-authorization-server  (RFC 8414)
//!   GET  /.well-known/oauth-protected-resource    (RFC 9728)
//!   POST /register                                (RFC 7591)
//!   GET  /authorize                               (PKCE S256, opens consent)
//!   POST /token                                   (auth_code | refresh_token)

use axum::{
    extract::{Form, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use uuid::Uuid;

use crate::mcp::McpAppState;

const ACCESS_TTL_SECS: i64 = 60 * 60; // 1 hour
const REFRESH_TTL_SECS: i64 = 30 * 24 * 60 * 60; // 30 days
const CONSENT_TIMEOUT: Duration = Duration::from_secs(5 * 60);

// =====================================================================
// Metadata documents
// =====================================================================

#[derive(Serialize)]
struct AuthServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: String,
    response_types_supported: Vec<&'static str>,
    grant_types_supported: Vec<&'static str>,
    code_challenge_methods_supported: Vec<&'static str>,
    token_endpoint_auth_methods_supported: Vec<&'static str>,
}

pub async fn well_known_authorization_server(
    State(state): State<McpAppState>,
) -> Json<serde_json::Value> {
    let base = state.oauth.base_url();
    let meta = AuthServerMetadata {
        issuer: base.clone(),
        authorization_endpoint: format!("{base}/authorize"),
        token_endpoint: format!("{base}/token"),
        registration_endpoint: format!("{base}/register"),
        response_types_supported: vec!["code"],
        grant_types_supported: vec!["authorization_code", "refresh_token"],
        code_challenge_methods_supported: vec!["S256"],
        token_endpoint_auth_methods_supported: vec!["none"],
    };
    Json(serde_json::to_value(meta).unwrap())
}

#[derive(Serialize)]
struct ProtectedResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    bearer_methods_supported: Vec<&'static str>,
}

pub async fn well_known_protected_resource(
    State(state): State<McpAppState>,
) -> Json<serde_json::Value> {
    let base = state.oauth.base_url();
    let meta = ProtectedResourceMetadata {
        resource: format!("{base}/mcp"),
        authorization_servers: vec![base],
        bearer_methods_supported: vec!["header"],
    };
    Json(serde_json::to_value(meta).unwrap())
}

// =====================================================================
// Dynamic Client Registration (RFC 7591)
// =====================================================================

#[derive(Deserialize)]
pub struct RegisterRequest {
    #[serde(default)]
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    client_id: String,
    client_id_issued_at: i64,
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: &'static str,
    grant_types: Vec<&'static str>,
    response_types: Vec<&'static str>,
    client_name: String,
}

pub async fn register(
    State(state): State<McpAppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, OAuthError> {
    if req.redirect_uris.is_empty() {
        return Err(OAuthError::invalid_request("redirect_uris is required"));
    }
    for uri in &req.redirect_uris {
        if !is_loopback_redirect(uri) {
            return Err(OAuthError::invalid_request(
                "only http://127.0.0.1:* / http://localhost:* redirect URIs are accepted",
            ));
        }
    }
    if matches!(
        req.token_endpoint_auth_method.as_deref(),
        Some(other) if other != "none"
    ) {
        return Err(OAuthError::invalid_request(
            "only token_endpoint_auth_method=none (public clients) is supported",
        ));
    }

    let name = req
        .client_name
        .unwrap_or_else(|| "Unnamed MCP client".to_string());
    let record = state
        .oauth
        .store
        .register_client(&name, &req.redirect_uris)
        .map_err(|e| OAuthError::server_error(e.to_string()))?;

    Ok(Json(RegisterResponse {
        client_id: record.id,
        client_id_issued_at: record.created_at,
        redirect_uris: record.redirect_uris,
        token_endpoint_auth_method: "none",
        grant_types: vec!["authorization_code", "refresh_token"],
        response_types: vec!["code"],
        client_name: record.name,
    }))
}

fn is_loopback_redirect(uri: &str) -> bool {
    let Ok(parsed) = url::Url::parse(uri) else {
        return false;
    };
    if parsed.scheme() != "http" {
        return false;
    }
    matches!(parsed.host_str(), Some("127.0.0.1") | Some("localhost"))
}

// =====================================================================
// Authorization endpoint (with consent)
// =====================================================================

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    #[serde(default)]
    pub scope: Option<String>,
    /// MCP/RFC 8707: resource indicator. Accepted but unused (single-resource
    /// server).
    #[serde(default, rename = "resource")]
    pub _resource: Option<String>,
}

pub async fn authorize(
    State(state): State<McpAppState>,
    Query(q): Query<AuthorizeQuery>,
) -> Result<Response, Response> {
    if q.response_type != "code" {
        return Err(redirect_error(&q.redirect_uri, q.state.as_deref(), "unsupported_response_type", None));
    }
    if q.code_challenge_method != "S256" {
        return Err(redirect_error(
            &q.redirect_uri,
            q.state.as_deref(),
            "invalid_request",
            Some("code_challenge_method must be S256"),
        ));
    }

    // Validate client + redirect URI exact-match before opening any UI.
    let client = match state
        .oauth
        .store
        .get_client(&q.client_id)
        .map_err(|e| html_error(&format!("server error: {e}")))?
    {
        Some(c) => c,
        None => return Err(html_error("Unknown client_id")),
    };
    if !client.redirect_uris.iter().any(|u| u == &q.redirect_uri) {
        return Err(html_error("redirect_uri does not match a registered URI"));
    }

    // Park the request and pop the consent window.
    let request_id = Uuid::new_v4().to_string();
    let info = super::consent::PendingConsent {
        request_id: request_id.clone(),
        client_id: client.id.clone(),
        client_name: client.name.clone(),
        redirect_uri: q.redirect_uri.clone(),
        scope: q.scope.clone(),
    };
    let waiter = state.oauth.consent.register(info);
    super::consent::open_consent_window(&state.app, &request_id)
        .map_err(|e| html_error(&format!("failed to open consent window: {e}")))?;

    let approved = match tokio::time::timeout(CONSENT_TIMEOUT, waiter).await {
        Ok(Ok(b)) => b,
        Ok(Err(_)) => false,
        Err(_) => {
            // Timed out — drop the registry entry if it's still there.
            state.oauth.consent.resolve(&request_id, false);
            false
        }
    };
    super::consent::close_consent_window(&state.app, &request_id);

    if !approved {
        return Err(redirect_error(
            &q.redirect_uri,
            q.state.as_deref(),
            "access_denied",
            Some("user denied authorization"),
        ));
    }

    // Mint a single-use code and persist with the PKCE challenge.
    let code = random_token(32);
    state
        .oauth
        .store
        .store_auth_code(
            &code,
            &client.id,
            &q.redirect_uri,
            &q.code_challenge,
            q.scope.as_deref(),
        )
        .map_err(|e| html_error(&format!("server error: {e}")))?;
    let _ = state.oauth.store.touch_client(&client.id);

    let mut url =
        url::Url::parse(&q.redirect_uri).map_err(|_| html_error("invalid redirect_uri"))?;
    url.query_pairs_mut().append_pair("code", &code);
    if let Some(s) = q.state.as_deref() {
        url.query_pairs_mut().append_pair("state", s);
    }
    Ok(Redirect::to(url.as_str()).into_response())
}

fn redirect_error(
    redirect_uri: &str,
    state: Option<&str>,
    error: &str,
    description: Option<&str>,
) -> Response {
    let Ok(mut url) = url::Url::parse(redirect_uri) else {
        return html_error(&format!("OAuth error: {error}"));
    };
    url.query_pairs_mut().append_pair("error", error);
    if let Some(d) = description {
        url.query_pairs_mut().append_pair("error_description", d);
    }
    if let Some(s) = state {
        url.query_pairs_mut().append_pair("state", s);
    }
    Redirect::to(url.as_str()).into_response()
}

fn html_error(msg: &str) -> Response {
    let body = format!("<html><body><h1>Authorization error</h1><p>{}</p></body></html>", html_escape(msg));
    (StatusCode::BAD_REQUEST, Html(body)).into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// =====================================================================
// Token endpoint
// =====================================================================

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    // authorization_code
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    // refresh_token
    #[serde(default)]
    pub refresh_token: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    refresh_token: String,
}

pub async fn token(
    State(state): State<McpAppState>,
    Form(req): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, OAuthError> {
    match req.grant_type.as_str() {
        "authorization_code" => token_authorization_code(state, req).await,
        "refresh_token" => token_refresh(state, req).await,
        other => Err(OAuthError::unsupported_grant_type(format!(
            "unsupported grant_type: {other}"
        ))),
    }
}

async fn token_authorization_code(
    state: McpAppState,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, OAuthError> {
    let code = req
        .code
        .ok_or_else(|| OAuthError::invalid_request("code required"))?;
    let redirect_uri = req
        .redirect_uri
        .ok_or_else(|| OAuthError::invalid_request("redirect_uri required"))?;
    let code_verifier = req
        .code_verifier
        .ok_or_else(|| OAuthError::invalid_request("code_verifier required"))?;
    let client_id = req
        .client_id
        .ok_or_else(|| OAuthError::invalid_request("client_id required"))?;

    let record = state
        .oauth
        .store
        .consume_auth_code(&code)
        .map_err(|e| OAuthError::server_error(e.to_string()))?
        .ok_or_else(|| OAuthError::invalid_grant("invalid or expired authorization code"))?;

    if record.client_id != client_id {
        return Err(OAuthError::invalid_grant("client_id mismatch"));
    }
    if record.redirect_uri != redirect_uri {
        return Err(OAuthError::invalid_grant("redirect_uri mismatch"));
    }

    // Verify PKCE: BASE64URL(SHA256(verifier)) == code_challenge
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    let challenge = URL_SAFE_NO_PAD.encode(hash);
    if challenge != record.code_challenge {
        return Err(OAuthError::invalid_grant("PKCE verifier mismatch"));
    }

    let _ = state.oauth.store.touch_client(&client_id);
    issue_token_pair(&state, &client_id)
}

async fn token_refresh(
    state: McpAppState,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, OAuthError> {
    let refresh = req
        .refresh_token
        .ok_or_else(|| OAuthError::invalid_request("refresh_token required"))?;
    let claimed_client_id = req
        .client_id
        .ok_or_else(|| OAuthError::invalid_request("client_id required"))?;

    // refresh tokens are opaque ids stored verbatim in the db (no JWT round-trip needed).
    let client_id = state
        .oauth
        .store
        .consume_refresh(&refresh)
        .map_err(|e| OAuthError::server_error(e.to_string()))?
        .ok_or_else(|| OAuthError::invalid_grant("invalid or expired refresh_token"))?;
    if client_id != claimed_client_id {
        return Err(OAuthError::invalid_grant("client_id mismatch"));
    }
    if state
        .oauth
        .store
        .get_client(&client_id)
        .map_err(|e| OAuthError::server_error(e.to_string()))?
        .is_none()
    {
        return Err(OAuthError::invalid_grant("client revoked"));
    }
    let _ = state.oauth.store.touch_client(&client_id);
    issue_token_pair(&state, &client_id)
}

fn issue_token_pair(
    state: &McpAppState,
    client_id: &str,
) -> Result<Json<TokenResponse>, OAuthError> {
    let now = Utc::now().timestamp();
    let access_jti = Uuid::new_v4().to_string();
    let refresh_jti = random_token(32);

    let claims = super::AccessClaims {
        sub: client_id.to_string(),
        iss: state.oauth.base_url(),
        aud: super::AUDIENCE.to_string(),
        exp: now + ACCESS_TTL_SECS,
        iat: now,
        jti: access_jti.clone(),
    };
    let access_token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(&state.oauth.signing_key),
    )
    .map_err(|e| OAuthError::server_error(format!("jwt sign: {e}")))?;

    state
        .oauth
        .store
        .store_refresh(&refresh_jti, client_id, now + REFRESH_TTL_SECS)
        .map_err(|e| OAuthError::server_error(e.to_string()))?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TTL_SECS,
        refresh_token: refresh_jti,
    }))
}

fn random_token(byte_len: usize) -> String {
    let mut buf = vec![0u8; byte_len];
    rand::thread_rng().fill(&mut buf[..]);
    URL_SAFE_NO_PAD.encode(buf)
}

// =====================================================================
// OAuth error type
// =====================================================================

pub struct OAuthError {
    status: StatusCode,
    code: &'static str,
    description: String,
}

impl OAuthError {
    fn invalid_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            description: msg.into(),
        }
    }
    fn invalid_grant(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_grant",
            description: msg.into(),
        }
    }
    fn unsupported_grant_type(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "unsupported_grant_type",
            description: msg.into(),
        }
    }
    fn server_error(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "server_error",
            description: msg.into(),
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": self.code,
            "error_description": self.description,
        });
        let mut resp = (self.status, Json(body)).into_response();
        resp.headers_mut().insert(
            header::CACHE_CONTROL,
            "no-store".parse().unwrap(),
        );
        resp
    }
}
