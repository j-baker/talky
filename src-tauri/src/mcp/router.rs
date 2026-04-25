//! Compose the axum router that the MCP server exposes on loopback.

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use tokio_util::sync::CancellationToken;

use crate::mcp::oauth::handlers::{
    authorize, register, token, well_known_authorization_server, well_known_protected_resource,
};
use crate::mcp::oauth::require_bearer;
use crate::mcp::service::TalkyMcpService;
use crate::mcp::McpAppState;

/// Build the full router. The cancellation token is passed to the rmcp
/// streamable HTTP service so it shuts down promptly when the parent
/// cancels.
pub fn build(state: McpAppState, ct: CancellationToken) -> Router {
    let mcp_app_state = state.clone();
    let app_for_factory = state.app.clone();
    let mcp_service = StreamableHttpService::new(
        move || Ok(TalkyMcpService::new(app_for_factory.clone())),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_cancellation_token(ct),
    );

    let mcp_router = Router::new()
        .nest_service("/mcp", mcp_service)
        .route_layer(middleware::from_fn_with_state(
            mcp_app_state.clone(),
            require_bearer,
        ));

    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(well_known_authorization_server),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(well_known_protected_resource),
        )
        .route("/register", post(register))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .merge(mcp_router)
        .with_state(state)
}
