//! HTTP MCP server for Talky.
//!
//! Off by default. Bound to 127.0.0.1. Configurable port. OAuth 2.1 + PKCE on
//! loopback. Exposes a configurable subset of notes (filtered by tag).

pub mod oauth;
pub mod router;
pub mod service;

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tauri::AppHandle;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::settings::get_settings;

/// State carried inside the running axum router. Cloned per request.
#[derive(Clone)]
pub struct McpAppState {
    pub app: AppHandle,
    pub oauth: Arc<oauth::OAuthState>,
}

struct RunningServer {
    port: u16,
    cancel: CancellationToken,
    join: JoinHandle<()>,
}

/// Tauri-managed handle that owns the optional running server. The frontend
/// flips MCP on/off and changes the port via settings; we reconcile here.
pub struct McpServerHandle {
    inner: Mutex<Option<RunningServer>>,
    oauth: Arc<oauth::OAuthState>,
}

impl McpServerHandle {
    pub fn new(app: &AppHandle) -> Result<Self> {
        let oauth = Arc::new(oauth::OAuthState::initialise(app)?);
        Ok(Self {
            inner: Mutex::new(None),
            oauth,
        })
    }

    pub fn oauth(&self) -> Arc<oauth::OAuthState> {
        self.oauth.clone()
    }

    pub async fn status(&self) -> McpStatus {
        let g = self.inner.lock().await;
        match &*g {
            Some(r) => McpStatus {
                running: true,
                port: Some(r.port),
                url: Some(public_url(r.port)),
            },
            None => McpStatus {
                running: false,
                port: None,
                url: None,
            },
        }
    }

    /// Bring the running server in line with the persisted settings.
    pub async fn reconcile(&self, app: &AppHandle) -> Result<()> {
        let s = get_settings(app);
        let mut g = self.inner.lock().await;

        match (&*g, s.mcp_enabled) {
            (None, false) => {}
            (Some(r), true) if r.port == s.mcp_port => {}
            (Some(_), false) => {
                if let Some(r) = g.take() {
                    stop(r).await;
                }
            }
            (None, true) | (Some(_), true) => {
                if let Some(r) = g.take() {
                    stop(r).await;
                }
                let started = start(app, s.mcp_port, self.oauth.clone()).await?;
                *g = Some(started);
            }
        }
        Ok(())
    }

    /// Stop the server unconditionally (e.g. on app exit).
    #[allow(dead_code)]
    pub async fn shutdown(&self) {
        let mut g = self.inner.lock().await;
        if let Some(r) = g.take() {
            stop(r).await;
        }
    }
}

async fn stop(r: RunningServer) {
    r.cancel.cancel();
    // Bound the wait so a hung TCP listener can't block app shutdown.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), r.join).await;
}

async fn start(
    app: &AppHandle,
    port: u16,
    oauth: Arc<oauth::OAuthState>,
) -> Result<RunningServer> {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound_addr = listener.local_addr()?;
    oauth.set_port(bound_addr.port());

    let cancel = CancellationToken::new();
    let state = McpAppState {
        app: app.clone(),
        oauth: oauth.clone(),
    };
    let router = router::build(state, cancel.child_token());

    let cancel_for_serve = cancel.clone();
    let join = tokio::spawn(async move {
        let result = axum::serve(listener, router)
            .with_graceful_shutdown(async move { cancel_for_serve.cancelled().await })
            .await;
        if let Err(e) = result {
            log::error!("MCP server exited with error: {e}");
        }
    });

    log::info!("MCP server listening on http://{bound_addr}/mcp");

    Ok(RunningServer {
        port,
        cancel,
        join,
    })
}

/// Public-facing base URL the server advertises in OAuth metadata.
pub fn public_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, specta::Type)]
pub struct McpStatus {
    pub running: bool,
    pub port: Option<u16>,
    pub url: Option<String>,
}
