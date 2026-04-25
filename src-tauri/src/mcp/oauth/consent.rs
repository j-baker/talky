//! Browser-mediated consent. When `/authorize` runs we open a small Tauri
//! window pointing at `/mcp-consent?request_id=...`. The frontend reads the
//! pending request via `mcp_get_pending_consent` and posts the user's
//! decision back via `mcp_consent_response`, which resolves the oneshot the
//! HTTP handler is parked on.

use std::collections::HashMap;
use std::sync::Mutex;
use tauri::{AppHandle, WebviewUrl, WebviewWindowBuilder};
use tokio::sync::oneshot;

#[derive(Debug, Clone, serde::Serialize, specta::Type)]
pub struct PendingConsent {
    pub request_id: String,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
}

struct PendingEntry {
    info: PendingConsent,
    responder: oneshot::Sender<bool>,
}

#[derive(Default)]
pub struct ConsentRegistry {
    inner: Mutex<HashMap<String, PendingEntry>>,
}

impl ConsentRegistry {
    pub fn register(
        &self,
        info: PendingConsent,
    ) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        let mut g = self.inner.lock().expect("consent registry poisoned");
        g.insert(
            info.request_id.clone(),
            PendingEntry { info, responder: tx },
        );
        rx
    }

    pub fn get(&self, request_id: &str) -> Option<PendingConsent> {
        let g = self.inner.lock().expect("consent registry poisoned");
        g.get(request_id).map(|e| e.info.clone())
    }

    /// Resolve a pending consent. Returns true if a consumer was waiting.
    pub fn resolve(&self, request_id: &str, approved: bool) -> bool {
        let entry = {
            let mut g = self.inner.lock().expect("consent registry poisoned");
            g.remove(request_id)
        };
        match entry {
            Some(entry) => entry.responder.send(approved).is_ok(),
            None => false,
        }
    }
}

/// Open the consent webview window for a given request_id. If the window
/// label collides with an existing one we focus the existing window.
pub fn open_consent_window(app: &AppHandle, request_id: &str) -> Result<(), String> {
    let label = consent_window_label(request_id);
    if let Some(existing) = tauri::Manager::get_webview_window(app, &label) {
        let _ = existing.set_focus();
        return Ok(());
    }

    let url = format!("index.html#/mcp-consent?request_id={request_id}");
    WebviewWindowBuilder::new(app, &label, WebviewUrl::App(url.into()))
        .title("Authorize MCP Client")
        .inner_size(520.0, 420.0)
        .resizable(false)
        .always_on_top(true)
        .focused(true)
        .build()
        .map_err(|e| format!("failed to open consent window: {e}"))?;
    Ok(())
}

pub fn close_consent_window(app: &AppHandle, request_id: &str) {
    let label = consent_window_label(request_id);
    if let Some(win) = tauri::Manager::get_webview_window(app, &label) {
        let _ = win.close();
    }
}

fn consent_window_label(request_id: &str) -> String {
    // Window labels can't contain hyphens in some Tauri versions; use only
    // safe characters.
    let sanitised: String = request_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    format!("mcpconsent_{sanitised}")
}
