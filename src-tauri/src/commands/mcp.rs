use std::sync::Arc;

use tauri::{AppHandle, Manager};

use crate::mcp::oauth::consent::PendingConsent;
use crate::mcp::McpServerHandle;
use crate::mcp::McpStatus;

#[tauri::command]
#[specta::specta]
pub async fn mcp_get_status(app: AppHandle) -> McpStatus {
    let handle = app.state::<Arc<McpServerHandle>>();
    handle.status().await
}

#[derive(Debug, Clone, serde::Serialize, specta::Type)]
pub struct McpClientInfo {
    pub id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[tauri::command]
#[specta::specta]
pub fn mcp_list_clients(app: AppHandle) -> Result<Vec<McpClientInfo>, String> {
    let handle = app.state::<Arc<McpServerHandle>>();
    let clients = handle
        .oauth()
        .store
        .list_clients()
        .map_err(|e| e.to_string())?;
    Ok(clients
        .into_iter()
        .map(|c| McpClientInfo {
            id: c.id,
            name: c.name,
            redirect_uris: c.redirect_uris,
            created_at: c.created_at,
            last_used_at: c.last_used_at,
        })
        .collect())
}

#[tauri::command]
#[specta::specta]
pub fn mcp_revoke_client(app: AppHandle, client_id: String) -> Result<(), String> {
    let handle = app.state::<Arc<McpServerHandle>>();
    handle
        .oauth()
        .store
        .revoke_client(&client_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
#[specta::specta]
pub fn mcp_get_pending_consent(
    app: AppHandle,
    request_id: String,
) -> Result<Option<PendingConsent>, String> {
    let handle = app.state::<Arc<McpServerHandle>>();
    Ok(handle.oauth().consent.get(&request_id))
}

#[tauri::command]
#[specta::specta]
pub fn mcp_consent_response(
    app: AppHandle,
    request_id: String,
    approved: bool,
) -> Result<(), String> {
    let handle = app.state::<Arc<McpServerHandle>>();
    handle.oauth().consent.resolve(&request_id, approved);
    Ok(())
}
