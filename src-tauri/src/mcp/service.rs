//! The MCP service: tools backed by the existing SessionManager.
//!
//! Visibility filter applied on every call:
//!   allowed(note) =
//!     (note.tags ∩ settings.mcp_exposed_label_ids).is_non_empty()
//!     OR (note.tags.is_empty() AND settings.mcp_expose_untagged)

use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content};
use rmcp::ServerHandler;
use rmcp::{tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::managers::session::SessionManager;
use crate::settings::get_settings;

type McpError = rmcp::ErrorData;

#[derive(Clone)]
pub struct TalkyMcpService {
    app: AppHandle,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl TalkyMcpService {
    pub fn new(app: AppHandle) -> Self {
        Self {
            app,
            tool_router: Self::tool_router(),
        }
    }

    fn session_manager(&self) -> Arc<SessionManager> {
        self.app.state::<Arc<SessionManager>>().inner().clone()
    }

    /// Compute the set of session ids the user has chosen to expose, given
    /// the current settings. Returns (allowed_ids, exposed_label_ids,
    /// expose_untagged) so callers can re-use the latter for filtering.
    fn build_visibility(&self) -> Result<Visibility, String> {
        let settings = get_settings(&self.app);
        Ok(Visibility {
            exposed_label_ids: settings.mcp_exposed_label_ids,
            expose_untagged: settings.mcp_expose_untagged,
        })
    }

    fn note_is_visible(
        &self,
        sm: &SessionManager,
        session_id: &str,
        v: &Visibility,
    ) -> Result<bool, String> {
        let tags = sm
            .get_session_tags(session_id)
            .map_err(|e| e.to_string())?;
        if tags.is_empty() {
            return Ok(v.expose_untagged);
        }
        Ok(tags.iter().any(|t| v.exposed_label_ids.contains(&t.id)))
    }

    // ---------- Tools ----------

    #[tool(
        name = "list_notes",
        description = "List Talky notes the user has chosen to expose via MCP. Returns id, title, started_at, ended_at, and labels for each."
    )]
    async fn list_notes_tool(
        &self,
        Parameters(_params): Parameters<ListNotesParams>,
    ) -> Result<CallToolResult, McpError> {
        let sm = self.session_manager();
        let visibility = self
            .build_visibility()
            .map_err(|e| McpError::internal_error(e, None))?;

        let sessions = sm
            .get_sessions()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut out = Vec::new();
        for session in sessions {
            let visible = self
                .note_is_visible(&sm, &session.id, &visibility)
                .map_err(|e| McpError::internal_error(e, None))?;
            if !visible {
                continue;
            }
            let tags = sm
                .get_session_tags(&session.id)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            out.push(NoteSummary {
                id: session.id,
                title: session.title,
                started_at: session.started_at,
                ended_at: session.ended_at,
                labels: tags
                    .into_iter()
                    .map(|t| LabelDto {
                        id: t.id,
                        name: t.name,
                    })
                    .collect(),
            });
        }
        json_result(&out)
    }

    #[tool(
        name = "get_note",
        description = "Fetch a single Talky note by id, returning its full transcript, summary, action items, decisions, and the user's typed notes."
    )]
    async fn get_note_tool(
        &self,
        Parameters(params): Parameters<GetNoteParams>,
    ) -> Result<CallToolResult, McpError> {
        let sm = self.session_manager();
        let visibility = self
            .build_visibility()
            .map_err(|e| McpError::internal_error(e, None))?;

        // Visibility check first — never leak existence.
        let visible = self
            .note_is_visible(&sm, &params.id, &visibility)
            .map_err(|e| McpError::internal_error(e, None))?;
        if !visible {
            return Ok(CallToolResult::error(vec![Content::text(
                "Note not found or not exposed via MCP",
            )]));
        }

        let session = sm
            .get_session(&params.id)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .ok_or_else(|| McpError::invalid_params("Note not found", None))?;

        let transcript = sm
            .get_session_transcript(&params.id)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let notes = sm
            .get_meeting_notes(&params.id)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let tags = sm
            .get_session_tags(&params.id)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let detail = NoteDetail {
            id: session.id,
            title: session.title,
            started_at: session.started_at,
            ended_at: session.ended_at,
            labels: tags
                .into_iter()
                .map(|t| LabelDto {
                    id: t.id,
                    name: t.name,
                })
                .collect(),
            summary: notes.as_ref().and_then(|n| n.summary.clone()),
            action_items: notes.as_ref().and_then(|n| n.action_items.clone()),
            decisions: notes.as_ref().and_then(|n| n.decisions.clone()),
            user_notes: notes.as_ref().and_then(|n| n.user_notes.clone()),
            enhanced_notes: notes.as_ref().and_then(|n| n.enhanced_notes.clone()),
            transcript: transcript
                .into_iter()
                .map(|s| TranscriptSegmentDto {
                    source: s.source,
                    start_ms: s.start_ms,
                    end_ms: s.end_ms,
                    text: s.text,
                })
                .collect(),
        };
        json_result(&detail)
    }

    #[tool(
        name = "search_notes",
        description = "Full-text search across Talky notes the user has chosen to expose. Matches title, user notes, and enhanced notes. Returns id, title, the field that matched, and a short snippet."
    )]
    async fn search_notes_tool(
        &self,
        Parameters(params): Parameters<SearchNotesParams>,
    ) -> Result<CallToolResult, McpError> {
        let sm = self.session_manager();
        let visibility = self
            .build_visibility()
            .map_err(|e| McpError::internal_error(e, None))?;

        let filters = crate::managers::session::SearchFilters::default();
        let hits = sm
            .search_sessions(&params.query, &filters)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut results = Vec::new();
        for hit in hits {
            let visible = self
                .note_is_visible(&sm, &hit.session.id, &visibility)
                .map_err(|e| McpError::internal_error(e, None))?;
            if !visible {
                continue;
            }
            results.push(SearchResult {
                id: hit.session.id,
                title: hit.session.title,
                started_at: hit.session.started_at,
                matched_field: hit.matched_field,
                snippet: hit.snippet,
            });
        }
        json_result(&results)
    }
}

#[tool_handler]
impl ServerHandler for TalkyMcpService {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        let mut info = rmcp::model::ServerInfo::default();
        info.instructions = Some(
            "Talky MCP server. Exposes a configurable subset of the user's notes \
             (transcripts, AI-generated summaries, and the user's typed notes). The \
             user controls which labels are visible from the Talky settings page."
                .into(),
        );
        info
    }
}

// ---------- Helpers ----------

struct Visibility {
    exposed_label_ids: Vec<String>,
    expose_untagged: bool,
}

fn json_result<T: Serialize>(value: &T) -> Result<CallToolResult, McpError> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| McpError::internal_error(format!("serialise: {e}"), None))?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
}

// ---------- Tool parameter types ----------

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListNotesParams {}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetNoteParams {
    /// The note id (a UUID string returned by `list_notes` or `search_notes`).
    pub id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchNotesParams {
    /// Free-text search query. Empty string returns no results.
    pub query: String,
}

// ---------- DTOs ----------

#[derive(Debug, Serialize)]
struct LabelDto {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct NoteSummary {
    id: String,
    title: String,
    started_at: i64,
    ended_at: Option<i64>,
    labels: Vec<LabelDto>,
}

#[derive(Debug, Serialize)]
struct NoteDetail {
    id: String,
    title: String,
    started_at: i64,
    ended_at: Option<i64>,
    labels: Vec<LabelDto>,
    summary: Option<String>,
    action_items: Option<String>,
    decisions: Option<String>,
    user_notes: Option<String>,
    enhanced_notes: Option<String>,
    transcript: Vec<TranscriptSegmentDto>,
}

#[derive(Debug, Serialize)]
struct TranscriptSegmentDto {
    source: String,
    start_ms: i64,
    end_ms: i64,
    text: String,
}

#[derive(Debug, Serialize)]
struct SearchResult {
    id: String,
    title: String,
    started_at: i64,
    matched_field: String,
    snippet: String,
}
