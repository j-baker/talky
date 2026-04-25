import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { RecordingPill } from "./components/RecordingPill";
import { McpConsent } from "./components/McpConsent";

// Initialize i18n
import "./i18n";

// Initialize model store (loads models and sets up event listeners)
import { useModelStore } from "./stores/modelStore";

const hash = window.location.hash;
const isPill = hash === "#/pill";
const isMcpConsent = hash.startsWith("#/mcp-consent");

// Skip the heavy global stores for the small consent window — it doesn't
// need recording / models / sessions, just a couple of MCP commands.
if (!isMcpConsent) {
  useModelStore.getState().initialize();
}

const root = isPill ? (
  <RecordingPill />
) : isMcpConsent ? (
  <McpConsent />
) : (
  <App />
);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>{root}</React.StrictMode>,
);
