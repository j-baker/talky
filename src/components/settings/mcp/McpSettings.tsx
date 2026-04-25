import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { commands, type Tag, type McpClientInfo } from "@/bindings";
import { useSettings } from "../../../hooks/useSettings";
import { SettingsGroup } from "../../ui/SettingsGroup";
import { SettingContainer } from "../../ui/SettingContainer";
import { ToggleSwitch } from "../../ui/ToggleSwitch";
import { Input } from "../../ui/Input";
import { Button } from "../../ui/Button";

export const McpSettings: React.FC = () => {
  const { t } = useTranslation();
  const { getSetting, updateSetting, isUpdating } = useSettings();

  const enabled = getSetting("mcp_enabled") ?? false;
  const port = getSetting("mcp_port") ?? 47823;
  const exposedLabelIds = getSetting("mcp_exposed_label_ids") ?? [];
  const exposeUntagged = getSetting("mcp_expose_untagged") ?? false;

  const [allTags, setAllTags] = useState<Tag[]>([]);
  const [clients, setClients] = useState<McpClientInfo[]>([]);
  const [portDraft, setPortDraft] = useState<string>(String(port));

  useEffect(() => {
    setPortDraft(String(port));
  }, [port]);

  // Load tags + clients (refresh whenever the server is enabled/disabled).
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      const tagsRes = await commands.getTags();
      if (!cancelled && tagsRes.status === "ok") setAllTags(tagsRes.data);
      const clientsRes = await commands.mcpListClients();
      if (!cancelled && clientsRes.status === "ok") setClients(clientsRes.data);
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [enabled]);

  const url = `http://127.0.0.1:${port}/mcp`;
  const copyUrl = async () => {
    try {
      await navigator.clipboard.writeText(url);
    } catch {
      // Best-effort copy. Browser security may block it from a non-user
      // gesture; we still have the visible value next to the button.
    }
  };

  const toggleLabel = (id: string) => {
    const next = exposedLabelIds.includes(id)
      ? exposedLabelIds.filter((x) => x !== id)
      : [...exposedLabelIds, id];
    updateSetting("mcp_exposed_label_ids", next);
  };

  const commitPort = () => {
    const parsed = Number(portDraft);
    if (!Number.isFinite(parsed) || parsed < 1024 || parsed > 65535) {
      setPortDraft(String(port));
      return;
    }
    if (parsed !== port) {
      updateSetting("mcp_port", parsed);
    }
  };

  const revokeClient = async (id: string) => {
    if (!window.confirm(t("settings.mcp.clients.confirmRevoke"))) return;
    const res = await commands.mcpRevokeClient(id);
    if (res.status === "ok") {
      const list = await commands.mcpListClients();
      if (list.status === "ok") setClients(list.data);
    }
  };

  return (
    <SettingsGroup title={t("settings.mcp.title")}>
      <ToggleSwitch
        checked={enabled}
        onChange={(v) => updateSetting("mcp_enabled", v)}
        isUpdating={isUpdating("mcp_enabled")}
        label={t("settings.mcp.enable.label")}
        description={t("settings.mcp.enable.description")}
        descriptionMode="tooltip"
        grouped
      />

      <SettingContainer
        title={t("settings.mcp.port.label")}
        description={t("settings.mcp.port.description")}
        descriptionMode="tooltip"
        grouped
        disabled={!enabled}
      >
        <Input
          type="number"
          min={1024}
          max={65535}
          value={portDraft}
          disabled={!enabled || isUpdating("mcp_port")}
          onChange={(e) => setPortDraft(e.target.value)}
          onBlur={commitPort}
          onKeyDown={(e) => {
            if (e.key === "Enter") (e.target as HTMLInputElement).blur();
          }}
          className="w-24"
        />
      </SettingContainer>

      <SettingContainer
        title={t("settings.mcp.url.label")}
        description={t("settings.mcp.url.description")}
        descriptionMode="tooltip"
        grouped
        disabled={!enabled}
      >
        <div className="flex items-center gap-2">
          <code className="text-xs px-2 py-1 bg-mid-gray/10 rounded select-all">
            {url}
          </code>
          <Button
            variant="secondary"
            size="sm"
            onClick={copyUrl}
            disabled={!enabled}
          >
            {t("settings.mcp.url.copy")}
          </Button>
        </div>
      </SettingContainer>

      <SettingContainer
        title={t("settings.mcp.labels.label")}
        description={t("settings.mcp.labels.description")}
        descriptionMode="tooltip"
        grouped
        layout="stacked"
        disabled={!enabled}
      >
        {allTags.length === 0 ? (
          <p className="text-xs text-mid-gray">
            {t("settings.mcp.labels.noTags")}
          </p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {allTags.map((tag) => {
              const selected = exposedLabelIds.includes(tag.id);
              return (
                <button
                  key={tag.id}
                  type="button"
                  disabled={!enabled}
                  onClick={() => toggleLabel(tag.id)}
                  className={`px-2 py-1 text-xs rounded border transition-colors ${
                    selected
                      ? "bg-logo-primary/20 border-logo-primary text-foreground"
                      : "bg-mid-gray/10 border-mid-gray/40 text-mid-gray hover:border-logo-primary/60"
                  } ${!enabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
                >
                  {tag.name}
                </button>
              );
            })}
          </div>
        )}
        {enabled &&
          allTags.length > 0 &&
          exposedLabelIds.length === 0 &&
          !exposeUntagged && (
            <p className="text-xs text-amber-500 mt-2">
              {t("settings.mcp.labels.empty")}
            </p>
          )}
      </SettingContainer>

      <ToggleSwitch
        checked={exposeUntagged}
        onChange={(v) => updateSetting("mcp_expose_untagged", v)}
        isUpdating={isUpdating("mcp_expose_untagged")}
        disabled={!enabled}
        label={t("settings.mcp.exposeUntagged.label")}
        description={t("settings.mcp.exposeUntagged.description")}
        descriptionMode="tooltip"
        grouped
      />

      <div className="px-4 py-3">
        <h3 className="text-sm font-medium mb-2">
          {t("settings.mcp.clients.title")}
        </h3>
        {clients.length === 0 ? (
          <p className="text-xs text-mid-gray">
            {t("settings.mcp.clients.empty")}
          </p>
        ) : (
          <ul className="divide-y divide-mid-gray/20">
            {clients.map((c) => (
              <li
                key={c.id}
                className="py-2 flex items-center justify-between gap-3"
              >
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium truncate">{c.name}</div>
                  <div className="text-xs text-mid-gray truncate">
                    {c.redirect_uris.join(", ")}
                  </div>
                  <div className="text-xs text-mid-gray">
                    {t("settings.mcp.clients.lastUsed")}:{" "}
                    {c.last_used_at
                      ? new Date(c.last_used_at * 1000).toLocaleString()
                      : t("settings.mcp.clients.never")}
                  </div>
                </div>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={() => revokeClient(c.id)}
                >
                  {t("settings.mcp.clients.revoke")}
                </Button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </SettingsGroup>
  );
};
