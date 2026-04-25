import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { commands, type PendingConsent } from "@/bindings";
import { Button } from "./ui/Button";

/**
 * Standalone consent window. Loaded into a Tauri WebviewWindow with the URL
 * `index.html#/mcp-consent?request_id=...`. main.tsx routes here based on
 * the hash. After Approve/Deny, we close the window — the Rust /authorize
 * handler is parked on a oneshot and resumes immediately.
 */
export const McpConsent: React.FC = () => {
  const { t } = useTranslation();
  const [info, setInfo] = useState<PendingConsent | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const requestId = (() => {
    const hash = window.location.hash;
    const queryStart = hash.indexOf("?");
    if (queryStart < 0) return null;
    return new URLSearchParams(hash.slice(queryStart + 1)).get("request_id");
  })();

  useEffect(() => {
    if (!requestId) {
      setError(t("settings.mcp.consent.expired"));
      return;
    }
    let cancelled = false;
    (async () => {
      const res = await commands.mcpGetPendingConsent(requestId);
      if (cancelled) return;
      if (res.status === "ok") {
        if (res.data) setInfo(res.data);
        else setError(t("settings.mcp.consent.expired"));
      } else {
        setError(res.error);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [requestId, t]);

  const respond = async (approved: boolean) => {
    if (!requestId || submitting) return;
    setSubmitting(true);
    await commands.mcpConsentResponse(requestId, approved);
    // Close the window. The Rust handler resumes regardless.
    try {
      const { getCurrentWebviewWindow } =
        await import("@tauri-apps/api/webviewWindow");
      await getCurrentWebviewWindow().close();
    } catch {
      window.close();
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-6 bg-background text-foreground">
      <div className="max-w-md w-full space-y-4 p-6 rounded-lg border border-mid-gray/20 bg-background">
        <h1 className="text-lg font-semibold">
          {t("settings.mcp.consent.title")}
        </h1>

        {error && <p className="text-sm text-red-500">{error}</p>}

        {!info && !error && (
          <p className="text-sm text-mid-gray">
            {t("settings.mcp.consent.loading")}
          </p>
        )}

        {info && (
          <>
            <p className="text-sm">{t("settings.mcp.consent.intro")}</p>
            <div className="text-sm space-y-2 p-3 rounded bg-mid-gray/10">
              <div>
                <span className="font-medium">{info.client_name}</span>
              </div>
              <div className="text-xs text-mid-gray">
                {t("settings.mcp.consent.redirectsTo")}{" "}
                <code className="select-all">{info.redirect_uri}</code>
              </div>
              {info.scope && (
                <div className="text-xs text-mid-gray">
                  {t("settings.mcp.consent.scope")} {info.scope}
                </div>
              )}
            </div>
            <p className="text-xs text-amber-500">
              {t("settings.mcp.consent.warning")}
            </p>
            <div className="flex gap-2 justify-end pt-2">
              <Button
                variant="secondary"
                onClick={() => respond(false)}
                disabled={submitting}
              >
                {t("settings.mcp.consent.deny")}
              </Button>
              <Button
                variant="primary"
                onClick={() => respond(true)}
                disabled={submitting}
              >
                {t("settings.mcp.consent.approve")}
              </Button>
            </div>
          </>
        )}
      </div>
    </div>
  );
};
