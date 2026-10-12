"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { ErrorNote, StatusBadge } from "@/components/ui/status-badge";
import { ApiError, api, describeError } from "@/lib/api";
import { CHECK_RESULT_MESSAGES } from "@/lib/scans";

type Target = {
  id: string;
  base_url: string;
  verification_status: string;
  verified_domain: string | null;
  verification_expires_at: string | null;
  scannable: boolean;
  project_id: string;
};

type Project = { id: string; name: string };

type Verification = {
  verification_status: string;
  domain: string;
  record_name: string;
  record_type: string;
  record_value: string | null;
  token_hint: string | null;
  challenge_status: string | null;
  challenge_expires_at: string | null;
  attempts: number;
  last_checked_at: string | null;
  last_result: string | null;
  check_result: string | null;
  verification_expires_at: string | null;
  message: string;
};

type PanelState = {
  info?: Verification;
  issuedValue?: string;
  busy?: boolean;
  notice?: string;
  error?: string;
};

function fmt(ts?: string | null) {
  return ts ? new Date(ts).toLocaleString() : "—";
}

export default function TargetsPage() {
  const router = useRouter();
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [baseUrl, setBaseUrl] = useState("");
  const [projectId, setProjectId] = useState("");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [createError, setCreateError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [panels, setPanels] = useState<Record<string, PanelState>>({});

  const setPanel = (id: string, patch: PanelState) =>
    setPanels((prev) => ({ ...prev, [id]: { ...prev[id], ...patch } }));

  const load = useCallback(async () => {
    try {
      const [t, p] = await Promise.all([api<Target[]>("/targets"), api<Project[]>("/projects")]);
      setTargets(t);
      setProjects(p);
      setProjectId((current) => current || p[0]?.id || "");
      setLoadError(null);
    } catch (e) {
      setLoadError(describeError(e));
      setTargets((current) => current ?? []);
    }
  }, []);

  useEffect(() => {
    if (!localStorage.getItem("access_token")) {
      router.push("/login");
      return;
    }
    load();
  }, [router, load]);

  const createTarget = async () => {
    setCreating(true);
    setCreateError(null);
    try {
      await api("/targets", {
        method: "POST",
        body: JSON.stringify({ project_id: projectId, base_url: baseUrl.trim(), allowed_hosts: [] }),
      });
      setBaseUrl("");
      await load();
    } catch (e) {
      setCreateError(describeError(e));
    } finally {
      setCreating(false);
    }
  };

  const showVerification = async (id: string) => {
    if (panels[id]?.info) {
      setPanel(id, { info: undefined, issuedValue: undefined, notice: undefined, error: undefined });
      return;
    }
    setPanel(id, { busy: true, error: undefined });
    try {
      setPanel(id, { info: await api<Verification>(`/targets/${id}/verification`) });
    } catch (e) {
      setPanel(id, { error: describeError(e) });
    } finally {
      setPanel(id, { busy: false });
    }
  };

  const issueChallenge = async (t: Target) => {
    if (
      t.verification_status === "verified" &&
      !window.confirm("Generating a new token revokes the current verification until it is re-checked. Continue?")
    ) {
      return;
    }
    setPanel(t.id, { busy: true, error: undefined, notice: undefined });
    try {
      const info = await api<Verification>(`/targets/${t.id}/verification/challenge`, {
        method: "POST",
      });
      setPanel(t.id, { info, issuedValue: info.record_value ?? undefined });
      await load();
    } catch (e) {
      setPanel(t.id, { error: describeError(e) });
    } finally {
      setPanel(t.id, { busy: false });
    }
  };

  const checkDns = async (t: Target) => {
    setPanel(t.id, { busy: true, error: undefined, notice: undefined });
    try {
      const info = await api<Verification>(`/targets/${t.id}/verify`, { method: "POST" });
      setPanel(t.id, {
        info,
        notice: CHECK_RESULT_MESSAGES[info.check_result || ""] || info.check_result || undefined,
      });
      await load();
    } catch (e) {
      const message =
        e instanceof ApiError && e.status === 409
          ? "Generate a verification token first."
          : describeError(e);
      setPanel(t.id, { error: message });
    } finally {
      setPanel(t.id, { busy: false });
    }
  };

  return (
    <DashboardShell>
      <h1 className="mb-6 text-2xl font-bold">Scan Targets</h1>
      <Card className="mb-6">
        <h2 className="mb-4 font-semibold">Add target</h2>
        <div className="flex flex-wrap gap-2">
          {projects.length > 1 && (
            <select
              aria-label="Project"
              className="rounded border px-2"
              value={projectId}
              onChange={(e) => setProjectId(e.target.value)}
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          )}
          <Input
            aria-label="Target URL"
            className="min-w-[280px] flex-1"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="https://app.your-domain.com"
          />
          <Button onClick={createTarget} disabled={creating || !baseUrl.trim() || !projectId}>
            {creating ? "Adding…" : "Add"}
          </Button>
        </div>
        <ErrorNote message={createError} />
        <p className="mt-2 text-xs text-slate-600">
          Only add domains you control. Scanning is enabled after you prove ownership with a DNS TXT
          record. Scope is limited to the exact hostname.
        </p>
      </Card>

      <ErrorNote message={loadError} />
      {targets === null && <p className="text-sm text-slate-500">Loading targets…</p>}
      {targets?.length === 0 && !loadError && (
        <p className="text-sm text-slate-500">No targets yet. Add one above to get started.</p>
      )}

      <div className="space-y-3">
        {targets?.map((t) => {
          const panel = panels[t.id] || {};
          const info = panel.info;
          return (
            <Card key={t.id} className="py-4">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <p className="font-medium">{t.base_url}</p>
                  <div className="mt-1 flex items-center gap-2 text-xs text-slate-600">
                    <StatusBadge status={t.verification_status} />
                    {t.scannable && t.verification_expires_at && (
                      <span>re-verify by {fmt(t.verification_expires_at)}</span>
                    )}
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button variant="outline" size="sm" onClick={() => showVerification(t.id)}>
                    {info ? "Hide verification" : "Verification"}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={panel.busy}
                    onClick={() => issueChallenge(t)}
                  >
                    {t.verification_status === "unverified" ? "Generate token" : "Rotate token"}
                  </Button>
                  <Button
                    size="sm"
                    disabled={panel.busy || t.verification_status === "unverified"}
                    onClick={() => checkDns(t)}
                  >
                    {panel.busy ? "Working…" : "Check DNS"}
                  </Button>
                </div>
              </div>
              <ErrorNote message={panel.error} />
              {panel.notice && (
                <p role="status" className="mt-2 rounded bg-slate-50 p-2 text-sm text-slate-700">
                  {panel.notice}
                </p>
              )}
              {info && (
                <div className="mt-3 space-y-1 rounded bg-slate-50 p-3 text-xs">
                  <p>
                    <span className="text-slate-500">Record:</span>{" "}
                    <code className="font-mono">{info.record_name}</code> ({info.record_type})
                  </p>
                  {panel.issuedValue ? (
                    <div className="rounded border border-amber-300 bg-amber-50 p-2">
                      <p className="font-semibold text-amber-800">
                        Copy this value now — it will not be shown again.
                      </p>
                      <div className="mt-1 flex items-center gap-2">
                        <code className="break-all font-mono">{panel.issuedValue}</code>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => navigator.clipboard?.writeText(panel.issuedValue || "")}
                        >
                          Copy
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <p>
                      <span className="text-slate-500">Value:</span>{" "}
                      {info.token_hint ? (
                        <code className="font-mono">orchestrasec-verify={info.token_hint}…</code>
                      ) : (
                        "Generate a token to get the record value."
                      )}
                    </p>
                  )}
                  {info.challenge_status && (
                    <p>
                      <span className="text-slate-500">Challenge:</span> {info.challenge_status}
                      {info.challenge_status === "pending" &&
                        ` · expires ${fmt(info.challenge_expires_at)}`}
                      {` · ${info.attempts} check(s)`}
                      {info.last_result && ` · last result: ${info.last_result}`}
                    </p>
                  )}
                  <p className="text-slate-600">{info.message}</p>
                </div>
              )}
            </Card>
          );
        })}
      </div>
    </DashboardShell>
  );
}
