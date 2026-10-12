"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { AgentTrace, TraceEntry } from "@/components/agent/AgentTrace";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ErrorNote, StatusBadge } from "@/components/ui/status-badge";
import { API_URL, ApiError, api, describeError, downloadFile } from "@/lib/api";
import { hasReport, isTerminal } from "@/lib/scans";
import { useScanEvents } from "@/hooks/useScanEvents";

type Scan = {
  id: string;
  status: string;
  mission?: string;
  stats: Record<string, number>;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error_code: string | null;
  error_message: string | null;
  attempts: number;
  active_probes_enabled: boolean;
};

type Finding = {
  id: string;
  severity: string;
  title: string;
  description: string;
  plugin_id: string;
  check_id: string | null;
  remediation: string | null;
  status: string;
  location: Record<string, unknown>;
  evidence: { type: string; payload: unknown }[];
};

type AgentSession = {
  mission: string;
  status: string;
  iteration: number;
  max_iterations: number;
  trace: TraceEntry[];
  summary: Record<string, unknown>;
};

const SEVERITY_RANK: Record<string, number> = { high: 0, medium: 1, low: 2, info: 3 };

function fmt(ts?: string | null) {
  return ts ? new Date(ts).toLocaleString() : "—";
}

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [agentSession, setAgentSession] = useState<AgentSession | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const terminal = isTerminal(scan?.status);
  const { events, status: eventStatus } = useScanEvents(id, !notFound && !terminal);

  const load = useCallback(async () => {
    try {
      const s = await api<Scan>(`/scans/${id}`);
      setScan(s);
      setError(null);
      const [f, session] = await Promise.all([
        api<Finding[]>(`/scans/${id}/findings?include_evidence=true`),
        api<AgentSession>(`/scans/${id}/agent-session`).catch(() => null),
      ]);
      setFindings(f.sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9)));
      setAgentSession(session);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) setNotFound(true);
      else setError(describeError(e));
    }
  }, [id]);

  useEffect(() => {
    if (!localStorage.getItem("access_token")) {
      router.push("/login");
      return;
    }
    load();
  }, [router, load]);

  // Poll while the scan is active; refresh immediately on live status changes.
  useEffect(() => {
    if (notFound || terminal) return;
    const interval = setInterval(load, 3000);
    return () => clearInterval(interval);
  }, [load, notFound, terminal]);
  useEffect(() => {
    if (eventStatus) load();
  }, [eventStatus, load]);

  const cancel = async () => {
    if (!window.confirm("Cancel this scan? Work in progress stops and no report is produced.")) return;
    setCancelling(true);
    setActionError(null);
    try {
      setScan(await api<Scan>(`/scans/${id}/cancel`, { method: "POST" }));
    } catch (e) {
      setActionError(describeError(e));
      load();
    } finally {
      setCancelling(false);
    }
  };

  const openReport = async () => {
    setActionError(null);
    try {
      const { url } = await api<{ url: string }>(`/scans/${id}/report/view-token?format=html`, {
        method: "POST",
      });
      window.open(`${API_URL}${url}`, "_blank", "noopener,noreferrer");
    } catch (e) {
      setActionError(describeError(e));
    }
  };

  const download = async (format: "json" | "html") => {
    setActionError(null);
    try {
      await downloadFile(`/scans/${id}/report?format=${format}&download=true`, `orchestrasecai-report-${id}.${format}`);
    } catch (e) {
      setActionError(
        e instanceof ApiError && e.status === 404 ? "The report is not ready yet." : describeError(e)
      );
    }
  };

  if (notFound) {
    return (
      <DashboardShell>
        <h1 className="mb-2 text-2xl font-bold">Scan not found</h1>
        <p className="text-sm text-slate-600">
          This scan does not exist or you do not have access to it.{" "}
          <Link className="underline" href="/scans">Back to scans</Link>
        </p>
      </DashboardShell>
    );
  }

  return (
    <DashboardShell>
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="mb-1 text-2xl font-bold">Scan detail</h1>
          <p className="font-mono text-sm text-slate-500">{id}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {scan && !terminal && (
            <Button variant="outline" onClick={cancel} disabled={cancelling}>
              {cancelling ? "Cancelling…" : "Cancel scan"}
            </Button>
          )}
          {hasReport(scan?.status) && (
            <>
              <Button onClick={openReport}>View report</Button>
              <Button variant="outline" onClick={() => download("json")}>
                Download JSON
              </Button>
              <Button variant="outline" onClick={() => download("html")}>
                Download HTML
              </Button>
            </>
          )}
        </div>
      </div>
      <ErrorNote message={error} />
      <ErrorNote message={actionError} />
      {!scan && !error && <p className="text-sm text-slate-500">Loading scan…</p>}

      {scan && (
        <>
          <div className="mb-6 grid gap-4 md:grid-cols-4">
            <Card>
              <p className="text-sm text-slate-500">Status</p>
              <StatusBadge status={scan.status} className="mt-1 inline-block text-sm" />
              {scan.active_probes_enabled && (
                <p className="mt-2 text-xs text-amber-700">Active probes opted in</p>
              )}
            </Card>
            <Card>
              <p className="text-sm text-slate-500">Pages crawled</p>
              <p className="text-xl font-semibold">{scan.stats?.pages_crawled ?? 0}</p>
            </Card>
            <Card>
              <p className="text-sm text-slate-500">Findings</p>
              <p className="text-xl font-semibold">{findings.length}</p>
            </Card>
            <Card>
              <p className="text-sm text-slate-500">Timing</p>
              <p className="text-xs">Started: {fmt(scan.started_at)}</p>
              <p className="text-xs">Finished: {fmt(scan.finished_at)}</p>
              {scan.attempts > 1 && <p className="text-xs">Attempts: {scan.attempts}</p>}
            </Card>
          </div>

          {scan.error_message && (
            <p
              className={`mb-6 rounded p-3 text-sm ${
                scan.status === "cancelled" ? "bg-slate-100 text-slate-700" : "bg-red-50 text-red-800"
              }`}
            >
              {scan.error_message} {scan.error_code && <code className="text-xs">({scan.error_code})</code>}
              {scan.status === "timed_out" && " Partial results are included in the report."}
            </p>
          )}
          {scan.status === "queued" && (
            <p className="mb-6 rounded bg-slate-50 p-3 text-sm text-slate-600">
              Waiting for a worker to pick up the scan…
            </p>
          )}
        </>
      )}

      <AgentTrace
        trace={agentSession?.trace ?? []}
        mission={agentSession?.mission ?? scan?.mission}
        iteration={agentSession?.iteration}
        maxIterations={agentSession?.max_iterations}
        status={agentSession?.status}
      />

      {!terminal && (
        <Card className="mb-6">
          <h2 className="mb-2 font-semibold">Live events</h2>
          {events.length === 0 ? (
            <p className="text-xs text-slate-500">Waiting for events…</p>
          ) : (
            <ul className="max-h-40 overflow-y-auto font-mono text-xs">
              {events.map((e, i) => (
                <li key={i}>
                  {e.event} {e.tool || e.status || e.url || e.reasoning?.slice(0, 40) || ""}
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}

      <Card>
        <h2 className="mb-1 font-semibold">Findings</h2>
        <p className="mb-4 text-xs text-slate-500">
          Produced by deterministic checks from observed evidence. Sensitive values are redacted.
        </p>
        {findings.length === 0 ? (
          <p className="text-sm text-slate-500">
            {terminal ? "No findings were produced." : "No findings yet."}
          </p>
        ) : (
          <ul className="space-y-3">
            {findings.map((f) => (
              <li key={f.id} className="border-b pb-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge status={f.severity} />
                  <span className="font-medium">{f.title}</span>
                </div>
                <p className="mt-1 text-slate-600">{f.description}</p>
                <p className="mt-1 text-xs text-slate-500">
                  {f.plugin_id}
                  {typeof f.location?.url === "string" && ` · ${f.location.url}`}
                </p>
                {f.remediation && (
                  <p className="mt-1 text-xs">
                    <span className="font-semibold">Remediation:</span> {f.remediation}
                  </p>
                )}
                {f.evidence.length > 0 && (
                  <details className="mt-1">
                    <summary className="cursor-pointer text-xs text-slate-600">
                      Evidence ({f.evidence.length})
                    </summary>
                    {f.evidence.map((e, i) => (
                      <pre key={i} className="mt-1 overflow-x-auto rounded bg-slate-50 p-2 text-xs">
                        {e.type}: {JSON.stringify(e.payload, null, 2)}
                      </pre>
                    ))}
                  </details>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </DashboardShell>
  );
}
