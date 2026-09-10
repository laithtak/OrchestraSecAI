"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { AgentTrace, TraceEntry } from "@/components/agent/AgentTrace";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { useScanEvents } from "@/hooks/useScanEvents";

type Scan = {
  id: string;
  status: string;
  mission?: string;
  stats: Record<string, number>;
  error_message?: string;
};

type Finding = {
  id: string;
  severity: string;
  title: string;
  plugin_id: string;
};

type AgentSession = {
  mission: string;
  status: string;
  iteration: number;
  max_iterations: number;
  trace: TraceEntry[];
  summary: Record<string, unknown>;
};

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [agentSession, setAgentSession] = useState<AgentSession | null>(null);
  const { events, status: eventStatus } = useScanEvents(id);

  const load = useCallback(() => {
    api<Scan>(`/scans/${id}`).then(setScan);
    api<Finding[]>(`/scans/${id}/findings`).then(setFindings);
    api<AgentSession>(`/scans/${id}/agent-session`)
      .then(setAgentSession)
      .catch(() => setAgentSession(null));
  }, [id]);

  useEffect(() => {
    if (!localStorage.getItem("access_token")) {
      router.push("/login");
      return;
    }
    load();
    const interval = setInterval(load, 3000);
    return () => clearInterval(interval);
  }, [id, router, eventStatus, load]);

  const openReport = async () => {
    const { url } = await api<{ url: string }>(
      `/scans/${id}/report/view-token?format=html`,
      { method: "POST" }
    );
    const base = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
    window.open(`${base}${url}`, "_blank");
  };

  const agentEvents = events.filter((e) => e.event.startsWith("agent."));

  return (
    <DashboardShell>
      <h1 className="mb-2 text-2xl font-bold">Scan detail</h1>
      <p className="mb-6 font-mono text-sm text-slate-500">{id}</p>
      <div className="mb-6 grid gap-4 md:grid-cols-3">
        <Card>
          <p className="text-sm text-slate-500">Status</p>
          <p className="text-xl font-semibold">{scan?.status || eventStatus || "..."}</p>
        </Card>
        <Card>
          <p className="text-sm text-slate-500">Pages crawled</p>
          <p className="text-xl font-semibold">{scan?.stats?.pages_crawled ?? 0}</p>
        </Card>
        <Card>
          <p className="text-sm text-slate-500">Findings</p>
          <p className="text-xl font-semibold">{scan?.stats?.findings_count ?? findings.length}</p>
        </Card>
      </div>
      {scan?.status === "completed" && (
        <Button className="mb-6" onClick={openReport}>
          View HTML report
        </Button>
      )}
      <AgentTrace
        trace={agentSession?.trace ?? []}
        mission={agentSession?.mission ?? scan?.mission}
        iteration={agentSession?.iteration}
        maxIterations={agentSession?.max_iterations}
        status={agentSession?.status}
      />
      <Card className="mb-6">
        <h2 className="mb-2 font-semibold">Live events</h2>
        <ul className="max-h-40 overflow-y-auto text-xs font-mono">
          {agentEvents.map((e, i) => (
            <li key={i}>
              {e.event} {e.tool || e.status || e.reasoning?.slice(0, 40) || ""}
            </li>
          ))}
          {events
            .filter((e) => !e.event.startsWith("agent."))
            .map((e, i) => (
              <li key={`o-${i}`}>
                {e.event} {e.status || e.url || ""}
              </li>
            ))}
        </ul>
      </Card>
      <Card>
        <h2 className="mb-4 font-semibold">Findings</h2>
        <ul className="space-y-2">
          {findings.map((f) => (
            <li key={f.id} className="border-b pb-2 text-sm">
              <span className="mr-2 rounded bg-slate-100 px-1 text-xs">{f.severity}</span>
              {f.title}
            </li>
          ))}
        </ul>
      </Card>
    </DashboardShell>
  );
}
