"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { api } from "@/lib/api";

type Scan = { id: string; status: string; stats: Record<string, number>; created_at: string };
type Target = { id: string; base_url: string };
type Policy = { id: string; name: string };

const DEFAULT_MISSION =
  "Find CORS misconfigurations and chain to CSRF on login forms. Report header and cookie issues.";

export default function ScansPage() {
  const router = useRouter();
  const [scans, setScans] = useState<Scan[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [targetId, setTargetId] = useState("");
  const [policyId, setPolicyId] = useState("");
  const [mission, setMission] = useState(DEFAULT_MISSION);

  const load = () => {
    api<Scan[]>("/scans").then(setScans);
    api<Target[]>("/targets").then((t) => {
      setTargets(t);
      if (t[0]) setTargetId(t[0].id);
    });
    api<Policy[]>("/scan-policies").then((p) => {
      setPolicies(p);
      if (p[0]) setPolicyId(p[0].id);
    });
  };

  useEffect(() => {
    if (!localStorage.getItem("access_token")) {
      router.push("/login");
      return;
    }
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, [router]);

  const startScan = async () => {
    if (mission.trim().length < 10) return;
    const scan = await api<{ id: string }>("/scans", {
      method: "POST",
      body: JSON.stringify({
        scan_target_id: targetId,
        scan_policy_id: policyId,
        mission: mission.trim(),
      }),
    });
    router.push(`/scans/${scan.id}`);
  };

  return (
    <DashboardShell>
      <h1 className="mb-6 text-2xl font-bold">Scans</h1>
      <Card className="mb-6">
        <h2 className="mb-4 font-semibold">Start agent scan</h2>
        <p className="mb-3 text-sm text-slate-600">
          Describe what the agent should investigate. All scans run through the LangGraph
          planner–executor–critic loop.
        </p>
        <div className="mb-3 flex flex-wrap gap-2">
          <select
            className="rounded border px-2"
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
          >
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.base_url}
              </option>
            ))}
          </select>
          <select
            className="rounded border px-2"
            value={policyId}
            onChange={(e) => setPolicyId(e.target.value)}
          >
            {policies.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </div>
        <textarea
          className="mb-3 w-full rounded border p-2 text-sm"
          rows={4}
          value={mission}
          onChange={(e) => setMission(e.target.value)}
          placeholder="Mission (min 10 characters)..."
        />
        <Button onClick={startScan} disabled={!targetId || !policyId || mission.trim().length < 10}>
          Run agent scan
        </Button>
      </Card>
      <div className="space-y-2">
        {scans.map((s) => (
          <Link key={s.id} href={`/scans/${s.id}`}>
            <Card className="hover:border-brand">
              <div className="flex justify-between">
                <span className="font-mono text-sm">{s.id.slice(0, 8)}...</span>
                <span className="rounded bg-slate-100 px-2 py-1 text-xs">{s.status}</span>
              </div>
              <p className="mt-1 text-xs text-slate-500">
                Pages: {s.stats?.pages_crawled ?? 0} | Findings: {s.stats?.findings_count ?? 0}
              </p>
            </Card>
          </Link>
        ))}
      </div>
    </DashboardShell>
  );
}
