"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { ErrorNote, StatusBadge } from "@/components/ui/status-badge";
import { api, describeError } from "@/lib/api";
import { isTerminal } from "@/lib/scans";

type Scan = {
  id: string;
  status: string;
  stats: Record<string, number>;
  created_at: string;
  error_code: string | null;
  active_probes_enabled: boolean;
};
type Target = { id: string; base_url: string; scannable: boolean };
type Policy = { id: string; name: string };

const DEFAULT_MISSION =
  "Review security headers, cookie attributes and CORS configuration across the application.";

export default function ScansPage() {
  const router = useRouter();
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [targetId, setTargetId] = useState("");
  const [policyId, setPolicyId] = useState("");
  const [mission, setMission] = useState(DEFAULT_MISSION);
  const [allowActive, setAllowActive] = useState(false);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const scannable = targets.filter((t) => t.scannable);

  const loadScans = useCallback(async () => {
    try {
      setScans(await api<Scan[]>("/scans"));
      setLoadError(null);
    } catch (e) {
      setLoadError(describeError(e));
      setScans((current) => current ?? []);
    }
  }, []);

  useEffect(() => {
    if (!localStorage.getItem("access_token")) {
      router.push("/login");
      return;
    }
    loadScans();
    api<Target[]>("/targets")
      .then((t) => {
        setTargets(t);
        setTargetId((current) => current || t.find((x) => x.scannable)?.id || "");
      })
      .catch((e) => setLoadError(describeError(e)));
    api<Policy[]>("/scan-policies")
      .then((p) => {
        setPolicies(p);
        setPolicyId((current) => current || p[0]?.id || "");
      })
      .catch((e) => setLoadError(describeError(e)));
  }, [router, loadScans]);

  const anyActive = scans?.some((s) => !isTerminal(s.status)) ?? false;
  useEffect(() => {
    if (!anyActive) return;
    const interval = setInterval(loadScans, 5000);
    return () => clearInterval(interval);
  }, [anyActive, loadScans]);

  const startScan = async () => {
    setStarting(true);
    setStartError(null);
    try {
      const scan = await api<{ id: string }>("/scans", {
        method: "POST",
        body: JSON.stringify({
          scan_target_id: targetId,
          scan_policy_id: policyId,
          mission: mission.trim(),
          allow_active_probes: allowActive,
        }),
      });
      router.push(`/scans/${scan.id}`);
    } catch (e) {
      setStartError(describeError(e));
      setStarting(false);
    }
  };

  return (
    <DashboardShell>
      <h1 className="mb-6 text-2xl font-bold">Scans</h1>
      <Card className="mb-6">
        <h2 className="mb-2 font-semibold">Start a scan</h2>
        <p className="mb-3 text-sm text-slate-600">
          The agent plans checks for your mission; every action runs through policy-enforced tools
          limited to the verified target.
        </p>
        {targets.length > 0 && scannable.length === 0 ? (
          <p className="mb-3 rounded bg-amber-50 p-2 text-sm text-amber-800">
            No verified targets yet. <Link className="underline" href="/targets">Verify a target</Link>{" "}
            before starting a scan.
          </p>
        ) : null}
        <div className="mb-3 flex flex-wrap gap-2">
          <select
            aria-label="Target"
            className="rounded border px-2 py-1"
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
          >
            {scannable.length === 0 && <option value="">No verified targets</option>}
            {scannable.map((t) => (
              <option key={t.id} value={t.id}>
                {t.base_url}
              </option>
            ))}
          </select>
          <select
            aria-label="Policy"
            className="rounded border px-2 py-1"
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
          aria-label="Mission"
          className="mb-3 w-full rounded border p-2 text-sm"
          rows={3}
          value={mission}
          onChange={(e) => setMission(e.target.value)}
          placeholder="Mission (min 10 characters)…"
        />
        <label className="mb-3 flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-1"
            checked={allowActive}
            onChange={(e) => setAllowActive(e.target.checked)}
          />
          <span>
            Allow allowlisted active probes (sends crafted requests, including one form POST).
            <span className="block text-xs text-slate-500">
              Off by default. Requires owner/admin role and deployment enablement; the opt-in is
              audited.
            </span>
          </span>
        </label>
        <Button
          onClick={startScan}
          disabled={starting || !targetId || !policyId || mission.trim().length < 10}
        >
          {starting ? "Starting…" : "Start scan"}
        </Button>
        <ErrorNote message={startError} />
      </Card>

      <ErrorNote message={loadError} />
      {scans === null && <p className="text-sm text-slate-500">Loading scans…</p>}
      {scans?.length === 0 && !loadError && (
        <p className="text-sm text-slate-500">No scans yet.</p>
      )}
      <div className="space-y-2">
        {scans?.map((s) => (
          <Link key={s.id} href={`/scans/${s.id}`} className="block">
            <Card className="py-4 hover:border-slate-400">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-sm">{s.id.slice(0, 8)}…</span>
                <div className="flex items-center gap-2">
                  {s.active_probes_enabled && (
                    <span className="text-xs text-amber-700">active probes</span>
                  )}
                  <StatusBadge status={s.status} />
                </div>
              </div>
              <p className="mt-1 text-xs text-slate-500">
                {new Date(s.created_at).toLocaleString()} · Pages: {s.stats?.pages_crawled ?? 0} ·
                Findings: {s.stats?.findings_count ?? 0}
                {s.error_code && ` · ${s.error_code}`}
              </p>
            </Card>
          </Link>
        ))}
      </div>
    </DashboardShell>
  );
}
