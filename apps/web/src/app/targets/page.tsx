"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { api } from "@/lib/api";

type Target = {
  id: string;
  base_url: string;
  verification_status: string;
  project_id: string;
};

type Project = { id: string; name: string };

type VerificationInfo = {
  verification_status: string;
  record_name: string;
  record_value: string;
  message: string;
};

export default function TargetsPage() {
  const router = useRouter();
  const [targets, setTargets] = useState<Target[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [baseUrl, setBaseUrl] = useState("https://example.com");
  const [projectId, setProjectId] = useState("");
  const [verification, setVerification] = useState<Record<string, VerificationInfo>>({});

  const load = () => {
    api<Target[]>("/targets").then(setTargets);
    api<Project[]>("/projects").then((p) => {
      setProjects(p);
      if (p[0]) setProjectId(p[0].id);
    });
  };

  useEffect(() => {
    if (!localStorage.getItem("access_token")) {
      router.push("/login");
      return;
    }
    load();
  }, [router]);

  const createTarget = async () => {
    await api("/targets", {
      method: "POST",
      body: JSON.stringify({ project_id: projectId, base_url: baseUrl, allowed_hosts: [] }),
    });
    load();
  };

  const loadVerification = async (targetId: string) => {
    const info = await api<VerificationInfo>(`/targets/${targetId}/verification`);
    setVerification((prev) => ({ ...prev, [targetId]: info }));
  };

  const verifyTarget = async (targetId: string) => {
    await api(`/targets/${targetId}/verify`, { method: "POST" });
    load();
    loadVerification(targetId);
  };

  return (
    <DashboardShell>
      <h1 className="mb-6 text-2xl font-bold">Scan Targets</h1>
      <Card className="mb-6">
        <h2 className="mb-4 font-semibold">Add target</h2>
        <div className="flex flex-wrap gap-2">
          <Input
            className="min-w-[280px] flex-1"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="https://example.com"
          />
          <Button onClick={createTarget}>Add</Button>
        </div>
        <p className="mt-2 text-xs text-amber-700">
          Targets must be DNS-verified before scanning. Add the TXT record below, then click Verify DNS.
        </p>
      </Card>
      <div className="space-y-2">
        {targets.map((t) => (
          <Card key={t.id} className="py-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <p className="font-medium">{t.base_url}</p>
                <p className="text-xs text-slate-500">Status: {t.verification_status}</p>
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => loadVerification(t.id)}>
                  Show DNS instructions
                </Button>
                <Button size="sm" onClick={() => verifyTarget(t.id)}>
                  Verify DNS
                </Button>
              </div>
            </div>
            {verification[t.id] && (
              <div className="mt-3 rounded bg-slate-50 p-3 text-xs font-mono">
                <p>Record: {verification[t.id].record_name}</p>
                <p>Value: {verification[t.id].record_value}</p>
                <p className="mt-1 text-slate-600">{verification[t.id].message}</p>
              </div>
            )}
          </Card>
        ))}
      </div>
    </DashboardShell>
  );
}
