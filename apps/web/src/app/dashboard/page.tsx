"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { Card } from "@/components/ui/card";
import { api } from "@/lib/api";

export default function DashboardPage() {
  const router = useRouter();
  const [me, setMe] = useState<{ user: { email: string }; org: { name: string } } | null>(null);
  const [multiTenant, setMultiTenant] = useState(false);

  useEffect(() => {
    if (!localStorage.getItem("access_token")) {
      router.push("/login");
      return;
    }
    api<{ user: { email: string }; org: { name: string } }>("/me")
      .then(setMe)
      .catch(() => router.push("/login"));
    api<{ multi_tenant_enabled: boolean }>("/orgs/current")
      .then((o) => setMultiTenant(o.multi_tenant_enabled))
      .catch(() => {});
  }, [router]);

  return (
    <DashboardShell>
      <h1 className="mb-6 text-2xl font-bold">Dashboard</h1>
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <h2 className="font-semibold">Welcome</h2>
          <p className="mt-2 text-slate-600">
            {me ? `${me.user.email} @ ${me.org.name}` : "Loading..."}
          </p>
          {multiTenant && (
            <p className="mt-2 text-xs text-amber-600">
              Multi-tenant mode enabled (org switcher coming soon)
            </p>
          )}
        </Card>
        <Card>
          <h2 className="font-semibold">Quick start</h2>
          <ol className="mt-2 list-decimal pl-5 text-sm text-slate-600">
            <li>Add a scan target</li>
            <li>Run a passive scan</li>
            <li>Review findings and AI report</li>
          </ol>
        </Card>
      </div>
    </DashboardShell>
  );
}
