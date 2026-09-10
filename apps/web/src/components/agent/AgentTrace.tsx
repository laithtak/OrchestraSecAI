"use client";

import { Card } from "@/components/ui/card";

export type TraceEntry = {
  seq: number;
  type: "plan" | "tool_call" | "critique";
  iteration: number;
  timestamp: string;
  payload: Record<string, unknown>;
};

type AgentTraceProps = {
  trace: TraceEntry[];
  mission?: string;
  iteration?: number;
  maxIterations?: number;
  status?: string;
};

function groupByIteration(trace: TraceEntry[]): Map<number, TraceEntry[]> {
  const groups = new Map<number, TraceEntry[]>();
  for (const entry of trace) {
    const list = groups.get(entry.iteration) || [];
    list.push(entry);
    groups.set(entry.iteration, list);
  }
  return new Map([...groups.entries()].sort((a, b) => a[0] - b[0]));
}

export function AgentTrace({
  trace,
  mission,
  iteration,
  maxIterations,
  status,
}: AgentTraceProps) {
  const groups = groupByIteration(trace);

  return (
    <Card className="mb-6">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <h2 className="font-semibold">Agent thinking</h2>
          {mission && (
            <p className="mt-1 text-sm text-slate-600">
              Mission: <span className="italic">{mission}</span>
            </p>
          )}
        </div>
        <div className="text-right text-xs text-slate-500">
          {status && <p>Session: {status}</p>}
          {maxIterations != null && (
            <p>
              Iteration {iteration ?? 0} / {maxIterations}
            </p>
          )}
        </div>
      </div>

      {trace.length === 0 ? (
        <p className="text-sm text-slate-500">Waiting for agent plan...</p>
      ) : (
        <div className="space-y-3">
          {[...groups.entries()].map(([iter, entries]) => (
            <details key={iter} open className="rounded border p-3">
              <summary className="cursor-pointer font-medium text-sm">
                Iteration {iter}
              </summary>
              <div className="mt-2 space-y-2">
                {entries.map((e) => (
                  <div key={e.seq} className="rounded bg-slate-50 p-2 text-xs">
                    <p className="font-mono text-slate-500">
                      {e.type} · {new Date(e.timestamp).toLocaleTimeString()}
                    </p>
                    {e.type === "plan" && (
                      <>
                        <p className="mt-1">{String(e.payload.reasoning || "")}</p>
                        <ul className="mt-1 list-inside list-disc">
                          {(e.payload.calls as { tool: string }[] | undefined)?.map(
                            (c, i) => (
                              <li key={i}>{c.tool}</li>
                            )
                          )}
                        </ul>
                      </>
                    )}
                    {e.type === "tool_call" && (
                      <p className="mt-1">
                        {String(e.payload.tool)} —{" "}
                        {e.payload.success ? "ok" : `error: ${e.payload.error}`} (
                        {String(e.payload.findings_count ?? 0)} findings)
                      </p>
                    )}
                    {e.type === "critique" && (
                      <>
                        <p className="mt-1">{String(e.payload.reasoning || "")}</p>
                        <p className="mt-1 font-semibold">
                          Decision: {String(e.payload.status)}
                        </p>
                      </>
                    )}
                  </div>
                ))}
              </div>
            </details>
          ))}
        </div>
      )}
    </Card>
  );
}
