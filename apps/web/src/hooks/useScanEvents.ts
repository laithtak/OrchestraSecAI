"use client";

import { useEffect, useState } from "react";
import { API_URL, getToken } from "@/lib/api";

export type ScanEvent = {
  event: string;
  status?: string;
  error_code?: string;
  url?: string;
  finding_id?: string;
  tool?: string;
  success?: boolean;
  iteration?: number;
  reasoning?: string;
  calls_count?: number;
  complete?: boolean;
};

/**
 * Live scan progress over SSE. Uses fetch streaming so the bearer token travels in a
 * header (never in the URL, where it would end up in logs and history).
 */
export function useScanEvents(scanId: string | null, enabled = true) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [status, setStatus] = useState<string>("");

  useEffect(() => {
    if (!scanId || !enabled) return;
    const token = getToken();
    const controller = new AbortController();

    async function connect() {
      const res = await fetch(`${API_URL}/api/v1/scans/${scanId}/events`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        signal: controller.signal,
      });
      if (!res.ok || !res.body) return;
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop() || "";
        for (const part of parts) {
          const eventLine = part.match(/^event: (.+)$/m);
          const dataLine = part.match(/^data: (.+)$/m);
          if (!dataLine) continue;
          try {
            const data = JSON.parse(dataLine[1]);
            const ev: ScanEvent = { event: data.event || eventLine?.[1] || "update", ...data };
            setEvents((prev) => [...prev.slice(-49), ev]);
            if (data.status) setStatus(data.status);
          } catch {
            /* ignore malformed frames */
          }
        }
      }
    }

    connect().catch(() => {
      /* live events are best-effort; the page also polls */
    });
    return () => controller.abort();
  }, [scanId, enabled]);

  return { events, status };
}
