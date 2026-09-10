"use client";

import { useEffect, useState } from "react";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export type ScanEvent = {
  event: string;
  status?: string;
  url?: string;
  finding_id?: string;
  tool?: string;
  success?: boolean;
  iteration?: number;
  reasoning?: string;
  calls_count?: number;
  complete?: boolean;
};

export function useScanEvents(scanId: string | null) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [status, setStatus] = useState<string>("");

  useEffect(() => {
    if (!scanId) return;
    const token = localStorage.getItem("access_token");
    const source = new EventSource(
      `${API_URL}/api/v1/scans/${scanId}/events?token=${token}`
    );

    let cancelled = false;

    async function connect() {
      const res = await fetch(`${API_URL}/api/v1/scans/${scanId}/events`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.body) return;
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (!cancelled) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop() || "";
        for (const part of parts) {
          const eventLine = part.match(/^event: (.+)$/m);
          const dataLine = part.match(/^data: (.+)$/m);
          if (dataLine) {
            try {
              const data = JSON.parse(dataLine[1]);
              const ev: ScanEvent = { event: eventLine?.[1] || data.event || "update", ...data };
              setEvents((prev) => [...prev.slice(-49), ev]);
              if (data.status) setStatus(data.status);
            } catch {
              /* ignore */
            }
          }
        }
      }
    }

    connect();
    return () => {
      cancelled = true;
      source.close();
    };
  }, [scanId]);

  return { events, status };
}
