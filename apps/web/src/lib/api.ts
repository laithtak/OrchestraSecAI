export const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("access_token");
}

function clearSessionAndRedirect() {
  localStorage.removeItem("access_token");
  localStorage.removeItem("refresh_token");
  if (window.location.pathname !== "/login") window.location.assign("/login");
}

function errorMessage(body: unknown, fallback: string): string {
  if (body && typeof body === "object") {
    const b = body as { detail?: unknown; title?: unknown };
    if (typeof b.detail === "string") return b.detail;
    if (Array.isArray(b.detail)) {
      return b.detail
        .map((d) => (d && typeof d === "object" && "msg" in d ? String(d.msg) : String(d)))
        .join("; ");
    }
    if (typeof b.title === "string") return b.title;
  }
  return fallback;
}

async function request(path: string, options: RequestInit = {}): Promise<Response> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Request-Id": crypto.randomUUID(),
    ...((options.headers as Record<string, string>) || {}),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  let res: Response;
  try {
    res = await fetch(`${API_URL}/api/v1${path}`, { ...options, headers });
  } catch {
    throw new ApiError(0, "Cannot reach the API. Check your connection and try again.");
  }
  if (res.status === 401 && token) {
    clearSessionAndRedirect();
    throw new ApiError(401, "Your session has expired. Please sign in again.");
  }
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new ApiError(res.status, errorMessage(body, res.statusText || "Request failed"));
  }
  return res;
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await request(path, options);
  if (res.headers.get("content-type")?.includes("text/html")) {
    return (await res.text()) as T;
  }
  return res.json();
}

/** Download an authenticated file without placing credentials in a URL. */
export async function downloadFile(path: string, filename: string): Promise<void> {
  const res = await request(path);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function describeError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 403) return `Not allowed: ${e.message}`;
    if (e.status === 404) return "Not found, or you do not have access to it.";
    if (e.status === 429) return e.message || "Too many requests; try again shortly.";
    return e.message;
  }
  return e instanceof Error ? e.message : "Unexpected error";
}

export async function login(email: string, password: string) {
  const data = await api<{ access_token: string; refresh_token: string }>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  localStorage.setItem("access_token", data.access_token);
  localStorage.setItem("refresh_token", data.refresh_token);
  return data;
}
