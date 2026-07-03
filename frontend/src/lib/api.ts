const DEFAULT_API_BASE_URL =
  typeof window === "undefined" ? "http://localhost:8000" : `${window.location.protocol}//${window.location.hostname}:8000`;

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || DEFAULT_API_BASE_URL;

export type Source = {
  id: number;
  name: string;
  kind: string;
  url?: string | null;
  trust_score: number;
};

export type Article = {
  id: number;
  title: string;
  url: string;
  published_at?: string | null;
  summary?: string | null;
  raw_excerpt?: string | null;
  tags?: unknown;
  risk_score: number;
  source?: Source | null;
};

export type Vulnerability = {
  id: number;
  cve_id: string;
  title?: string | null;
  description?: string | null;
  cvss_score?: number | null;
  cvss_severity?: string | null;
  epss_score?: number | null;
  kev: boolean;
  vendor?: string | null;
  product?: string | null;
  source_url?: string | null;
  published_at?: string | null;
};

export type DashboardSummary = {
  vulnerability_count: number;
  kev_count: number;
  article_count: number;
  endpoint_count: number;
  detection_count: number;
  top_risks: Vulnerability[];
  latest_articles: Article[];
};

export type EndpointSnapshot = {
  id: number;
  tanium_endpoint_id?: string | null;
  hostname?: string | null;
  ip_address?: string | null;
  os_name?: string | null;
  os_version?: string | null;
  software?: unknown;
  last_seen_at?: string | null;
};

export type Detection = {
  id: number;
  match_reason: string;
  confidence: number;
  status: string;
  vulnerability: Vulnerability;
  endpoint: EndpointSnapshot;
};

export type TaniumStatus = {
  configured: boolean;
  gateway_url?: string | null;
  message: string;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {}),
    },
    ...init,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  return response.json() as Promise<T>;
}

export const api = {
  summary: () => request<DashboardSummary>("/api/dashboard/summary"),
  vulnerabilities: () => request<Vulnerability[]>("/api/vulnerabilities?limit=25"),
  articles: () => request<Article[]>("/api/articles?limit=25"),
  taniumStatus: () => request<TaniumStatus>("/api/tanium/status"),
  taniumTest: () => request<Record<string, unknown>>("/api/tanium/test", { method: "POST" }),
  taniumSyncEndpoints: () => request<Record<string, unknown>>("/api/tanium/sync-endpoints", { method: "POST" }),
  taniumAnalyzeImpact: () => request<Record<string, unknown>>("/api/tanium/analyze-impact", { method: "POST" }),
  detections: () => request<Detection[]>("/api/tanium/detections?limit=25"),
  collectNvd: () => request("/api/collect/nvd", { method: "POST" }),
  collectCisaKev: () => request("/api/collect/cisa-kev", { method: "POST" }),
  collectEpss: () => request("/api/collect/epss", { method: "POST" }),
  collectNews: () => request("/api/collect/news", { method: "POST" }),
};
