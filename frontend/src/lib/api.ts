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
  summary?: string | null;
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

export type TrendReport = {
  themes: string[];
  news: {
    title: string;
    summary: string;
    source?: string | null;
    url: string;
    published_at?: string | null;
  }[];
  vulnerabilities: {
    title: string;
    summary: string;
    cve_id: string;
    url?: string | null;
    kev: boolean;
    cvss_score?: number | null;
    epss_score?: number | null;
  }[];
};

export type TaniumStatus = {
  configured: boolean;
  gateway_url?: string | null;
  message: string;
};

export type LlmProvider = "disabled" | "ollama" | "openai" | "gemini" | "anthropic";

export type LlmSettings = {
  provider: LlmProvider;
  base_url?: string | null;
  model?: string | null;
  timeout_seconds: number;
  max_tokens: number;
  has_api_key: boolean;
  source: string;
};

export type LlmSettingsUpdate = {
  provider: LlmProvider;
  base_url?: string | null;
  model?: string | null;
  api_key?: string | null;
  clear_api_key?: boolean;
  timeout_seconds: number;
  max_tokens: number;
};

export type LlmTestResult = {
  ok: boolean;
  provider: string;
  model?: string | null;
  message: string;
};

type ListParams = {
  limit?: number;
  offset?: number;
  q?: string;
  sort?: "date" | "name";
};

type SummaryParams = {
  days?: number;
  includeExisting?: boolean;
  limit?: number;
};

function listQuery(params?: ListParams) {
  const search = new URLSearchParams();
  if (params?.limit != null) search.set("limit", String(params.limit));
  if (params?.offset != null) search.set("offset", String(params.offset));
  if (params?.q) search.set("q", params.q);
  if (params?.sort) search.set("sort", params.sort);
  const query = search.toString();
  return query ? `?${query}` : "";
}

function summaryQuery(params?: SummaryParams) {
  const search = new URLSearchParams();
  if (params?.days != null) search.set("days", String(params.days));
  if (params?.includeExisting != null) search.set("include_existing", String(params.includeExisting));
  if (params?.limit != null) search.set("limit", String(params.limit));
  const query = search.toString();
  return query ? `?${query}` : "";
}

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
  vulnerabilities: (params?: ListParams) => request<Vulnerability[]>(`/api/vulnerabilities${listQuery(params ?? { limit: 25 })}`),
  vulnerabilityCount: (params?: ListParams) => request<number>(`/api/vulnerabilities/count${listQuery(params)}`),
  articles: (params?: ListParams) => request<Article[]>(`/api/articles${listQuery(params ?? { limit: 25 })}`),
  articleCount: (params?: ListParams) => request<number>(`/api/articles/count${listQuery(params)}`),
  taniumStatus: () => request<TaniumStatus>("/api/tanium/status"),
  llmSettings: () => request<LlmSettings>("/api/settings/llm"),
  updateLlmSettings: (payload: LlmSettingsUpdate) =>
    request<LlmSettings>("/api/settings/llm", { method: "PUT", body: JSON.stringify(payload) }),
  testLlmSettings: (payload?: LlmSettingsUpdate) =>
    request<LlmTestResult>("/api/settings/llm/test", { method: "POST", body: payload ? JSON.stringify(payload) : undefined }),
  taniumTest: () => request<Record<string, unknown>>("/api/tanium/test", { method: "POST" }),
  taniumSyncEndpoints: () => request<Record<string, unknown>>("/api/tanium/sync-endpoints", { method: "POST" }),
  taniumAnalyzeImpact: () => request<Record<string, unknown>>("/api/tanium/analyze-impact", { method: "POST" }),
  detections: () => request<Detection[]>("/api/tanium/detections?limit=25"),
  trends: () => request<TrendReport>("/api/summaries/trends?limit=8"),
  summarizeArticles: (params?: SummaryParams) => request<Record<string, unknown>>(`/api/summaries/articles${summaryQuery(params ?? { limit: 20 })}`, { method: "POST" }),
  summarizeVulnerabilities: (params?: SummaryParams) => request<Record<string, unknown>>(`/api/summaries/vulnerabilities${summaryQuery(params ?? { limit: 20 })}`, { method: "POST" }),
  summarizeAll: (params?: SummaryParams) => request<Record<string, unknown>[]>(`/api/summaries/all${summaryQuery(params)}`, { method: "POST" }),
  collectNvd: () => request("/api/collect/nvd", { method: "POST" }),
  collectCisaKev: () => request("/api/collect/cisa-kev", { method: "POST" }),
  collectEpss: () => request("/api/collect/epss", { method: "POST" }),
  collectNews: () => request("/api/collect/news", { method: "POST" }),
};
