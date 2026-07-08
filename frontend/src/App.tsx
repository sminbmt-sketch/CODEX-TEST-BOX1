import { type Dispatch, type ReactNode, type SetStateAction, useEffect, useMemo, useState } from "react";
import { DatabaseZap, ExternalLink, FileText, Plus, Radar, RefreshCw, Search, Server, Trash2, Wifi } from "lucide-react";
import { api, type Article, type CollectionJobStatus, type DashboardSummary, type DataResetTarget, type Detection, type EndpointSnapshot, type LlmProvider, type LlmSettings, type Source, type TaniumStatus, type TrendReport, type Vulnerability } from "./lib/api";

type Route = "dashboard" | "cves" | "security-news" | "tanium-inventory" | "reports" | "settings";

type LoadState = {
  summary?: DashboardSummary;
  vulnerabilities: Vulnerability[];
  articles: Article[];
  vulnerabilityTotal: number;
  articleTotal: number;
  inventory: EndpointSnapshot[];
  detections: Detection[];
  trends?: TrendReport;
  tanium?: TaniumStatus;
  llm?: LlmSettings;
  nvdYearJob?: CollectionJobStatus;
  sources: Source[];
  loading: boolean;
  error?: string;
  action?: string;
};

const emptyState: LoadState = {
  vulnerabilities: [],
  articles: [],
  vulnerabilityTotal: 0,
  articleTotal: 0,
  inventory: [],
  detections: [],
  sources: [],
  loading: true,
};

const navItems: { route: Route; label: string }[] = [
  { route: "dashboard", label: "Dashboard" },
  { route: "cves", label: "CVE" },
  { route: "security-news", label: "Security News" },
  { route: "tanium-inventory", label: "Tanium Inventory" },
  { route: "reports", label: "Reports" },
  { route: "settings", label: "Settings" },
];

const pageSizeOptions = [10, 30, 50, 100];
const currentYear = new Date().getFullYear();
const llmDefaults: Record<LlmProvider, { baseUrl: string; model: string }> = {
  disabled: { baseUrl: "", model: "" },
  ollama: { baseUrl: "http://localhost:11434/v1", model: "qwen2.5:1.5b" },
  openai: { baseUrl: "https://api.openai.com/v1", model: "gpt-4o-mini" },
  gemini: { baseUrl: "https://generativelanguage.googleapis.com/v1beta", model: "gemini-3.1-flash-lite" },
  anthropic: { baseUrl: "https://api.anthropic.com/v1", model: "claude-3-5-haiku-latest" },
};

function routeFromHash(): Route {
  const value = window.location.hash.replace(/^#\/?/, "");
  if (value === "cves" || value === "security-news" || value === "tanium-inventory" || value === "reports" || value === "settings") {
    return value;
  }
  return "dashboard";
}

function formatDate(value?: string | null) {
  if (!value) return "-";
  return new Intl.DateTimeFormat("ko-KR", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function severityClass(severity?: string | null) {
  const value = severity?.toLowerCase();
  if (value === "critical") return "chip critical";
  if (value === "high") return "chip high";
  if (value === "medium") return "chip neutral";
  return "chip neutral";
}

function severityLabel(severity?: string | null) {
  const value = severity?.trim().toLowerCase();
  if (value === "critical") return "CRITICAL";
  if (value === "high") return "HIGH";
  if (value === "medium") return "MEDIUM";
  if (value === "low") return "LOW";
  return "N/A";
}

function epss(value?: number | null) {
  return value != null ? `${Math.round(value * 1000) / 10}%` : "-";
}

function endpointPlatform(endpoint: EndpointSnapshot) {
  if (endpoint.platform) return endpoint.platform;
  const osText = `${endpoint.os_name || ""} ${endpoint.os_version || ""}`.toLowerCase();
  if (osText.includes("windows")) return "Windows";
  if (osText.includes("macos") || osText.includes("mac os")) return "macOS";
  if (osText.includes("linux")) return "Linux";
  if (osText.includes("ubuntu")) return "Linux";
  if (osText.includes("debian")) return "Linux";
  if (osText.includes("aix")) return "AIX";
  return "-";
}

function vulnerabilitySummary(item: Vulnerability) {
  return item.summary || item.description || "수집된 원문 링크와 CVE 메타데이터 확인이 필요합니다.";
}

const summaryMarkerPattern = /\[\s*(?:보안\s*)?(?:이슈\s*)?요약\s*\]|\[\s*security\s+summary\s*\]|^\s*(?:보안\s*)?(?:이슈\s*)?요약\s*[:：-]\s*/gim;

function cleanSummaryText(value?: string | null) {
  if (!value) return "";
  return value
    .replace(/\*\*\s*\[?번역\]?\s*\*\*/gi, "")
    .replace(summaryMarkerPattern, "")
    .replace(/^\s*\[?번역\]?\s*[:：-]?\s*/gim, "")
    .replace(/^\s*\*\*\s*(제목|본문)\s*[:：,]\s*/gim, "")
    .replace(/^\s*\*\*\s*(제목|본문)\s*[:：,]?\s*\*\*\s*/gim, "")
    .replace(/^\s*\*\*\s*(제목|본문)\s*\*\*\s*[:：,]?\s*/gim, "")
    .replace(/^\s*(제목|본문)\s*[:：,]\s*/gim, "")
    .replace(/\*\*/g, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function stripLeadingTitle(text: string, title: string) {
  const normalizedTitle = cleanSummaryText(title);
  let value = text.trim();
  if (normalizedTitle && value.startsWith(normalizedTitle)) {
    value = value.slice(normalizedTitle.length).trim();
  }
  const lines = value.split("\n").map((line) => line.trim()).filter(Boolean);
  if (lines.length > 1 && lines[0].length <= 120 && !/[.!?。]$/.test(lines[0])) {
    value = lines.slice(1).join("\n").trim();
  }
  return value.replace(/^\n+/, "").trim();
}

const summarySplitPattern = /\[\s*(?:보안\s*)?(?:이슈\s*)?요약\s*\]|\[\s*security\s+summary\s*\]|^\s*(?:보안\s*)?(?:이슈\s*)?요약\s*[:：-]\s*/im;

function shouldShowSourceExcerpt(excerpt: string, summary: string) {
  if (!excerpt || excerpt === summary) return false;
  const compactExcerpt = excerpt.replace(/\s+/g, " ").trim();
  const compactSummary = summary.replace(/\s+/g, " ").trim();
  if (!compactExcerpt || compactSummary.includes(compactExcerpt)) return false;
  return compactExcerpt.length >= 90;
}

function articleDisplay(article: Article) {
  const summarySource = article.summary || "";
  const rawSource = article.raw_excerpt || "";
  const summaryParts = summarySource.split(summarySplitPattern);
  const hasEmbeddedSummary = summaryParts.length > 1;
  const title = cleanSummaryText(article.title);
  const sourceExcerpt = stripLeadingTitle(cleanSummaryText(hasEmbeddedSummary ? summaryParts.slice(0, -1).join("\n") : rawSource), title);
  const summary = stripLeadingTitle(cleanSummaryText(hasEmbeddedSummary ? summaryParts[summaryParts.length - 1] : summarySource), title) || sourceExcerpt || "원문 링크 확인이 필요합니다.";
  const excerpt = shouldShowSourceExcerpt(sourceExcerpt, summary) ? sourceExcerpt : "";
  return {
    title,
    summary,
    excerpt,
  };
}

function SummaryStatusBadge({ status }: { status?: string | null }) {
  if (status === "llm") return <span className="pill ok">LLM</span>;
  if (status === "fallback") return <span className="pill neutral">Fallback</span>;
  return <span className="pill neutral">No LLM</span>;
}

export default function App() {
  const [state, setState] = useState<LoadState>(emptyState);
  const [route, setRoute] = useState<Route>(() => routeFromHash());
  const [cvePage, setCvePage] = useState(1);
  const [cvePageSize, setCvePageSize] = useState(30);
  const [cveSearch, setCveSearch] = useState("");
  const [cveSort, setCveSort] = useState<"date" | "name">("date");
  const [newsPage, setNewsPage] = useState(1);
  const [newsPageSize, setNewsPageSize] = useState(30);
  const [newsSearch, setNewsSearch] = useState("");
  const [newsSort, setNewsSort] = useState<"date" | "name">("date");
  const [newsCategory, setNewsCategory] = useState<"news" | "kisa">("news");
  const [sourceDrafts, setSourceDrafts] = useState<Record<number, { name: string; kind: string; url: string; enabled: boolean }>>({});
  const [newSourceDrafts, setNewSourceDrafts] = useState<Record<"cve" | "news", { name: string; kind: string; url: string; enabled: boolean }>>({
    cve: { name: "", kind: "vulnerability", url: "", enabled: true },
    news: { name: "", kind: "rss", url: "", enabled: true },
  });
  const [summaryDays, setSummaryDays] = useState(7);
  const [newsDays, setNewsDays] = useState(7);
  const [includeExistingSummaries, setIncludeExistingSummaries] = useState(false);
  const [nvdStartYear, setNvdStartYear] = useState(currentYear);
  const [nvdEndYear, setNvdEndYear] = useState(currentYear);
  const [llmForm, setLlmForm] = useState({
    provider: "disabled" as LlmProvider,
    baseUrl: "",
    model: "",
    apiKey: "",
    clearApiKey: false,
    timeoutSeconds: 180,
    maxTokens: 512,
  });
  const [llmMessage, setLlmMessage] = useState<string | undefined>();

  async function load() {
    setState((current) => ({ ...current, loading: true, error: undefined }));
    try {
      const cveParams = { limit: cvePageSize, offset: (cvePage - 1) * cvePageSize, q: cveSearch.trim() || undefined, sort: cveSort };
      const newsParams = { limit: newsPageSize, offset: (newsPage - 1) * newsPageSize, q: newsSearch.trim() || undefined, sort: newsSort, category: newsCategory };
      const [summary, vulnerabilities, vulnerabilityTotal, articles, articleTotal, tanium, inventory, detections, trends, llm, sources, nvdYearJob] = await Promise.all([
        api.summary(),
        api.vulnerabilities(cveParams),
        api.vulnerabilityCount(cveParams),
        api.articles(newsParams),
        api.articleCount(newsParams),
        api.taniumStatus(),
        api.inventory(),
        api.detections(),
        api.trends(),
        api.llmSettings(),
        api.sources(),
        api.nvdYearStatus(),
      ]);
      setState({ summary, vulnerabilities, vulnerabilityTotal, articles, articleTotal, tanium, inventory, detections, trends, llm, nvdYearJob, sources, loading: false });
      setSourceDrafts(Object.fromEntries(sources.map((source) => [source.id, { name: source.name, kind: source.kind, url: source.url || "", enabled: source.enabled }])));
      setLlmForm((current) => ({
        ...current,
        provider: llm.provider,
        baseUrl: llm.base_url || "",
        model: llm.model || "",
        apiKey: "",
        clearApiKey: false,
        timeoutSeconds: llm.timeout_seconds,
        maxTokens: llm.max_tokens,
      }));
    } catch (error) {
      setState((current) => ({
        ...current,
        loading: false,
        error: error instanceof Error ? error.message : "Unknown error",
      }));
    }
  }

  async function saveLlmSettings() {
    setState((current) => ({ ...current, action: "Save LLM settings", error: undefined }));
    setLlmMessage(undefined);
    try {
      const updated = await api.updateLlmSettings(llmPayload(llmForm));
      setState((current) => ({ ...current, llm: updated, action: undefined }));
      setLlmForm((current) => ({ ...current, apiKey: "", clearApiKey: false }));
      setLlmMessage("LLM 설정을 저장했습니다.");
    } catch (error) {
      setState((current) => ({
        ...current,
        action: undefined,
        error: error instanceof Error ? error.message : "Unknown error",
      }));
    }
  }

  async function testLlmSettings() {
    setState((current) => ({ ...current, action: "Test LLM", error: undefined }));
    setLlmMessage(undefined);
    try {
      const result = await api.testLlmSettings(llmPayload(llmForm));
      setState((current) => ({ ...current, action: undefined }));
      setLlmMessage(`${result.ok ? "연결 성공" : "연결 실패"}: ${result.message}`);
    } catch (error) {
      setState((current) => ({
        ...current,
        action: undefined,
        error: error instanceof Error ? error.message : "Unknown error",
      }));
    }
  }

  async function runAction(label: string, action: () => Promise<unknown>) {
    setState((current) => ({ ...current, action: label, error: undefined }));
    try {
      await action();
      await load();
    } catch (error) {
      setState((current) => ({
        ...current,
        action: undefined,
        error: error instanceof Error ? error.message : "Unknown error",
      }));
    }
  }

  async function runLatestCveUpdate() {
    await runAction("최신 CVE Update", () => api.collectNvdRecentFeed());
  }

  async function runNvdYearUpdate() {
    const startYear = Math.min(nvdStartYear, nvdEndYear);
    const endYear = Math.max(nvdStartYear, nvdEndYear);
    await runAction(`NVD ${startYear}-${endYear}`, () => api.collectNvdYear(startYear, endYear));
  }

  async function runNewsUpdate() {
    await runAction("News", () => api.collectNews({ days: newsDays }));
  }

  async function runSummariesUpdate() {
    await runAction("Summaries", () => api.summarizeAll({ days: summaryDays, includeExisting: includeExistingSummaries }));
  }

  async function saveSource(source: Source) {
    const draft = sourceDrafts[source.id];
    if (!draft) return;
    await runAction(`Save source ${source.name}`, () => api.updateSource(source.id, draft));
  }

  async function createSource(group: "cve" | "news") {
    const draft = newSourceDrafts[group];
    if (!draft.name.trim() || !draft.kind.trim() || !draft.url.trim()) return;
    await runAction(`Add source ${draft.name}`, () => api.createSource(draft));
    setNewSourceDrafts((current) => ({
      ...current,
      [group]: { name: "", kind: group === "cve" ? "vulnerability" : "rss", url: "", enabled: true },
    }));
  }

  async function deleteSource(source: Source) {
    await runAction(`Delete source ${source.name}`, () => api.deleteSource(source.id));
  }

  async function resetData(target: DataResetTarget, label: string) {
    const confirmed = window.confirm(`${label} 데이터를 삭제합니다. 설정과 수집 소스 링크는 유지됩니다. 계속할까요?`);
    if (!confirmed) return;
    await runAction(`Delete ${label}`, () => api.resetData(target));
  }

  useEffect(() => {
    const onHashChange = () => setRoute(routeFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    void load();
  }, [cvePage, cvePageSize, cveSearch, cveSort, newsPage, newsPageSize, newsSearch, newsSort, newsCategory]);

  const metrics = useMemo(() => {
    const summary = state.summary;
    return [
      { label: "CVE / KEV", value: `${summary?.vulnerability_count ?? 0} / ${summary?.kev_count ?? 0}` },
      { label: "News", value: summary?.article_count ?? 0 },
      { label: "Endpoints", value: summary?.endpoint_count ?? 0 },
      { label: "Detections", value: summary?.detection_count ?? 0 },
      {
        label: "Tanium",
        value: state.tanium?.configured ? "Online" : "Missing",
        sub: state.tanium?.configured ? "Gateway/API 정상" : "연결 설정 필요",
      },
    ];
  }, [state.summary, state.tanium]);

  const newsSources = state.sources.filter((source) => source.kind !== "vulnerability");

  return (
    <main className="ops-app">
      <aside className="sidebar">
        <div className="brand">
          <strong>SecureWatch</strong>
          <span>Security Operations</span>
        </div>
        <nav className="nav" aria-label="SecureWatch navigation">
          {navItems.map((item) => (
            <a key={item.route} className={route === item.route ? "active" : undefined} href={`#/${item.route}`}>
              {item.label}
            </a>
          ))}
        </nav>
      </aside>

      <section className="workspace">
        {state.error && <div className="notice error">{state.error}</div>}
        {state.action && <div className="notice">Running {state.action}</div>}

        {route === "dashboard" && (
          <>
            <header className="top">
              <div>
                <h1>Security Operations</h1>
                <p>수집한 보안 뉴스, CVE, Tanium 단말 정보를 한 화면에서 요약합니다.</p>
              </div>
              <span className="time">{state.loading ? "Loading" : "Live data"}</span>
            </header>

            <section className="metrics" aria-label="Dashboard metrics">
              {metrics.map((metric) => (
                <article key={metric.label} className="metric">
                  <label>{metric.label}</label>
                  <strong>{metric.value}</strong>
                  {metric.sub && <small>{metric.sub}</small>}
                </article>
              ))}
            </section>

            <section className="dashboard-grid">
              <article className="panel">
                <div className="panel-header">
                  <h2>CVE / KEV</h2>
                  <a className="link-button" href="#/cves">
                    CVE / KEV 전체 보기
                  </a>
                </div>
                <div className="table">
                  <div className="cve-row header">
                    <span className="center-cell">CVE</span>
                    <span>KEV/Severity</span>
                    <span className="center-cell">EPSS</span>
                    <span>요약 내용</span>
                  </div>
                  {(state.summary?.top_risks || []).slice(0, 4).map((item) => (
                    <div key={item.id} className="cve-row">
                      <strong className="center-cell cve-id-cell">{item.cve_id}</strong>
                      <span className={item.kev ? "chip critical" : severityClass(item.cvss_severity)} title={item.cvss_severity || undefined}>
                        {item.kev ? "KEV" : severityLabel(item.cvss_severity)}
                      </span>
                      <span className="center-cell epss-cell">{epss(item.epss_score)}</span>
                      <span>{vulnerabilitySummary(item)}</span>
                    </div>
                  ))}
                  {!state.summary?.top_risks.length && <div className="empty block">No vulnerability data</div>}
                </div>
              </article>

              <article className="panel news-panel">
                <div className="panel-header">
                  <h2>Security News</h2>
                  <a className="link-button" href="#/security-news">
                    Security News 전체 보기
                  </a>
                </div>
                <div className="brief">
                  {(state.summary?.latest_articles || []).slice(0, 10).map((item) => (
                    <article key={item.url}>
                      <strong>{item.title}</strong>
                      <p>{articleDisplay(item).summary}</p>
                    </article>
                  ))}
                  {!state.summary?.latest_articles.length && <div className="empty block">No news summary</div>}
                </div>
              </article>
            </section>
          </>
        )}

        {route === "cves" && (
          <section>
            <div className="sticky-list-header">
              <PageTitle
                title="CVE"
                description="수집한 CVE, KEV, EPSS, 영향 단말 후보를 게시글 형태로 확인합니다."
                badge={`${state.summary?.vulnerability_count ?? state.vulnerabilities.length} CVEs`}
                tone="critical"
              />
              <ListToolbar>
                <ListControls
                  search={cveSearch}
                  searchLabel="CVE 검색"
                  sort={cveSort}
                  onSearchChange={(value) => {
                    setCveSearch(value);
                    setCvePage(1);
                  }}
                  onSortChange={(value) => {
                    setCveSort(value);
                    setCvePage(1);
                  }}
                />
                <Pager
                  page={cvePage}
                  pageSize={cvePageSize}
                  total={state.vulnerabilityTotal}
                  onPageChange={setCvePage}
                  onPageSizeChange={(value) => {
                    setCvePageSize(value);
                    setCvePage(1);
                  }}
                />
              </ListToolbar>
            </div>
            <div className="page-grid">
              {state.vulnerabilities.map((item) => (
                <article key={item.id} className="page-card">
                  <header>
                    <div>
                      <h3>
                        {item.source_url ? (
                          <a href={item.source_url} target="_blank" rel="noreferrer">
                            {item.cve_id} <ExternalLink size={13} />
                          </a>
                        ) : (
                          item.cve_id
                        )}
                      </h3>
                      <p>{item.title || [item.vendor, item.product].filter(Boolean).join(" / ") || "제품 식별 정보 확인 필요"}</p>
                    </div>
                    <div className="badge-stack">
                      <span className={item.kev ? "pill critical" : severityClass(item.cvss_severity)}>{item.kev ? "KEV" : item.cvss_severity || "CVE"}</span>
                      <SummaryStatusBadge status={item.summary_status} />
                    </div>
                  </header>
                  <div className="body">
                    <div className="stat-grid">
                      <div className="stat">
                        <label>CVSS</label>
                        <strong>{item.cvss_score ?? "-"}</strong>
                      </div>
                      <div className="stat">
                        <label>EPSS</label>
                        <strong>{epss(item.epss_score)}</strong>
                      </div>
                      <div className="stat">
                        <label>Published</label>
                        <strong>{formatDate(item.published_at)}</strong>
                      </div>
                    </div>
                    <article className="post">
                      <h4>요약 내용</h4>
                      <p>{vulnerabilitySummary(item)}</p>
                      <div className="meta">
                        {item.vendor && <span>{item.vendor}</span>}
                        {item.product && <span>{item.product}</span>}
                        {item.kev && <span>CISA KEV</span>}
                      </div>
                    </article>
                  </div>
                </article>
              ))}
              {!state.vulnerabilities.length && <div className="empty block">No CVE data</div>}
            </div>
          </section>
        )}

        {route === "security-news" && (
          <section>
            <div className="sticky-list-header">
              <PageTitle
                title="Security News"
                description="수집한 보안 뉴스와 KISA 보안 공지를 분리해서 확인합니다."
                badge={`${state.articleTotal} ${newsCategory === "kisa" ? "KISA notices" : "news"}`}
              />
              <div className="segmented">
                <button
                  type="button"
                  className={newsCategory === "news" ? "active" : undefined}
                  onClick={() => {
                    setNewsCategory("news");
                    setNewsPage(1);
                  }}
                >
                  News
                </button>
                <button
                  type="button"
                  className={newsCategory === "kisa" ? "active" : undefined}
                  onClick={() => {
                    setNewsCategory("kisa");
                    setNewsPage(1);
                  }}
                >
                  KISA 보안공지
                </button>
              </div>
              <ListToolbar>
                <ListControls
                  search={newsSearch}
                  searchLabel="뉴스 검색"
                  sort={newsSort}
                  onSearchChange={(value) => {
                    setNewsSearch(value);
                    setNewsPage(1);
                  }}
                  onSortChange={(value) => {
                    setNewsSort(value);
                    setNewsPage(1);
                  }}
                />
                <Pager
                  page={newsPage}
                  pageSize={newsPageSize}
                  total={state.articleTotal}
                  onPageChange={setNewsPage}
                  onPageSizeChange={(value) => {
                    setNewsPageSize(value);
                    setNewsPage(1);
                  }}
                />
              </ListToolbar>
            </div>
            <div className="page-grid">
              {state.articles.map((article) => {
                const display = articleDisplay(article);
                return (
                  <article key={article.id} className="page-card">
                    <header>
                      <div>
                        <h3>
                          <a href={article.url} target="_blank" rel="noreferrer">
                            {article.title} <ExternalLink size={13} />
                          </a>
                        </h3>
                        <p>
                          {article.source?.name || "Source"} · {formatDate(article.published_at)}
                        </p>
                      </div>
                      <div className="badge-stack">
                        <span className="pill neutral">{article.source?.kind || "news"}</span>
                        <SummaryStatusBadge status={article.summary_status} />
                      </div>
                    </header>
                    <div className="body">
                      <article className="post news-summary-post">
                        <h4>요약</h4>
                        <p className="summary-primary">{display.summary}</p>
                        {display.excerpt && (
                          <div className="source-excerpt">
                            <strong>원문 일부</strong>
                            <p>{display.excerpt}</p>
                          </div>
                        )}
                        <div className="meta">
                          <span>원문 링크</span>
                          <span>{article.source?.kind || "RSS"}</span>
                        </div>
                      </article>
                    </div>
                  </article>
                );
              })}
              {!state.articles.length && <div className="empty block">No news data</div>}
            </div>
          </section>
        )}

        {route === "tanium-inventory" && (
          <section>
            <PageTitle title="Tanium Inventory" description="Tanium API로 수집한 단말 기본 정보를 제공합니다." badge={`${state.summary?.endpoint_count ?? state.inventory.length} endpoints`} tone="ok" />
            <article className="page-card">
              <header>
                <div>
                  <h3>수집 단말 목록</h3>
                  <p>Host Name, IP, MAC, Operating System, Platform 기준으로 표시합니다.</p>
                </div>
                <span className={state.tanium?.configured ? "pill ok" : "pill neutral"}>{state.tanium?.configured ? "Online" : "Missing"}</span>
              </header>
              <div className="table">
                <div className="inventory-row header">
                  <span>Host Name</span>
                  <span>IP</span>
                  <span>MAC</span>
                  <span>Operating System</span>
                  <span>Platform</span>
                </div>
                {state.inventory.map((endpoint) => (
                  <div key={endpoint.id} className="inventory-row">
                    <strong>{endpoint.hostname || endpoint.tanium_endpoint_id || "Unknown"}</strong>
                    <span>{endpoint.ip_address || "-"}</span>
                    <span>{endpoint.mac_address || "-"}</span>
                    <span>{[endpoint.os_name, endpoint.os_version].filter(Boolean).join(" ") || "-"}</span>
                    <span>{endpointPlatform(endpoint)}</span>
                  </div>
                ))}
                {!state.inventory.length && <div className="empty block">No endpoint inventory</div>}
              </div>
            </article>
          </section>
        )}

        {route === "reports" && (
          <section>
            <PageTitle title="Reports" description="운영 보고서 영역입니다. 이후 CVE 조치 현황과 뉴스 브리핑 내보내기를 연결합니다." />
            <div className="page-card placeholder">Reports page placeholder</div>
          </section>
        )}

        {route === "settings" && (
          <section>
            <div className="sticky-list-header settings-sticky-header">
              <PageTitle title="Settings" description="수집 주기, LLM 모델, Tanium 연결 설정을 관리하는 영역입니다." />
              <div className="toolbar settings-top-actions">
                <button title="Refresh dashboard" onClick={() => void load()} disabled={state.loading}>
                  <RefreshCw size={16} />
                  <span>Refresh</span>
                </button>
                <button title="Collect new CVEs from NVD CVE-Recent feed and skip duplicates" onClick={() => void runLatestCveUpdate()} disabled={Boolean(state.action)}>
                  <DatabaseZap size={16} />
                  <span>최신 CVE Update</span>
                </button>
                <button title="Collect security news for the configured date range" onClick={() => void runNewsUpdate()} disabled={Boolean(state.action)}>
                  <FileText size={16} />
                  <span>News</span>
                </button>
                <button title="Translate and summarize using the configured summary period" onClick={() => void runSummariesUpdate()} disabled={Boolean(state.action)}>
                  <FileText size={16} />
                  <span>Summarize</span>
                </button>
                <button title="Sync Tanium endpoint inventory" onClick={() => void runAction("Endpoint sync", api.taniumSyncEndpoints)} disabled={Boolean(state.action)}>
                  <Server size={16} />
                  <span>Endpoints</span>
                </button>
                <button title="Analyze CVE impact against Tanium inventory" onClick={() => void runAction("Impact analysis", api.taniumAnalyzeImpact)} disabled={Boolean(state.action)}>
                  <Radar size={16} />
                  <span>Analyze</span>
                </button>
                <button title="Run read-only Gateway test" onClick={() => void runAction("Tanium test", api.taniumTest)} disabled={Boolean(state.action)}>
                  <Wifi size={16} />
                  <span>Test Gateway</span>
                </button>
              </div>
            </div>
            <article className="page-card settings-card data-management-card">
              <header>
                <div>
                  <h3>Data Management</h3>
                  <p>수집된 운영 데이터를 삭제합니다. LLM 설정과 수집 소스 링크는 유지됩니다.</p>
                </div>
                <span className="pill neutral">Reset</span>
              </header>
              <div className="data-actions">
                <button type="button" className="danger-button" onClick={() => void resetData("all", "전체")} disabled={Boolean(state.action)}>
                  <Trash2 size={16} />
                  <span>데이터 리셋</span>
                </button>
                <button type="button" onClick={() => void resetData("cves", "CVE")} disabled={Boolean(state.action)}>
                  <Trash2 size={16} />
                  <span>CVE 삭제</span>
                </button>
                <button type="button" onClick={() => void resetData("news", "Security News")} disabled={Boolean(state.action)}>
                  <Trash2 size={16} />
                  <span>Security News 삭제</span>
                </button>
                <button type="button" onClick={() => void resetData("inventory", "Tanium Inventory")} disabled={Boolean(state.action)}>
                  <Trash2 size={16} />
                  <span>Tanium Inventory 삭제</span>
                </button>
              </div>
              <div className="settings-note">
                <span>전체: CVE, Security News, Tanium Inventory, Detection 삭제</span>
                <span>부분: CVE, Security News, Tanium Inventory만 삭제</span>
              </div>
            </article>
            <div className="source-settings-grid">
              <SourceSettingsCard
                title="News Sources"
                description="Security News와 KISA 보안공지 수집에 사용하는 링크입니다."
                sources={newsSources}
                drafts={sourceDrafts}
                setDrafts={setSourceDrafts}
                newDraft={newSourceDrafts.news}
                setNewDraft={(draft) => setNewSourceDrafts((current) => ({ ...current, news: draft }))}
                onCreate={() => createSource("news")}
                onSave={saveSource}
                onDelete={deleteSource}
                allowCreate
                actionDisabled={Boolean(state.action)}
              >
                <div className="settings-form news-days-form">
                  <label>
                    수집 기간(최근 N일)
                    <input
                      type="number"
                      min={1}
                      max={365}
                      value={newsDays}
                      onChange={(event) => setNewsDays(Number(event.target.value))}
                    />
                  </label>
                  <span className="settings-note-inline">기본값은 최근 7일입니다. KISA 게시판은 이 기간까지만 pageIndex를 넘기며 수집합니다.</span>
                </div>
              </SourceSettingsCard>
            </div>
            <article className="page-card settings-card">
              <header>
                <div>
                  <h3>NVD Year Feed</h3>
                  <p>NVD JSON 2.0 Feeds 페이지를 기준으로 선택한 연도 범위의 CVE 전체 feed를 가져옵니다.</p>
                </div>
                <span className="pill neutral">{Math.min(nvdStartYear, nvdEndYear)} - {Math.max(nvdStartYear, nvdEndYear)}</span>
              </header>
              <div className="settings-form nvd-year-form">
                <label>
                  최소 연도
                  <input
                    type="number"
                    min={2002}
                    max={currentYear}
                    value={nvdStartYear}
                    onChange={(event) => setNvdStartYear(Number(event.target.value))}
                  />
                </label>
                <label>
                  최대 연도
                  <input
                    type="number"
                    min={2002}
                    max={currentYear}
                    value={nvdEndYear}
                    onChange={(event) => setNvdEndYear(Number(event.target.value))}
                  />
                </label>
                <div className="settings-actions">
                  <button
                    title="Collect NVD CVE JSON feeds for selected year range"
                    onClick={() => void runNvdYearUpdate()}
                    disabled={Boolean(state.action) || nvdStartYear < 2002 || nvdEndYear < 2002 || nvdStartYear > currentYear || nvdEndYear > currentYear}
                  >
                    <DatabaseZap size={16} />
                    <span>Year Range Update</span>
                  </button>
                </div>
              </div>
              <div className="settings-note">
                <span>Source: NVD JSON Feeds</span>
                <span>2002 - {currentYear}</span>
                <span>Status: {state.nvdYearJob?.status || "idle"}</span>
                {state.nvdYearJob?.current_year && <span>Current: {state.nvdYearJob.current_year}</span>}
                <span>Fetched: {state.nvdYearJob?.fetched ?? 0}</span>
                <span>Updated: {state.nvdYearJob?.created_or_updated ?? 0}</span>
                {state.nvdYearJob?.error && <strong>{state.nvdYearJob.error}</strong>}
              </div>
            </article>
            <article className="page-card settings-card">
              <header>
                <div>
                  <h3>LLM Provider</h3>
                  <p>로컬 LLM 성능 저하 시 OpenAI, Gemini, Claude API로 요약 기능을 대체합니다.</p>
                </div>
                <span className={state.llm?.provider === "disabled" ? "pill neutral" : "pill ok"}>
                  {state.llm?.provider === "disabled" ? "Disabled" : state.llm?.provider || "Loading"}
                </span>
              </header>
              <div className="settings-form">
                <label>
                  Provider
                  <select
                    value={llmForm.provider}
                    onChange={(event) => {
                      const provider = event.target.value as LlmProvider;
                      setLlmForm((current) => ({
                        ...current,
                        provider,
                        baseUrl: llmDefaults[provider].baseUrl,
                        model: llmDefaults[provider].model,
                      }));
                    }}
                  >
                    <option value="disabled">Disabled</option>
                    <option value="ollama">Local Ollama</option>
                    <option value="openai">ChatGPT / OpenAI API</option>
                    <option value="gemini">Gemini API</option>
                    <option value="anthropic">Claude / Anthropic API</option>
                  </select>
                </label>
                <label>
                  Base URL
                  <input value={llmForm.baseUrl} placeholder={llmDefaults[llmForm.provider].baseUrl} onChange={(event) => setLlmForm((current) => ({ ...current, baseUrl: event.target.value }))} />
                </label>
                <label>
                  Model
                  <input value={llmForm.model} placeholder={llmDefaults[llmForm.provider].model} onChange={(event) => setLlmForm((current) => ({ ...current, model: event.target.value }))} />
                </label>
                <label>
                  API Key
                  <input
                    type="password"
                    value={llmForm.apiKey}
                    placeholder={state.llm?.has_api_key ? "저장된 키 유지" : "API 키 입력"}
                    onChange={(event) => setLlmForm((current) => ({ ...current, apiKey: event.target.value, clearApiKey: false }))}
                  />
                </label>
                <label>
                  Timeout
                  <input
                    type="number"
                    min={30}
                    max={600}
                    value={llmForm.timeoutSeconds}
                    onChange={(event) => setLlmForm((current) => ({ ...current, timeoutSeconds: Number(event.target.value) }))}
                  />
                </label>
                <label>
                  Max tokens
                  <input
                    type="number"
                    min={64}
                    max={4096}
                    value={llmForm.maxTokens}
                    onChange={(event) => setLlmForm((current) => ({ ...current, maxTokens: Number(event.target.value) }))}
                  />
                </label>
                <label className="check-field">
                  <input
                    type="checkbox"
                    checked={llmForm.clearApiKey}
                    onChange={(event) => setLlmForm((current) => ({ ...current, clearApiKey: event.target.checked, apiKey: event.target.checked ? "" : current.apiKey }))}
                  />
                  저장된 API Key 삭제
                </label>
                <div className="settings-actions">
                  <button title="Save LLM provider settings" onClick={() => void saveLlmSettings()} disabled={Boolean(state.action)}>
                    <DatabaseZap size={16} />
                    <span>Save LLM</span>
                  </button>
                  <button title="Test selected LLM provider" onClick={() => void testLlmSettings()} disabled={Boolean(state.action) || llmForm.provider === "disabled"}>
                    <Radar size={16} />
                    <span>Test LLM</span>
                  </button>
                </div>
              </div>
              <div className="settings-note">
                <span>Source: {state.llm?.source || "-"}</span>
                <span>API Key: {state.llm?.has_api_key ? "Stored" : "Not set"}</span>
                {llmMessage && <strong>{llmMessage}</strong>}
              </div>
            </article>
            <article className="page-card settings-card">
              <header>
                <div>
                  <h3>Summaries</h3>
                  <p>선택한 기간의 뉴스와 CVE를 LLM으로 번역/요약합니다. 기본값은 기존 요약 완료 항목을 다시 요청하지 않습니다.</p>
                </div>
                <span className="pill neutral">{summaryDays} days</span>
              </header>
              <div className="settings-form summary-settings-form">
                <label>
                  업데이트 기간(최근 N일)
                  <input
                    type="number"
                    min={1}
                    max={365}
                    value={summaryDays}
                    onChange={(event) => setSummaryDays(Number(event.target.value))}
                  />
                </label>
                <label className="check-field">
                  <input
                    type="checkbox"
                    checked={includeExistingSummaries}
                    onChange={(event) => setIncludeExistingSummaries(event.target.checked)}
                  />
                  기존 업데이트 정보 요청
                </label>
                <div className="settings-actions">
                  <button title="Translate and summarize selected period" onClick={() => void runSummariesUpdate()} disabled={Boolean(state.action)}>
                    <FileText size={16} />
                    <span>Summaries</span>
                  </button>
                </div>
              </div>
              <div className="settings-note">
                <span>{includeExistingSummaries ? "기존 요약 포함" : "요약 완료 항목 제외"}</span>
                <span>최근 {summaryDays}일 기준</span>
              </div>
            </article>
          </section>
        )}
      </section>
    </main>
  );
}

function llmPayload(form: {
  provider: LlmProvider;
  baseUrl: string;
  model: string;
  apiKey: string;
  clearApiKey: boolean;
  timeoutSeconds: number;
  maxTokens: number;
}) {
  return {
    provider: form.provider,
    base_url: form.baseUrl || llmDefaults[form.provider].baseUrl || null,
    model: form.model || llmDefaults[form.provider].model || null,
    api_key: form.apiKey || null,
    clear_api_key: form.clearApiKey,
    timeout_seconds: form.timeoutSeconds,
    max_tokens: form.maxTokens,
  };
}

function SourceSettingsCard({
  title,
  description,
  sources,
  drafts,
  setDrafts,
  newDraft,
  setNewDraft,
  onCreate,
  onSave,
  onDelete,
  allowCreate = true,
  actionDisabled,
  children,
}: {
  title: string;
  description: string;
  sources: Source[];
  drafts: Record<number, { name: string; kind: string; url: string; enabled: boolean }>;
  setDrafts: Dispatch<SetStateAction<Record<number, { name: string; kind: string; url: string; enabled: boolean }>>>;
  newDraft: { name: string; kind: string; url: string; enabled: boolean };
  setNewDraft: (draft: { name: string; kind: string; url: string; enabled: boolean }) => void;
  onCreate: () => Promise<void>;
  onSave: (source: Source) => Promise<void>;
  onDelete: (source: Source) => Promise<void>;
  allowCreate?: boolean;
  actionDisabled: boolean;
  children?: ReactNode;
}) {
  const addDisabled = actionDisabled || !newDraft.name.trim() || !newDraft.kind.trim() || !newDraft.url.trim();

  return (
    <article className="page-card settings-card source-card">
      <header>
        <div>
          <h3>{title}</h3>
          <p>{description}</p>
        </div>
        <span className="pill neutral">{sources.filter((source) => source.enabled).length} active</span>
      </header>
      {children}
      <div className="source-list">
        {allowCreate && (
          <div className="source-row source-add-row">
            <label>
              Name
              <input value={newDraft.name} onChange={(event) => setNewDraft({ ...newDraft, name: event.target.value })} placeholder="Source name" />
            </label>
            <label>
              Kind
              <input value={newDraft.kind} onChange={(event) => setNewDraft({ ...newDraft, kind: event.target.value })} placeholder="rss" />
            </label>
            <label className="source-url-field">
              URL
              <input value={newDraft.url} onChange={(event) => setNewDraft({ ...newDraft, url: event.target.value })} placeholder="https://..." />
            </label>
            <label className="check-field source-enabled">
              <input
                type="checkbox"
                checked={newDraft.enabled}
                onChange={(event) => setNewDraft({ ...newDraft, enabled: event.target.checked })}
              />
              Enabled
            </label>
            <div className="source-actions">
              <button type="button" className="source-add-button" onClick={() => void onCreate()} disabled={addDisabled}>
                <Plus size={14} />
                링크 추가
              </button>
            </div>
          </div>
        )}
        {sources.map((source) => {
          const draft = drafts[source.id] || { name: source.name, kind: source.kind, url: source.url || "", enabled: source.enabled };
          return (
            <div key={source.id} className={!draft.enabled ? "source-row disabled" : "source-row"}>
              <label>
                Name
                <input
                  value={draft.name}
                  onChange={(event) => setDrafts((current) => ({ ...current, [source.id]: { ...draft, name: event.target.value } }))}
                />
              </label>
              <label>
                Kind
                <input
                  value={draft.kind}
                  onChange={(event) => setDrafts((current) => ({ ...current, [source.id]: { ...draft, kind: event.target.value } }))}
                />
              </label>
              <label className="source-url-field">
                URL
                <input
                  value={draft.url}
                  onChange={(event) => setDrafts((current) => ({ ...current, [source.id]: { ...draft, url: event.target.value } }))}
                />
              </label>
              <label className="check-field source-enabled">
                <input
                  type="checkbox"
                  checked={draft.enabled}
                  onChange={(event) => setDrafts((current) => ({ ...current, [source.id]: { ...draft, enabled: event.target.checked } }))}
                />
                Enabled
              </label>
              <div className="source-actions">
                <button type="button" onClick={() => void onSave(source)} disabled={actionDisabled}>
                  Save
                </button>
                <button type="button" onClick={() => void onDelete(source)} disabled={actionDisabled || !source.enabled}>
                  Delete
                </button>
              </div>
            </div>
          );
        })}
        {!sources.length && <div className="empty block">No configured sources</div>}
      </div>
    </article>
  );
}

function PageTitle({
  title,
  description,
  badge,
  tone = "neutral",
  children,
}: {
  title: string;
  description: string;
  badge?: string;
  tone?: "neutral" | "critical" | "ok";
  children?: ReactNode;
}) {
  return (
    <div className="section-title">
      <div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <div className="section-actions">
        {badge && <span className={`pill ${tone}`}>{badge}</span>}
        {children}
      </div>
    </div>
  );
}

function ListToolbar({ children }: { children: ReactNode }) {
  return <div className="list-toolbar">{children}</div>;
}

function ListControls({
  search,
  searchLabel,
  sort,
  onSearchChange,
  onSortChange,
}: {
  search: string;
  searchLabel: string;
  sort: "date" | "name";
  onSearchChange: (value: string) => void;
  onSortChange: (value: "date" | "name") => void;
}) {
  return (
    <div className="list-controls">
      <label className="search-field">
        <Search size={15} />
        <input value={search} placeholder={searchLabel} onChange={(event) => onSearchChange(event.target.value)} />
      </label>
      <label className="sort-field">
        정렬
        <select value={sort} onChange={(event) => onSortChange(event.target.value as "date" | "name")}>
          <option value="date">날짜순</option>
          <option value="name">이름순</option>
        </select>
      </label>
    </div>
  );
}

function Pager({
  page,
  pageSize,
  total,
  onPageChange,
  onPageSizeChange,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (value: number) => void;
  onPageSizeChange: (value: number) => void;
}) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(total, page * pageSize);

  return (
    <div className="pager">
      <label>
        표시
        <select value={pageSize} onChange={(event) => onPageSizeChange(Number(event.target.value))}>
          {pageSizeOptions.map((option) => (
            <option key={option} value={option}>
              {option}개
            </option>
          ))}
        </select>
      </label>
      <span>
        {start}-{end} / {total}
      </span>
      <button type="button" onClick={() => onPageChange(Math.max(1, page - 1))} disabled={page <= 1}>
        이전
      </button>
      <button type="button" onClick={() => onPageChange(Math.min(totalPages, page + 1))} disabled={page >= totalPages}>
        다음
      </button>
    </div>
  );
}
