import { type ReactNode, useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, DatabaseZap, ExternalLink, FileText, Radar, RefreshCw, Server, ShieldCheck, Wifi } from "lucide-react";
import { api, type Article, type DashboardSummary, type Detection, type TaniumStatus, type TrendReport, type Vulnerability } from "./lib/api";

type Route = "dashboard" | "cves" | "security-news" | "tanium-inventory" | "reports" | "settings";

type LoadState = {
  summary?: DashboardSummary;
  vulnerabilities: Vulnerability[];
  articles: Article[];
  detections: Detection[];
  trends?: TrendReport;
  tanium?: TaniumStatus;
  loading: boolean;
  error?: string;
  action?: string;
};

const emptyState: LoadState = {
  vulnerabilities: [],
  articles: [],
  detections: [],
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

function epss(value?: number | null) {
  return value != null ? `${Math.round(value * 1000) / 10}%` : "-";
}

function vulnerabilitySummary(item: Vulnerability) {
  return item.summary || item.description || "수집된 원문 링크와 CVE 메타데이터 확인이 필요합니다.";
}

export default function App() {
  const [state, setState] = useState<LoadState>(emptyState);
  const [route, setRoute] = useState<Route>(() => routeFromHash());
  const [cvePage, setCvePage] = useState(1);
  const [cvePageSize, setCvePageSize] = useState(30);
  const [newsPage, setNewsPage] = useState(1);
  const [newsPageSize, setNewsPageSize] = useState(30);

  async function load() {
    setState((current) => ({ ...current, loading: true, error: undefined }));
    try {
      const [summary, vulnerabilities, articles, tanium, detections, trends] = await Promise.all([
        api.summary(),
        api.vulnerabilities({ limit: cvePageSize, offset: (cvePage - 1) * cvePageSize }),
        api.articles({ limit: newsPageSize, offset: (newsPage - 1) * newsPageSize }),
        api.taniumStatus(),
        api.detections(),
        api.trends(),
      ]);
      setState({ summary, vulnerabilities, articles, tanium, detections, trends, loading: false });
    } catch (error) {
      setState((current) => ({
        ...current,
        loading: false,
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

  useEffect(() => {
    const onHashChange = () => setRoute(routeFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    void load();
  }, [cvePage, cvePageSize, newsPage, newsPageSize]);

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

  const endpointRows = useMemo(() => {
    const seen = new Set<number>();
    return state.detections
      .filter((detection) => {
        if (seen.has(detection.endpoint.id)) return false;
        seen.add(detection.endpoint.id);
        return true;
      })
      .map((detection) => ({ endpoint: detection.endpoint, detection }));
  }, [state.detections]);

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
                  <h2>High Priority CVE / KEV</h2>
                  <a className="link-button" href="#/cves">
                    CVE / KEV 전체 보기
                  </a>
                </div>
                <div className="table">
                  <div className="cve-row header">
                    <span>CVE</span>
                    <span>KEV/Severity</span>
                    <span>EPSS</span>
                    <span>한글 요약</span>
                  </div>
                  {state.vulnerabilities.slice(0, 4).map((item) => (
                    <div key={item.id} className="cve-row">
                      <strong>{item.cve_id}</strong>
                      <span className={item.kev ? "chip critical" : severityClass(item.cvss_severity)}>{item.kev ? "KEV" : item.cvss_severity || "-"}</span>
                      <span>{epss(item.epss_score)}</span>
                      <span>{vulnerabilitySummary(item)}</span>
                    </div>
                  ))}
                  {!state.vulnerabilities.length && <div className="empty block">No vulnerability data</div>}
                </div>
              </article>

              <article className="panel">
                <div className="panel-header">
                  <h2>Trend Brief</h2>
                  <a className="link-button" href="#/security-news">
                    Trend 게시글 전체 보기
                  </a>
                </div>
                <div className="brief">
                  {(state.trends?.themes || []).slice(0, 2).map((theme) => (
                    <article key={theme}>
                      <strong>Trend</strong>
                      <p>{theme}</p>
                    </article>
                  ))}
                  {(state.trends?.news || []).slice(0, 2).map((item) => (
                    <article key={item.url}>
                      <strong>{item.title}</strong>
                      <p>{item.summary}</p>
                    </article>
                  ))}
                  {!state.trends?.themes.length && !state.trends?.news.length && <div className="empty block">No trend summary</div>}
                </div>
              </article>
            </section>
          </>
        )}

        {route === "cves" && (
          <section>
            <PageTitle
              title="CVE"
              description="수집한 CVE, KEV, EPSS, 영향 단말 후보를 게시글 형태로 확인합니다."
              badge={`${state.summary?.vulnerability_count ?? state.vulnerabilities.length} CVEs`}
              tone="critical"
            >
              <Pager
                page={cvePage}
                pageSize={cvePageSize}
                total={state.summary?.vulnerability_count ?? state.vulnerabilities.length}
                onPageChange={setCvePage}
                onPageSizeChange={(value) => {
                  setCvePageSize(value);
                  setCvePage(1);
                }}
              />
            </PageTitle>
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
                    <span className={item.kev ? "pill critical" : severityClass(item.cvss_severity)}>{item.kev ? "KEV" : item.cvss_severity || "CVE"}</span>
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
                      <h4>한글 요약</h4>
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
            <PageTitle
              title="Security News"
              description="수집한 보안 뉴스, 사건사고, KISA 공지, 해외 뉴스를 한글 요약과 함께 제공합니다."
              badge={`${state.summary?.article_count ?? state.articles.length} news`}
            >
              <Pager
                page={newsPage}
                pageSize={newsPageSize}
                total={state.summary?.article_count ?? state.articles.length}
                onPageChange={setNewsPage}
                onPageSizeChange={(value) => {
                  setNewsPageSize(value);
                  setNewsPage(1);
                }}
              />
            </PageTitle>
            <div className="page-grid">
              {state.articles.map((article) => (
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
                    <span className="pill neutral">{article.source?.kind || "news"}</span>
                  </header>
                  <div className="body">
                    <article className="post">
                      <h4>한글 요약</h4>
                      <p>{article.summary || article.raw_excerpt || "요약 생성 전입니다. 원문 링크 확인이 필요합니다."}</p>
                      <div className="meta">
                        <span>원문 링크</span>
                        <span>RSS</span>
                      </div>
                    </article>
                  </div>
                </article>
              ))}
              {!state.articles.length && <div className="empty block">No news data</div>}
            </div>
          </section>
        )}

        {route === "tanium-inventory" && (
          <section>
            <PageTitle title="Tanium Inventory" description="Tanium API로 수집한 단말, OS, IP, 설치 소프트웨어, CVE 매칭 근거를 제공합니다." badge={`${state.summary?.endpoint_count ?? 0} endpoints`} tone="ok" />
            <article className="page-card">
              <header>
                <div>
                  <h3>수집 단말 목록</h3>
                  <p>현재 화면은 CVE 영향 분석 결과에 포함된 단말 정보를 우선 표시합니다.</p>
                </div>
                <span className={state.tanium?.configured ? "pill ok" : "pill neutral"}>{state.tanium?.configured ? "Online" : "Missing"}</span>
              </header>
              <div className="table">
                <div className="inventory-row header">
                  <span>Endpoint</span>
                  <span>IP</span>
                  <span>OS / Evidence</span>
                  <span>Risk</span>
                </div>
                {endpointRows.map(({ endpoint, detection }) => (
                  <div key={endpoint.id} className="inventory-row">
                    <strong>{endpoint.hostname || endpoint.tanium_endpoint_id || "Unknown"}</strong>
                    <span>{endpoint.ip_address || "-"}</span>
                    <span>
                      {endpoint.os_name || "-"} · {detection.vulnerability.cve_id} · {detection.match_reason}
                    </span>
                    <span className={detection.confidence >= 0.8 ? "chip critical" : "chip high"}>{Math.round(detection.confidence * 100)}%</span>
                  </div>
                ))}
                {!endpointRows.length && <div className="empty block">No inventory detections</div>}
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
            <PageTitle title="Settings" description="수집 주기, LLM 모델, Tanium 연결 설정을 관리하는 영역입니다." />
            <div className="toolbar">
              <button title="Refresh dashboard" onClick={() => void load()} disabled={state.loading}>
                <RefreshCw size={16} />
                <span>Refresh</span>
              </button>
              <button title="Collect NVD CVEs" onClick={() => void runAction("NVD", api.collectNvd)} disabled={Boolean(state.action)}>
                <DatabaseZap size={16} />
                <span>NVD</span>
              </button>
              <button title="Collect CISA KEV" onClick={() => void runAction("CISA KEV", api.collectCisaKev)} disabled={Boolean(state.action)}>
                <AlertTriangle size={16} />
                <span>KEV</span>
              </button>
              <button title="Update EPSS scores" onClick={() => void runAction("EPSS", api.collectEpss)} disabled={Boolean(state.action)}>
                <Activity size={16} />
                <span>EPSS</span>
              </button>
              <button title="Collect security news" onClick={() => void runAction("News", api.collectNews)} disabled={Boolean(state.action)}>
                <FileText size={16} />
                <span>News</span>
              </button>
              <button title="Generate Korean news and CVE summaries" onClick={() => void runAction("Summaries", api.summarizeAll)} disabled={Boolean(state.action)}>
                <FileText size={16} />
                <span>Summaries</span>
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
          </section>
        )}
      </section>
    </main>
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
