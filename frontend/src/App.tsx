import { useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, DatabaseZap, ExternalLink, FileText, Radar, RefreshCw, Server, ShieldCheck, Wifi } from "lucide-react";
import { api, type Article, type DashboardSummary, type Detection, type TaniumStatus, type Vulnerability } from "./lib/api";
import { MetricCard } from "./components/MetricCard";

type LoadState = {
  summary?: DashboardSummary;
  vulnerabilities: Vulnerability[];
  articles: Article[];
  detections: Detection[];
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

function formatDate(value?: string | null) {
  if (!value) return "-";
  return new Intl.DateTimeFormat("ko-KR", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function severityClass(severity?: string | null) {
  const value = severity?.toLowerCase();
  if (value === "critical") return "severity critical";
  if (value === "high") return "severity high";
  if (value === "medium") return "severity medium";
  return "severity";
}

export default function App() {
  const [state, setState] = useState<LoadState>(emptyState);

  async function load() {
    setState((current) => ({ ...current, loading: true, error: undefined }));
    try {
      const [summary, vulnerabilities, articles, tanium, detections] = await Promise.all([
        api.summary(),
        api.vulnerabilities(),
        api.articles(),
        api.taniumStatus(),
        api.detections(),
      ]);
      setState({ summary, vulnerabilities, articles, tanium, detections, loading: false });
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
    void load();
  }, []);

  const metrics = useMemo(() => {
    const summary = state.summary;
    return [
      { label: "CVE", value: summary?.vulnerability_count ?? 0, icon: <ShieldCheck size={20} /> },
      { label: "KEV", value: summary?.kev_count ?? 0, icon: <AlertTriangle size={20} />, tone: "danger" as const },
      { label: "News", value: summary?.article_count ?? 0, icon: <FileText size={20} /> },
      { label: "Endpoints", value: summary?.endpoint_count ?? 0, icon: <Server size={20} /> },
      { label: "Detections", value: summary?.detection_count ?? 0, icon: <Activity size={20} />, tone: "warning" as const },
    ];
  }, [state.summary]);

  return (
    <main className="app-shell">
      <header className="topbar">
        <div>
          <h1>SecureWatch</h1>
          <p>Security trend and Tanium impact dashboard</p>
        </div>
        <div className={state.tanium?.configured ? "status ok" : "status warn"}>
          <Wifi size={18} />
          <span>{state.tanium?.configured ? "Tanium configured" : "Tanium not configured"}</span>
        </div>
      </header>

      <section className="toolbar">
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
        <button title="Sync Tanium endpoint inventory" onClick={() => void runAction("Endpoint sync", api.taniumSyncEndpoints)} disabled={Boolean(state.action)}>
          <Server size={16} />
          <span>Endpoints</span>
        </button>
        <button title="Analyze CVE impact against Tanium inventory" onClick={() => void runAction("Impact analysis", api.taniumAnalyzeImpact)} disabled={Boolean(state.action)}>
          <Radar size={16} />
          <span>Analyze</span>
        </button>
      </section>

      {state.error && <div className="notice error">{state.error}</div>}
      {state.action && <div className="notice">Running {state.action}</div>}

      <section className="metrics-grid">
        {metrics.map((metric) => (
          <MetricCard key={metric.label} {...metric} />
        ))}
      </section>

      <section className="content-grid">
        <div className="panel wide">
          <div className="panel-header">
            <h2>High Priority Vulnerabilities</h2>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Severity</th>
                  <th>CVSS</th>
                  <th>EPSS</th>
                  <th>Vendor</th>
                  <th>Published</th>
                </tr>
              </thead>
              <tbody>
                {state.vulnerabilities.map((item) => (
                  <tr key={item.id}>
                    <td>
                      {item.source_url ? (
                        <a href={item.source_url} target="_blank" rel="noreferrer">
                          {item.cve_id}
                          <ExternalLink size={13} />
                        </a>
                      ) : (
                        item.cve_id
                      )}
                      {item.kev && <span className="kev">KEV</span>}
                    </td>
                    <td>
                      <span className={severityClass(item.cvss_severity)}>{item.cvss_severity || "-"}</span>
                    </td>
                    <td>{item.cvss_score ?? "-"}</td>
                    <td>{item.epss_score != null ? `${Math.round(item.epss_score * 1000) / 10}%` : "-"}</td>
                    <td>{[item.vendor, item.product].filter(Boolean).join(" / ") || "-"}</td>
                    <td>{formatDate(item.published_at)}</td>
                  </tr>
                ))}
                {!state.vulnerabilities.length && (
                  <tr>
                    <td colSpan={6} className="empty">
                      No vulnerability data
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>Security News</h2>
          </div>
          <div className="news-list">
            {state.articles.map((article) => (
              <article key={article.id} className="news-item">
                <a href={article.url} target="_blank" rel="noreferrer">
                  {article.title}
                  <ExternalLink size={13} />
                </a>
                <span>{article.source?.name || "Source"} · {formatDate(article.published_at)}</span>
              </article>
            ))}
            {!state.articles.length && <div className="empty block">No news data</div>}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>Tanium</h2>
          </div>
          <dl className="status-list">
            <div>
              <dt>Gateway</dt>
              <dd>{state.tanium?.configured ? "Configured" : "Missing"}</dd>
            </div>
            <div>
              <dt>Endpoint</dt>
              <dd>{state.tanium?.gateway_url || "-"}</dd>
            </div>
          </dl>
          <button className="full" title="Run read-only Gateway test" onClick={() => void runAction("Tanium test", api.taniumTest)} disabled={Boolean(state.action)}>
            <Wifi size={16} />
            <span>Test Gateway</span>
          </button>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>Impact Detections</h2>
          </div>
          <div className="detection-list">
            {state.detections.map((detection) => (
              <article key={detection.id} className="detection-item">
                <div>
                  <strong>{detection.vulnerability.cve_id}</strong>
                  <span className={severityClass(detection.vulnerability.cvss_severity)}>
                    {detection.vulnerability.cvss_severity || "match"}
                  </span>
                </div>
                <p>{detection.endpoint.hostname || detection.endpoint.tanium_endpoint_id || "Unknown endpoint"}</p>
                <span>
                  {detection.endpoint.ip_address || "-"} · {detection.endpoint.os_name || "-"} · {Math.round(detection.confidence * 100)}%
                </span>
              </article>
            ))}
            {!state.detections.length && <div className="empty block">No impact detections</div>}
          </div>
        </div>
      </section>
    </main>
  );
}
