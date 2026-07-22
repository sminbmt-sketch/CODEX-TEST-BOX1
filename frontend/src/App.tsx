import { type Dispatch, type ReactNode, type SetStateAction, useEffect, useMemo, useState } from "react";
import { CalendarClock, DatabaseZap, ExternalLink, FileText, Mail, Plus, Radar, RefreshCw, Search, Server, Trash2, Wifi } from "lucide-react";
import { api, type Article, type AutomationSettings, type CollectionJobStatus, type DashboardSummary, type DataResetTarget, type Detection, type EmailSettings, type EndpointSnapshot, type InvestigationRun, type LlmProvider, type LlmSettings, type Source, type SummaryLogItem, type TaniumStatus, type TrendReport, type Vulnerability } from "./lib/api";

type Route = "dashboard" | "cves" | "security-news" | "tanium-inventory" | "investigation" | "reports" | "logs" | "settings";
type InvestigationTargetType = "news" | "kisa" | "cve";

type LoadState = {
  summary?: DashboardSummary;
  vulnerabilities: Vulnerability[];
  articles: Article[];
  vulnerabilityTotal: number;
  articleTotal: number;
  inventory: EndpointSnapshot[];
  detections: Detection[];
  trends?: TrendReport;
  summaryLogs: SummaryLogItem[];
  tanium?: TaniumStatus;
  llm?: LlmSettings;
  automation?: AutomationSettings;
  email?: EmailSettings;
  nvdYearJob?: CollectionJobStatus;
  epssJob?: CollectionJobStatus;
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
  summaryLogs: [],
  loading: true,
};

const navItems: { route: Route; label: string }[] = [
  { route: "dashboard", label: "Dashboard" },
  { route: "cves", label: "CVE" },
  { route: "security-news", label: "Security News" },
  { route: "tanium-inventory", label: "Tanium Inventory" },
  { route: "investigation", label: "Investigation" },
  { route: "reports", label: "Reports" },
  { route: "logs", label: "Logs" },
  { route: "settings", label: "Settings" },
];

const pageSizeOptions = [10, 30, 50, 100];
const currentYear = new Date().getFullYear();
const llmDefaults: Record<LlmProvider, { baseUrl: string; model: string }> = {
  disabled: { baseUrl: "", model: "" },
  ollama: { baseUrl: "http://localhost:11434", model: "qwen2.5:1.5b" },
  openai: { baseUrl: "https://api.openai.com/v1", model: "gpt-4o-mini" },
  gemini: { baseUrl: "https://generativelanguage.googleapis.com/v1beta", model: "gemini-3.1-flash-lite" },
  anthropic: { baseUrl: "https://api.anthropic.com/v1", model: "claude-3-5-haiku-latest" },
};

function routeFromHash(): Route {
  const value = window.location.hash.replace(/^#\/?/, "");
  if (value === "cves" || value === "security-news" || value === "tanium-inventory" || value === "investigation" || value === "reports" || value === "logs" || value === "settings") {
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

function asRecordList(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item)) : [];
}

function itemCount(value: unknown) {
  return Array.isArray(value) ? value.length : 0;
}

function displayField(item: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = item[key];
    if (value == null) continue;
    if (Array.isArray(value)) {
      const text = value.filter(Boolean).join(", ");
      if (text) return text;
      continue;
    }
    const text = String(value).trim();
    if (text) return text;
  }
  return "-";
}

function previewItems(value: unknown, limit = 3) {
  return asRecordList(value).slice(0, limit);
}

function processValues(value: unknown) {
  return asRecordList(value).flatMap((item) => {
    const values = item.values;
    if (Array.isArray(values)) return values.map((entry) => String(entry)).filter(Boolean);
    const text = displayField(item, ["name", "process", "command", "column"]);
    return text === "-" ? [] : [text];
  });
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

function asPlainRecord(value: unknown): Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function asStringList(value: unknown): string[] {
  return Array.isArray(value) ? value.map((item) => String(item)).filter(Boolean) : [];
}

function investigationResults(run?: InvestigationRun) {
  return asPlainRecord(run?.results);
}

function investigationPlan(run?: InvestigationRun) {
  return asPlainRecord(investigationResults(run).investigation_plan);
}

function investigationCounts(run?: InvestigationRun) {
  const counts = asPlainRecord(investigationResults(run).summary_counts);
  return {
    confirmed: Number(counts.confirmed || 0),
    potential: Number(counts.potential || 0),
    environment_candidate: Number(counts.environment_candidate || 0),
    insufficient_data: Number(counts.insufficient_data || 0),
    not_affected: Number(counts.not_affected || 0),
    total_endpoints: Number(counts.total_endpoints || 0),
  };
}

function investigationBucket(run: InvestigationRun | undefined, key: "confirmed" | "potential" | "environment_candidates" | "insufficient_data" | "not_affected") {
  return asRecordList(investigationResults(run)[key]);
}

function investigationMeta(run: InvestigationRun | undefined, key: "analysis_mode" | "planner" | "judge" | "tanium_evidence") {
  return investigationResults(run)[key];
}

function investigationModeLabel(run?: InvestigationRun) {
  const mode = String(investigationMeta(run, "analysis_mode") || "rules_fallback");
  if (mode === "llm_planned") return "LLM 계획 + LLM 판정";
  if (mode === "llm_plan_rules_assessment") return "LLM 계획 + 룰 판정";
  return "룰 fallback";
}

function investigationMethodLabel(run: InvestigationRun | undefined, key: "planner" | "judge") {
  const value = asPlainRecord(investigationMeta(run, key));
  const method = value.method ? String(value.method) : "-";
  const error = value.error ? ` · ${String(value.error)}` : "";
  return `${method}${error}`;
}

function investigationEmptyReason(run?: InvestigationRun) {
  const evidence = asPlainRecord(investigationMeta(run, "tanium_evidence"));
  return evidence.empty_match_reason ? String(evidence.empty_match_reason) : "";
}

function evidenceSummary(item: Record<string, unknown>) {
  const evidence = asRecordList(item.evidence);
  if (!evidence.length) return "-";
  return evidence
    .slice(0, 3)
    .map((entry) => {
      const scope = String(entry.scope || "evidence");
      const product = entry.product ? String(entry.product) : "";
      const installed = entry.installed_name ? String(entry.installed_name) : "";
      const version = entry.installed_version ? ` ${String(entry.installed_version)}` : "";
      const keyword = entry.keyword ? String(entry.keyword) : "";
      const service = entry.service_name ? `(${String(entry.service_name)})` : "";
      const status = entry.version_status ? ` · ${String(entry.version_status)}` : "";
      return [scope, product || keyword, installed ? `(${installed}${version})` : service, status].filter(Boolean).join(" ");
    })
    .join(" / ");
}

function endpointValue(item: Record<string, unknown>, key: string) {
  const endpoint = asPlainRecord(item.endpoint);
  return endpoint[key] != null ? String(endpoint[key]) : "-";
}

function classificationLabel(key: string) {
  if (key === "confirmed") return "확정 영향";
  if (key === "potential") return "추가 확인";
  if (key === "environment_candidates") return "환경 후보";
  if (key === "insufficient_data") return "증거 부족";
  if (key === "not_affected") return "영향 없음";
  return key;
}

function classificationPill(key: string) {
  if (key === "confirmed") return "pill critical";
  if (key === "potential") return "pill high";
  if (key === "environment_candidates") return "pill neutral";
  if (key === "insufficient_data") return "pill neutral";
  return "pill ok";
}

function InvestigationAssessmentList({ title, bucketKey, rows }: { title: string; bucketKey: string; rows: Record<string, unknown>[] }) {
  return (
    <article className="assessment-section">
      <header>
        <h4>{title}</h4>
        <span className={classificationPill(bucketKey)}>{rows.length}</span>
      </header>
      <div className="assessment-table">
        <div className="assessment-row header">
          <span>Host</span>
          <span>IP</span>
          <span>OS</span>
          <span>근거</span>
        </div>
        {rows.slice(0, 20).map((item, index) => (
          <div key={`${bucketKey}-${endpointValue(item, "id")}-${index}`} className="assessment-row">
            <strong>{endpointValue(item, "hostname")}</strong>
            <span>{endpointValue(item, "ip_address")}</span>
            <span>{endpointValue(item, "os")}</span>
            <span>{evidenceSummary(item)}</span>
          </div>
        ))}
        {!rows.length && <div className="empty block">해당 결과 없음</div>}
      </div>
    </article>
  );
}

function summaryErrorLabel(error?: string | null) {
  if (error === "json_parse_failed") return "JSON 파싱 실패";
  if (error === "missing_cve_id") return "CVE ID 누락";
  if (error === "not_korean") return "한국어 요약 부족";
  if (error === "llm_exception") return "LLM 호출 실패";
  return error || "사유 미기록";
}

function summaryErrorAction(error?: string | null) {
  if (error === "json_parse_failed") return "max_tokens를 늘리거나 JSON 응답 프롬프트를 더 짧게 조정합니다.";
  if (error === "missing_cve_id") return "CVE 전용 프롬프트를 재시도하거나 백엔드 CVE ID 자동 보정을 적용합니다.";
  if (error === "not_korean") return "한국어 출력 지시를 강화하거나 같은 항목을 재요약합니다.";
  if (error === "llm_exception") return "LLM Provider 연결, quota, timeout, 모델 상태를 확인합니다.";
  return "해당 항목을 개별 재요약하고 필요 시 LLM 설정을 확인합니다.";
}

export default function App() {
  const [state, setState] = useState<LoadState>(emptyState);
  const [route, setRoute] = useState<Route>(() => routeFromHash());
  const [cvePage, setCvePage] = useState(1);
  const [cvePageSize, setCvePageSize] = useState(30);
  const [cveSearch, setCveSearch] = useState("");
  const [cveSort, setCveSort] = useState<"date" | "name">("date");
  const [cveSeverity, setCveSeverity] = useState<"" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW">("");
  const [newsPage, setNewsPage] = useState(1);
  const [newsPageSize, setNewsPageSize] = useState(30);
  const [newsSearch, setNewsSearch] = useState("");
  const [newsSort, setNewsSort] = useState<"date" | "name">("date");
  const [newsCategory, setNewsCategory] = useState<"news" | "kisa">("news");
  const [cveSummaryMode, setCveSummaryMode] = useState(false);
  const [newsSummaryMode, setNewsSummaryMode] = useState(false);
  const [selectedCveIds, setSelectedCveIds] = useState<number[]>([]);
  const [selectedArticleIds, setSelectedArticleIds] = useState<number[]>([]);
  const [investigationTarget, setInvestigationTarget] = useState<{ sourceType: InvestigationTargetType; itemId: number | "" }>({ sourceType: "news", itemId: "" });
  const [investigationItems, setInvestigationItems] = useState<(Article | Vulnerability)[]>([]);
  const [investigationTotal, setInvestigationTotal] = useState(0);
  const [investigationLimit, setInvestigationLimit] = useState(50);
  const [investigationLoading, setInvestigationLoading] = useState(false);
  const [investigationResult, setInvestigationResult] = useState<InvestigationRun | undefined>();
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
  const [automationForm, setAutomationForm] = useState<AutomationSettings>({
    enabled: false,
    cve_enabled: true,
    news_enabled: true,
    frequency: "daily",
    day_of_week: 0,
    day_of_month: 1,
    run_time: "09:00",
    timezone: "Asia/Seoul",
    collection_days: 7,
  });
  const [emailForm, setEmailForm] = useState({
    enabled: false,
    smtp_host: "",
    smtp_port: 587,
    smtp_username: "",
    smtp_password: "",
    clear_password: false,
    sender: "",
    recipients: "",
    use_tls: true,
  });
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
  const [llmModels, setLlmModels] = useState<string[]>([]);
  const [inventoryDetail, setInventoryDetail] = useState<{ endpoint: EndpointSnapshot; type: "software" | "processes" } | null>(null);

  async function load() {
    setState((current) => ({ ...current, loading: true, error: undefined }));
    try {
      const cveParams = { limit: cvePageSize, offset: (cvePage - 1) * cvePageSize, q: cveSearch.trim() || undefined, sort: cveSort, severity: cveSeverity || undefined };
      const newsParams = { limit: newsPageSize, offset: (newsPage - 1) * newsPageSize, q: newsSearch.trim() || undefined, sort: newsSort, category: newsCategory };
      const [summary, vulnerabilities, vulnerabilityTotal, articles, articleTotal, tanium, inventory, detections, trends, llm, automation, email, sources, nvdYearJob, epssJob, summaryLogs] = await Promise.all([
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
        api.automationSettings(),
        api.emailSettings(),
        api.sources(),
        api.nvdYearStatus(),
        api.epssStatus(),
        api.summaryFailureLogs(),
      ]);
      setState({ summary, vulnerabilities, vulnerabilityTotal, articles, articleTotal, tanium, inventory, detections, trends, llm, automation, email, nvdYearJob, epssJob, sources, summaryLogs, loading: false });
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
      setAutomationForm(automation);
      setEmailForm({
        enabled: email.enabled,
        smtp_host: email.smtp_host || "",
        smtp_port: email.smtp_port,
        smtp_username: email.smtp_username || "",
        smtp_password: "",
        clear_password: false,
        sender: email.sender || "",
        recipients: email.recipients || "",
        use_tls: email.use_tls,
      });
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
    setLlmMessage("LLM 연결을 테스트하는 중입니다.");
    try {
      const result = await api.testLlmSettings(llmPayload(llmForm));
      setLlmMessage(`${result.ok ? "연결 성공" : "연결 실패"}: ${result.message}`);
      if (result.ok) {
        setLlmMessage("연결 성공. 모델 목록을 불러오는 중입니다.");
        const modelList = await api.llmModels(llmPayload(llmForm));
        setLlmModels(modelList.models);
        setLlmMessage(`연결 성공. ${modelList.models.length}개 모델을 불러왔습니다.`);
        if (modelList.models.length && !modelList.models.includes(llmForm.model)) {
          setLlmForm((current) => ({ ...current, model: modelList.models[0] }));
        }
      }
      setState((current) => ({ ...current, action: undefined }));
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      setState((current) => ({
        ...current,
        action: undefined,
        error: message,
      }));
      setLlmMessage(`LLM 작업 실패: ${message}`);
    }
  }

  async function loadLlmModels() {
    setState((current) => ({ ...current, action: "Load LLM models", error: undefined }));
    setLlmMessage("모델 목록을 불러오는 중입니다.");
    try {
      const modelList = await api.llmModels(llmPayload(llmForm));
      setLlmModels(modelList.models);
      setState((current) => ({ ...current, action: undefined }));
      setLlmMessage(`${modelList.models.length}개 모델을 불러왔습니다.`);
      if (modelList.models.length && !modelList.models.includes(llmForm.model)) {
        setLlmForm((current) => ({ ...current, model: modelList.models[0] }));
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      setState((current) => ({
        ...current,
        action: undefined,
        error: message,
      }));
      setLlmMessage(`모델 목록 조회 실패: ${message}`);
    }
  }

  async function saveAutomationSettings() {
    await runAction("Save automation", async () => {
      const updated = await api.updateAutomationSettings(automationForm);
      setState((current) => ({ ...current, automation: updated }));
    });
  }

  async function saveEmailSettings() {
    await runAction("Save email", async () => {
      const updated = await api.updateEmailSettings({
        enabled: emailForm.enabled,
        smtp_host: emailForm.smtp_host || null,
        smtp_port: emailForm.smtp_port,
        smtp_username: emailForm.smtp_username || null,
        smtp_password: emailForm.smtp_password || null,
        clear_password: emailForm.clear_password,
        sender: emailForm.sender || null,
        recipients: emailForm.recipients || null,
        use_tls: emailForm.use_tls,
        has_password: false,
      });
      setState((current) => ({ ...current, email: updated }));
      setEmailForm((current) => ({ ...current, smtp_password: "", clear_password: false }));
    });
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

  async function runCveSummariesUpdate() {
    await runAction("CVE summaries", () => api.summarizeVulnerabilities({ days: summaryDays, includeExisting: includeExistingSummaries }));
  }

  async function runNewsSummariesUpdate() {
    await runAction("News summaries", () => api.summarizeArticles({ days: summaryDays, includeExisting: includeExistingSummaries }));
  }

  async function runSelectedInvestigation() {
    if (!investigationTarget.itemId) return;
    setState((current) => ({ ...current, action: "Tanium Investigation", error: undefined }));
    try {
      const run = await api.runInvestigation({
        source_type: investigationTarget.sourceType === "cve" ? "cve" : "news",
        item_id: Number(investigationTarget.itemId),
        refresh_intelligence: true,
      });
      setInvestigationResult(run);
      await load();
    } catch (error) {
      setState((current) => ({
        ...current,
        action: undefined,
        error: error instanceof Error ? error.message : "Unknown error",
      }));
    }
  }

  async function loadInvestigationTargets(type = investigationTarget.sourceType, limit = investigationLimit) {
    if (route !== "investigation") return;
    setInvestigationLoading(true);
    try {
      if (type !== "cve") {
        const params = { limit, offset: 0, sort: "date" as const, category: type === "kisa" ? "kisa" as const : "news" as const };
        const [items, total] = await Promise.all([api.articles(params), api.articleCount(params)]);
        setInvestigationItems(items);
        setInvestigationTotal(total);
      } else {
        const params = { limit, offset: 0, sort: "date" as const };
        const [items, total] = await Promise.all([api.vulnerabilities(params), api.vulnerabilityCount(params)]);
        setInvestigationItems(items);
        setInvestigationTotal(total);
      }
    } catch (error) {
      setState((current) => ({ ...current, error: error instanceof Error ? error.message : "Unknown error" }));
    } finally {
      setInvestigationLoading(false);
    }
  }

  async function runSelectedCveSummaries() {
    await runAction(`Summarize ${selectedCveIds.length} CVEs`, async () => {
      await api.summarizeSelectedVulnerabilities(selectedCveIds);
      setSelectedCveIds([]);
      setCveSummaryMode(false);
    });
  }

  async function runSelectedArticleSummaries() {
    await runAction(`Summarize ${selectedArticleIds.length} news`, async () => {
      await api.summarizeSelectedArticles(selectedArticleIds);
      setSelectedArticleIds([]);
      setNewsSummaryMode(false);
    });
  }

  function toggleSelected(setter: Dispatch<SetStateAction<number[]>>, id: number) {
    setter((current) => (current.includes(id) ? current.filter((value) => value !== id) : [...current, id]));
  }

  function selectVisible(setter: Dispatch<SetStateAction<number[]>>, ids: number[]) {
    setter((current) => Array.from(new Set([...current, ...ids])));
  }

  function clearVisible(setter: Dispatch<SetStateAction<number[]>>, ids: number[]) {
    const visible = new Set(ids);
    setter((current) => current.filter((id) => !visible.has(id)));
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
  }, [cvePage, cvePageSize, cveSearch, cveSort, cveSeverity, newsPage, newsPageSize, newsSearch, newsSort, newsCategory]);

  useEffect(() => {
    void loadInvestigationTargets();
  }, [route, investigationTarget.sourceType, investigationLimit]);

  useEffect(() => {
    setSelectedCveIds([]);
  }, [cvePage, cvePageSize, cveSearch, cveSort, cveSeverity]);

  useEffect(() => {
    setSelectedArticleIds([]);
  }, [newsPage, newsPageSize, newsSearch, newsSort, newsCategory]);

  useEffect(() => {
    const shouldPoll =
      state.nvdYearJob?.status === "queued" ||
      state.nvdYearJob?.status === "running" ||
      state.epssJob?.status === "queued" ||
      state.epssJob?.status === "running";
    if (!shouldPoll) return undefined;
    const timer = window.setInterval(async () => {
      try {
        const [nvdYearJob, epssJob] = await Promise.all([api.nvdYearStatus(), api.epssStatus()]);
        setState((current) => ({ ...current, nvdYearJob, epssJob }));
      } catch {
        window.clearInterval(timer);
      }
    }, 3000);
    return () => window.clearInterval(timer);
  }, [state.nvdYearJob?.status, state.epssJob?.status]);

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
  const visibleCveIds = state.vulnerabilities.map((item) => item.id);
  const visibleArticleIds = state.articles.map((item) => item.id);
  const dashboardCves = (state.summary?.top_risks || []).slice(0, 10);
  const selectedInvestigationTitle =
    investigationTarget.sourceType !== "cve"
      ? (investigationItems.find((item) => item.id === investigationTarget.itemId) as Article | undefined)?.title
      : (investigationItems.find((item) => item.id === investigationTarget.itemId) as Vulnerability | undefined)?.cve_id;

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
              <article className="panel cve-panel">
                <div className="panel-header">
                  <h2>CVE / KEV</h2>
                  <a className="link-button" href="#/cves">
                    CVE / KEV 전체 보기
                  </a>
                </div>
                <div className="table dashboard-cve-table">
                  <div className="cve-row header">
                    <span className="center-cell">CVE</span>
                    <span>KEV/Severity</span>
                    <span className="center-cell">EPSS</span>
                    <span>요약 내용</span>
                  </div>
                  {dashboardCves.map((item) => (
                    <div key={item.id} className="cve-row">
                      <strong className="center-cell cve-id-cell">{item.cve_id}</strong>
                      <span className={item.kev ? "chip critical" : severityClass(item.cvss_severity)} title={item.cvss_severity || undefined}>
                        {item.kev ? "KEV" : severityLabel(item.cvss_severity)}
                      </span>
                      <span className="center-cell epss-cell">{epss(item.epss_score)}</span>
                      <span>{vulnerabilitySummary(item)}</span>
                    </div>
                  ))}
                  {!dashboardCves.length && <div className="empty block">No vulnerability data</div>}
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
              >
                <button type="button" onClick={() => setCveSummaryMode((value) => !value)} disabled={Boolean(state.action)}>
                  Summarize
                </button>
              </PageTitle>
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
                <div className="toolbar-side">
                  <label className="sort-field">
                    위험도
                    <select
                      value={cveSeverity}
                      onChange={(event) => {
                        setCveSeverity(event.target.value as "" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW");
                        setCvePage(1);
                      }}
                    >
                      <option value="">기본</option>
                      <option value="CRITICAL">Critical</option>
                      <option value="HIGH">High</option>
                      <option value="MEDIUM">Medium</option>
                      <option value="LOW">Low</option>
                    </select>
                  </label>
                </div>
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
                <article key={item.id} className={cveSummaryMode ? "page-card selectable-card" : "page-card"}>
                  {cveSummaryMode && (
                    <label className="select-check">
                      <input
                        type="checkbox"
                        checked={selectedCveIds.includes(item.id)}
                        onChange={() => toggleSelected(setSelectedCveIds, item.id)}
                      />
                      선택
                    </label>
                  )}
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
            {cveSummaryMode && (
              <SelectionBar
                selectedCount={selectedCveIds.length}
                visibleCount={visibleCveIds.length}
                onSelectVisible={() => selectVisible(setSelectedCveIds, visibleCveIds)}
                onClearVisible={() => clearVisible(setSelectedCveIds, visibleCveIds)}
                onRun={() => void runSelectedCveSummaries()}
                disabled={Boolean(state.action) || selectedCveIds.length === 0}
              />
            )}
          </section>
        )}

        {route === "security-news" && (
          <section>
            <div className="sticky-list-header">
              <PageTitle
                title="Security News"
                description="수집한 보안 뉴스와 KISA 보안 공지를 분리해서 확인합니다."
                badge={`${state.articleTotal} ${newsCategory === "kisa" ? "KISA notices" : "news"}`}
              >
                <button type="button" onClick={() => setNewsSummaryMode((value) => !value)} disabled={Boolean(state.action)}>
                  Summarize
                </button>
              </PageTitle>
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
                  <article key={article.id} className={newsSummaryMode ? "page-card selectable-card" : "page-card"}>
                    {newsSummaryMode && (
                      <label className="select-check">
                        <input
                          type="checkbox"
                          checked={selectedArticleIds.includes(article.id)}
                          onChange={() => toggleSelected(setSelectedArticleIds, article.id)}
                        />
                        선택
                      </label>
                    )}
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
            {newsSummaryMode && (
              <SelectionBar
                selectedCount={selectedArticleIds.length}
                visibleCount={visibleArticleIds.length}
                onSelectVisible={() => selectVisible(setSelectedArticleIds, visibleArticleIds)}
                onClearVisible={() => clearVisible(setSelectedArticleIds, visibleArticleIds)}
                onRun={() => void runSelectedArticleSummaries()}
                disabled={Boolean(state.action) || selectedArticleIds.length === 0}
              />
            )}
          </section>
        )}

        {route === "tanium-inventory" && (
          <section>
            <PageTitle title="Tanium Inventory" description="Tanium API로 수집한 단말, 설치 프로그램, 실행 프로세스 정보를 제공합니다." badge={`${state.summary?.endpoint_count ?? state.inventory.length} endpoints`} tone="ok" />
            <article className="page-card">
              <header>
                <div>
                  <h3>수집 단말 목록</h3>
                  <p>Host Name, IP, MAC, OS, Platform과 확장 inventory 개수를 표시합니다.</p>
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
                  <span>Inventory</span>
                </div>
                {state.inventory.map((endpoint) => (
                  <article key={endpoint.id} className="inventory-card">
                    <div className="inventory-row">
                      <strong>{endpoint.hostname || endpoint.tanium_endpoint_id || "Unknown"}</strong>
                      <span>{endpoint.ip_address || "-"}</span>
                      <span>{endpoint.mac_address || "-"}</span>
                      <span>{[endpoint.os_name, endpoint.os_version].filter(Boolean).join(" ") || "-"}</span>
                      <span>{endpointPlatform(endpoint)}</span>
                      <span className="inventory-counts">
                        <button type="button" onClick={() => setInventoryDetail({ endpoint, type: "software" })}>Software {itemCount(endpoint.software)}</button>
                        <button type="button" onClick={() => setInventoryDetail({ endpoint, type: "processes" })}>Process {processValues(endpoint.processes).length}</button>
                      </span>
                    </div>
                  </article>
                ))}
                {!state.inventory.length && <div className="empty block">No endpoint inventory</div>}
              </div>
            </article>
          </section>
        )}

        {route === "investigation" && (
          <section>
            <PageTitle title="Investigation" description="원문 링크를 다시 분석해 조사 키워드를 추출하고, Tanium read-only API 기준으로 영향 단말을 확인합니다." badge={`${investigationItems.length} / ${investigationTotal} loaded`} />
            <div className="investigation-layout">
              <article className="page-card investigation-target-card">
                <header>
                  <div>
                    <h3>조사 대상 선택</h3>
                    <p>대상 유형을 선택한 뒤 아래 목록에서 조사할 항목을 고릅니다.</p>
                  </div>
                  <span className="pill neutral">{selectedInvestigationTitle || "미선택"}</span>
                </header>
                <div className="investigation-tabs segmented">
                  <button
                    type="button"
                    className={investigationTarget.sourceType === "news" ? "active" : undefined}
                    onClick={() => {
                      setInvestigationTarget({ sourceType: "news", itemId: "" });
                      setInvestigationLimit(50);
                      setInvestigationResult(undefined);
                    }}
                  >
                    Security News
                  </button>
                  <button
                    type="button"
                    className={investigationTarget.sourceType === "kisa" ? "active" : undefined}
                    onClick={() => {
                      setInvestigationTarget({ sourceType: "kisa", itemId: "" });
                      setInvestigationLimit(50);
                      setInvestigationResult(undefined);
                    }}
                  >
                    KISA 보안공지
                  </button>
                  <button
                    type="button"
                    className={investigationTarget.sourceType === "cve" ? "active" : undefined}
                    onClick={() => {
                      setInvestigationTarget({ sourceType: "cve", itemId: "" });
                      setInvestigationLimit(50);
                      setInvestigationResult(undefined);
                    }}
                  >
                    CVE
                  </button>
                </div>
                <div className="investigation-list" role="list">
                  {investigationItems.map((item) => {
                    const isArticleTarget = investigationTarget.sourceType !== "cve";
                    const article = isArticleTarget ? (item as Article) : undefined;
                    const cve = !isArticleTarget ? (item as Vulnerability) : undefined;
                    const title = article?.title || cve?.cve_id || "Untitled";
                    const subtitle = article
                      ? `${article.source?.name || "Security News"} · ${formatDate(article.published_at)}`
                      : `${cve?.cvss_severity || "N/A"} · ${formatDate(cve?.published_at)}`;
                    const summary = article ? articleDisplay(article).summary : vulnerabilitySummary(cve as Vulnerability);
                    const selectTarget = () => {
                      setInvestigationTarget((current) => ({ ...current, itemId: item.id }));
                      setInvestigationResult(undefined);
                    };
                    return (
                      <article
                        key={`${investigationTarget.sourceType}-${item.id}`}
                        className={investigationTarget.itemId === item.id ? "investigation-item selected" : "investigation-item"}
                        role="button"
                        tabIndex={0}
                        onClick={selectTarget}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            selectTarget();
                          }
                        }}
                      >
                        <span className="investigation-item-title">{title}</span>
                        <span className="investigation-item-meta">{subtitle}</span>
                        <span className="investigation-item-summary">{summary}</span>
                      </article>
                    );
                  })}
                  {investigationLoading && <div className="empty block">조사 대상 목록을 불러오는 중입니다.</div>}
                  {!investigationLoading && !investigationItems.length && <div className="empty block">조사 대상 데이터가 없습니다.</div>}
                </div>
                <div className="investigation-list-footer">
                  <span>{investigationItems.length}개 표시 / 전체 {investigationTotal}개</span>
                  <button
                    type="button"
                    onClick={() => setInvestigationLimit((value) => value + 50)}
                    disabled={investigationLoading || investigationItems.length >= investigationTotal}
                  >
                    더 불러오기
                  </button>
                </div>
                <div className="investigation-actions">
                  <div>
                    <strong>{selectedInvestigationTitle || "조사 대상을 선택하세요"}</strong>
                    <span>조사 실행 시 원문 링크 본문을 다시 가져와 분석합니다.</span>
                  </div>
                  <button type="button" onClick={() => void runSelectedInvestigation()} disabled={Boolean(state.action) || !investigationTarget.itemId}>
                    <Radar size={16} />
                    <span>조사 실행</span>
                  </button>
                </div>
              </article>

              {investigationResult && (
                <article className="page-card investigation-result-card">
                  <header>
                    <div>
                      <h3>조사 결과</h3>
                      <p>{investigationResult.source_title}</p>
                    </div>
                    <span className="pill ok">{investigationResult.status}</span>
                  </header>
                  <div className="investigation-result-body">
                    <div className="investigation-summary-strip">
                      {[
                        ["confirmed", "확정 영향", investigationCounts(investigationResult).confirmed],
                        ["potential", "추가 확인", investigationCounts(investigationResult).potential],
                        ["environment_candidates", "환경 후보", investigationCounts(investigationResult).environment_candidate],
                        ["insufficient_data", "증거 부족", investigationCounts(investigationResult).insufficient_data],
                        ["not_affected", "영향 없음", investigationCounts(investigationResult).not_affected],
                      ].map(([key, label, value]) => (
                        <div key={String(key)} className="result-metric">
                          <span className={classificationPill(String(key))}>{label}</span>
                          <strong>{String(value)}</strong>
                        </div>
                      ))}
                    </div>

                    <article className="investigation-plan">
                      <div>
                        <h4>영향 제품 / 버전 조건</h4>
                        <p>{investigationResult.summary || "조사 결과 요약 없음"}</p>
                        {investigationEmptyReason(investigationResult) && <p className="investigation-empty-reason">{investigationEmptyReason(investigationResult)}</p>}
                        <div className="investigation-methods">
                          <span>{investigationModeLabel(investigationResult)}</span>
                          <span>Planner: {investigationMethodLabel(investigationResult, "planner")}</span>
                          <span>Judge: {investigationMethodLabel(investigationResult, "judge")}</span>
                        </div>
                      </div>
                      <div className="affected-product-list">
                        {asRecordList(investigationPlan(investigationResult).affected_products).slice(0, 8).map((product, index) => (
                          <div key={`${String(product.name)}-${index}`} className="affected-product">
                            <strong>{String(product.name || "-")}</strong>
                            <span>{String(product.platform || "unknown")} · before {asStringList(product.affected_versions).join(", ") || "-"}</span>
                          </div>
                        ))}
                        {!asRecordList(investigationPlan(investigationResult).affected_products).length && <div className="empty block">영향 제품 정보 없음</div>}
                      </div>
                    </article>

                    <div className="assessment-grid">
                      <InvestigationAssessmentList title={classificationLabel("confirmed")} bucketKey="confirmed" rows={investigationBucket(investigationResult, "confirmed")} />
                      <InvestigationAssessmentList title={classificationLabel("potential")} bucketKey="potential" rows={investigationBucket(investigationResult, "potential")} />
                      <InvestigationAssessmentList title={classificationLabel("environment_candidates")} bucketKey="environment_candidates" rows={investigationBucket(investigationResult, "environment_candidates")} />
                      <InvestigationAssessmentList title={classificationLabel("insufficient_data")} bucketKey="insufficient_data" rows={investigationBucket(investigationResult, "insufficient_data")} />
                      <InvestigationAssessmentList title={classificationLabel("not_affected")} bucketKey="not_affected" rows={investigationBucket(investigationResult, "not_affected")} />
                    </div>

                    <details className="investigation-raw">
                      <summary>조사 원본 JSON</summary>
                      <pre className="json-panel compact">{JSON.stringify(investigationResult.results || {}, null, 2)}</pre>
                    </details>
                  </div>
                </article>
              )}
            </div>
          </section>
        )}

        {route === "reports" && (
          <section>
            <PageTitle title="Reports" description="운영 보고서 영역입니다. 이후 CVE 조치 현황과 뉴스 브리핑 내보내기를 연결합니다." />
            <div className="page-card placeholder">Reports page placeholder</div>
          </section>
        )}

        {route === "logs" && (
          <section>
            <PageTitle title="Logs" description="요약 실패와 fallback 사유를 확인하고 재시도 기준을 판단합니다." badge={`${state.summaryLogs.length} fallback logs`} />
            <div className="page-grid">
              <article className="page-card">
                <header>
                  <div>
                    <h3>로그 확인 방법</h3>
                    <p>요약 요청은 성공했지만 LLM 검증을 통과하지 못하면 fallback으로 저장됩니다.</p>
                  </div>
                  <span className="pill neutral">Summary</span>
                </header>
                <div className="body">
                  <article className="post">
                    <h4>운영 기준</h4>
                    <p>
                      `processed`는 처리한 항목 수, `llm_success`는 LLM 요약 저장 성공 수, `fallback`은 원문 일부로 대체된 수입니다.
                      fallback 항목은 아래 사유를 보고 프롬프트, max_tokens, LLM 연결 상태를 조정한 뒤 개별 또는 선택 요약으로 재시도합니다.
                    </p>
                    <div className="meta">
                      <span>json_parse_failed: JSON 출력 깨짐</span>
                      <span>missing_cve_id: CVE ID 미포함</span>
                      <span>not_korean: 한국어 부족</span>
                      <span>llm_exception: 호출 실패</span>
                    </div>
                  </article>
                </div>
              </article>
              {state.summaryLogs.map((item) => (
                <article key={`${item.target}-${item.item_id}`} className="page-card">
                  <header>
                    <div>
                      <h3>
                        {item.source_url ? (
                          <a href={item.source_url} target="_blank" rel="noreferrer">
                            {item.title} <ExternalLink size={13} />
                          </a>
                        ) : (
                          item.title
                        )}
                      </h3>
                      <p>{item.target.toUpperCase()} · {formatDate(item.published_at)}</p>
                    </div>
                    <div className="badge-stack">
                      <span className="pill neutral">{summaryErrorLabel(item.error)}</span>
                      <span className="pill neutral">{item.status || "fallback"}</span>
                    </div>
                  </header>
                  <div className="body">
                    <article className="post">
                      <h4>조치 방향</h4>
                      <p>{summaryErrorAction(item.error)}</p>
                      {item.error_detail && (
                        <div className="source-excerpt">
                          <strong>상세 원인</strong>
                          <p>{item.error_detail}</p>
                        </div>
                      )}
                      {item.summary_preview && (
                        <div className="source-excerpt">
                          <strong>저장된 fallback 내용</strong>
                          <p>{item.summary_preview}</p>
                        </div>
                      )}
                    </article>
                  </div>
                </article>
              ))}
              {!state.summaryLogs.length && <div className="empty block">No summary fallback logs</div>}
            </div>
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
                <button title="Collect new CVEs from NVD CVE-Recent feed, then queue FIRST EPSS automatically" onClick={() => void runLatestCveUpdate()} disabled={Boolean(state.action)}>
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
            <article className="page-card settings-card">
              <header>
                <div>
                  <h3>Automatic Updates</h3>
                  <p>CVE와 Security News를 지정한 날짜와 시간에 자동 수집합니다. CVE 수집 후 EPSS도 자동 갱신됩니다.</p>
                </div>
                <span className={automationForm.enabled ? "pill ok" : "pill neutral"}>{automationForm.enabled ? "Enabled" : "Disabled"}</span>
              </header>
              <div className="settings-form">
                <label className="check-field">
                  <input
                    type="checkbox"
                    checked={automationForm.enabled}
                    onChange={(event) => setAutomationForm((current) => ({ ...current, enabled: event.target.checked }))}
                  />
                  자동 업데이트 사용
                </label>
                <label className="check-field">
                  <input
                    type="checkbox"
                    checked={automationForm.cve_enabled}
                    onChange={(event) => setAutomationForm((current) => ({ ...current, cve_enabled: event.target.checked }))}
                  />
                  CVE 자동 업데이트
                </label>
                <label className="check-field">
                  <input
                    type="checkbox"
                    checked={automationForm.news_enabled}
                    onChange={(event) => setAutomationForm((current) => ({ ...current, news_enabled: event.target.checked }))}
                  />
                  Security News 자동 업데이트
                </label>
                <label>
                  스케줄
                  <select
                    value={automationForm.frequency}
                    onChange={(event) => setAutomationForm((current) => ({ ...current, frequency: event.target.value as AutomationSettings["frequency"] }))}
                  >
                    <option value="daily">매일</option>
                    <option value="weekly">매주</option>
                    <option value="monthly">매월</option>
                  </select>
                </label>
                {automationForm.frequency === "weekly" && (
                  <label>
                    요일
                    <select
                      value={automationForm.day_of_week ?? 0}
                      onChange={(event) => setAutomationForm((current) => ({ ...current, day_of_week: Number(event.target.value) }))}
                    >
                      <option value={0}>월요일</option>
                      <option value={1}>화요일</option>
                      <option value={2}>수요일</option>
                      <option value={3}>목요일</option>
                      <option value={4}>금요일</option>
                      <option value={5}>토요일</option>
                      <option value={6}>일요일</option>
                    </select>
                  </label>
                )}
                {automationForm.frequency === "monthly" && (
                  <label>
                    일자
                    <input
                      type="number"
                      min={1}
                      max={31}
                      value={automationForm.day_of_month ?? 1}
                      onChange={(event) => setAutomationForm((current) => ({ ...current, day_of_month: Number(event.target.value) }))}
                    />
                  </label>
                )}
                <label>
                  실행 시간
                  <input
                    type="time"
                    value={automationForm.run_time}
                    onChange={(event) => setAutomationForm((current) => ({ ...current, run_time: event.target.value }))}
                  />
                </label>
                <label>
                  Timezone
                  <input
                    value={automationForm.timezone}
                    onChange={(event) => setAutomationForm((current) => ({ ...current, timezone: event.target.value }))}
                  />
                </label>
                <label>
                  수집 기간(최근 N일)
                  <input
                    type="number"
                    min={1}
                    max={365}
                    value={automationForm.collection_days}
                    onChange={(event) => setAutomationForm((current) => ({ ...current, collection_days: Number(event.target.value) }))}
                  />
                </label>
                <div className="settings-actions">
                  <button title="Save automatic update schedule" onClick={() => void saveAutomationSettings()} disabled={Boolean(state.action)}>
                    <CalendarClock size={16} />
                    <span>Save Schedule</span>
                  </button>
                </div>
              </div>
              <div className="settings-note">
                <span>Last run: {formatDate(state.automation?.last_run_at)}</span>
                <span>CVE Update 이후 EPSS recent 자동 실행</span>
                <span>News 수집 기간: {automationForm.collection_days} days</span>
              </div>
            </article>
            <article className="page-card settings-card">
              <header>
                <div>
                  <h3>Email Delivery</h3>
                  <p>전송할 정보는 추후 확정합니다. 현재는 SMTP 연결 설정과 수신자 정보만 저장합니다.</p>
                </div>
                <span className={emailForm.enabled ? "pill ok" : "pill neutral"}>{emailForm.enabled ? "Enabled" : "Disabled"}</span>
              </header>
              <div className="settings-form">
                <label className="check-field">
                  <input
                    type="checkbox"
                    checked={emailForm.enabled}
                    onChange={(event) => setEmailForm((current) => ({ ...current, enabled: event.target.checked }))}
                  />
                  이메일 모듈 사용
                </label>
                <label>
                  SMTP Host
                  <input value={emailForm.smtp_host} onChange={(event) => setEmailForm((current) => ({ ...current, smtp_host: event.target.value }))} />
                </label>
                <label>
                  SMTP Port
                  <input type="number" min={1} max={65535} value={emailForm.smtp_port} onChange={(event) => setEmailForm((current) => ({ ...current, smtp_port: Number(event.target.value) }))} />
                </label>
                <label>
                  Username
                  <input value={emailForm.smtp_username} onChange={(event) => setEmailForm((current) => ({ ...current, smtp_username: event.target.value }))} />
                </label>
                <label>
                  Password
                  <input
                    type="password"
                    value={emailForm.smtp_password}
                    placeholder={state.email?.has_password ? "저장된 비밀번호 유지" : "SMTP 비밀번호"}
                    onChange={(event) => setEmailForm((current) => ({ ...current, smtp_password: event.target.value, clear_password: false }))}
                  />
                </label>
                <label>
                  Sender
                  <input value={emailForm.sender} onChange={(event) => setEmailForm((current) => ({ ...current, sender: event.target.value }))} />
                </label>
                <label>
                  Recipients
                  <input value={emailForm.recipients} placeholder="security@example.com, admin@example.com" onChange={(event) => setEmailForm((current) => ({ ...current, recipients: event.target.value }))} />
                </label>
                <label className="check-field">
                  <input
                    type="checkbox"
                    checked={emailForm.use_tls}
                    onChange={(event) => setEmailForm((current) => ({ ...current, use_tls: event.target.checked }))}
                  />
                  TLS 사용
                </label>
                <label className="check-field">
                  <input
                    type="checkbox"
                    checked={emailForm.clear_password}
                    onChange={(event) => setEmailForm((current) => ({ ...current, clear_password: event.target.checked, smtp_password: event.target.checked ? "" : current.smtp_password }))}
                  />
                  저장된 SMTP 비밀번호 삭제
                </label>
                <div className="settings-actions">
                  <button title="Save email delivery settings" onClick={() => void saveEmailSettings()} disabled={Boolean(state.action)}>
                    <Mail size={16} />
                    <span>Save Email</span>
                  </button>
                </div>
              </div>
              <div className="settings-note">
                <span>Password: {state.email?.has_password ? "Stored" : "Not set"}</span>
                <span>Recipients: {emailForm.recipients || "-"}</span>
              </div>
            </article>
            <article className="page-card settings-card">
              <header>
                <div>
                  <h3>EPSS Status</h3>
                  <p>최신 CVE Update 완료 후 FIRST EPSS 점수, percentile, 확인 시각을 자동으로 갱신합니다.</p>
                </div>
                <span className={state.epssJob?.status === "completed" ? "pill ok" : "pill neutral"}>{state.epssJob?.status || "idle"}</span>
              </header>
              <div className="settings-note">
                <span>Trigger: 최신 CVE Update 이후 자동 실행</span>
                <span>Mode: {state.epssJob?.mode || "recent"}</span>
                <span>Retry: {state.epssJob?.retry_days ?? 1} day</span>
                <span>Batch: {state.epssJob?.current_batch ?? 0} / {state.epssJob?.total_batches ?? 0}</span>
                <span>Fetched: {state.epssJob?.fetched ?? 0}</span>
                <span>Updated: {state.epssJob?.created_or_updated ?? 0}</span>
                {state.epssJob?.finished_at && <span>Finished: {formatDate(state.epssJob.finished_at)}</span>}
                {state.epssJob?.error && <strong>{state.epssJob.error}</strong>}
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
                      setLlmModels([]);
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
                  {llmModels.length ? (
                    <select value={llmForm.model} onChange={(event) => setLlmForm((current) => ({ ...current, model: event.target.value }))}>
                      {llmModels.map((model) => (
                        <option key={model} value={model}>
                          {model}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <input value={llmForm.model} placeholder={llmDefaults[llmForm.provider].model} onChange={(event) => setLlmForm((current) => ({ ...current, model: event.target.value }))} />
                  )}
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
                    <span>{state.action === "Test LLM" ? "Testing..." : "Test LLM"}</span>
                  </button>
                  <button title="Load available models from selected LLM provider" onClick={() => void loadLlmModels()} disabled={Boolean(state.action) || llmForm.provider === "disabled"}>
                    <RefreshCw size={16} />
                    <span>{state.action === "Load LLM models" ? "Loading..." : "Load Models"}</span>
                  </button>
                </div>
              </div>
              <div className="settings-note">
                <span>Source: {state.llm?.source || "-"}</span>
                <span>API Key: {state.llm?.has_api_key ? "Stored" : "Not set"}</span>
                <span>Models: {llmModels.length ? `${llmModels.length} loaded` : "Not loaded"}</span>
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
                  <button title="Translate and summarize CVE and Security News for selected period" onClick={() => void runSummariesUpdate()} disabled={Boolean(state.action)}>
                    <FileText size={16} />
                    <span>All Summaries</span>
                  </button>
                  <button title="Translate and summarize CVEs for selected period" onClick={() => void runCveSummariesUpdate()} disabled={Boolean(state.action)}>
                    <FileText size={16} />
                    <span>CVE Summary</span>
                  </button>
                  <button title="Translate and summarize Security News for selected period" onClick={() => void runNewsSummariesUpdate()} disabled={Boolean(state.action)}>
                    <FileText size={16} />
                    <span>News Summary</span>
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
      {inventoryDetail && (
        <InventoryDetailModal
          endpoint={inventoryDetail.endpoint}
          type={inventoryDetail.type}
          onClose={() => setInventoryDetail(null)}
        />
      )}
    </main>
  );
}

function InventoryDetailModal({
  endpoint,
  type,
  onClose,
}: {
  endpoint: EndpointSnapshot;
  type: "software" | "processes";
  onClose: () => void;
}) {
  const title = type === "software" ? "Software" : "Process";
  const hostname = endpoint.hostname || endpoint.tanium_endpoint_id || "Unknown";
  const processes = processValues(endpoint.processes);

  return (
    <div className="modal-backdrop" role="presentation" onClick={onClose}>
      <section className="inventory-modal" role="dialog" aria-modal="true" aria-label={`${hostname} ${title}`} onClick={(event) => event.stopPropagation()}>
        <header>
          <div>
            <h2>{title}</h2>
            <p>{hostname}</p>
          </div>
          <button type="button" onClick={onClose}>Close</button>
        </header>
        <div className="inventory-modal-body">
          {type === "software" && (
            <details open>
              <summary>Installed Software ({itemCount(endpoint.software)})</summary>
              <div className="detail-table software-detail-table">
                <span>Name</span>
                <span>Version</span>
                {asRecordList(endpoint.software).map((item, index) => (
                  <div key={`software-detail-${index}`} className="detail-row">
                    <strong>{displayField(item, ["name"])}</strong>
                    <span>{displayField(item, ["version"])}</span>
                  </div>
                ))}
              </div>
              {!itemCount(endpoint.software) && <p className="muted">수집된 설치 프로그램 없음</p>}
            </details>
          )}
          {type === "processes" && (
            <details open>
              <summary>Running Processes ({processes.length})</summary>
              <div className="detail-list">
                {processes.map((process, index) => (
                  <p key={`process-detail-${index}`}>{process}</p>
                ))}
              </div>
              {!processes.length && <p className="muted">프로세스 센서 결과 없음</p>}
            </details>
          )}
        </div>
      </section>
    </div>
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

function SelectionBar({
  selectedCount,
  visibleCount,
  onSelectVisible,
  onClearVisible,
  onRun,
  disabled,
}: {
  selectedCount: number;
  visibleCount: number;
  onSelectVisible: () => void;
  onClearVisible: () => void;
  onRun: () => void;
  disabled: boolean;
}) {
  return (
    <div className="selection-bar">
      <strong>{selectedCount}개 선택됨</strong>
      <span>현재 화면 {visibleCount}개 기준</span>
      <button type="button" onClick={onSelectVisible} disabled={!visibleCount}>
        전체 선택
      </button>
      <button type="button" onClick={onClearVisible} disabled={!visibleCount}>
        전체 해제
      </button>
      <button type="button" onClick={onRun} disabled={disabled}>
        선택 요약 실행
      </button>
    </div>
  );
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
