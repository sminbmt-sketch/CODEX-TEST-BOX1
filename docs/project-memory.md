# SecureWatch MVP Project Memory

Last updated: 2026-07-03

## Fixed Rules

- Keep the agreed implementation order and feature scope visible in this file.
- When the user changes requirements, update this file before implementing the change.
- Do not store real API tokens in source code, documentation, commits, or sample files.
- Treat Tanium endpoint control as a later phase. Phase 1 is read-only detection and analysis.

## Phase 1 Goal

Build a Web + Dashboard system that collects security news and vulnerability data, summarizes recent issues, and analyzes whether internal endpoints are affected through Tanium read-only APIs.

## Phase 1 Feature Scope

1. Web + Dashboard
   - Fast access to current security issues.
   - Summary cards, issue lists, CVE detail, source links, and Tanium impact views.
2. Security trends
   - Collect and normalize security news and vulnerability information.
   - Keep original links for every summarized item.
   - Avoid storing full copyrighted news articles by default.
3. Latest issue analysis
   - Match CVE/vendor/product/version data with internal endpoint inventory.
   - Use Tanium API for read-only endpoint discovery and analysis.
4. LLM support
   - Summarize only from collected evidence.
   - Always expose source URLs and CVE references.
   - Start with CPU-friendly local models or an OpenAI-compatible local endpoint.
5. Business-readiness
   - Prefer permissive licenses: MIT, Apache-2.0, BSD.
   - Avoid GPL/AGPL/SSPL/RSAL/Commons Clause dependencies unless explicitly approved.

## Implementation Order

1. Server and project base
   - Docker Compose, FastAPI backend, React dashboard, PostgreSQL/pgvector.
2. Database schema
   - Sources, articles, vulnerabilities, references, endpoint snapshots, detections, audit logs.
3. Vulnerability collectors
   - NVD CVE API, CISA KEV, FIRST EPSS.
4. News collectors
   - RSS/API-based metadata ingestion with source links.
5. Dashboard
   - Latest issues, risk ranking, filters, and detail pages.
6. LLM summary/RAG
   - Summaries with citations and source references.
7. Tanium read-only integration
   - Gateway GraphQL first, REST only where Gateway lacks capability.
8. Impact analysis
   - Map latest CVEs/issues to endpoint OS/software/version data.
9. Operations
   - Auth/RBAC, audit logs, backup, scheduled jobs, deployment hardening.

## Current Environment

- Target server: Ubuntu 24.04, 8 vCPU, 32 GB RAM, 200 GB disk.
- Suitable for Phase 1 MVP, PostgreSQL, workers, dashboard, and small CPU-based local LLM.
- Not suitable for practical Qwen3-32B/Mistral Small 24B serving without GPU.

## Tanium Integration Notes

- Tanium URL was provided by the user and must be configured through environment variables.
- API token was provided by the user and must not be written to source files.
- Gateway external root endpoint from the provided Gateway guide:
  `https://<server>/plugin/products/gateway/graphql`
- Phase 1 uses read-only queries only.

## Structured Intelligence Model

- Security News and CVE records should remain source documents, not catch-all IOC containers.
- Future object extraction should separate:
  - `content`: source type (`news` or `cve`), title, risk, summary/body, source URL, publication time.
  - `entities`: semantic objects such as attacker, victim sector, vendor, software, version, vulnerability name, and CVE IDs.
  - `iocs`: detection indicators such as IP, domain, URL, hash, file, process, and command line.
  - `inventory`: internal Tanium endpoint assets and software inventory.
  - `detections`: matching results between CVE/entity/IOC objects and internal inventory or endpoint evidence.
- IP, domain, hash, file, process, and command line values should not be modeled as default CVE/News fields. They should be extracted into IOC records only when the source actually contains them.
- CVE-focused extraction should prioritize CVE ID, affected vendor/product/software/version, CVSS/EPSS/KEV, CPE/CWE/reference data, and matching hints for Tanium inventory.
- News-focused extraction should prioritize threat category, attacker, victim sector, affected software, mentioned CVEs, and optional IOC records.
- Extracted objects should preserve source linkage and extraction confidence so reports, Tanium queries, IOC exports, and future STIX/TAXII/Sigma/YARA-style integrations can reuse the same normalized data.

## Change Log

- 2026-07-03: Initial MVP scope, implementation order, environment assessment, and Tanium safety rules recorded.
- 2026-07-03: Created Phase 1 project skeleton with FastAPI backend, React dashboard, Docker Compose, PostgreSQL/pgvector setup, collector service stubs, LLM summary adapter, and read-only Tanium Gateway client.
- 2026-07-03: Fixed NVD reference parsing for NVD 2.0 list-shaped `references`. Added optional `BACKEND_DNS` startup override for Podman environments where container DNS fails.
- 2026-07-03: Deployment note added that backend `CORS_ORIGINS` must include the deployed dashboard origin, such as `http://10.10.10.63:5173`.
- 2026-07-03: Added Korean and external news/advisory sources: Boannews security news and incident RSS, KISA security info RSS, KISA vulnerability notice RSS, KISA security/vulnerability list pages, and Krebs on Security RSS.
- 2026-07-03: Added Tanium read-only endpoint inventory sync, basic CVE impact analysis against installed applications, detection listing API, and dashboard controls for endpoint sync/impact analysis.
- 2026-07-03: Next impact-analysis hardening step is NVD CPE/version-range extraction and version-aware endpoint matching before moving to LLM summaries.
- 2026-07-03: Added LLM-ready article summarization API with deterministic fallback summaries and a dashboard Trend Brief panel with source-linked news and priority CVE summaries.
- 2026-07-03: Installed Ollama on the Ubuntu server. `qwen3:4b` was too slow on CPU-only, so `qwen2.5:1.5b` is the active local LLM for first-pass Korean security summaries.
- 2026-07-03: Extended local LLM summaries to CVE data. Dashboard summaries now generate Korean news and vulnerability summaries together and avoid displaying raw English descriptions as fallback summary text.
- 2026-07-06: Confirmed the A operations-console UI direction and applied it to the React app as a dark, hash-routed dashboard with separate CVE, Security News, Tanium Inventory, Reports, and Settings views.
- 2026-07-06: Added offset-based pagination to CVE and Security News list APIs. The React CVE and Security News pages now support 10/30/50/100 item page sizes with previous/next navigation while Dashboard keeps summary counts.
- 2026-07-06: Removed the frontend `limit=2` cap from full summaries. `/api/summaries/all` now accepts an optional limit and runs without a limit when omitted, prioritizing rows without summaries first.
- 2026-07-06: Changed Korean summary generation policy to process only items from the last 7 days. News uses `published_at` with `created_at` fallback when publication date is missing; CVEs use NVD `published_at`. LLM prompt now translates English source text into Korean before summarizing.
- 2026-07-06: Dashboard High Priority CVE / KEV now prioritizes latest CVEs first. Trend Brief shows one trend theme. CVE and Security News list pages now support date/name sorting and keyword search with filtered result counts.
- 2026-07-06: Added Settings-based LLM provider switching. The app can use local Ollama or external OpenAI/ChatGPT, Gemini, and Claude/Anthropic APIs for Korean translation summaries when local CPU LLM performance is insufficient. API keys are stored outside source code and masked in the UI.
- 2026-07-06: Updated Gemini default model from deprecated `gemini-1.5-flash` to current `gemini-3.5-flash` and added LLM provider error sanitization so API keys are not echoed in test failures.
- 2026-07-06: Changed summary display policy. LLM summaries now translate English into Korean and store a 1-5 line Korean summary. UI labels changed from "한글 요약" to "요약 내용". If LLM summarization is not run or fails, the app shows only the top portion of the collected original excerpt/description instead of generated fallback wording.
- 2026-07-06: Settings page updates: NVD, KEV, and EPSS actions are combined into "CVE Update"; Summaries is a separate section with a configurable recent-day window and an option to include existing summaries. New summary runs write `summary_status`; by default, only rows marked as successful LLM summaries are skipped so failed/fallback items can be retried.
- 2026-07-06: Gemini LLM default changed to `gemini-3.1-flash-lite` for lower-latency, cost-sensitive summary work.
- 2026-07-06: Tanium Inventory now defaults to the full collected endpoint inventory instead of detection-only endpoints, showing Host Name, IP, MAC, Operating System, and Platform.
- 2026-07-06: Security News page now separates general News and KISA security notices. Settings now includes editable source-link sections for CVE Update sources and News sources; deleting a source disables it so collectors skip it without recreating it.
- 2026-07-07: Settings source sections now support adding new CVE Update and News source links. Dashboard High Priority CVE / KEV severity chips now use compact normalized labels and fixed chip sizing to avoid distorted badges when source severity text is long.
- 2026-07-07: Dashboard renamed the CVE panel to "last CVE / KEV", centers the CVE and EPSS columns, and replaces Trend Brief with a recent Security News summary panel. Security News article summaries now render separated Title and Body rows while hiding legacy LLM markers such as `[번역]`, `**제목`, and `**본문`.
- 2026-07-07: Dashboard CVE panel label changed back to "CVE / KEV" with centered body cells for CVE and EPSS. Security News summary display now also removes plain `번역:` prefixes. Settings now includes a Data Management section with confirmed deletion actions for all collected data, CVE data, or Security News data while preserving settings and source links.
- 2026-07-07: Data Management now also supports deleting only Tanium Inventory data; related detections are deleted first to avoid endpoint reference conflicts. Dashboard CVE and EPSS body cells use flex/grid centering to keep values centered in their columns.
- 2026-07-07: Settings top action bar now includes a Summarize button that runs summaries using the configured recent-day window and existing-summary option. CVE and Security News list header/filter areas are sticky during page scroll; Security News keeps the News/KISA segmented selector in the sticky region.
- 2026-07-07: Confirmed structured intelligence direction: keep CVE/News as source documents, extract semantic entities separately, and manage IP/domain/hash/file/process/commandline as IOC objects only when present in source content.
- 2026-07-07: Security News cards now prioritize LLM summary text and move source excerpt text into a separate "원문 일부" area. Embedded `[요약]` content is split for display and leading duplicated title lines are removed from excerpts.
- 2026-07-07: Security News display parser now treats `[보안 요약]`, `[보안요약]`, and `[Security Summary]` as summary markers. Short lead text that is already covered by the summary can be hidden from the source excerpt area to avoid duplicate-looking cards.
- 2026-07-07: Summary generation now uses stricter no-label prompt rules and backend canonicalization before storing LLM summaries. Variants such as `[보안 이슈 요약]`, `요약:`, and `보안 요약:` are removed at storage/display time instead of adding one-off UI exceptions.
- 2026-07-07: LLM summary prompts now request the agreed structured JSON shape (`content`, `entities`, `iocs`) and extract `content.summary` for the current summary field. Article and CVE APIs expose `summary_status`; CVE and Security News cards show LLM/Fallback/No LLM badges.
- 2026-07-07: Added NVD JSON 2.0 yearly feed support. Settings includes an `NVD JSON Feeds` source with `https://nvd.nist.gov/vuln/data-feeds#divJson20Feeds`, plus an `NVD Year Feed` control that imports `nvdcve-2.0-{year}.json.gz` for years 2002 through the current year. Existing recent CVE Update still uses the NVD CVE API.
- 2026-07-07: Settings top title/action area is sticky during scroll. NVD Year Feed now supports a minimum and maximum year range; backend accepts `start_year` and `end_year` and imports each yearly feed in the selected range.
- 2026-07-07: NVD Year Feed import now runs as a backend background job instead of a blocking HTTP request. The previous synchronous import could appear to do nothing for large ranges like 2025-2026 because the yearly feeds download/parse/upsert slowly and only commit after the request completes. Settings displays job status, current year, fetched count, updated count, and error details via `/api/collect/nvd/year/status`.
- 2026-07-08: Settings CVE collection is split into `NVD Year Feed` for full yearly JSON feed imports and `최신 CVE Update` for the NVD `nvdcve-2.0-recent.json.gz` feed. The latest CVE update skips CVE IDs that already exist in the database, so it acts as a lightweight incremental collector instead of reprocessing duplicates.
- 2026-07-08: Settings source management no longer exposes CVE/NVD source cards; only `News Sources` is shown for editable source links. Deleting a source now removes the source row instead of disabling it, clears existing articles' `source_id`, and records a deletion audit entry so default news sources are not recreated on the next `/settings/sources` load.
- 2026-07-08: KISA Security Notices HTML collection skips pinned notice rows where the table number cell is `<td class="num">공지</td>`, so fixed announcements are not imported as normal news/advisory articles.
- 2026-07-08: KISA board HTML collection is scoped to the content between `<!-- board list start -->` and `<!-- board list end //-->`. For `krcert.or.kr/kr/bbs/list.do`, collection follows `pageIndex` pagination and stops once board post dates are older than the configured recent-day window. Settings > News Sources includes a recent-day input, defaulting to 7 days, and the News action passes it as `/api/collect/news?days=N`.
- 2026-07-08: KISA Security Notices source URLs may be stored as the shortened `https://krcert.or.kr/kr/bbs/list.do`; the collector now adds `menuNo=205020` and `bbsId=B0000133` automatically before adding `pageIndex`, so the Security News > KISA tab receives the intended board rows.
- 2026-07-08: LLM CVE summary validation treats responses that start with JSON syntax but fail JSON extraction as unusable. This prevents truncated provider responses such as an incomplete `{"content": ...` object from being marked `summary_status='llm'` and displayed as JSON text.
- 2026-07-08: Dashboard CVE/KEV and Security News panels render more rows with internal scroll areas. CVE list keeps the existing date/name sort and has a separate `위험도` Severity filter with `기본`, `Critical`, `High`, `Medium`, and `Low` options. CVE and Security News pages include an explicit Summarize mode; clicking Summarize reveals per-card checkboxes and a bottom selection bar for visible-page select/clear and selected-ID summarization. Cards do not reserve checkbox space until Summarize mode is enabled.
- 2026-07-08: FIRST EPSS updates now use a background batch job instead of only updating the first limited CVE rows synchronously. The job supports `missing`, `recent`, `stale`, and `all` modes, batches CVE IDs for FIRST API calls, stores EPSS score, percentile, score date, and checked date, and exposes progress through `/api/collect/epss/status`. CVEs that FIRST has no score for are marked checked and skipped until the configured retry window expires.
- 2026-07-08: Settings no longer requires users to run CVE Update and EPSS Update separately. `최신 CVE Update` collects the NVD CVE Recent feed first, then automatically queues a FIRST EPSS background job in `recent` mode for CVEs published in the last 30 days. The Settings EPSS area is a status panel only.
- 2026-07-08: Settings now includes Automatic Updates for CVE and Security News collection. The schedule supports daily, weekly, and monthly execution with configurable time, timezone, and recent-day collection window. Scheduled CVE updates also refresh EPSS for the configured recent window. Settings also includes an Email Delivery module for storing SMTP host, port, TLS, sender, recipients, and masked password; report content and actual notification triggers remain a later decision.
- 2026-07-09: LLM Settings now supports remote Ollama hosts using the normal Ollama root URL such as `http://10.10.10.29:11434`; the backend automatically uses `/v1` for chat completions and `/api/tags` for model discovery. Successful model discovery populates the Settings model selector with completion-capable Ollama models only.
- 2026-07-13: CVE summaries now use CVE-specific prompt rules. The prompt requires `content.summary` to include the exact CVE ID, mentions the configured `max_tokens` budget for compact JSON output, and asks for plain vulnerability content focused on affected component, vulnerability type, impact, and mitigation while avoiding technical interpretation or unsupported exploit speculation.
- 2026-07-13: Selected summary runs now report `processed`, `llm_success`, and `fallback` separately. Fallback rows store `summary_error` with one of `json_parse_failed`, `missing_cve_id`, `not_korean`, or `llm_exception`. The UI includes a Logs menu showing fallback summary logs, failure reason labels, stored fallback previews, and suggested retry/setting checks.
- 2026-07-13: Summary fallback logging now stores `summary_error_detail` for root-cause analysis. LLM exceptions record provider, model, timeout, max token setting, sanitized HTTP status/error text, timeout, or response-parse error details. Logs cards display this detail so operators can distinguish quota/rate-limit, timeout, model/API errors, and response parsing failures.
- 2026-07-16: Tanium Inventory was extended beyond endpoint basics. Endpoint snapshots now store installed software, optional process sensor readings, and service details in JSON fields. The inventory UI shows per-endpoint Software and Process buttons that open scrollable detail dialogs. Process values are split into individual rows. SBOM was removed from the Inventory screen and sync flow because the current Tanium environment does not expose usable SBOM package rows through read-only Gateway queries.
- 2026-07-16: Added the first Investigation workflow. `news_intelligence` stores LLM/rule-extracted endpoint investigation keywords from Security News or CVE items. `investigation_runs` stores Tanium read-only inventory investigation results. The Investigation tab lets operators select a Security News or CVE item, generate intelligence JSON, review Tanium investigation capabilities, and run software/process/OS/IP matching against collected Tanium inventory. LLMs may propose query keywords, but backend validation executes only read-only local inventory matching.
- 2026-07-16: Investigation intelligence extraction now prioritizes re-fetching the original source URL instead of relying on previously generated summaries. If source fetch fails or produces too little text, it falls back to the locally collected excerpt/CVE text and records the fetch error. The Investigation UI was reorganized into top-level Security News/CVE tabs with a scrollable target list, explicit source-link analysis messaging, and a Tanium API definition panel that separates News Intelligence JSON schema from read-only Tanium Gateway operations.
- 2026-07-16: Investigation fallback extraction now captures affected product/version statements such as `Zoom Workplace for Windows before version 7.0.0`. News Intelligence stores `affected_products`, `versions`, software search keywords, OS keywords, and CVEs separately so Tanium investigations can match installed software while preserving affected version context.
- 2026-07-16: Investigation was redesigned from raw keyword matching into an investigation workflow. Backend results now classify endpoints as `confirmed`, `potential`, `environment_candidate`, or `not_affected` using installed software, platform, and version comparison. OS-only matches are no longer treated as impacted endpoints. The UI now shows result counts, affected product/version rules, classified endpoint tables, and keeps raw JSON behind a details panel.
- 2026-07-16: Investigation UI was simplified by removing the Tanium API definition, News Intelligence, and Investigation Runs sections from the main screen. Investigation target lists now load independently from the CVE/Security News pages, default to the latest 50 items, and support a `더 불러오기` control that increases the loaded target list by 50 items at a time.
- 2026-07-20: Investigation target cards now force left-aligned text inside the selectable article buttons. Rules-based investigation extraction now supports fixed-release wording such as `7-Zip version 26.02 was released ... to fix`, converting it into an affected product/version rule (`7-Zip` before `26.02`). Product matching recognizes `p7zip` as a 7-Zip family alias, and news CVE extraction filters out unrelated CVEs unless they appear in product-relevant sentences.
