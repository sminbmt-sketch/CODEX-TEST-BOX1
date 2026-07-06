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
