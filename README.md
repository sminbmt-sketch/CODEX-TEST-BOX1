# SecureWatch MVP

Security trend dashboard and Tanium read-only impact analysis MVP.

## Phase 1 Scope

- Web dashboard for security news, recent CVEs, risk priority, and source links.
- Collectors for NVD, CISA KEV, FIRST EPSS, and RSS-style news sources.
- News/advisory inputs include CISA, The Hacker News, BleepingComputer, Boannews, KISA/KrCERT, and Krebs on Security.
- LLM-ready summary layer with source references.
- Tanium Gateway read-only integration for endpoint impact analysis.
- No endpoint control in Phase 1.

## Local Start

```bash
cp .env.example .env
# Fill TANIUM_API_TOKEN only on the deployment host.
docker compose up --build
```

Services:

- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API docs: http://localhost:8000/docs

## Secret Handling

Real API tokens must stay in `.env` or server-side secret storage. Do not put tokens in source files, docs, screenshots, commits, or issue trackers.

## Project Memory

Implementation order and requirement changes are tracked in `docs/project-memory.md`.
