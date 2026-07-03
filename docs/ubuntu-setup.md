# Ubuntu 24.04 Setup Guide

Target server:

- 8 vCPU
- 32 GB RAM
- 200 GB disk
- Ubuntu 24.04

This is enough for the Phase 1 MVP: backend, frontend, PostgreSQL/pgvector, collectors, and CPU-based small LLM testing.

## Required Packages

```bash
sudo apt update
sudo apt install -y ca-certificates curl git ufw
```

Install Docker Engine and Docker Compose from Docker's official repository.

## Recommended Firewall

Internal MVP:

```bash
sudo ufw allow 22/tcp
sudo ufw allow 8000/tcp
sudo ufw allow 5173/tcp
sudo ufw enable
```

Production should put HTTPS reverse proxy in front and avoid exposing PostgreSQL externally.

## Project Setup

```bash
git clone <repo-url> securewatch
cd securewatch
cp .env.example .env
```

Set these values in `.env` on the server:

```text
TANIUM_BASE_URL=<internal Tanium URL>
TANIUM_API_TOKEN=<read-only API token>
TANIUM_VERIFY_TLS=false
NVD_API_KEY=<optional but recommended>
```

## Start

```bash
docker compose up --build -d
docker compose ps
```

Open:

- Frontend: `http://<server-ip>:5173`
- Backend API: `http://<server-ip>:8000/docs`

## Disk Notes

The 200 GB disk is acceptable for MVP if:

- Full news article bodies are not stored.
- Docker images and logs are pruned regularly.
- LLM model files are limited to small/quantized models.
- Database backups are rotated.

For longer pilot operation, 500 GB or external backup storage is recommended.

## Tanium Safety

Use a read-only Tanium service account for Phase 1.

Do not enable endpoint control until these exist:

- RBAC separation.
- Approval workflow.
- Dry-run mode.
- Command allowlist.
- Audit log and rollback procedure.
