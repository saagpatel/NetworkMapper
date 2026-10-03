# NetMapper

Local network discovery and security posture tool. Python FastAPI backend (requires sudo) drives nmap + ARP scanning, stores history in SQLite, classifies devices via rule-based logic, cross-references service versions against a local NIST CVE feed, and serves a built React SPA via Cytoscape.js. Single-user, local service — scan history stays local; scanning and OUI/NVD downloads use the network.

## Stack

- Python 3.11+ / FastAPI 0.141.1+ — serves the API and mounts the built React SPA at `/` when `backend/static/` exists
- python-nmap ≥0.7.1 — programmatic nmap wrapper
- scapy 2.7+ — ARP scanning for fast LAN discovery
- SQLite via Python `sqlite3` stdlib — single-file DB at `netmapper.db` under `NETMAPPER_DATA_DIR` (default: `~/.netmapper/`)
- APScheduler 3.11.3+ — background scheduled scanning
- React 19+ / TypeScript 6.0.3 strict / Cytoscape.js 3.33+ / Vite 8+

## Build / Test / Run

```bash
# Backend (requires sudo for raw sockets)
./scripts/run.sh            # default port 8000
./scripts/run.sh 9000       # custom port; env: NETMAPPER_DATA_DIR=~/.netmapper

# Frontend (dev mode — separate terminal)
(cd frontend && npm run dev)  # http://localhost:5173
(cd frontend && npm run build)  # tsc -b && vite build

# Tests and lint
pytest backend/tests/ -v
ruff check backend/        # optional; Ruff is not in backend/requirements.txt
```

## Conventions

- All nmap and scapy calls route through `backend/scanner/` — never call subprocess directly from route handlers.
- Store scan results and config under `NETMAPPER_DATA_DIR` (default: `~/.netmapper/`).
- Scan gate: manual API and scheduled scans validate the whitelist; the frontend modal confirms manual UI scans only.
- CVE refresh runs as a background job with progress feedback; an existing cached CVE index loads synchronously at startup.
- Quick and Standard scan profiles: restrict to safe nmap flags; `-T5` and `--script vuln` are reserved for Deep profile only.
- React: hooks only (no class components); TypeScript strict mode; no `any` types; interfaces over types for object shapes.
- Python: type hints on all functions; no bare `except`; Pydantic models for all API I/O.
- File naming: `snake_case` Python, `kebab-case` TS files, `PascalCase` React components.
- Scope to phases defined in IMPLEMENTATION-ROADMAP.md — new features belong in a roadmap entry first.

## Key Decisions

| Decision | Choice | Why |
|----------|--------|-----|
| Frontend delivery | FastAPI serves built React SPA on single port | Prod-like from day 1, no CORS complexity |
| CVE data | NVD API 2.0 JSON pages, downloaded on explicit refresh | Cached local matching; rate-limited downloads; no API key required |
| Scan gate | Whitelist validation in API and scheduler; GUI modal for manual UI scans | Scheduled and direct API scans do not require the modal |
| Device classification | Rule-based only (open ports + MAC OUI vendor + hostname) | Deterministic, fast, no API dependency |
| Scheduling | Manual trigger + optional APScheduler cron config | Flexibility without complexity |
| Scan profiles | Three: Quick / Standard / Deep | User selects per scan; sane defaults prevent accidental aggressive scans |

<!-- portfolio-context:start -->
# Portfolio Context

## What This Project Is

NetMapper is a local network discovery and security posture tool. It runs as a Python FastAPI backend (requires sudo) that drives nmap + ARP scanning, stores scan history in SQLite, classifies devices via rule-based logic, cross-references service versions against a local NIST CVE feed, and serves a built React SPA for visualization via Cytoscape.js. Single-user, local service; scan history stays local, while scanning and OUI/NVD downloads use the network.

## Current State

**Phases 0–4 implementation present; roadmap acceptance is incomplete (e.g., changed-device deltas remain empty).**
See IMPLEMENTATION-ROADMAP.md for full phase details and acceptance criteria.

## Stack

- Python: 3.11+
- FastAPI: 0.141.1+ — serves the API and mounts the built React SPA at `/` when `backend/static/` exists
- python-nmap: ≥0.7.1 — programmatic nmap wrapper
- scapy: 2.7+ — ARP scanning for fast LAN discovery
- SQLite: via Python `sqlite3` stdlib — single-file DB at `netmapper.db` under `NETMAPPER_DATA_DIR` (default: `~/.netmapper/`)
- APScheduler: 3.11.3+ — background scheduled scanning
- React: 19+ — frontend SPA
- Cytoscape.js: 3.33+ — network topology graph
- Vite: 8+ — frontend build tool (output served by FastAPI)
- TypeScript: 6.0.3 — strict mode throughout; kept below 6.1 for the lint tooling's peer range

## How To Run

```bash
# Start backend
./scripts/run.sh

# Start frontend (separate terminal, dev mode)
cd frontend && npm run dev
# Open http://localhost:5173
```

## Known Risks

- Store scan results and config under `NETMAPPER_DATA_DIR` (default: `~/.netmapper/`)
- Do not call nmap or scapy directly from FastAPI route handlers — route through `scanner/` module
- Require whitelist validation for manual API and scheduled scans; frontend modal confirmation applies to manual UI scans
- Do not add features not in the current phase of IMPLEMENTATION-ROADMAP.md
- Do not use class components in React — hooks only
- CVE refresh is a background job with progress feedback; cached CVE index loading at startup is synchronous
- Do not use aggressive nmap scan flags (e.g., `-T5`, `--script vuln`) in Quick or Standard profiles

## Next Recommended Move

Use this context plus the README and supporting docs to resume the next active task, then promote the repo beyond minimum-viable by capturing a dedicated handoff, roadmap, or discovery artifact.

<!-- portfolio-context:end -->
