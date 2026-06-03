# NetMapper

Local network discovery and security posture tool. Python FastAPI backend (requires sudo) drives nmap + ARP scanning, stores history in SQLite, classifies devices via rule-based logic, cross-references service versions against a local NIST CVE feed, and serves a built React SPA via Cytoscape.js. Single-user, local-only — no data leaves the machine.

## Stack

- Python 3.11+ / FastAPI 0.111+ — serves both API and built React SPA from `/static`
- python-nmap ≥0.7 — programmatic nmap wrapper
- scapy 2.5+ — ARP scanning for fast LAN discovery
- SQLite via Python `sqlite3` stdlib — single-file DB at `~/.netmapper/netmapper.db`
- APScheduler 3.10+ — background scheduled scanning
- React 19+ / TypeScript 5+ strict / Cytoscape.js 3.33+ / Vite 8+

## Build / Test / Run

```bash
# Backend (requires sudo for raw sockets)
./scripts/run.sh            # default port 8000
./scripts/run.sh 9000       # custom port; env: NETMAPPER_DATA_DIR=~/.netmapper

# Frontend (dev mode — separate terminal)
cd frontend && npm run dev  # http://localhost:5173
cd frontend && npm run build  # tsc -b && vite build

# Tests and lint
pytest backend/tests/ -v
ruff check backend/
```

## Conventions

- All nmap and scapy calls route through `backend/scanner/` — never call subprocess directly from route handlers.
- Store all scan results, credentials, and config under `~/.netmapper/` — no data outside that directory.
- Scan gate: every scan requires whitelist validation AND a frontend modal confirmation before executing.
- CVE data import runs as a background job with progress feedback — never imported synchronously at startup.
- Quick and Standard scan profiles: restrict to safe nmap flags; `-T5` and `--script vuln` are reserved for Deep profile only.
- React: hooks only (no class components); TypeScript strict mode; no `any` types; interfaces over types for object shapes.
- Python: type hints on all functions; no bare `except`; Pydantic models for all API I/O.
- File naming: `snake_case` Python, `kebab-case` TS files, `PascalCase` React components.
- Scope to phases defined in IMPLEMENTATION-ROADMAP.md — new features belong in a roadmap entry first.

## Key Decisions

| Decision | Choice | Why |
|----------|--------|-----|
| Frontend delivery | FastAPI serves built React SPA on single port | Prod-like from day 1, no CORS complexity |
| CVE data | Local NIST NVD JSON feed (~1GB, downloaded on first run) | Offline after init, no rate limits, no API key |
| Scan gate | GUI confirmation modal in React frontend | User must confirm target CIDR before any scan executes |
| Device classification | Rule-based only (port ranges + MAC OUI + service names) | Deterministic, fast, no API dependency |
| Scheduling | Manual trigger + optional APScheduler cron config | Flexibility without complexity |
| Scan profiles | Three: Quick / Standard / Deep | User selects per scan; sane defaults prevent accidental aggressive scans |

<!-- portfolio-context:start -->
# Portfolio Context

## What This Project Is

NetMapper is a local network discovery and security posture tool. It runs as a Python FastAPI backend (requires sudo) that drives nmap + ARP scanning, stores scan history in SQLite, classifies devices via rule-based logic, cross-references service versions against a local NIST CVE feed, and serves a built React SPA for visualization via Cytoscape.js. Single-user, local-only, no data leaves the machine.

## Current State

**Phase 4: Complete (Phases 0–4 shipped)**
See IMPLEMENTATION-ROADMAP.md for full phase details and acceptance criteria.

## Stack

- Python: 3.11+
- FastAPI: 0.111+ — serves both API and built React SPA from `/static`
- python-nmap: ≥0.7 — programmatic nmap wrapper
- scapy: 2.5+ — ARP scanning for fast LAN discovery
- SQLite: via Python `sqlite3` stdlib — single-file DB at `~/.netmapper/netmapper.db`
- APScheduler: 3.10+ — background scheduled scanning
- React: 19+ — frontend SPA
- Cytoscape.js: 3.33+ — network topology graph
- Vite: 8+ — frontend build tool (output served by FastAPI)
- TypeScript: 5+ — strict mode throughout

## How To Run

```bash
# Start backend
./scripts/run.sh

# Start frontend (separate terminal, dev mode)
cd frontend && npm run dev
# Open http://localhost:5173
```

## Known Risks

- Do not store any scan results, credentials, or config outside `~/.netmapper/` — all data stays local
- Do not call nmap or scapy directly from FastAPI route handlers — route through `scanner/` module
- Do not run any scan without whitelist validation AND frontend modal confirmation
- Do not add features not in the current phase of IMPLEMENTATION-ROADMAP.md
- Do not use class components in React — hooks only
- Do not import CVE data synchronously at startup — it must be a background job with progress feedback
- Do not use aggressive nmap scan flags (e.g., `-T5`, `--script vuln`) in Quick or Standard profiles

## Next Recommended Move

Use this context plus the README and supporting docs to resume the next active task, then promote the repo beyond minimum-viable by capturing a dedicated handoff, roadmap, or discovery artifact.

<!-- portfolio-context:end -->
