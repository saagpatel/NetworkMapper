# NetMapper

## Overview
NetMapper is a local network discovery and security posture tool. It runs as a Python FastAPI backend (requires sudo) that drives nmap + ARP scanning, stores scan history in SQLite, classifies devices via rule-based logic, cross-references service versions against a local NIST CVE feed, and serves a built React SPA for visualization via Cytoscape.js. Single-user, local-only, no data leaves the machine.

## Tech Stack
- Python: 3.11+
- FastAPI: 0.111+ — serves both API and built React SPA from `/static`
- python-nmap: 1.6+ — programmatic nmap wrapper
- scapy: 2.5+ — ARP scanning for fast LAN discovery
- SQLite: via Python `sqlite3` stdlib — single-file DB at `~/.netmapper/netmapper.db`
- APScheduler: 3.10+ — background scheduled scanning
- React: 18+ — frontend SPA
- Cytoscape.js: 3.28+ — network topology graph
- Vite: 5+ — frontend build tool (output served by FastAPI)
- TypeScript: 5+ — strict mode throughout

## Development Conventions
- Python: type hints on all functions, no bare `except`, Pydantic models for all API I/O
- TypeScript: strict mode, no `any` types, interfaces over types for object shapes
- File naming: `snake_case` for Python, `kebab-case` for TS files, `PascalCase` for React components
- All nmap and scapy calls go through `src/scanner/` — never call subprocess directly from routes
- Git commits: conventional commits — feat:, fix:, chore:, docs:
- Never run scans without a confirmed target in the whitelist AND a frontend modal confirmation

## Current Phase
**Phase 0: Foundation**
See IMPLEMENTATION-ROADMAP.md for full phase details and acceptance criteria.

## Key Decisions
| Decision | Choice | Why |
|----------|--------|-----|
| Frontend delivery | FastAPI serves built React SPA on single port | Prod-like from day 1, no CORS complexity |
| CVE data | Local NIST NVD JSON feed (~1GB, downloaded on first run) | Offline after init, no rate limits, no API key |
| Scan gate | GUI confirmation modal in React frontend | User must confirm target CIDR before any scan executes |
| Device classification | Rule-based only (port ranges + MAC OUI + service names) | Deterministic, fast, no API dependency |
| Scheduling | Manual trigger + optional APScheduler cron config | Flexibility without complexity |
| Scan profiles | Three: Quick / Standard / Deep | User selects per scan; sane defaults prevent accidental aggressive scans |

## Do NOT
- Do not store any scan results, credentials, or config outside `~/.netmapper/` — all data stays local
- Do not call nmap or scapy directly from FastAPI route handlers — route through `scanner/` module
- Do not run any scan without whitelist validation AND frontend modal confirmation
- Do not add features not in the current phase of IMPLEMENTATION-ROADMAP.md
- Do not use class components in React — hooks only
- Do not import CVE data synchronously at startup — it must be a background job with progress feedback
- Do not use aggressive nmap scan flags (e.g., `-T5`, `--script vuln`) in Quick or Standard profiles

<!-- portfolio-context:start -->
# Portfolio Context

## What This Project Is

NetMapper is a local network discovery and security posture tool. It runs as a Python FastAPI backend (requires sudo) that drives nmap + ARP scanning, stores scan history in SQLite, classifies devices via rule-based logic, cross-references service versions against a local NIST CVE feed, and serves a built React SPA for visualization via Cytoscape.js. Single-user, local-only, no data leaves the machine.

## Current State

**Phase 0: Foundation**
See IMPLEMENTATION-ROADMAP.md for full phase details and acceptance criteria.

## Stack

- Python: 3.11+
- FastAPI: 0.111+ — serves both API and built React SPA from `/static`
- python-nmap: 1.6+ — programmatic nmap wrapper
- scapy: 2.5+ — ARP scanning for fast LAN discovery
- SQLite: via Python `sqlite3` stdlib — single-file DB at `~/.netmapper/netmapper.db`
- APScheduler: 3.10+ — background scheduled scanning
- React: 18+ — frontend SPA
- Cytoscape.js: 3.28+ — network topology graph
- Vite: 5+ — frontend build tool (output served by FastAPI)
- TypeScript: 5+ — strict mode throughout

## How To Run

```bash
# Start backend
cd backend && sudo python main.py

# Start frontend (separate terminal)
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
