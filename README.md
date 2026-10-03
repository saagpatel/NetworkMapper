# NetMapper

[![Python](https://img.shields.io/badge/python-%233776ab?style=flat-square&logo=python)](#) [![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](#)

> Know every device on your network, what ports it's exposing, and whether any of them are in the CVE database.

NetMapper is a local network scanner with a browser-based UI. Sweep your LAN with ARP, enrich results with nmap port/service/OS detection, classify devices by type, flag open-port risks, and optionally match against the NIST NVD CVE feed — all from a single process on your machine.

## Features

- **ARP sweep** — fast LAN discovery via scapy, no credentials required
- **nmap enrichment** — port scanning, service banners, OS fingerprinting (Quick / Standard / Deep profiles)
- **Device classification** — rule-based categorization using open ports, OUI vendor lookup, and service names
- **Risk engine** — flags high-risk open ports and matches service versions against NVD CVEs
- **Topology graph** — interactive Cytoscape.js network map in the browser
- **Persistent history** — scan results in SQLite at `~/.netmapper/netmapper.db`
- **Scheduled scans** — optional cron expression via the settings UI (APScheduler)

## Quick Start

### Prerequisites
- Python 3.11+
- nmap installed (`brew install nmap` on macOS)
- Node.js 24+ and npm for the locked ESLint/Vite frontend
- Root/sudo access for ARP scanning

### Installation
```bash
git clone https://github.com/saagpatel/NetworkMapper
cd NetworkMapper
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r backend/requirements.txt
(cd frontend && npm ci)
```

### Usage
```bash
# Start backend
./scripts/run.sh

# Start frontend (separate terminal, dev mode)
cd frontend && npm run dev
# Open http://localhost:5173
```

## Verification without a network scan

Run from the repository root with the isolated `.venv` activated:

```sh
PYTHONPATH=backend python -m pytest backend/tests/test_classifier.py -q
PYTHONPATH=backend python -m pytest backend/tests -v
(cd frontend && npm ci)
(cd frontend && npm run lint)
(cd frontend && npm run build)  # tsc -b plus Vite production build
```

The focused classifier tests are synthetic. Broader tests use temporary database
fixtures and mocked scanner/download dependencies; they do not require sudo or a
running backend. CI covers the backend pytest command, not frontend lint/build.
There is no frontend unit/browser test suite configured. `make lint` is an optional
Ruff lane, but Ruff is not installed by `backend/requirements.txt`; provision it
separately before invoking that target. No formatter is configured.

The current frontend lock has TypeScript 7 while `typescript-eslint` declares
TypeScript support below 6.1, so normal `npm ci` can fail with `ERESOLVE`. Treat that
as a dependency compatibility gate: do not bypass peers with `--force` or
`--legacy-peer-deps`, and do not claim frontend checks passed when installation
failed. Dependency repair is separate from these instructions.

For changed UI/scan-report behavior, use a disposable local checkout, temporary
`NETMAPPER_DATA_DIR`, and synthetic or mocked API responses. Inspect the affected
browser states at desktop/mobile widths. `scripts/run.sh`, scanning endpoints,
scheduled scans, OUI/CVE downloads and personal scan history are runtime behavior;
do not start them merely to verify documentation or pure classifier changes.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3.11+, FastAPI, uvicorn |
| Scanning | scapy (ARP), python-nmap |
| Storage | SQLite (stdlib sqlite3) |
| Scheduling | APScheduler 3.x |
| CVE data | NIST NVD JSON feed (optional) |
| Frontend | React 19 + TypeScript + Tailwind CSS 4 + Vite |
| Graph | Cytoscape.js |

## License

MIT
