# NetMapper

[![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Local network scanner with a browser-based UI. Sweep your LAN with ARP, enrich results with nmap port/service/OS detection, classify devices by type, flag open-port risks, and optionally match against the NIST NVD CVE feed — all from a single process running on your machine.

---

## Features

- **ARP sweep** — fast LAN discovery via scapy; no credentials required
- **nmap enrichment** — port scanning, service banners, OS fingerprinting (Quick / Standard / Deep profiles)
- **Device classification** — rule-based categorisation using open ports, OUI vendor lookup, and service names
- **Risk engine** — flags high-risk open ports and matches detected service versions against NVD CVEs
- **Persistent history** — scan results stored in SQLite at `~/.netmapper/netmapper.db`
- **Scheduled scans** — optional cron expression via the settings UI (APScheduler)
- **Topology graph** — interactive Cytoscape.js network map in the browser
- **Timeline view** — track device appearance and disappearance across scans

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11+, FastAPI, uvicorn |
| Scanning | scapy (ARP), python-nmap |
| Storage | SQLite (stdlib `sqlite3`) |
| Scheduling | APScheduler 3.x |
| CVE data | NIST NVD JSON feed (optional, ~1 GB) |
| Frontend | React 19, TypeScript, Tailwind CSS 4, Vite |
| Graph | Cytoscape.js |
| Routing | React Router 7 |

## Prerequisites

- Python 3.11 or newer
- Node.js 18+ and npm (only needed to build the frontend from source)
- nmap installed and on `PATH` (`brew install nmap` / `apt install nmap`)
- sudo access — raw sockets require root for ARP scanning

## Getting Started

```bash
# Clone
git clone https://github.com/saagpatel/NetworkMapper.git
cd NetworkMapper

# Run (creates .venv, installs deps, starts on :8000)
./scripts/run.sh

# Optional: custom port
./scripts/run.sh 9000

# Optional: custom data directory
NETMAPPER_DATA_DIR=/var/lib/netmapper ./scripts/run.sh
```

Open `http://localhost:8000` in your browser. The React SPA is served as static files from the same FastAPI process.

### Backend only (development)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo uvicorn main:app --host 127.0.0.1 --port 8000
```

### Frontend development server

```bash
cd frontend
npm install
npm run dev   # proxies API to :8000
```

### CVE matching (optional)

Trigger a one-time NVD feed download from the settings panel or via:

```
POST http://localhost:8000/api/cve/refresh
```

The feed is cached under `~/.netmapper/nvd_cache/` and loaded into memory on subsequent starts.

## Project Structure

```
NetworkMapper/
├── backend/
│   ├── main.py               # FastAPI app, lifespan, router mounting
│   ├── config.py             # AppConfig — data dir, whitelist, schedule
│   ├── db/
│   │   ├── schema.py         # CREATE TABLE statements
│   │   └── repository.py     # All SQLite reads/writes
│   ├── scanner/
│   │   ├── orchestrator.py   # ARP → nmap → classify → risk pipeline
│   │   ├── arp_scanner.py    # scapy ARP sweep
│   │   ├── nmap_scanner.py   # python-nmap wrapper
│   │   ├── profile.py        # Quick / Standard / Deep scan profiles
│   │   ├── classifier.py     # Device type rules
│   │   └── risk_engine.py    # Port risk flags + CVE matching
│   ├── cve/                  # NVD feed loader and in-memory index
│   ├── oui/                  # MAC vendor (OUI) resolver
│   ├── routes/               # FastAPI routers (scans, devices, cve, schedule, config)
│   └── tests/                # pytest suite
├── frontend/
│   └── src/
│       ├── components/       # TopologyGraph, RiskDashboard, TimelineView, …
│       ├── hooks/            # Data-fetching hooks
│       └── types/            # Shared TypeScript types
└── scripts/
    └── run.sh                # One-command launcher
```

## Screenshot

> _Screenshot placeholder — add an image of the topology graph or risk dashboard here._

## License

MIT — see [LICENSE](LICENSE).
