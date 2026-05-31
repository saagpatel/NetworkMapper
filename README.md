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
- Node.js 18+ and npm
- Root/sudo access for ARP scanning

### Installation
```bash
git clone https://github.com/saagpatel/NetworkMapper
cd NetworkMapper
pip install -r backend/requirements.txt
cd frontend && npm install
```

### Usage
```bash
# Start backend
./scripts/run.sh

# Start frontend (separate terminal, dev mode)
cd frontend && npm run dev
# Open http://localhost:5173
```

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
