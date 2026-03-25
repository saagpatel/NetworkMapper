# NetMapper — Implementation Roadmap

## Architecture

### System Overview

```
[React SPA (Cytoscape.js + Dashboard)]
        ↓ HTTP (fetch)
[FastAPI — single port :8000]
        ├── /api/scans      → ScanRouter
        ├── /api/devices    → DeviceRouter
        ├── /api/cve        → CVERouter
        ├── /api/schedule   → ScheduleRouter
        └── /static/*       → Serves built React SPA

[ScanRouter]
        ↓ dispatches to
[scanner/orchestrator.py]
        ├── scanner/arp_scanner.py     (scapy — fast LAN sweep)
        ├── scanner/nmap_scanner.py    (python-nmap — port/service/OS)
        └── scanner/profile.py         (Quick / Standard / Deep configs)
                ↓
        [scanner/classifier.py]        (rule-based device categorization)
                ↓
        [scanner/risk_engine.py]       (port risk flags + CVE version matching)
                ↓
        [db/repository.py]             (SQLite writes via sqlite3)
                ↓
        [~/.netmapper/netmapper.db]    (persistent scan history)

[cve/loader.py]
        ↓ on first run (background job)
[~/.netmapper/nvd_cache/]             (NIST NVD JSON feed, ~1GB)
        ↓
[cve/index.py]                        (in-memory CPE → CVE lookup index)

[APScheduler]
        ↓ fires on cron config
[scanner/orchestrator.py]             (same path as manual scan)
```

---

### File Structure

```
netmapper/
├── backend/
│   ├── main.py                        # FastAPI app init, static mount, lifespan
│   ├── config.py                      # AppConfig — data dir, whitelist, schedule
│   ├── db/
│   │   ├── schema.py                  # CREATE TABLE statements, run on startup
│   │   └── repository.py             # All SQLite read/write — no raw SQL elsewhere
│   ├── scanner/
│   │   ├── orchestrator.py            # Coordinates ARP → nmap → classify → risk
│   │   ├── arp_scanner.py             # scapy ARP sweep, returns list[ARPHost]
│   │   ├── nmap_scanner.py            # python-nmap wrapper, returns NmapResult
│   │   ├── profile.py                 # ScanProfile dataclass + Quick/Standard/Deep defs
│   │   ├── classifier.py              # Rule-based device type from ports + OUI + services
│   │   └── risk_engine.py             # Port risk flags, CVE version matching, score calc
│   ├── cve/
│   │   ├── loader.py                  # Download + parse NIST NVD JSON feed
│   │   └── index.py                   # CPE string → CVE list lookup, loaded into memory
│   ├── oui/
│   │   └── resolver.py               # MAC prefix → vendor name (IEEE OUI CSV)
│   ├── routes/
│   │   ├── scans.py                   # POST /api/scans, GET /api/scans/{id}, SSE progress
│   │   ├── devices.py                 # GET /api/devices, GET /api/devices/{id}
│   │   ├── cve.py                     # GET /api/cve/status, POST /api/cve/refresh
│   │   └── schedule.py               # GET/PUT /api/schedule
│   ├── models/
│   │   └── schemas.py                 # All Pydantic request/response models
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── main.tsx                   # React entry point
│   │   ├── App.tsx                    # Router — TopologyView / HistoryView / RiskView
│   │   ├── components/
│   │   │   ├── TopologyGraph.tsx      # Cytoscape.js canvas + node click handler
│   │   │   ├── DevicePanel.tsx        # Slide-out panel: device profile, ports, CVEs
│   │   │   ├── ScanModal.tsx          # Confirmation modal — target CIDR, profile select
│   │   │   ├── RiskDashboard.tsx      # Overall score, top vulns ranked by severity
│   │   │   ├── TimelineView.tsx       # Scan history — new/disappeared devices delta
│   │   │   ├── SubnetView.tsx         # Cytoscape grouped by subnet
│   │   │   ├── CVEStatusBar.tsx       # NVD feed download progress / last updated
│   │   │   └── ScheduleConfig.tsx     # Cron config UI
│   │   ├── hooks/
│   │   │   ├── useScanStream.ts       # SSE hook — scan progress events
│   │   │   ├── useDevices.ts          # Fetch + cache device list
│   │   │   └── useScanHistory.ts      # Fetch scan runs for timeline
│   │   ├── lib/
│   │   │   ├── api.ts                 # Typed fetch wrappers for all API endpoints
│   │   │   ├── cytoscape-config.ts    # Node/edge style definitions, layout config
│   │   │   └── risk-colors.ts         # Score → green/yellow/red color mapping
│   │   └── types/
│   │       └── index.ts               # Shared TS interfaces (Device, ScanRun, CVEMatch, etc.)
│   ├── index.html
│   ├── vite.config.ts
│   ├── tsconfig.json
│   └── package.json
├── scripts/
│   └── run.sh                         # sudo wrapper — sets env, runs uvicorn
├── CLAUDE.md
└── IMPLEMENTATION-ROADMAP.md
```

---

### Data Model

```sql
-- All tables in ~/.netmapper/netmapper.db

CREATE TABLE scan_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    target_cidr TEXT NOT NULL,                    -- e.g., "192.168.1.0/24"
    profile     TEXT NOT NULL CHECK (profile IN ('quick', 'standard', 'deep')),
    status      TEXT NOT NULL DEFAULT 'running'
                     CHECK (status IN ('running', 'completed', 'failed')),
    host_count  INTEGER DEFAULT 0,
    error_msg   TEXT
);
CREATE INDEX idx_scan_runs_started ON scan_runs(started_at DESC);

CREATE TABLE devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address     TEXT NOT NULL,                 -- normalized, uppercase, colon-delimited
    ip_address      TEXT NOT NULL,
    hostname        TEXT,
    vendor          TEXT,                          -- from IEEE OUI lookup
    device_type     TEXT CHECK (device_type IN
                        ('router', 'server', 'workstation', 'mobile', 'iot', 'printer', 'unknown')),
    os_guess        TEXT,
    os_accuracy     INTEGER,                       -- nmap confidence 0-100
    first_seen_scan INTEGER NOT NULL REFERENCES scan_runs(id),
    last_seen_scan  INTEGER NOT NULL REFERENCES scan_runs(id),
    risk_score      INTEGER NOT NULL DEFAULT 0,    -- 0-100
    UNIQUE(mac_address)
);
CREATE INDEX idx_devices_ip ON devices(ip_address);
CREATE INDEX idx_devices_risk ON devices(risk_score DESC);

CREATE TABLE scan_device_appearances (
    scan_run_id  INTEGER NOT NULL REFERENCES scan_runs(id),
    device_id    INTEGER NOT NULL REFERENCES devices(id),
    ip_address   TEXT NOT NULL,                    -- IP may change between scans
    PRIMARY KEY (scan_run_id, device_id)
);

CREATE TABLE open_ports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL REFERENCES devices(id),
    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id),
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL DEFAULT 'tcp',
    state       TEXT NOT NULL,                     -- open / filtered / closed
    service     TEXT,                              -- nmap service name
    version     TEXT,                              -- nmap version string
    risk_flag   TEXT,                              -- 'unexpected' | 'outdated' | 'critical' | null
    UNIQUE(device_id, scan_run_id, port, protocol)
);
CREATE INDEX idx_ports_device ON open_ports(device_id, scan_run_id);

CREATE TABLE cve_matches (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL REFERENCES devices(id),
    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id),
    port        INTEGER NOT NULL,
    cve_id      TEXT NOT NULL,                     -- e.g., "CVE-2024-12345"
    cvss_score  REAL,                              -- 0.0-10.0
    severity    TEXT CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    description TEXT,
    service     TEXT,
    version     TEXT
);
CREATE INDEX idx_cve_device ON cve_matches(device_id, scan_run_id);
CREATE INDEX idx_cve_severity ON cve_matches(severity, cvss_score DESC);

CREATE TABLE app_config (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);
-- Seed rows: 'whitelist_cidrs' (JSON array), 'schedule_cron' (cron string or null),
--            'nvd_last_updated' (ISO datetime), 'nvd_download_complete' (0/1)
```

---

### TypeScript Interfaces

```typescript
// frontend/src/types/index.ts

export type DeviceType =
  | 'router' | 'server' | 'workstation' | 'mobile' | 'iot' | 'printer' | 'unknown';

export type ScanProfile = 'quick' | 'standard' | 'deep';
export type ScanStatus = 'running' | 'completed' | 'failed';
export type RiskSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface Device {
  id: number;
  mac_address: string;
  ip_address: string;
  hostname: string | null;
  vendor: string | null;
  device_type: DeviceType;
  os_guess: string | null;
  os_accuracy: number | null;
  risk_score: number;            // 0-100
  first_seen_scan: number;
  last_seen_scan: number;
}

export interface OpenPort {
  port: number;
  protocol: string;
  state: string;
  service: string | null;
  version: string | null;
  risk_flag: 'unexpected' | 'outdated' | 'critical' | null;
}

export interface CVEMatch {
  cve_id: string;
  cvss_score: number | null;
  severity: RiskSeverity;
  description: string;
  port: number;
  service: string | null;
  version: string | null;
}

export interface DeviceDetail extends Device {
  ports: OpenPort[];
  cve_matches: CVEMatch[];
  risk_summary: string;          // plain-English summary from risk_engine
}

export interface ScanRun {
  id: number;
  started_at: string;            // ISO 8601
  completed_at: string | null;
  target_cidr: string;
  profile: ScanProfile;
  status: ScanStatus;
  host_count: number;
  error_msg: string | null;
}

export interface ScanDelta {
  scan_run_id: number;
  new_devices: Device[];
  disappeared_devices: Device[];
  changed_devices: Array<{ device: Device; changes: string[] }>;
}

export interface ScanProgressEvent {
  type: 'arp_complete' | 'host_scanned' | 'classification_done' | 'complete' | 'error';
  message: string;
  hosts_found?: number;
  hosts_total?: number;
  current_host?: string;
}

export interface NetworkStats {
  total_devices: number;
  risk_score_avg: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  new_devices_last_scan: number;
}

export interface CVEIndexStatus {
  download_complete: boolean;
  last_updated: string | null;    // ISO 8601
  cve_count: number;
  downloading: boolean;
  download_progress: number | null; // 0-100
}
```

---

### Pydantic Models (Backend)

```python
# backend/models/schemas.py

from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime

ScanProfile = Literal['quick', 'standard', 'deep']
DeviceType = Literal['router','server','workstation','mobile','iot','printer','unknown']

class ScanRequest(BaseModel):
    target_cidr: str          # e.g., "192.168.1.0/24" — must be in whitelist
    profile: ScanProfile

class ScanRunResponse(BaseModel):
    id: int
    started_at: datetime
    completed_at: Optional[datetime]
    target_cidr: str
    profile: ScanProfile
    status: str
    host_count: int
    error_msg: Optional[str]

class PortResponse(BaseModel):
    port: int
    protocol: str
    state: str
    service: Optional[str]
    version: Optional[str]
    risk_flag: Optional[Literal['unexpected', 'outdated', 'critical']]

class CVEMatchResponse(BaseModel):
    cve_id: str
    cvss_score: Optional[float]
    severity: Literal['CRITICAL','HIGH','MEDIUM','LOW']
    description: str
    port: int

class DeviceResponse(BaseModel):
    id: int
    mac_address: str
    ip_address: str
    hostname: Optional[str]
    vendor: Optional[str]
    device_type: DeviceType
    os_guess: Optional[str]
    os_accuracy: Optional[int]
    risk_score: int
    first_seen_scan: int
    last_seen_scan: int

class DeviceDetailResponse(DeviceResponse):
    ports: list[PortResponse]
    cve_matches: list[CVEMatchResponse]
    risk_summary: str

class ScheduleConfig(BaseModel):
    cron_expression: Optional[str]    # null = disabled; e.g., "0 */6 * * *"
    target_cidr: Optional[str]
    profile: Optional[ScanProfile]
```

---

### Scan Profiles

```python
# backend/scanner/profile.py

from dataclasses import dataclass
from typing import Optional

@dataclass
class ScanProfile:
    name: str
    arp_only: bool              # True = skip nmap entirely (not used for any profile here)
    nmap_args: str              # passed directly to python-nmap
    os_detection: bool          # requires sudo; Deep only
    version_detection: bool     # -sV flag
    top_ports: Optional[int]    # None = all ports
    timing: str                 # -T2 / -T3 / -T4

PROFILES = {
    "quick": ScanProfile(
        name="quick",
        arp_only=False,
        nmap_args="-sS --top-ports 100 -T3",
        os_detection=False,
        version_detection=False,
        top_ports=100,
        timing="-T3",
    ),
    "standard": ScanProfile(
        name="standard",
        nmap_args="-sS -sV --top-ports 1000 -T3",
        arp_only=False,
        os_detection=False,
        version_detection=True,
        top_ports=1000,
        timing="-T3",
    ),
    "deep": ScanProfile(
        name="deep",
        nmap_args="-sS -sV -O --top-ports 65535 -T4",
        arp_only=False,
        os_detection=True,
        version_detection=True,
        top_ports=None,
        timing="-T4",
    ),
}
```

---

### API Contracts

**Internal API (FastAPI → React SPA)**

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/scans` | POST | none (local) | Start a scan — body: `ScanRequest` |
| `/api/scans` | GET | none | List all scan runs, paginated |
| `/api/scans/{id}` | GET | none | Single scan run details |
| `/api/scans/{id}/stream` | GET (SSE) | none | Real-time scan progress events |
| `/api/scans/{id}/delta` | GET | none | New/disappeared/changed devices vs prior scan |
| `/api/devices` | GET | none | All known devices (latest state) |
| `/api/devices/{id}` | GET | none | Full device detail: ports + CVE matches + summary |
| `/api/cve/status` | GET | none | NVD feed status: downloaded, count, last updated |
| `/api/cve/refresh` | POST | none | Trigger NVD feed re-download in background |
| `/api/schedule` | GET | none | Current schedule config |
| `/api/schedule` | PUT | none | Update schedule config |
| `/api/config/whitelist` | GET | none | Current whitelisted CIDRs |
| `/api/config/whitelist` | PUT | none | Update whitelist |

**External — NIST NVD Feed**

| Source | URL | Method | Auth | Size | Purpose |
|--------|-----|--------|------|------|---------|
| NIST NVD | `https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz` | GET | none | ~1GB total | Annual CVE feeds 2002–present |
| IEEE OUI | `https://standards-oui.ieee.org/oui/oui.csv` | GET | none | ~5MB | MAC vendor resolution |

Both are downloaded once to `~/.netmapper/` and used offline. NVD feed refresh is user-triggered via `/api/cve/refresh`.

---

### Risk Scoring Logic

```
device.risk_score (0–100) is computed by risk_engine.py:

Base score = 0
Per open port:
  - Port in CRITICAL_PORTS (23/telnet, 21/ftp, 512-514/rsh, 5900/vnc): +15
  - Port unexpected for device_type (e.g., port 22 on device_type=iot): +10
  - Port has CVE match with severity=CRITICAL (cvss >= 9.0): +20
  - Port has CVE match with severity=HIGH (cvss 7.0–8.9): +10
  - Port has CVE match with severity=MEDIUM (cvss 4.0–6.9): +5

Cap at 100.

risk_score bands:
  0–29:   green   (low risk)
  30–59:  yellow  (medium risk)
  60–100: red     (high/critical risk)
```

---

### Device Classifier Rules

```
# backend/scanner/classifier.py — rule priority order

1. MAC OUI lookup → known router vendors (Cisco, Ubiquiti, MikroTik, TP-Link, Netgear, ASUS, etc.)
   AND (port 80 OR 443 OR 53 open) → "router"

2. Ports 22 + 80 + 443 open AND hostname contains 'server'/'nas'/'pi' → "server"

3. MAC OUI → known mobile vendors (Apple iPhone/iPad, Samsung, Pixel) → "mobile"

4. MAC OUI → known IoT vendors (Philips Hue, Nest, Ring, Sonos, Tuya, Espressif)
   OR (only port 1883/MQTT or 8883 open) → "iot"

5. MAC OUI → known printer vendors (HP, Canon, Epson, Brother, Lexmark)
   OR port 9100 open → "printer"

6. Port 3389 open OR (ports 135+139+445 open) → "workstation" (Windows indicators)

7. Port 22 open AND port 3389 NOT open AND OUI not mobile → "server" (fallback for Linux)

8. Default → "unknown"
```

---

### Dependencies

```bash
# Backend
cd backend
pip install fastapi==0.111.* uvicorn[standard]==0.30.* python-nmap==1.6.* \
    scapy==2.5.* apscheduler==3.10.* pydantic==2.7.* requests==2.32.* \
    aiofiles==23.2.*

# System dependencies (macOS)
brew install nmap

# Frontend
cd frontend
npm install react@18 react-dom@18 cytoscape@3.28 cytoscape-layout-utilities \
    @types/react @types/react-dom typescript@5 vite@5 tailwindcss@3 \
    autoprefixer postcss lucide-react

# Verify nmap is accessible with sudo
sudo nmap --version
```

---

## Scope Boundaries

**In scope:**
- Local subnet scanning only (user-owned networks, whitelist-gated)
- ARP sweep + nmap port/service/OS detection
- Rule-based device classification (7 types)
- CVE matching from local NIST NVD feed
- Risk scoring per device and per port
- Topology graph (Cytoscape.js) with node click → device detail
- Scan history + delta detection (new/disappeared devices)
- Three scan profiles: Quick / Standard / Deep
- Manual scan trigger + optional APScheduler cron
- IEEE OUI vendor resolution

**Out of scope (v1):**
- Authentication (local tool, no auth needed)
- Multi-user or remote access
- Network packet capture / traffic analysis
- Remediation automation (tool observes, does not act)
- Wireless network discovery (no WiFi-specific scanning)
- Cloud/SaaS topology (AWS VPC, Azure, GCP)
- Custom CVE suppression/false-positive management

**Deferred (Phase 4+):**
- Export: PDF risk report, CSV device inventory
- Push notifications (email/Slack) on new device detection
- Custom classification rules UI

---

## Security

- All data in `~/.netmapper/` — nothing leaves the machine
- No API keys, no auth tokens, no credentials stored
- NVD feed and OUI CSV downloaded over HTTPS, stored in `~/.netmapper/nvd_cache/` and `~/.netmapper/oui.csv`
- Backend requires sudo for nmap OS detection and raw socket ARP scanning — `run.sh` handles this explicitly
- Whitelist validation: every scan request validated against `app_config.whitelist_cidrs` before nmap is invoked — 403 if target not in list
- Frontend confirmation modal is a UX gate, not a security gate — the real gate is whitelist validation in the API

---

## Phase 0: Foundation (Week 1)

**Objective:** Project scaffolded, SQLite schema live, ARP scanner working, OUI resolver working, config system in place. No UI. Everything verifiable via CLI/curl.

**Tasks:**

1. Scaffold directory structure per file structure above — **Acceptance:** `ls` shows all dirs; `cd backend && python -c "import fastapi, nmap, scapy"` exits 0

2. Implement `db/schema.py` — run `CREATE TABLE` statements on startup against `~/.netmapper/netmapper.db` — **Acceptance:** `sqlite3 ~/.netmapper/netmapper.db ".tables"` outputs all 6 table names

3. Implement `oui/resolver.py` — download `oui.csv` on first run to `~/.netmapper/oui.csv`, parse into dict, expose `lookup(mac: str) -> str | None` — **Acceptance:** `python -c "from oui.resolver import lookup; print(lookup('00:1A:2B'))"` returns a vendor string

4. Implement `scanner/arp_scanner.py` — scapy ARP sweep of a CIDR, returns `list[dict]` with keys `ip`, `mac` — **Acceptance:** `sudo python -c "from scanner.arp_scanner import sweep; print(sweep('192.168.1.0/24'))"` returns at least 1 host on your LAN

5. Implement `config.py` — loads/saves `app_config` table; seeds whitelist and schedule defaults on first run — **Acceptance:** `python -c "from config import AppConfig; c = AppConfig(); print(c.whitelist_cidrs)"` returns default list

6. Wire FastAPI `main.py` with lifespan: init DB schema, load OUI resolver, start APScheduler — **Acceptance:** `sudo uvicorn main:app --port 8000` starts without errors; `curl localhost:8000/api/cve/status` returns JSON with `download_complete: false`

**Verification checklist:**
- [ ] `sqlite3 ~/.netmapper/netmapper.db ".tables"` → `scan_runs devices scan_device_appearances open_ports cve_matches app_config`
- [ ] `sudo python -m scanner.arp_scanner 192.168.1.0/24` → prints JSON array of hosts
- [ ] `curl localhost:8000/api/cve/status` → `{"download_complete": false, "last_updated": null, ...}`
- [ ] `~/.netmapper/oui.csv` exists and is > 4MB

**Risks:**
- scapy requires sudo on macOS for raw sockets → always run backend with `sudo`; document in `run.sh`
- macOS may block ARP packets depending on firewall config → test on your M4 LAN first, fallback: use nmap host discovery (`-sn`) in place of scapy ARP

---

## Phase 1: Scanner Core + API (Week 2)

**Objective:** Full scan pipeline working end-to-end. Manual scan trigger via API. Scan results written to SQLite. SSE progress stream working.

**Tasks:**

1. Implement `scanner/profile.py` — `PROFILES` dict with Quick/Standard/Deep as defined in Architecture — **Acceptance:** `python -c "from scanner.profile import PROFILES; print(PROFILES['deep'].nmap_args)"` prints correct flags

2. Implement `scanner/nmap_scanner.py` — takes `list[str]` of IPs + `ScanProfile`, returns `list[NmapHostResult]` with ports, services, versions, OS guess — **Acceptance:** `sudo python -m scanner.nmap_scanner 192.168.1.1 quick` prints JSON with at least port 80 or 443 for your router

3. Implement `scanner/classifier.py` — rule-based device type classification per Architecture rules — **Acceptance:** unit test: router MAC + ports 80/443 → `"router"`; IoT MAC + port 1883 → `"iot"`

4. Implement `scanner/risk_engine.py` — computes `risk_score` and `risk_flag` per port; generates `risk_summary` string — **Acceptance:** device with port 23 open scores >= 15; plain-English summary string non-empty

5. Implement `scanner/orchestrator.py` — ARP sweep → nmap scan → classify → risk score → write to SQLite via `db/repository.py`; emits progress events via `asyncio.Queue` — **Acceptance:** running orchestrator on LAN creates rows in all 4 tables; scan_runs.status = 'completed'

6. Implement `db/repository.py` — all read/write for scan_runs, devices, open_ports, cve_matches, scan_device_appearances; upsert logic for devices (keyed on mac_address) — **Acceptance:** two scans of same host → 1 device row, 2 scan_device_appearance rows

7. Implement `routes/scans.py` — `POST /api/scans` validates whitelist, fires orchestrator as background task, returns scan_run id; `GET /api/scans/{id}/stream` SSE endpoint streaming progress events — **Acceptance:** `curl -X POST localhost:8000/api/scans -d '{"target_cidr":"192.168.1.0/24","profile":"quick"}'` returns `{"id": 1, "status": "running"}`; SSE stream emits at least `arp_complete` and `complete` events

8. Implement `routes/devices.py` — `GET /api/devices` returns all devices; `GET /api/devices/{id}` returns `DeviceDetailResponse` with ports + CVE placeholders (empty array until Phase 2) + risk_summary — **Acceptance:** `curl localhost:8000/api/devices` returns JSON array after a scan

**Verification checklist:**
- [ ] POST `/api/scans` with whitelisted CIDR → scan completes, `scan_runs.status = 'completed'`
- [ ] POST `/api/scans` with non-whitelisted CIDR → 403 response
- [ ] GET `/api/scans/{id}/stream` → SSE events flow in real time during scan
- [ ] GET `/api/devices` → array with device_type populated for each host
- [ ] `sqlite3` query: `SELECT mac_address, device_type, risk_score FROM devices` → non-empty, device_types are valid enum values

**Risks:**
- Full subnet nmap scans take 2–15 minutes depending on profile and host count → SSE stream is non-negotiable for UX; don't fake progress, emit real events per host
- python-nmap returns inconsistent output for offline hosts → always check `host.state()` before parsing ports; skip hosts with state != 'up'

---

## Phase 2: CVE Integration (Week 3)

**Objective:** NIST NVD feed downloaded and indexed. CVE matches populated on scan completion. `/api/devices/{id}` returns real CVE data.

**Tasks:**

1. Implement `cve/loader.py` — download NVD JSON.gz feeds for years 2002–present to `~/.netmapper/nvd_cache/`; emit download progress via callback; parse into `list[CVERecord]`; stream progress to SSE — **Acceptance:** after `POST /api/cve/refresh`, files appear in `~/.netmapper/nvd_cache/`; `GET /api/cve/status` shows `download_complete: true` and `cve_count > 100000`

2. Implement `cve/index.py` — build in-memory dict: `{product_name: {version_prefix: [CVERecord]}}` from parsed NVD data; expose `match(service: str, version: str) -> list[CVERecord]` — **Acceptance:** `match("openssh", "8.0")` returns at least 1 CVE; response time < 50ms for a single lookup

3. Wire CVE matching into `scanner/risk_engine.py` — after ports scored, call `cve_index.match(service, version)` for each port with a version string; write matches to `cve_matches` table — **Acceptance:** after Standard/Deep scan of a host with OpenSSH, `cve_matches` has rows; `risk_score` increases for matched CVEs

4. Update `routes/devices.py` `GET /api/devices/{id}` — populate `cve_matches` array in response — **Acceptance:** device with known vulnerable service returns non-empty `cve_matches` array with `cvss_score` and `severity`

5. Implement CVE index load on FastAPI startup (if `nvd_download_complete = 1`) — log warning if index not loaded, CVE matching disabled — **Acceptance:** restart server after NVD download → `GET /api/cve/status` shows `cve_count > 0` immediately

**Verification checklist:**
- [ ] `GET /api/cve/status` → `{"download_complete": true, "cve_count": [> 100000], ...}` after refresh
- [ ] Standard scan of any host with SSH open → `cve_matches` rows in DB
- [ ] `GET /api/devices/{id}` → `cve_matches` array populated with severity + cvss_score
- [ ] `~/.netmapper/nvd_cache/` contains `.json.gz` files totaling > 800MB
- [ ] CVE index lookup benchmarks < 50ms (test with `time` in Python REPL)

**Risks:**
- NVD JSON feeds are ~1GB total, download takes 5–20 min on first run → show download progress in UI via SSE; never block startup on NVD load
- NVD CPE version matching is fuzzy — product names in nmap output ("openssh") may not match NVD product names exactly → normalize: lowercase, strip spaces, common aliases dict (e.g., "apache httpd" → "apache_http_server")
- Memory: full CVE index in-memory is ~200–400MB → benchmark on startup; if > 500MB, switch to SQLite FTS5 index as fallback

---

## Phase 3: React Frontend + Topology (Week 4)

**Objective:** Full React SPA built and served by FastAPI. Topology graph live. Device panel working. Scan modal + SSE progress. Risk dashboard.

**Tasks:**

1. Scaffold Vite + React + TypeScript + Tailwind frontend in `frontend/` — configure `vite.config.ts` to build to `backend/static/` — **Acceptance:** `npm run build` produces `backend/static/index.html`; `curl localhost:8000/` returns HTML

2. Implement `TopologyGraph.tsx` — Cytoscape.js canvas; nodes = devices, color-coded by risk_score band (green/yellow/red); click node → emit `onDeviceSelect(device_id)` — **Acceptance:** graph renders after scan; node colors match risk bands; clicking a node fires the handler

3. Implement `DevicePanel.tsx` — slide-out panel triggered by node click; shows: IP, MAC, vendor, device_type badge, OS guess, open ports table (port/service/version/risk_flag), CVE matches table (CVE-ID/severity/cvss/description) — **Acceptance:** clicking a red node shows its CVE matches in the panel

4. Implement `ScanModal.tsx` — confirmation modal with CIDR input (pre-filled with first whitelist entry), profile selector (Quick/Standard/Deep with descriptions), "Start Scan" button that fires `POST /api/scans` — **Acceptance:** CIDR not in whitelist → API returns 403 → modal shows error; valid scan → modal closes, progress bar appears

5. Implement `useScanStream.ts` hook — connects to SSE `/api/scans/{id}/stream`, parses `ScanProgressEvent`, exposes `progress`, `status`, `currentHost` state — **Acceptance:** progress bar advances in real time during a Quick scan

6. Implement `RiskDashboard.tsx` — overall network risk score (average), count by severity (CRITICAL/HIGH/MEDIUM/LOW), top 10 CVEs ranked by cvss_score, new devices from last scan — **Acceptance:** dashboard shows correct counts after a Standard scan with CVE matches

7. Implement `TimelineView.tsx` — list of scan runs; select two scans → show delta (new devices in green, disappeared in red, changed ports in yellow) using `GET /api/scans/{id}/delta` — **Acceptance:** run two scans, timeline shows delta correctly

8. Implement `SubnetView.tsx` — Cytoscape grouped/compound nodes by subnet prefix — **Acceptance:** devices on 192.168.1.x and 192.168.2.x appear in separate visual groups

9. Wire `ScheduleConfig.tsx` — cron expression input + target CIDR + profile selector; PUT `/api/schedule` — **Acceptance:** set schedule, restart server, scheduled scan fires at correct time

**Verification checklist:**
- [ ] `npm run build && sudo uvicorn main:app --port 8000` → `localhost:8000` serves full React app
- [ ] Topology graph renders all discovered devices with correct colors
- [ ] Click node → DevicePanel shows correct port + CVE data
- [ ] Scan modal rejects non-whitelisted CIDRs with error message
- [ ] SSE progress bar moves during scan
- [ ] Timeline delta correctly shows new device when a new host joins the network between scans

**Risks:**
- Cytoscape.js layout with 50+ nodes can be slow — use `cose-bilkent` layout with `animate: false` for initial render; switch to `fcose` if performance is poor
- SSE in React requires careful cleanup — always close EventSource in useEffect cleanup to prevent connection leaks
- FastAPI static file serving: configure `app.mount("/", StaticFiles(directory="static", html=True), name="static")` AFTER all API routes are registered — order matters

---

## Phase 4: Polish + Scheduler + Run Script (Week 5)

**Objective:** Production-ready local tool. Scheduled scanning works. `run.sh` wraps sudo. CVE status bar in UI. Edge cases handled.

**Tasks:**

1. Implement `routes/schedule.py` + APScheduler wiring — read cron config from DB, register job on startup; update via `PUT /api/schedule` hot-reloads the job — **Acceptance:** set `"0 */6 * * *"` cron, wait for trigger, confirm scan_runs row created

2. Implement `CVEStatusBar.tsx` — persistent top bar: "NVD feed: 237,422 CVEs | Last updated 2025-03-10 | [Refresh]"; shows download progress bar during `POST /api/cve/refresh` — **Acceptance:** refresh button triggers download, progress bar animates, count updates after completion

3. Write `scripts/run.sh` — checks nmap installed, checks Python 3.11+, `cd backend && sudo uvicorn main:app --host 127.0.0.1 --port 8000` with env setup — **Acceptance:** `chmod +x run.sh && ./run.sh` starts the server without manual sudo invocation

4. Handle scan error states — nmap not found, sudo permission denied, target unreachable — surface errors in frontend toast notifications — **Acceptance:** remove nmap temporarily → scan returns 500 with `{"error": "nmap not found"}` → frontend shows toast

5. Add `GET /api/scans/{id}/delta` implementation in `routes/scans.py` — compare device list from scan N vs scan N-1, return `ScanDelta` — **Acceptance:** delta endpoint returns correct new/disappeared arrays when a device is added or removed between scans

6. Whitelist management UI — settings page: add/remove CIDRs from whitelist, persists to `app_config` — **Acceptance:** add new CIDR in UI, restart server, new CIDR scannable

**Verification checklist:**
- [ ] Scheduled scan fires at configured time → new scan_run row in DB
- [ ] `./run.sh` starts cleanly on fresh terminal
- [ ] All 6 error states (nmap not found, non-whitelisted CIDR, scan already running, CVE index not loaded, invalid CIDR format, DB write failure) return structured JSON errors, not 500 stack traces
- [ ] CVE status bar shows correct count and refresh works end-to-end

---

## Testing Strategy

### Unit tests (pytest — backend)
- `test_classifier.py` — 8 test cases covering each device_type rule, including ambiguous/fallback cases
- `test_risk_engine.py` — verify score computation: known port combos → expected score; cap at 100
- `test_cve_index.py` — verify `match()` returns correct CVEs for known service/version pairs
- `test_whitelist.py` — valid CIDR passes, invalid rejected, non-whitelisted rejected

### Integration tests
- Full scan pipeline: mock nmap output → verify DB rows created correctly
- CVE loader: parse a single NVD JSON file → verify CVERecord count and field mapping

### Manual verification checklist (per phase)
- Phase 0: ARP sweep returns real hosts from your LAN
- Phase 1: Quick scan of your home router correctly classifies it as "router"
- Phase 2: Standard scan of a Raspberry Pi running SSH → CVE matches appear
- Phase 3: New device joins network between scans → timeline delta shows it in green
- Phase 4: Scheduled scan fires; run.sh starts cleanly after reboot

### macOS-specific testing
- Test ARP scanner with and without macOS firewall enabled — document if fallback to nmap `-sn` is needed
- Test Deep profile (OS fingerprinting) — macOS may return inconsistent OS results for some devices; log `os_accuracy` and only display OS guess if `os_accuracy >= 70`
- Test on M4 — scapy and python-nmap both have ARM64 wheels; verify no Rosetta layer
