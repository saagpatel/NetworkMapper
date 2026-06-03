# NetworkMapper (NetMapper) — Portfolio Disposition

**Status:** Active (operator-tool, local network audit) — Python +
scapy + nmap + APScheduler backend + React + Cytoscape.js frontend
local network scanner on `origin/main`. ARP sweep + nmap
port/service/OS detection + rule-based device classification +
NIST NVD CVE matching + interactive topology graph + SQLite
history at `~/.netmapper/netmapper.db` + scheduled scans. Recent
security hardening: requests-2.33.0 CVE bump + empty-whitelist
bypass + schedule validation gap closure. **Third member of the
operator-tool / dogfood cluster**; introduces new sub-shape:
**single-user local-audit clone-and-run** (distinct from
GithubRepoAuditor's PyPI distribution and AIWorkFlow's monorepo
with client portal).

> Disposition uses strict `origin/main` verification.
> **Operator-tool cluster reaches 3 with 3 distinct sub-shapes.**

---

## Verification posture

Only `origin` (`saagpatel/NetworkMapper`). Clean.

`origin/main`:

- Tip: `6bebd57` chore(deps): bump requests minimum to 2.33.0 to
  fix 3 CVEs
- **Recent security hardening commits**:
  - `6bebd57` chore(deps): bump requests minimum to 2.33.0 (3 CVEs)
  - `6045aae` **fix(security): close empty-whitelist bypass and
    schedule validation gap** (suggests active discovery /
    bug-fix cadence)
- Full OSS scaffolding wave further back
- Repo tree:
  - `backend/` (Python + scapy + nmap + APScheduler + FastAPI)
  - `frontend/` (React + Cytoscape.js topology graph)
  - `scripts/`
  - Standard scaffolding
- Default branch: `main`

---

## Current state in one paragraph

NetworkMapper (CLI: `netmapper`, internal name: NetMapper) is a
**local network scanner with browser-based UI**. Architecture:

1. **Python backend** uses **scapy** for ARP sweep (LAN discovery,
   no credentials required) + **nmap** for port scanning, service
   banners, and OS fingerprinting (Quick / Standard / Deep
   profiles) + **APScheduler** for scheduled scans + **FastAPI**
   for the API surface.
2. **Rule-based device classification** using open ports + OUI
   vendor lookup + service names.
3. **Risk engine** flags high-risk open ports and matches service
   versions against the **NIST NVD CVE feed**.
4. **React + Cytoscape.js frontend** renders an interactive
   topology graph.
5. **SQLite history** at `~/.netmapper/netmapper.db` (private
   app-data directory).
6. **Scheduled scans** via APScheduler cron expression configured
   in settings UI.
7. **Sudo required** for ARP scanning.

Per memory: 35 tests, Phase 0. The canonical state is
substantively beyond Phase 0 — full feature set described in
README is shipped, plus recent security-hardening cadence (CVE
fix + whitelist bypass + schedule validation gap). Active state
reflects ongoing operator use + occasional bug discovery, not
ship-readiness gaps.

---

## Why "Active (operator-tool, local network audit)" — third cluster member, new sub-shape

The operator-tool / dogfood cluster reaches 3 members with 3
distinct sub-shapes:

| Member | Sub-shape | Distribution |
|---|---|---|
| GithubRepoAuditor (R11) | pure-internal, PyPI-published | `pip install github-repo-auditor` |
| AIWorkFlow (R17.2) | multi-surface with client portal | Vercel (portal) + service host (Slack bots) + local CLI |
| **NetworkMapper (NetMapper)** | **single-user local-audit clone-and-run** | **`git clone` + `pip install` + sudo run** |

NetworkMapper's sub-shape distinguishes:
- **No PyPI** (unlike GithubRepoAuditor) — clone-and-run only
- **No external client surface** (unlike AIWorkFlow) — operator
  audits own network
- **Requires sudo** (unique among cluster) — root access for ARP
  is the load-bearing prerequisite
- **Single-user, single-machine** scope — designed for one
  operator on one home/office LAN

This is **infrastructure-adjacent** operator tooling: the operator
audits their own home / office network for device inventory + open
port risk + CVE exposure. Similar genre to MCPAudit (audits
operator's own MCP servers) but different cluster (MCPAudit is
PyPI-distributed).

Active state because:
- Recent security hardening commits suggest active production use
  with bug discovery
- No "v1.0" tag visible — operator treats this as continuous
  internal tool, not release artifact
- Memory says "Phase 0" but canonical state is substantively
  beyond — memory drift; update record

---

## Cluster taxonomy update

| Cluster | Count | Sub-shapes |
|---|---|---|
| **Operator-tool / dogfood** | **3** | pure-internal-PyPI (GithubRepoAuditor) / multi-surface-with-portal (AIWorkFlow) / **single-user-local-audit (NetworkMapper)** |
| (others unchanged) | | |

Operator-tool cluster reaches 3 with 3 distinct sub-shapes. This
matches the maturity pattern seen in iOS App Store / static-host
clusters where multiple sub-shapes emerge as cluster grows.

---

## Unblock trigger (operator)

This is operator-internal infrastructure tooling. "Ship public"
doesn't apply. Operational concerns:

1. **Sudo access posture** — ARP requires root. On macOS, this
   means `./scripts/run.sh`. Verify the operator's workflow
   handles this cleanly (alias, sudoers entry for the specific
   command, or run-as-root LaunchAgent).
2. **NIST NVD CVE feed sync cadence** — verify feed is being
   pulled regularly and CVE matches are current. `6bebd57`
   pattern of CVE fixes in own deps + matching CVEs in scanned
   devices = double-loop security posture.
3. **nmap profile selection** — Quick / Standard / Deep
   trade-offs (Deep can take hours on a `/16`); document
   recommended default.
4. **OUI vendor database refresh** — IEEE OUI registry updates
   monthly; verify lookup data is current.
5. **APScheduler bypass fix** (`6045aae`) — verify the
   empty-whitelist bypass and schedule validation gap remain
   closed in any new feature work.
6. **`~/.netmapper/netmapper.db` privacy** — scan results contain
   device inventory of the operator's LAN (sensitive). Verify
   backup posture if any (default: no backup; lose if disk fails).
7. **Update memory record**: "Phase 0" → substantively shipped.

Estimated operator time: ~1-2 hours for OUI database refresh +
NVD feed verification.

---

## Portfolio operating system instructions

| Aspect | Posture |
|---|---|
| Portfolio status | `Active (operator-tool, local network audit)` |
| Audience | **Operator self** (audits own LAN) |
| Distribution | **Clone + pip install + sudo run** (not PyPI, not Vercel, not Chrome Web Store) |
| Review cadence | Active — operator-cadence + occasional security hardening |
| Resurface conditions | (a) NVD feed format change, (b) nmap or scapy major version, (c) discovered security bug in scanner itself, (d) macOS network stack change breaks ARP, (e) home network growth past current performance budget |
| Co-batch with | Operator-tool cluster — **now 3 repos** |
| Sub-shape | **Single-user local-audit clone-and-run** (new) |
| Special concern | **Sudo posture.** ARP requires root; verify clean operator workflow. |
| Special concern | **NIST NVD CVE feed sync.** Feed format changes break match logic silently. |
| Special concern | **Self-scanner-CVE awareness.** Tool's own deps need CVE auditing too (`6bebd57` pattern). |
| Special concern | **Sensitive scan data privacy.** `~/.netmapper/netmapper.db` has operator's full LAN inventory. |
| Special concern | **Memory drift correction**: "Phase 0" → substantively shipped. |

---

## Reactivation procedure

1. Verify branch tracking.
2. Review stash `r17-nm-stash` (CLAUDE.md mod + .agents/ +
   .claude/ + .codex/ + AGENTS.md). Multiple agent harness
   directories — operator may be running multi-agent workflows
   on this repo.
3. **Update memory record**: "Phase 0" → "Active (operator-tool,
   local network audit), substantively shipped."
4. Verify NIST NVD CVE feed connectivity.
5. Verify OUI vendor database freshness.
6. Run `pytest backend/tests/` — expect ~150 tests passing (code-verified).
7. Run a Quick-profile scan against operator's LAN as smoke test
   (sudo required).

---

## Last known reference

| Field | Value |
|---|---|
| `origin/main` tip | `6bebd57` chore(deps): bump requests minimum to 2.33.0 to fix 3 CVEs |
| Default branch | `main` |
| Build system | Python 3.11+ + FastAPI + scapy + nmap + APScheduler + React + Cytoscape.js |
| Audience | **Operator self** (own LAN) |
| Distribution | **`git clone` + `pip install` + `./scripts/run.sh`** (not PyPI) |
| Required prerequisites | nmap (`brew install nmap`), Python 3.11+, Node 18+, **root/sudo for ARP** |
| Phases shipped | ARP sweep + nmap enrichment + device classification + risk engine + CVE matching + Cytoscape topology + APScheduler + SQLite history. **Substantively beyond memory's "Phase 0".** |
| Test count | ~150 (code-verified) |
| Sensitive data | `~/.netmapper/netmapper.db` (operator's full LAN inventory) |
| Migration state | No `legacy-origin` remote |
| Distinguishing feature | **Third operator-tool cluster member. Introduces single-user local-audit clone-and-run sub-shape.** Operator-tool cluster reaches 3 with 3 distinct sub-shapes (matches iOS / static-host cluster maturity pattern). Memory drift correction (Phase 0 → substantively shipped). |
