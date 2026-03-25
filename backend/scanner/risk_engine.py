"""Risk scoring engine — per-port risk flags + CVE matching + score calculation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from models.internal import CVERecord, PortResult

if TYPE_CHECKING:
    from cve.index import CVEIndex

# Ports that are inherently risky when open
CRITICAL_PORTS: dict[int, str] = {
    21: "FTP (plaintext credentials)",
    23: "Telnet (plaintext credentials)",
    512: "rexec (remote execution)",
    513: "rlogin (remote login)",
    514: "rsh (remote shell)",
    5900: "VNC (often unencrypted)",
}

# Ports that are unexpected for certain device types
UNEXPECTED_PORTS: dict[str, set[int]] = {
    "printer": {22, 23, 3389, 5900},
    "iot": {22, 23, 3389, 445, 5900},
    "mobile": {22, 80, 443, 445, 3389},
}

_CRITICAL_PORT_SCORE = 15
_UNEXPECTED_PORT_SCORE = 10
_CVE_CRITICAL_SCORE = 20
_CVE_HIGH_SCORE = 10
_CVE_MEDIUM_SCORE = 5
_MAX_SCORE = 100


def score_device(
    device_type: str,
    ports: list[PortResult],
    cve_index: CVEIndex | None = None,
) -> tuple[int, dict[int, str], str, list[tuple[int, CVERecord]]]:
    """Compute risk score, per-port risk flags, summary, and CVE matches.

    Returns:
        (risk_score, port_risk_flags, risk_summary, cve_matches)
        - risk_score: 0–100
        - port_risk_flags: {port_number: flag_value}
        - risk_summary: plain-English description
        - cve_matches: [(port_number, CVERecord), ...]
    """
    score = 0
    flags: dict[int, str] = {}
    issues: list[str] = []
    cve_matches: list[tuple[int, CVERecord]] = []

    open_ports = [p for p in ports if p.state == "open"]
    unexpected_set = UNEXPECTED_PORTS.get(device_type, set())

    for port in open_ports:
        # Check critical ports
        if port.port in CRITICAL_PORTS:
            score += _CRITICAL_PORT_SCORE
            flags[port.port] = "critical"
            issues.append(
                f"{CRITICAL_PORTS[port.port]} on port {port.port} is open"
            )

        # Check unexpected ports (only if not already flagged as critical)
        elif port.port in unexpected_set:
            score += _UNEXPECTED_PORT_SCORE
            flags[port.port] = "unexpected"
            service_name = port.service or f"port {port.port}"
            issues.append(
                f"{service_name} (port {port.port}) is unexpected for a {device_type} device"
            )

        # CVE matching
        if cve_index is not None and port.service and port.version:
            matches = cve_index.match(port.service, port.version)
            for cve in matches:
                cve_matches.append((port.port, cve))

                if cve.cvss_score is not None:
                    if cve.cvss_score >= 9.0:
                        score += _CVE_CRITICAL_SCORE
                    elif cve.cvss_score >= 7.0:
                        score += _CVE_HIGH_SCORE
                    elif cve.cvss_score >= 4.0:
                        score += _CVE_MEDIUM_SCORE

                # Mark port as outdated if it has CVE matches
                if port.port not in flags:
                    flags[port.port] = "outdated"

            if matches:
                sev_counts = _count_severities(matches)
                issues.append(
                    f"{len(matches)} CVE(s) for {port.service} {port.version} "
                    f"on port {port.port} ({sev_counts})"
                )

    score = min(score, _MAX_SCORE)

    if not issues:
        summary = "No significant risks detected."
    elif score >= 60:
        summary = f"High risk: {'; '.join(issues)}."
    elif score >= 30:
        summary = f"Medium risk: {'; '.join(issues)}."
    else:
        summary = f"Low risk: {'; '.join(issues)}."

    return score, flags, summary, cve_matches


def _count_severities(cves: list[CVERecord]) -> str:
    """Summarize severity counts for a list of CVEs."""
    counts: dict[str, int] = {}
    for cve in cves:
        sev = cve.severity or "UNKNOWN"
        counts[sev] = counts.get(sev, 0) + 1
    return ", ".join(f"{count} {sev}" for sev, count in sorted(counts.items()))
