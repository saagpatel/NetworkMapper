"""Nmap scanner wrapper — port, service, OS detection via python-nmap."""

import logging

import nmap

from models.internal import NmapHostResult, PortResult
from scanner.arp_scanner import normalize_mac
from scanner.profile import ScanProfile

logger = logging.getLogger(__name__)


def scan_hosts(ips: list[str], profile: ScanProfile) -> list[NmapHostResult]:
    """Scan a list of IPs using nmap with the given profile.

    Returns NmapHostResult for each host that is 'up'. Hosts that are down
    or cause errors are skipped with a warning log.
    """
    if not ips:
        return []

    targets = " ".join(ips)
    logger.info("Starting nmap scan of %d hosts with profile %s", len(ips), profile.name)

    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=targets, arguments=profile.nmap_args, sudo=profile.os_detection)
    except nmap.PortScannerError:
        logger.exception("nmap scan failed for targets: %s", targets)
        return []

    results: list[NmapHostResult] = []

    for host_ip in scanner.all_hosts():
        try:
            host_data = scanner[host_ip]

            if host_data.state() != "up":
                logger.debug("Skipping host %s — state: %s", host_ip, host_data.state())
                continue

            ports = _parse_ports(host_data)
            mac = _parse_mac(host_data)
            hostname = _parse_hostname(host_data)
            os_guess, os_accuracy = _parse_os(host_data) if profile.os_detection else (None, 0)

            results.append(
                NmapHostResult(
                    ip=host_ip,
                    mac=mac,
                    hostname=hostname,
                    state="up",
                    ports=ports,
                    os_guess=os_guess,
                    os_accuracy=os_accuracy,
                )
            )
        except (KeyError, IndexError, TypeError):
            logger.exception("Failed to parse nmap results for host %s — skipping", host_ip)
            continue

    logger.info("nmap scan complete: %d hosts up", len(results))
    return results


def _parse_ports(host_data: dict) -> list[PortResult]:
    """Extract open ports from nmap host data."""
    ports: list[PortResult] = []

    for protocol in ("tcp", "udp"):
        if protocol not in host_data:
            continue
        for port_num, port_info in host_data[protocol].items():
            state = port_info.get("state", "unknown")
            if state not in ("open", "filtered"):
                continue
            ports.append(
                PortResult(
                    port=int(port_num),
                    protocol=protocol,
                    state=state,
                    service=port_info.get("name") or None,
                    version=_build_version_string(port_info),
                )
            )

    return ports


def _build_version_string(port_info: dict) -> str | None:
    """Build a version string from nmap port info fields."""
    product = port_info.get("product", "")
    version = port_info.get("version", "")
    extra = port_info.get("extrainfo", "")

    parts = [p for p in (product, version, extra) if p]
    return " ".join(parts) if parts else None


def _parse_mac(host_data: dict) -> str | None:
    """Extract and normalize MAC address from nmap results."""
    addresses = host_data.get("addresses", {})
    mac = addresses.get("mac")
    if mac:
        return normalize_mac(mac)
    return None


def _parse_hostname(host_data: dict) -> str | None:
    """Extract hostname from nmap results."""
    hostnames = host_data.get("hostnames", [])
    if hostnames and isinstance(hostnames, list):
        for entry in hostnames:
            name = entry.get("name", "") if isinstance(entry, dict) else ""
            if name:
                return name
    return None


def _parse_os(host_data: dict) -> tuple[str | None, int]:
    """Extract OS guess and accuracy from nmap osmatch results."""
    osmatch = host_data.get("osmatch", [])
    if not osmatch:
        return None, 0

    best = osmatch[0]
    name = best.get("name")
    try:
        accuracy = int(best.get("accuracy", 0))
    except (ValueError, TypeError):
        accuracy = 0

    return name, accuracy


if __name__ == "__main__":
    import json
    import sys

    from scanner.profile import get_profile

    logging.basicConfig(level=logging.INFO)
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.1"
    profile_name = sys.argv[2] if len(sys.argv) > 2 else "quick"
    profile = get_profile(profile_name)
    results = scan_hosts([target], profile)
    for r in results:
        print(json.dumps({
            "ip": r.ip,
            "mac": r.mac,
            "hostname": r.hostname,
            "os_guess": r.os_guess,
            "os_accuracy": r.os_accuracy,
            "ports": [{"port": p.port, "protocol": p.protocol, "state": p.state,
                        "service": p.service, "version": p.version} for p in r.ports],
        }, indent=2))
