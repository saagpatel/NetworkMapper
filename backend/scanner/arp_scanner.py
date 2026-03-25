"""ARP scanner — fast LAN host discovery using scapy."""

import logging

from scapy.all import ARP, Ether, conf, srp

logger = logging.getLogger(__name__)


def normalize_mac(mac: str) -> str:
    """Normalize a MAC address to uppercase colon-delimited format (AA:BB:CC:DD:EE:FF)."""
    clean = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    if len(clean) != 12:
        return mac.upper()
    return ":".join(clean[i : i + 2] for i in range(0, 12, 2))


def sweep(cidr: str, timeout: float = 2.0) -> list[dict[str, str]]:
    """ARP sweep a CIDR range and return discovered hosts.

    Requires root/sudo for raw socket access.

    Returns a list of dicts with keys 'ip' and 'mac'.
    """
    logger.info("Starting ARP sweep of %s (timeout=%.1fs)", cidr, timeout)
    conf.verb = 0

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)

    try:
        answered, _ = srp(packet, timeout=timeout, retry=1)
    except PermissionError:
        logger.error(
            "Permission denied — ARP scanning requires root/sudo. "
            "Run the backend with: sudo python -m scanner.arp_scanner <cidr>"
        )
        raise

    hosts: list[dict[str, str]] = []
    for _, received in answered:
        hosts.append(
            {
                "ip": received.psrc,
                "mac": normalize_mac(received.hwsrc),
            }
        )

    logger.info("ARP sweep complete: %d hosts found", len(hosts))
    return hosts


if __name__ == "__main__":
    import json
    import sys

    logging.basicConfig(level=logging.INFO)
    cidr = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
    results = sweep(cidr)
    print(json.dumps(results, indent=2))
