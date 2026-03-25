"""Rule-based device type classifier — ports + OUI + service heuristics."""

from models.internal import NmapHostResult, PortResult

# Vendor pattern lists — matched via substring against lowercased vendor name
ROUTER_VENDOR_PATTERNS = [
    "cisco", "netgear", "tp-link", "asus", "linksys", "ubiquiti",
    "mikrotik", "arris", "motorola", "zyxel", "draytek", "juniper",
]
MOBILE_VENDOR_PATTERNS = [
    "apple", "samsung", "google", "huawei", "xiaomi", "oneplus",
    "oppo", "vivo", "pixel", "iphone", "ipad",
]
IOT_VENDOR_PATTERNS = [
    "espressif", "tuya", "shelly", "sonoff", "ring", "nest", "philips",
    "ikea", "sonos", "ecobee", "wemo", "hue",
]
PRINTER_VENDOR_PATTERNS = [
    "hp", "hewlett", "canon", "epson", "brother", "lexmark", "xerox", "ricoh",
]


def classify(host: NmapHostResult, vendor: str | None) -> str:
    """Classify a device type based on OUI vendor, open ports, and hostname.

    Returns one of: 'router', 'server', 'workstation', 'mobile', 'iot',
    'printer', 'unknown'. Rules are applied in priority order.
    """
    open_ports = {p.port for p in host.ports if p.state == "open"}
    vendor_lower = vendor.lower() if vendor else ""
    hostname_lower = (host.hostname or "").lower()

    # Rule 1: Router vendor + web/DNS ports
    if _vendor_matches(vendor_lower, ROUTER_VENDOR_PATTERNS):
        if open_ports & {80, 443, 53}:
            return "router"

    # Rule 2: Server ports + server-like hostname
    if {22, 80, 443}.issubset(open_ports):
        if any(kw in hostname_lower for kw in ("server", "nas", "pi")):
            return "server"

    # Rule 3: Mobile vendor
    if _vendor_matches(vendor_lower, MOBILE_VENDOR_PATTERNS):
        return "mobile"

    # Rule 4: IoT vendor OR MQTT-only ports
    if _vendor_matches(vendor_lower, IOT_VENDOR_PATTERNS):
        return "iot"
    if open_ports and open_ports.issubset({1883, 8883}):
        return "iot"

    # Rule 5: Printer vendor OR port 9100
    if _vendor_matches(vendor_lower, PRINTER_VENDOR_PATTERNS):
        return "printer"
    if 9100 in open_ports:
        return "printer"

    # Rule 6: Windows workstation indicators
    if 3389 in open_ports:
        return "workstation"
    if {135, 139, 445}.issubset(open_ports):
        return "workstation"

    # Rule 7: SSH without RDP and not mobile → server fallback
    if 22 in open_ports and 3389 not in open_ports:
        if not _vendor_matches(vendor_lower, MOBILE_VENDOR_PATTERNS):
            return "server"

    # Rule 8: Default
    return "unknown"


def _vendor_matches(vendor_lower: str, patterns: list[str]) -> bool:
    """Check if a lowercased vendor string matches any pattern."""
    if not vendor_lower:
        return False
    return any(pattern in vendor_lower for pattern in patterns)
