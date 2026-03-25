"""Scan profiles — Quick / Standard / Deep nmap configurations."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    """Configuration for a scan's nmap behavior."""

    name: str
    arp_only: bool
    nmap_args: str
    os_detection: bool
    version_detection: bool
    top_ports: int | None  # None = all ports
    timing: str  # -T2 / -T3 / -T4


PROFILES: dict[str, ScanProfile] = {
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
        arp_only=False,
        nmap_args="-sS -sV --top-ports 1000 -T3",
        os_detection=False,
        version_detection=True,
        top_ports=1000,
        timing="-T3",
    ),
    "deep": ScanProfile(
        name="deep",
        arp_only=False,
        nmap_args="-sS -sV -O --top-ports 65535 -T4",
        os_detection=True,
        version_detection=True,
        top_ports=None,
        timing="-T4",
    ),
}


def get_profile(name: str) -> ScanProfile:
    """Get a scan profile by name. Raises ValueError for unknown profiles."""
    if name not in PROFILES:
        raise ValueError(f"Unknown scan profile: {name!r}. Valid: {list(PROFILES.keys())}")
    return PROFILES[name]
