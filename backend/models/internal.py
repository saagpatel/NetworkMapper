"""Internal pipeline data types — used between scanner modules, never cross API boundary."""

from dataclasses import dataclass, field


@dataclass
class PortResult:
    """A single port result from an nmap scan."""

    port: int
    protocol: str  # "tcp" | "udp"
    state: str  # "open" | "filtered" | "closed"
    service: str | None = None
    version: str | None = None


@dataclass
class NmapHostResult:
    """Result of scanning a single host with nmap."""

    ip: str
    mac: str | None = None
    hostname: str | None = None
    state: str = "up"
    ports: list[PortResult] = field(default_factory=list)
    os_guess: str | None = None
    os_accuracy: int = 0


@dataclass
class CVERecord:
    """A single CVE entry from the NVD database."""

    cve_id: str  # "CVE-2024-12345"
    description: str
    cvss_score: float | None = None
    severity: str | None = None  # CRITICAL/HIGH/MEDIUM/LOW
    products: list[str] = field(default_factory=list)  # normalized product names
    versions: list[str] = field(default_factory=list)  # affected version strings


@dataclass
class ClassifiedDevice:
    """A device after classification — enriched with vendor and device_type."""

    ip: str
    mac: str
    hostname: str | None
    vendor: str | None
    device_type: str  # DeviceTypeValue literal
    os_guess: str | None
    os_accuracy: int
    ports: list[PortResult] = field(default_factory=list)
