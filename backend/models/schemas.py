"""Pydantic request/response models for all API endpoints."""

from datetime import UTC, datetime
from typing import Generic, Literal, Optional, TypeVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

# --- Response Envelope ---

T = TypeVar("T")


class Meta(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SuccessResponse(BaseModel, Generic[T]):
    success: bool = True
    data: T
    meta: Meta = Field(default_factory=Meta)


class ErrorDetail(BaseModel):
    code: str
    message: str
    status_code: int
    details: Optional[dict[str, object]] = None


class ErrorResponse(BaseModel):
    success: bool = False
    error: ErrorDetail
    meta: Meta = Field(default_factory=Meta)


# --- Scan Models ---

ScanProfileType = Literal["quick", "standard", "deep"]
ScanStatusType = Literal["running", "completed", "failed"]
DeviceTypeValue = Literal[
    "router", "server", "workstation", "mobile", "iot", "printer", "unknown"
]
RiskSeverityValue = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
RiskFlagValue = Literal["unexpected", "outdated", "critical"]


class ScanRequest(BaseModel):
    target_cidr: str
    profile: ScanProfileType


class ScanRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    target_cidr: str
    profile: ScanProfileType
    status: ScanStatusType
    host_count: int
    error_msg: Optional[str] = None


# --- Port / CVE Models ---


class PortResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    risk_flag: Optional[RiskFlagValue] = None


class CVEMatchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: str
    cvss_score: Optional[float] = None
    severity: RiskSeverityValue
    description: str
    port: int


# --- Device Models ---


class DeviceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    mac_address: str
    ip_address: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: DeviceTypeValue
    os_guess: Optional[str] = None
    os_accuracy: Optional[int] = None
    risk_score: int
    first_seen_scan: int
    last_seen_scan: int


class DeviceDetailResponse(DeviceResponse):
    ports: list[PortResponse] = []
    cve_matches: list[CVEMatchResponse] = []
    risk_summary: str = ""


# --- Schedule Models ---


class ScheduleConfig(BaseModel):
    cron_expression: Optional[str] = None
    target_cidr: Optional[str] = None
    profile: Optional[ScanProfileType] = None


# --- CVE Status ---


class CVEIndexStatus(BaseModel):
    download_complete: bool
    last_updated: Optional[str] = None
    cve_count: int
    downloading: bool
    download_progress: Optional[float] = None


# --- Scan Progress (SSE) ---

ScanEventType = Literal[
    "arp_complete", "host_scanned", "classification_done", "complete", "error"
]


class ScanProgressEvent(BaseModel):
    type: ScanEventType
    message: str
    hosts_found: Optional[int] = None
    hosts_total: Optional[int] = None
    current_host: Optional[str] = None
