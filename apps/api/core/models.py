from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VulnClass(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    IDOR = "idor"
    BROKEN_AUTH = "broken_auth"
    INFO_DISCLOSURE = "info_disclosure"


class VulnStatus(str, Enum):
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    EXPLOITED = "exploited"


class ScanRequest(BaseModel):
    repo_url: str
    deployed_url: str


class ScanResponse(BaseModel):
    scan_id: str
    ws_url: str


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: float
    current_stage: str


class ScanEvent(BaseModel):
    type: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload: dict[str, Any] = Field(default_factory=dict)


class CVEMatch(BaseModel):
    cve_id: str
    similarity: float


class FunctionInfo(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_path: str
    name: str
    line: int
    source_code: str
    parameters: list[str] = Field(default_factory=list)
    risk_signals: list[str] = Field(default_factory=list)
    cve_matches: list[CVEMatch] = Field(default_factory=list)


class EndpointInfo(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    method: str
    path: str
    parameters: list[str] = Field(default_factory=list)
    auth_required: bool | None = None


class Vulnerability(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vuln_class: VulnClass
    severity: Severity
    status: VulnStatus = VulnStatus.SUSPECTED
    confidence: float = 0.0
    function_id: str | None = None
    endpoint_id: str | None = None
    title: str = ""
    description: str = ""


class ExploitResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vulnerability_id: str
    endpoint_id: str
    technique: str
    payload: str
    response_status: int | None = None
    response_body: str = ""
    proof: str = ""
    repro_curl: str = ""
    success: bool = False


class Correlation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    function_id: str
    endpoint_id: str
    confidence: float
    reasoning: str
