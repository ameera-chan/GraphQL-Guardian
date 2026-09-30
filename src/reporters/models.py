from dataclasses import dataclass, asdict, field as dataclass_field
from typing import Optional, Any, Dict, List
import uuid
from datetime import datetime


STATE_ALIASES = {
    "confirmed": "confirmed",
    "reviewed": "confirmed",
    "possible": "possible",
    "probable": "possible",
    "needs-review": "possible",
    "needs_review": "possible",
    "informational": "informational",
    "info": "informational",
}


def normalize_state(state: Optional[str], severity: Optional[str] = None) -> str:
    if severity and str(severity).upper() == "INFO":
        return "informational"
    return STATE_ALIASES.get(str(state or "").lower(), "possible")


@dataclass
class HTTPRequestEvidence:
    method: str
    url: str
    headers: Dict[str, str] = dataclass_field(default_factory=dict)
    body: Optional[Any] = None


@dataclass
class HTTPResponseEvidence:
    status_code: int = 0
    response_time_ms: Optional[float] = None
    headers: Dict[str, str] = dataclass_field(default_factory=dict)
    body_sample: Optional[str] = None


@dataclass
class EvidenceArtifact:
    type: str
    path: str
    description: Optional[str] = None


@dataclass
class Evidence:
    rule_id: str
    confidence: str
    state: str
    details: Optional[Any] = None
    request: Optional[HTTPRequestEvidence] = None
    response: Optional[HTTPResponseEvidence] = None
    reproduction: Optional[str] = None
    artifacts: List[EvidenceArtifact] = dataclass_field(default_factory=list)


@dataclass
class Finding:
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # CONFIG, DOS, INJECTION, AUTH
    endpoint: Optional[str] = None
    operation_name: Optional[str] = None
    field: Optional[str] = None
    evidence: Optional[Any] = None
    remediation: Optional[str] = None
    risk: Optional[Dict[str, Any]] = None
    rule_id: Optional[str] = None
    confidence: str = "medium"
    state: str = "possible"
    reproduction: Optional[str] = None
    ai_validation: Optional[Dict[str, Any]] = None
    timestamp: str = dataclass_field(default_factory=lambda: datetime.now().isoformat())
    id: str = dataclass_field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict:
        data = asdict(self)
        data["state"] = normalize_state(self.state, self.severity)
        data["verification_status"] = data["state"]
        return data
