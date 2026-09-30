"""Helpers for reproducible, redacted finding evidence."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, Optional

from src.reporters.models import (
    Evidence,
    EvidenceArtifact,
    HTTPRequestEvidence,
    HTTPResponseEvidence,
)


SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "proxy-authorization",
    "password",
    "passwd",
    "token",
    "secret",
    "session",
}


def default_rule_id(category: str, title: str) -> str:
    """Build a stable rule id from a category and finding title."""
    slug = re.sub(r"[^A-Z0-9]+", "-", title.upper()).strip("-")
    slug = re.sub(r"-+", "-", slug)
    category_slug = re.sub(r"[^A-Z0-9]+", "-", category.upper()).strip("-")
    return f"GG-{category_slug}-{slug[:48]}"


def default_state(severity: str, has_http_evidence: bool = False) -> str:
    """Return a normalized finding state for report consumers."""
    if severity == "INFO":
        return "informational"
    if has_http_evidence:
        return "confirmed"
    return "possible"


def redact_value(key: str, value: Any) -> Any:
    """Redact sensitive values while keeping evidence structurally useful."""
    if key.lower() in SENSITIVE_KEYS:
        return "<redacted>"
    return value


def redact_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """Redact sensitive HTTP headers."""
    redacted: Dict[str, str] = {}
    for key, value in (headers or {}).items():
        redacted[key] = str(redact_value(key, value))
    return redacted


def redact_body(value: Any) -> Any:
    """Recursively redact common secret-bearing JSON keys."""
    if isinstance(value, dict):
        return {key: redact_body(redact_value(key, nested)) for key, nested in value.items()}
    if isinstance(value, list):
        return [redact_body(item) for item in value]
    return value


def sample_text(text: Optional[str], limit: int = 1200) -> Optional[str]:
    """Return a compact response sample for reports."""
    if not text:
        return None
    clean = text.strip()
    if len(clean) <= limit:
        return clean
    return clean[:limit] + "...<truncated>"


def _quote(value: Any) -> str:
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def build_curl_command(
    method: str,
    url: str,
    headers: Optional[Dict[str, Any]] = None,
    body: Optional[Any] = None,
) -> str:
    """Build a copyable cURL command with secrets redacted."""
    parts = ["curl", "-i", "-sS", "-X", method.upper(), _quote(url)]

    for key, value in redact_headers(headers).items():
        parts.extend(["-H", _quote(f"{key}: {value}")])

    if body is not None:
        safe_body = redact_body(body)
        body_text = json.dumps(safe_body, separators=(",", ":"))
        parts.extend(["--data-raw", _quote(body_text)])

    return " ".join(parts)


def _artifact_from_dict(data: Dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        type=str(data.get("type", "artifact")),
        path=str(data.get("path", "")),
        description=data.get("description"),
    )


def normalize_artifacts(artifacts: Optional[Iterable[Any]]) -> list[EvidenceArtifact]:
    """Normalize artifact dicts/dataclasses into EvidenceArtifact objects."""
    normalized: list[EvidenceArtifact] = []
    for artifact in artifacts or []:
        if isinstance(artifact, EvidenceArtifact):
            normalized.append(artifact)
        elif isinstance(artifact, dict):
            normalized.append(_artifact_from_dict(artifact))
    return normalized


def request_from_response(response: Any) -> Optional[HTTPRequestEvidence]:
    """Extract request evidence from GraphQLResponse-like objects."""
    method = getattr(response, "request_method", None)
    url = getattr(response, "request_url", None)
    if not method or not url:
        return None
    return HTTPRequestEvidence(
        method=method,
        url=url,
        headers=redact_headers(getattr(response, "request_headers", None)),
        body=redact_body(getattr(response, "request_body", None)),
    )


def response_from_any(response: Any) -> Optional[HTTPResponseEvidence]:
    """Extract response evidence from dicts or response-like objects."""
    if response is None:
        return None
    if isinstance(response, dict):
        return HTTPResponseEvidence(
            status_code=int(response.get("status_code", 0) or 0),
            response_time_ms=response.get("response_time_ms"),
            headers=redact_headers(response.get("headers")),
            body_sample=sample_text(response.get("body_sample") or response.get("raw_text")),
        )
    return HTTPResponseEvidence(
        status_code=int(getattr(response, "status_code", 0) or 0),
        response_time_ms=round(float(getattr(response, "response_time", 0.0)) * 1000, 2),
        headers=redact_headers(getattr(response, "response_headers", None)),
        body_sample=sample_text(getattr(response, "raw_text", None)),
    )


def request_from_any(request: Any) -> Optional[HTTPRequestEvidence]:
    """Normalize a manual request dict or an HTTPRequestEvidence instance."""
    if request is None:
        return None
    if isinstance(request, HTTPRequestEvidence):
        return request
    if isinstance(request, dict):
        return HTTPRequestEvidence(
            method=str(request.get("method", "GET")),
            url=str(request.get("url", "")),
            headers=redact_headers(request.get("headers")),
            body=redact_body(request.get("body")),
        )
    return None


def build_evidence(
    *,
    rule_id: str,
    confidence: str,
    state: str,
    details: Optional[Any] = None,
    request: Optional[Any] = None,
    response: Optional[Any] = None,
    artifacts: Optional[Iterable[Any]] = None,
    reproduction: Optional[str] = None,
) -> Evidence:
    """Create a normalized Evidence object for a finding."""
    request_evidence = request_from_any(request) or request_from_response(response)
    response_evidence = response_from_any(response)

    if not reproduction and request_evidence:
        reproduction = build_curl_command(
            request_evidence.method,
            request_evidence.url,
            request_evidence.headers,
            request_evidence.body,
        )

    return Evidence(
        rule_id=rule_id,
        confidence=confidence,
        state=state,
        details=redact_body(details),
        request=request_evidence,
        response=response_evidence,
        reproduction=reproduction,
        artifacts=normalize_artifacts(artifacts),
    )
