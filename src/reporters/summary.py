"""Shared report-level summaries for human and machine-readable outputs."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Iterable, List

from .models import Finding, normalize_state


SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
STATE_RANK = {"confirmed": 0, "possible": 1, "informational": 2}


def sort_findings_for_report(findings: Iterable[Finding]) -> List[Finding]:
    """Return findings in the order a tester should review them."""
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_RANK.get(str(finding.severity or "INFO").upper(), 5),
            STATE_RANK.get(normalize_state(finding.state, finding.severity), 3),
            str(finding.category or ""),
            str(finding.title or ""),
        ),
    )


def build_remediation_summary(findings: Iterable[Finding]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        remediation = str(finding.remediation or "").strip()
        if not remediation:
            continue
        # Group findings that share the same fix so the report avoids repeated advice.
        item = grouped.setdefault(
            remediation,
            {
                "remediation": remediation,
                "count": 0,
                "highest_severity": "INFO",
                "categories": set(),
                "findings": [],
            },
        )
        item["count"] += 1
        item["categories"].add(str(finding.category or "UNKNOWN").upper())
        if SEVERITY_RANK.get(str(finding.severity).upper(), 5) < SEVERITY_RANK.get(item["highest_severity"], 5):
            item["highest_severity"] = str(finding.severity).upper()
        item["findings"].append(
            {
                "title": finding.title,
                "severity": finding.severity,
                "state": normalize_state(finding.state, finding.severity),
                "category": finding.category,
                "rule_id": finding.rule_id,
            }
        )

    summary = list(grouped.values())
    for item in summary:
        item["categories"] = sorted(item["categories"])
        item["findings"] = sorted(
            item["findings"],
            key=lambda row: (
                SEVERITY_RANK.get(str(row.get("severity") or "INFO").upper(), 5),
                STATE_RANK.get(str(row.get("state") or "possible"), 3),
                str(row.get("title") or ""),
            ),
        )

    return sorted(
        summary,
        key=lambda item: (
            SEVERITY_RANK.get(item["highest_severity"], 5),
            -item["count"],
            item["remediation"],
        ),
    )


def build_evidence_summary(findings: Iterable[Finding]) -> Dict[str, Any]:
    levels = Counter()
    request_response = 0
    reproduction = 0
    ai_reviewed = 0

    for finding in findings:
        evidence = _to_plain(finding.evidence)
        level = evidence_level(finding, evidence)
        # Evidence level helps the tester separate replayable proof from context-only signals.
        levels[level] += 1
        if _has_request(evidence) and _has_response(evidence):
            request_response += 1
        if finding.reproduction or (isinstance(evidence, dict) and evidence.get("reproduction")):
            reproduction += 1
        if finding.ai_validation:
            ai_reviewed += 1

    return {
        "levels": dict(levels),
        "request_response_findings": request_response,
        "replayable_findings": reproduction,
        "ai_reviewed_findings": ai_reviewed,
    }


def evidence_level(finding: Finding, evidence: Any | None = None) -> str:
    data = _to_plain(finding.evidence) if evidence is None else evidence
    if finding.reproduction or (isinstance(data, dict) and data.get("reproduction")):
        return "replayable"
    if _has_request(data) and _has_response(data):
        return "request_response"
    if _has_response(data):
        return "response_only"
    if isinstance(data, dict) and data.get("artifacts"):
        return "artifact"
    if data:
        return "context_only"
    return "not_recorded"


def _has_request(evidence: Any) -> bool:
    return isinstance(evidence, dict) and bool(evidence.get("request"))


def _has_response(evidence: Any) -> bool:
    return isinstance(evidence, dict) and bool(evidence.get("response"))


def _to_plain(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return {key: _to_plain(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [_to_plain(item) for item in value]
    return value
