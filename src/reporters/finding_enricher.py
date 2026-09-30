"""Normalize explanation and remediation quality across findings."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Dict, List

from src.reporters.models import Finding, normalize_state
from src.risk.rating import rate_finding


DEFAULT_REMEDIATION = {
    "AUTH": "Verify authentication and authorization server-side for this flow, then replay the captured request to confirm the control blocks the behavior.",
    "CONFIG": "Reduce the exposed attack surface for this behavior and confirm the server rejects the captured request pattern after the fix.",
    "RECON": "Review whether this exposed behavior is intended in production and remove or restrict it if it helps attackers map the GraphQL surface.",
    "AUDIT": "Confirm the schema element is intentionally exposed and apply field-level restrictions, masking, or redesign if it should not be broadly visible.",
    "INJECTION": "Validate and constrain the affected input server-side, then replay the payload carefully in a controlled environment to confirm the issue is closed.",
    "DOS": "Add server-side complexity, depth, batching, or rate protections and re-run the captured request pattern in a safe environment to confirm the limit works.",
}

WHY_IT_MATTERS = {
    "AUTH": "Authentication or access-control weaknesses can let attackers impersonate users, recover session data, or perform actions outside their allowed role.",
    "CONFIG": "Misconfigurations often turn otherwise ordinary GraphQL features into easy entry points for reconnaissance, request forgery, or abuse.",
    "RECON": "Even informational GraphQL exposure can materially reduce attacker effort by revealing endpoints, engines, schemas, or transport behavior.",
    "AUDIT": "Schema and data-surface issues often become the bridge between harmless discovery and real sensitive-data exposure.",
    "INJECTION": "Injection weaknesses can let attacker-controlled input alter backend behavior, leak data, or trigger follow-on compromise.",
    "DOS": "GraphQL-specific denial-of-service patterns can amplify backend work and exhaust server resources with surprisingly small requests.",
}

POSSIBLE_SIGNAL_TERMS = (
    "reflected payload",
    "sensitive field",
    "reviewed sensitive field",
    "subscription exposed",
    "websocket endpoint active",
    "bidirectional relationships",
    "pagination override",
    "field suggestions",
    "inconclusive",
    "candidate",
)

CONFIRMED_SIGNAL_TERMS = (
    "sql injection error",
    "stored xss",
    "authorization bypass",
    "anonymous access executed",
    "unauthorized access",
)


def enrich_findings(findings: List[Finding]) -> List[Finding]:
    for finding in findings:
        _enrich_finding(finding)
    return findings


def enrich_finding_dicts(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for finding in findings:
        _enrich_finding_dict(finding)
    return findings


def _enrich_finding(finding: Finding) -> None:
    if not finding.risk:
        # Recalculate severity from category, likelihood, impact, and evidence factors.
        finding.risk = rate_finding(
            category=finding.category,
            severity=finding.severity,
        )
        finding.severity = finding.risk["severity"]

    evidence = _normalize_evidence(finding.evidence)
    details = evidence.setdefault("details", {})
    if not isinstance(details, dict):
        details = {"raw": details}
        evidence["details"] = details

    # Add explanation fields used by the dashboard and formal report.
    details.setdefault("why_it_matters", WHY_IT_MATTERS.get(finding.category, "This finding may help an attacker compromise confidentiality, integrity, or availability if the behavior is confirmed."))
    details.setdefault("verification_guidance", _verification_guidance(finding, evidence))
    finding.state, verification_reason = _classify_finding_state(
        title=finding.title,
        description=finding.description,
        category=finding.category,
        severity=finding.severity,
        current_state=finding.state,
        confidence=finding.confidence,
        evidence=evidence,
    )
    details.setdefault("verification_status", finding.state)
    details.setdefault("verification_reason", verification_reason)

    if not finding.remediation:
        # Use category defaults when a scanner module did not provide a specific fix.
        finding.remediation = DEFAULT_REMEDIATION.get(
            finding.category,
            "Replay the captured behavior after remediation to confirm the issue is no longer reproducible.",
        )

    finding.evidence = evidence


def _enrich_finding_dict(finding: Dict[str, Any]) -> None:
    if not finding.get("risk"):
        finding["risk"] = rate_finding(
            category=finding.get("category"),
            severity=finding.get("severity"),
        )
        finding["severity"] = finding["risk"]["severity"]

    evidence = _normalize_evidence(finding.get("evidence"))
    details = evidence.setdefault("details", {})
    if not isinstance(details, dict):
        details = {"raw": details}
        evidence["details"] = details

    category = finding.get("category")
    details.setdefault("why_it_matters", WHY_IT_MATTERS.get(category, "This finding may help an attacker compromise confidentiality, integrity, or availability if the behavior is confirmed."))
    details.setdefault("verification_guidance", _verification_guidance_dict(finding, evidence))
    status, verification_reason = _classify_finding_state(
        title=finding.get("title"),
        description=finding.get("description"),
        category=category,
        severity=finding.get("severity"),
        current_state=finding.get("state"),
        confidence=finding.get("confidence"),
        evidence=evidence,
    )
    finding["state"] = status
    finding["verification_status"] = status
    details.setdefault("verification_status", status)
    details.setdefault("verification_reason", verification_reason)

    if not finding.get("remediation"):
        finding["remediation"] = DEFAULT_REMEDIATION.get(
            category,
            "Replay the captured behavior after remediation to confirm the issue is no longer reproducible.",
        )

    finding["evidence"] = evidence


def _classify_finding_state(
    *,
    title: Any,
    description: Any,
    category: Any,
    severity: Any,
    current_state: Any,
    confidence: Any,
    evidence: Dict[str, Any],
) -> tuple[str, str]:
    severity_name = str(severity or "INFO").upper()
    if severity_name == "INFO":
        return "informational", "The finding is useful for reconnaissance, but it is not a confirmed vulnerability by itself."

    state = normalize_state(current_state, severity_name)
    if state == "informational":
        return "informational", "The scanner marked this as security information rather than a confirmed vulnerability."

    text = " ".join(
        str(part or "")
        for part in (
            title,
            description,
            category,
            evidence.get("details"),
        )
    ).lower()

    has_request = bool(evidence.get("request"))
    has_response = bool(evidence.get("response"))
    has_reproduction = bool(evidence.get("reproduction"))
    confidence_name = str(confidence or "").lower()

    if any(term in text for term in POSSIBLE_SIGNAL_TERMS):
        return "possible", "Guardian found a useful signal, but this type needs manual proof before it is treated as confirmed."

    if any(term in text for term in CONFIRMED_SIGNAL_TERMS) and (has_response or has_reproduction):
        return "confirmed", "Guardian captured evidence that directly shows the vulnerable behavior."

    if str(category or "").upper() == "AUTH" and has_request and has_response:
        return "confirmed", "Guardian compared an access-control request and response for the affected role."

    if has_request and has_response and confidence_name == "high":
        return "confirmed", "Guardian captured request and response evidence with high confidence."

    if state == "confirmed" and (has_response or has_reproduction):
        return "confirmed", "Guardian kept this as confirmed because replayable evidence is present."

    return "possible", "Guardian found a strong sign, but the report does not include enough proof to mark it confirmed."


def _normalize_evidence(evidence: Any) -> Dict[str, Any]:
    if evidence is None:
        return {}
    if isinstance(evidence, dict):
        return dict(evidence)
    if is_dataclass(evidence):
        return asdict(evidence)
    return {"details": {"raw": str(evidence)}}


def _verification_guidance(finding: Finding, evidence: Dict[str, Any]) -> List[str]:
    guidance: List[str] = []
    if finding.reproduction or evidence.get("reproduction"):
        guidance.append("Replay the stored reproduction command and compare the response with the finding evidence.")
    if evidence.get("request"):
        guidance.append("Review the stored request to confirm the exact GraphQL operation, arguments, and headers that triggered the behavior.")
    if evidence.get("response"):
        guidance.append("Inspect the stored response status, body sample, and timing to verify the behavior is observable and repeatable.")

    category_specific = {
        "AUTH": "Re-test the flow with the intended role and with a less-privileged or anonymous role to confirm the access decision really changes.",
        "AUDIT": "Query the referenced field or schema element with the lowest-privilege context available and confirm whether the sensitive value is actually reachable.",
        "CONFIG": "Retry the request through the same transport or endpoint variant after configuration changes to confirm the surface is closed.",
        "INJECTION": "Use a safe, controlled payload variant first and compare the server response before trying stronger payloads in a lab target only.",
        "DOS": "Only verify this against a controlled target and watch server timing or error behavior rather than scaling the request aggressively.",
        "RECON": "Confirm the exposed endpoint, IDE, or protocol behavior still appears from an unauthenticated or minimally privileged client.",
    }.get(finding.category)

    if category_specific:
        guidance.append(category_specific)

    return guidance


def _verification_guidance_dict(finding: Dict[str, Any], evidence: Dict[str, Any]) -> List[str]:
    proxy = type(
        "FindingProxy",
        (),
        {
            "reproduction": finding.get("reproduction"),
            "category": finding.get("category"),
            "remediation": finding.get("remediation"),
        },
    )()
    return _verification_guidance(proxy, evidence)
