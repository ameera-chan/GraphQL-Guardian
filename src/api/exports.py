"""Helpers for exporting scan artifacts for manual workflows."""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse


DEFAULT_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}


def build_finding_dossier(
    report: Dict[str, Any],
    *,
    scan_id: str = "",
    finding_id: str | None = None,
) -> Dict[str, Any]:
    findings = list(report.get("findings") or [])
    relationship_map = report.get("relationship_map") or {}
    selected = [
        finding for finding in findings
        if (finding_id and finding.get("id") == finding_id) or (not finding_id and _is_important_finding(finding))
    ]

    items = []
    for finding in selected:
        items.append(
            {
                "finding": finding,
                "reproduction": finding.get("reproduction") or (finding.get("evidence") or {}).get("reproduction"),
                "evidence": finding.get("evidence"),
                "relationship_context": _relationship_context_for_finding(relationship_map, finding),
                "verification_steps": _verification_steps_for_finding(finding),
            }
        )

    return {
        "scan_id": scan_id,
        "endpoint": report.get("metadata", {}).get("endpoint"),
        "summary": {
            "total_items": len(items),
            "critical": sum(1 for item in items if item["finding"].get("severity") == "CRITICAL"),
            "high": sum(1 for item in items if item["finding"].get("severity") == "HIGH"),
            "medium": sum(1 for item in items if item["finding"].get("severity") == "MEDIUM"),
        },
        "items": items,
    }


def render_finding_dossier_text(export_payload: Dict[str, Any]) -> str:
    items = export_payload.get("items") or []
    if not items:
        return "# finding-dossier\n\nNo important findings were available for export."

    lines = [
        "# finding-dossier",
        f"scan_id: {export_payload.get('scan_id', '')}",
        f"endpoint: {export_payload.get('endpoint', '')}",
        f"items: {len(items)}",
    ]

    for item in items:
        finding = item.get("finding") or {}
        evidence = finding.get("evidence") or {}
        relationship_context = item.get("relationship_context") or {}
        lines.extend(
            [
                "",
                f"## {finding.get('title', 'finding')}",
                f"finding_id: {finding.get('id', '')}",
                f"severity: {finding.get('severity', '')}",
                f"category: {finding.get('category', '')}",
                f"state: {finding.get('state', '')}",
                f"confidence: {finding.get('confidence', '')}",
                f"field: {finding.get('field', '')}",
                "",
                "### description",
                finding.get("description", "") or "-",
                "",
                "### evidence",
                json.dumps(evidence, indent=2),
                "",
                "### reproduction",
                item.get("reproduction") or "-",
                "",
                "### remediation",
                finding.get("remediation", "") or "-",
                "",
                "### relationship_context",
                json.dumps(relationship_context, indent=2),
                "",
                "### verification_steps",
            ]
        )
        for step in item.get("verification_steps") or ["-"]:
            lines.append(f"- {step}")

    return "\n".join(lines)


def render_relationship_map_text(report: Dict[str, Any]) -> str:
    relationship_map = report.get("relationship_map") or {}
    items = relationship_map.get("items") or []
    lines = [
        "# relationship-map",
        json.dumps(relationship_map.get("summary") or {}, indent=2),
    ]
    if not items:
        lines.append("\nNo mapped relationships were available.")
        return "\n".join(lines)

    for item in items:
        lines.extend(
            [
                "",
                f"## {item.get('location', 'unknown')}",
                f"score: {item.get('review_score', '')}",
                f"disposition: {item.get('disposition', '')}",
                f"recommended_focus: {item.get('recommended_focus', '')}",
                "",
                "### related_paths",
                json.dumps(item.get("related_paths") or [], indent=2),
                "",
                "### related_operations",
                json.dumps(item.get("related_operations") or [], indent=2),
                "",
                "### auth_signals",
                json.dumps(
                    {
                        "resource_checks": item.get("related_resource_checks") or [],
                        "mutation_checks": item.get("related_mutation_checks") or [],
                        "subscription_checks": item.get("related_subscription_checks") or [],
                    },
                    indent=2,
                ),
            ]
        )
    return "\n".join(lines)


def render_operation_pack_text(report: Dict[str, Any]) -> str:
    operation_pack = report.get("operation_pack", {})
    sections = []
    for pack_name, operations in (operation_pack.get("packs") or {}).items():
        lines = [f"# {pack_name}"]
        for operation in operations:
            document = operation.get("full_operation") or operation.get("operation")
            if not document:
                continue
            lines.append(f"## {operation.get('operation_name', 'unknown')}")
            lines.append(f"# tags: {', '.join(operation.get('tags', []))}")
            lines.append(document)
        if len(lines) > 1:
            sections.append("\n\n".join(lines))
    if not sections:
        sections.append("# operation-pack\n\nNo generated operations available.")
    return "\n\n".join(sections)


def render_points_of_interest_text(report: Dict[str, Any]) -> str:
    poi = report.get("points_of_interest", {})
    sections = []
    sections.append(_render_section("Sensitive fields", poi.get("sensitive_fields", []), lambda item: item.get("location", "")))
    sections.append(_render_section("Risky mutations", poi.get("risky_mutations", []), lambda item: item.get("operation_name", "")))
    sections.append(_render_section("ID arguments", poi.get("id_arguments", []), lambda item: f"{item.get('operation_name', '')} :: {item.get('argument', '')}"))
    sections.append(_render_section("Auth-critical paths", poi.get("auth_critical_paths", []), lambda item: item.get("path", "")))
    return "\n\n".join(sections)


def render_manual_finding_provenance_text(export_payload: Dict[str, Any]) -> str:
    items = export_payload.get("items") or []
    if not items:
        return "# manual-finding-provenance\n\nNo promoted manual findings were available for export."

    sections = [
        "# manual-finding-provenance",
        f"scan_id: {export_payload.get('scan_id', '')}",
        f"endpoint: {export_payload.get('endpoint', '')}",
        f"items: {len(items)}",
    ]

    for item in items:
        finding = item.get("finding") or {}
        note = item.get("note") or {}
        promotion = item.get("promotion") or {}
        replay_history = item.get("replay_history") or []
        sections.extend(
            [
                "",
                f"## {finding.get('title') or item.get('finding_id') or 'manual-finding'}",
                f"finding_id: {item.get('finding_id', '')}",
                f"operation: {item.get('operation_name', '')}",
                f"severity: {finding.get('severity', '')}",
                f"category: {finding.get('category', '')}",
                f"promoted_at: {promotion.get('promoted_at', '')}",
                f"note_status: {promotion.get('note_status', '')}",
                f"manual_mode_path: {promotion.get('manual_mode_path', '')}",
                "",
                "### description",
                finding.get("description", "") or "-",
                "",
                "### note",
                json.dumps(note, indent=2),
                "",
                "### request_override",
                json.dumps(item.get("request_override"), indent=2),
                "",
                "### replay_history",
                json.dumps(replay_history, indent=2),
            ]
        )

    return "\n".join(sections)


def to_pretty_json(data: Any) -> str:
    return json.dumps(data, indent=2)


def render_operation_pack_http(report: Dict[str, Any]) -> str:
    requests = build_operation_pack_requests(report)
    if not requests:
        return "# burp-http\n\nNo generated operations available."

    sections = []
    for request in requests:
        sections.append(
            "\n".join(
                [
                    f"# {request['role']} :: {request['name']}",
                    request["raw_http"],
                ]
            )
        )
    return "\n\n".join(sections)


def render_intruder_payloads(report: Dict[str, Any]) -> str:
    requests = build_operation_pack_requests(report)
    if not requests:
        return ""
    return "\n".join(json.dumps(item["body"], separators=(",", ":")) for item in requests)


def build_repeater_collection(report: Dict[str, Any]) -> Dict[str, Any]:
    requests = build_operation_pack_requests(report)
    endpoint = report.get("metadata", {}).get("endpoint", "")
    return {
        "format": "guardian-burp-repeater/v1",
        "endpoint": endpoint,
        "generated_at": report.get("metadata", {}).get("completed_at"),
        "items": requests,
    }


def build_operation_pack_requests(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    operation_pack = report.get("operation_pack", {})
    endpoint = report.get("metadata", {}).get("endpoint", "")
    request_meta = _request_metadata(endpoint)
    items: List[Dict[str, Any]] = []

    for pack_name, operations in (operation_pack.get("packs") or {}).items():
        for operation in operations:
            document = operation.get("full_operation") or operation.get("operation")
            if not document:
                continue

            body = {
                "query": document,
                "variables": {},
            }
            item = {
                "name": operation.get("operation_name", "unknown"),
                "role": pack_name,
                "tags": operation.get("tags", []),
                "method": "POST",
                "url": endpoint,
                "headers": DEFAULT_HEADERS,
                "body": body,
                "raw_http": _raw_http_request(request_meta, body),
            }
            items.append(item)

    return items


def _render_section(title: str, items: Iterable[Dict[str, Any]], label_fn) -> str:
    lines = [f"# {title}"]
    collected = list(items or [])
    if not collected:
        lines.append("- None")
        return "\n".join(lines)
    for item in collected:
        lines.append(f"- {label_fn(item)}")
    return "\n".join(lines)


def _is_important_finding(finding: Dict[str, Any]) -> bool:
    severity = finding.get("severity")
    state = finding.get("state")
    source = finding.get("source")
    evidence = finding.get("evidence") or {}
    return (
        severity in {"CRITICAL", "HIGH", "MEDIUM"}
        or state in {"confirmed", "reviewed", "needs-review"}
        or source == "manual"
        or bool(finding.get("reproduction") or evidence.get("reproduction"))
    )


def _relationship_context_for_finding(relationship_map: Dict[str, Any], finding: Dict[str, Any]) -> Dict[str, Any]:
    field = finding.get("field")
    operation_name = finding.get("operation_name")
    for item in relationship_map.get("items") or []:
        if field and item.get("location") == field:
            return item
        related_operations = item.get("related_operations") or []
        if operation_name and any(op.get("operation_name") == operation_name for op in related_operations):
            return item
    return {}


def _verification_steps_for_finding(finding: Dict[str, Any]) -> List[str]:
    evidence = finding.get("evidence") or {}
    details = evidence.get("details") or {}
    if isinstance(details, dict) and details.get("verification_guidance"):
        return list(details["verification_guidance"])
    steps = []
    if finding.get("reproduction") or evidence.get("reproduction"):
        steps.append("Replay the captured reproduction command and confirm the server response matches the report.")
    if evidence.get("request"):
        steps.append("Compare the stored request payload with the target's expected authorization or validation controls.")
    if evidence.get("response"):
        steps.append("Review the stored HTTP status, body sample, and timing for proof of the condition.")
    if finding.get("remediation"):
        steps.append("Use the remediation guidance in the finding to verify whether the server-side control is missing or incomplete.")
    return steps or ["Review the finding details and manually confirm the behavior against the target application."]


def _request_metadata(endpoint: str) -> Dict[str, str]:
    parsed = urlparse(endpoint or "http://localhost/graphql")
    host = parsed.netloc or "localhost"
    path = parsed.path or "/graphql"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return {
        "host": host,
        "path": path,
    }


def _raw_http_request(request_meta: Dict[str, str], body: Dict[str, Any]) -> str:
    payload = json.dumps(body, separators=(",", ":"))
    header_lines = "\n".join(f"{name}: {value}" for name, value in DEFAULT_HEADERS.items())
    return (
        f"POST {request_meta['path']} HTTP/1.1\n"
        f"Host: {request_meta['host']}\n"
        f"{header_lines}\n"
        f"Content-Length: {len(payload.encode('utf-8'))}\n"
        f"\n"
        f"{payload}"
    )
