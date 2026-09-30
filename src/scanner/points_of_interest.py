"""High-signal points of interest extracted from schema intelligence."""

from __future__ import annotations

from typing import Any, Dict, List

from src.scanner.operation_pack import ID_ARGUMENT_NAMES
from src.scanner.path_enumerator import SENSITIVE_KEYWORDS, normalize_schema


PII_KEYWORDS = (
    "address",
    "birth",
    "card",
    "dob",
    "email",
    "license",
    "mobile",
    "passport",
    "phone",
    "ssn",
    "tax",
)


def build_points_of_interest(
    schema_data: Dict[str, Any],
    operation_pack: Dict[str, Any],
    path_report: Dict[str, Any],
    dependency_graph: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    schema = normalize_schema(schema_data)
    operations = operation_pack.get("operations", [])
    paths = path_report.get("paths", [])
    graph_analysis = (dependency_graph or {}).get("analysis", {})

    sensitive_fields = _sensitive_fields(schema)
    risky_mutations = _risky_mutations(operations)
    id_arguments = _id_arguments(operations)
    auth_critical_paths = _auth_critical_paths(paths, operations, graph_analysis)

    return {
        "summary": {
            "sensitive_fields": len(sensitive_fields),
            "risky_mutations": len(risky_mutations),
            "id_arguments": len(id_arguments),
            "auth_critical_paths": len(auth_critical_paths),
        },
        "sensitive_fields": sensitive_fields[:20],
        "risky_mutations": risky_mutations[:20],
        "id_arguments": id_arguments[:20],
        "auth_critical_paths": auth_critical_paths[:20],
    }


def _sensitive_fields(schema: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    for type_def in schema["__schema"].get("types", []):
        type_name = type_def.get("name", "")
        if type_name.startswith("__"):
            continue
        for field in type_def.get("fields") or []:
            field_name = field.get("name", "")
            matched = _matched_keywords(field_name)
            if not matched:
                continue
            findings.append(
                {
                    "location": f"{type_name}.{field_name}",
                    "keywords": matched,
                    "kind": field.get("type", {}).get("kind"),
                    "signal": "sensitive-field",
                }
            )
    findings.sort(key=lambda item: (-len(item["keywords"]), item["location"]))
    return findings


def _risky_mutations(operations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    risky = []
    for operation in operations:
        if operation.get("operation_type") != "mutation":
            continue
        tags = set(operation.get("tags", []))
        if not tags.intersection({"idor-candidate", "input-fuzz-candidate", "sensitive-surface", "requires-input"}):
            continue
        risky.append(
            {
                "operation_name": operation.get("operation_name"),
                "risk_score": operation.get("risk_score", 0),
                "tags": operation.get("tags", []),
                "required_args": operation.get("required_args", []),
            }
        )
    risky.sort(key=lambda item: (-item["risk_score"], item["operation_name"] or ""))
    return risky


def _id_arguments(operations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    items = []
    for operation in operations:
        for arg in operation.get("all_args", []):
            if arg.get("name", "").lower() not in ID_ARGUMENT_NAMES:
                continue
            items.append(
                {
                    "operation_name": operation.get("operation_name"),
                    "argument": arg.get("name"),
                    "type": arg.get("type"),
                    "tags": operation.get("tags", []),
                    "risk_score": operation.get("risk_score", 0),
                }
            )
    items.sort(key=lambda item: (-item["risk_score"], item["operation_name"] or ""))
    return items


def _auth_critical_paths(
    paths: List[Dict[str, Any]],
    operations: List[Dict[str, Any]],
    graph_analysis: Dict[str, Any],
) -> List[Dict[str, Any]]:
    idor_targets = {
        (operation.get("return_type") or "").lower()
        for operation in operations
        if "idor-candidate" in operation.get("tags", [])
    }
    graph_targets = {
        (item.get("resource") or "").lower()
        for item in graph_analysis.get("accessors", []) + graph_analysis.get("creators", [])
    }
    critical = []
    for path in paths:
        target = (path.get("target_type") or "").lower()
        if target not in idor_targets and target not in graph_targets and path.get("score", 0) < 40:
            continue
        critical.append(
            {
                "path": path.get("path"),
                "target_type": path.get("target_type"),
                "score": path.get("score", 0),
                "reasons": path.get("reasons", []),
                "required_args": path.get("required_args", []),
            }
        )
    critical.sort(key=lambda item: (-item["score"], item["path"] or ""))
    return critical


def _matched_keywords(name: str) -> List[str]:
    lowered = (name or "").lower()
    keywords = [
        keyword
        for keyword in [*SENSITIVE_KEYWORDS, *PII_KEYWORDS]
        if keyword.lower() in lowered
    ]
    return sorted(set(keywords))
