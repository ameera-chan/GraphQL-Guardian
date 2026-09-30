"""Build compact, pentest-friendly schema overviews for CLI and reports."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.scanner.path_enumerator import normalize_schema
from src.scanner.schema_parser import parse_schema_details


ROOT_TYPE_NAMES = {"Query", "Mutation", "Subscription"}


def build_schema_overview(
    schema_data: Dict[str, Any],
    *,
    endpoint: Optional[str] = None,
    source: Optional[str] = None,
    verified_graphql: Optional[bool] = None,
    discovered_endpoints: Optional[List[str]] = None,
    fingerprint: Optional[Dict[str, Any]] = None,
    path_report: Optional[Dict[str, Any]] = None,
    operation_pack: Optional[Dict[str, Any]] = None,
    dependency_graph: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a concise, schema-aware overview for operators and reports."""

    normalized = normalize_schema(schema_data)
    details = parse_schema_details(normalized)
    type_map = {
        item["name"]: item
        for item in normalized["__schema"].get("types", [])
        if item.get("name")
    }

    root_types = normalized["__schema"]
    query_root = (root_types.get("queryType") or {}).get("name")
    mutation_root = (root_types.get("mutationType") or {}).get("name")
    subscription_root = (root_types.get("subscriptionType") or {}).get("name")

    graph_analysis = (dependency_graph or {}).get("analysis", {})
    creators = graph_analysis.get("creators", [])
    accessors = graph_analysis.get("accessors", [])
    operation_summary = (operation_pack or {}).get("summary", {})
    paths = (path_report or {}).get("paths", [])

    return {
        "target": {
            "endpoint": endpoint,
            "verified_graphql": verified_graphql,
            "discovered_endpoints": discovered_endpoints or [],
            "fingerprint": fingerprint or {},
        },
        "schema_source": source or "unknown",
        "root_types": {
            "query": query_root,
            "mutation": mutation_root,
            "subscription": subscription_root,
        },
        "counts": {
            "types": len([name for name in details.get("types", []) if not name.startswith("__")]),
            "queries": len(details.get("queries", [])),
            "mutations": len(details.get("mutations", [])),
            "subscriptions": len(details.get("subscriptions", [])),
            "input_objects": len(details.get("input_objects", [])),
            "enums": len(details.get("enums", [])),
            "abstract_types": len(details.get("interfaces", [])) + len(details.get("unions", [])),
            "custom_scalars": len(details.get("custom_scalars", [])),
        },
        "samples": {
            "queries": details.get("queries", [])[:8],
            "mutations": details.get("mutations", [])[:8],
            "subscriptions": details.get("subscriptions", [])[:8],
        },
        "key_types": _key_types(type_map, creators, accessors),
        "operation_surface": {
            "total_generated_operations": operation_summary.get("total_operations", 0),
            "access_control_candidates": operation_summary.get("access_control_candidates", 0),
            "injection_candidates": operation_summary.get("injection_candidates", 0),
            "batch_candidates": operation_summary.get("batch_candidates", 0),
            "top_operations": _top_operations(operation_pack),
        },
        "auth_surface": {
            "creators": creators[:8],
            "accessors": accessors[:8],
            "auth_paths": [
                {
                    "path": item.get("path"),
                    "target_type": item.get("target_type"),
                    "score": item.get("score"),
                }
                for item in paths[:8]
            ],
        },
    }


def _key_types(
    type_map: Dict[str, Dict[str, Any]],
    creators: List[Dict[str, Any]],
    accessors: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    creator_resources = {item.get("resource") for item in creators}
    accessor_resources = {item.get("resource") for item in accessors}
    ranked: List[Dict[str, Any]] = []

    for type_name, type_def in type_map.items():
        if type_name.startswith("__") or type_name in ROOT_TYPE_NAMES:
            continue
        if type_def.get("kind") != "OBJECT":
            continue

        fields = type_def.get("fields") or []
        relation_fields = 0
        scalar_fields = 0
        for field in fields:
            inner = _unwrap_type(field.get("type"))
            if not inner:
                continue
            if inner.get("kind") in {"OBJECT", "INTERFACE", "UNION"}:
                relation_fields += 1
            else:
                scalar_fields += 1

        rank = relation_fields * 3 + scalar_fields
        if type_name in creator_resources:
            rank += 8
        if type_name in accessor_resources:
            rank += 8

        ranked.append(
            {
                "type": type_name,
                "fields": len(fields),
                "relation_fields": relation_fields,
                "scalar_fields": scalar_fields,
                "creator_surface": type_name in creator_resources,
                "access_surface": type_name in accessor_resources,
                "score": rank,
            }
        )

    ranked.sort(key=lambda item: (-item["score"], item["type"]))
    return ranked[:10]


def _top_operations(operation_pack: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    operations = (operation_pack or {}).get("operations", [])
    ranked = sorted(
        operations,
        key=lambda item: (-item.get("risk_score", 0), item.get("operation_name", "")),
    )
    return [
        {
            "operation_name": item.get("operation_name"),
            "operation_type": item.get("operation_type"),
            "return_type": item.get("return_type"),
            "tags": item.get("tags", [])[:4],
            "risk_score": item.get("risk_score", 0),
        }
        for item in ranked[:10]
    ]


def _unwrap_type(type_ref: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    current = type_ref
    while current and current.get("kind") in {"NON_NULL", "LIST"}:
        current = current.get("ofType")
    return current
