"""Build relationship views across schema findings, paths, and operations."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def build_relationship_map(report: Dict[str, Any]) -> Dict[str, Any]:
    return build_relationship_map_from_parts(
        sensitive_field_review=report.get("sensitive_field_review", {}),
        points_of_interest=report.get("points_of_interest", {}),
        path_report=report.get("paths", {}),
        operation_pack=report.get("operation_pack", {}),
        authorization_matrix=report.get("authorization_matrix", {}),
    )


def build_relationship_map_from_parts(
    *,
    sensitive_field_review: Dict[str, Any],
    points_of_interest: Dict[str, Any],
    path_report: Dict[str, Any],
    operation_pack: Dict[str, Any],
    authorization_matrix: Dict[str, Any],
) -> Dict[str, Any]:
    reviewed_fields = list(sensitive_field_review.get("reported") or [])
    auth_paths = list(points_of_interest.get("auth_critical_paths") or path_report.get("paths") or [])
    operations = list(operation_pack.get("operations") or [])
    resource_checks = list(authorization_matrix.get("resource_checks") or [])
    mutation_vulns = list(authorization_matrix.get("mutation_vulnerabilities") or [])
    subscription_vulns = list(authorization_matrix.get("subscription_vulnerabilities") or [])

    items: List[Dict[str, Any]] = []
    with_paths = 0
    with_operations = 0
    with_auth_signals = 0

    for entry in reviewed_fields:
        location = entry.get("location") or ""
        if "." not in location:
            continue
        parent_type, field_name = location.split(".", 1)
        parent_type_lower = parent_type.lower()
        field_name_lower = field_name.lower()

        related_paths = [
            path
            for path in auth_paths
            if (path.get("target_type") or "").lower() == parent_type_lower
            or parent_type_lower in (path.get("path") or "").lower()
        ][:4]

        related_operations = sorted(
            [
                operation
                for operation in operations
                if _operation_matches_field(operation, parent_type_lower, field_name_lower)
            ],
            key=lambda item: (-item.get("risk_score", 0), item.get("operation_name") or ""),
        )[:5]

        related_resource_checks = [
            item
            for item in resource_checks
            if (item.get("resource") or "").lower() == parent_type_lower and item.get("vulnerable_roles")
        ][:4]

        related_mutation_checks = [
            item
            for item in mutation_vulns
            if (item.get("resource") or "").lower() == parent_type_lower
            or parent_type_lower in (item.get("operation_name") or "").lower()
        ][:3]

        related_subscription_checks = [
            item
            for item in subscription_vulns
            if parent_type_lower in (item.get("operation_name") or "").lower()
        ][:2]

        if related_paths:
            with_paths += 1
        if related_operations:
            with_operations += 1
        if related_resource_checks or related_mutation_checks or related_subscription_checks:
            with_auth_signals += 1

        items.append(
            {
                "location": location,
                "field_type": entry.get("field_type"),
                "disposition": entry.get("disposition"),
                "review_score": entry.get("review_score"),
                "matched_keywords": entry.get("matched_keywords", []),
                "sources": entry.get("sources", []),
                "related_paths": related_paths,
                "related_operations": related_operations,
                "related_resource_checks": related_resource_checks,
                "related_mutation_checks": related_mutation_checks,
                "related_subscription_checks": related_subscription_checks,
                "recommended_focus": _recommended_focus(
                    location,
                    related_paths,
                    related_operations,
                    related_resource_checks,
                    related_mutation_checks,
                    related_subscription_checks,
                ),
            }
        )

    return {
        "summary": {
            "sensitive_fields_mapped": len(items),
            "fields_with_paths": with_paths,
            "fields_with_operations": with_operations,
            "fields_with_auth_signals": with_auth_signals,
        },
        "items": items[:20],
    }


def _operation_matches_field(operation: Dict[str, Any], parent_type_lower: str, field_name_lower: str) -> bool:
    return_type = (operation.get("return_type") or "").lower()
    operation_name = (operation.get("operation_name") or "").lower()
    tags = set(operation.get("tags") or [])
    arg_names = " ".join(arg.get("name", "") for arg in operation.get("all_args") or []).lower()
    searchable = " ".join([operation_name, return_type, arg_names])

    if return_type == parent_type_lower:
        return True
    if parent_type_lower in searchable and field_name_lower in searchable:
        return True
    if field_name_lower in searchable and tags.intersection({"sensitive-surface", "idor-candidate", "object-accessor"}):
        return True
    return parent_type_lower in searchable and tags.intersection({"idor-candidate", "sensitive-surface", "object-accessor", "state-changing"})


def _recommended_focus(
    location: str,
    related_paths: List[Dict[str, Any]],
    related_operations: List[Dict[str, Any]],
    related_resource_checks: List[Dict[str, Any]],
    related_mutation_checks: List[Dict[str, Any]],
    related_subscription_checks: List[Dict[str, Any]],
) -> str:
    if related_resource_checks:
        top = related_resource_checks[0]
        return (
            f"Start with {top.get('accessor', 'the accessor operation')} against "
            f"{top.get('resource', 'the mapped resource')} #{top.get('id', '?')} because Guardian already "
            f"saw cross-role exposure tied to {location}."
        )
    if related_mutation_checks:
        return (
            f"Validate {related_mutation_checks[0].get('operation_name', 'the related mutation')} "
            f"because it touches the same object type as {location}."
        )
    if related_subscription_checks:
        return (
            f"Check the related subscription path for {location} because Guardian found a subscription auth signal."
        )
    if related_paths and related_operations:
        return (
            f"Follow {related_paths[0].get('path', 'the highest-scoring path')} with "
            f"{related_operations[0].get('operation_name', 'the related operation')} to verify access around {location}."
        )
    if related_operations:
        return (
            f"Use {related_operations[0].get('operation_name', 'the related operation')} as the first verification step for {location}."
        )
    return f"Review {location} manually because no direct access-control path was mapped for it yet."
