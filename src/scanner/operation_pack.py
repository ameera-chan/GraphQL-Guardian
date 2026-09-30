"""Generate InQL-style GraphQL operation packs from introspection schemas."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from src.scanner.path_enumerator import (
    SENSITIVE_KEYWORDS,
    is_required,
    normalize_schema,
    type_ref_to_string,
    unwrap_type,
)
from src.scanner.query_builder import QueryBuilder


ID_ARGUMENT_NAMES = {"id", "uuid", "key", "nodeid", "node_id", "objectid", "object_id"}
AUTH_QUERY_HINTS = {
    "me",
    "viewer",
    "session",
    "currentuser",
    "current_user",
    "whoami",
    "profile",
}
AUTH_MUTATION_HINTS = {
    "login",
    "signin",
    "sign_in",
    "authenticate",
    "auth",
    "token",
    "refresh",
    "logout",
    "signup",
    "sign_up",
    "register",
    "resetpassword",
    "reset_password",
    "forgotpassword",
    "forgot_password",
    "verifyotp",
    "verify_otp",
}


@dataclass
class GeneratedOperation:
    operation_type: str
    root_type: str
    field: str
    operation_name: str
    return_type: Optional[str]
    return_kind: Optional[str]
    required_args: List[Dict[str, str]]
    all_args: List[Dict[str, str]]
    tags: List[str] = field(default_factory=list)
    risk_score: int = 0
    operation: Optional[str] = None
    full_operation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class OperationPackGenerator:
    """Build ready-to-edit query, mutation, and subscription documents.

    This is intentionally not a wrapper around InQL. It brings the same useful
    idea into Guardian: once a schema is known, testers get a pack of generated
    operations plus tags that point each operation toward recon, IDOR/BOLA,
    injection, or DoS workflows.
    """

    def __init__(self, schema_data: Dict[str, Any]):
        self.schema = normalize_schema(schema_data)
        self.type_map = {
            type_def["name"]: type_def
            for type_def in self.schema["__schema"].get("types", [])
            if type_def.get("name")
        }
        self.builder = QueryBuilder(self.type_map)

    def generate(self) -> Dict[str, Any]:
        operations = [item.to_dict() for item in self._generate_operations()]
        grouped = {
            "reconnaissance": self._select_by_tag(operations, "recon"),
            "access_control": self._select_by_tag(operations, "idor-candidate"),
            "authentication": self._select_by_tag(operations, "auth-surface"),
            "injection": self._select_by_tag(operations, "input-fuzz-candidate"),
            "dos": self._select_by_tag(operations, "list-response"),
            "batching": self._select_batch_candidates(operations),
        }
        return {
            "summary": {
                "total_operations": len(operations),
                "queries": self._count(operations, "query"),
                "mutations": self._count(operations, "mutation"),
                "subscriptions": self._count(operations, "subscription"),
                "access_control_candidates": len(grouped["access_control"]),
                "authentication_candidates": len(grouped["authentication"]),
                "injection_candidates": len(grouped["injection"]),
                "batch_candidates": len(grouped["batching"]),
            },
            "operations": operations,
            "packs": grouped,
        }

    def _generate_operations(self) -> List[GeneratedOperation]:
        generated: List[GeneratedOperation] = []
        for operation_type, root_type in self._operation_roots():
            root_def = self.type_map.get(root_type)
            if not root_def:
                continue
            for field_def in root_def.get("fields") or []:
                generated.append(self._build_operation(operation_type, root_type, field_def))

        generated.sort(key=lambda item: (-item.risk_score, item.operation_type, item.field))
        return generated

    def _operation_roots(self) -> Iterable[tuple[str, str]]:
        schema = self.schema["__schema"]
        roots = [
            ("query", schema.get("queryType")),
            ("mutation", schema.get("mutationType")),
            ("subscription", schema.get("subscriptionType")),
        ]
        for operation_type, root in roots:
            if root and root.get("name"):
                yield operation_type, root["name"]

    def _build_operation(
        self,
        operation_type: str,
        root_type: str,
        field_def: Dict[str, Any],
    ) -> GeneratedOperation:
        field_name = field_def.get("name", "")
        return_ref = unwrap_type(field_def.get("type"))
        required_args = self._arg_summary(
            arg for arg in field_def.get("args") or [] if is_required(arg.get("type"))
        )
        all_args = self._arg_summary(field_def.get("args") or [])
        tags, score = self._classify(operation_type, field_name, return_ref, all_args, required_args)

        return GeneratedOperation(
            operation_type=operation_type,
            root_type=root_type,
            field=field_name,
            operation_name=f"{root_type}.{field_name}",
            return_type=return_ref.name if return_ref else None,
            return_kind=return_ref.kind if return_ref else None,
            required_args=required_args,
            all_args=all_args,
            tags=tags,
            risk_score=score,
            operation=self.builder.construct_operation(
                root_type,
                field_name,
                include_optional_args=False,
            ),
            full_operation=self.builder.construct_operation(
                root_type,
                field_name,
                include_optional_args=True,
            ),
        )

    def _arg_summary(self, args: Iterable[Dict[str, Any]]) -> List[Dict[str, str]]:
        return [
            {
                "name": arg.get("name", ""),
                "type": type_ref_to_string(arg.get("type")),
            }
            for arg in args
        ]

    def _classify(
        self,
        operation_type: str,
        field_name: str,
        return_ref: Any,
        all_args: List[Dict[str, str]],
        required_args: List[Dict[str, str]],
    ) -> tuple[List[str], int]:
        tags = {"recon"}
        score = 0

        if operation_type == "mutation":
            tags.add("state-changing")
            score += 10
        elif operation_type == "subscription":
            tags.add("realtime")
            score += 10

        if all_args:
            tags.add("input-fuzz-candidate")
            score += min(25, 5 * len(all_args))
        if required_args:
            tags.add("requires-input")
            score += 5
        if any(arg["name"].lower() in ID_ARGUMENT_NAMES for arg in all_args):
            tags.add("idor-candidate")
            score += 35

        if return_ref:
            if return_ref.is_list:
                tags.add("list-response")
                tags.add("batch-candidate")
                score += 15
            if return_ref.kind in {"OBJECT", "INTERFACE", "UNION"} and operation_type == "query":
                tags.add("object-accessor")
                score += 10
            if operation_type == "query":
                tags.add("batch-candidate")

        searchable = " ".join(
            [
                field_name,
                getattr(return_ref, "name", "") or "",
                " ".join(arg["name"] for arg in all_args),
            ]
        ).lower()
        normalized_name = field_name.replace("-", "_").lower()
        matched_keywords = [
            keyword for keyword in SENSITIVE_KEYWORDS if keyword.lower() in searchable
        ]
        if matched_keywords:
            tags.add("sensitive-surface")
            score += min(40, 10 * len(matched_keywords))
            if operation_type == "query":
                tags.add("idor-candidate")

        if operation_type == "query" and any(hint in normalized_name for hint in AUTH_QUERY_HINTS):
            tags.add("auth-surface")
            tags.add("identity-query")
            score += 20
        if operation_type == "mutation" and any(hint in normalized_name for hint in AUTH_MUTATION_HINTS):
            tags.add("auth-surface")
            tags.add("credential-flow")
            score += 20
            if any(arg["name"].lower() in {"password", "passwd", "pin", "otp", "token", "refresh_token"} for arg in all_args):
                tags.add("credential-input")
                score += 5

        return sorted(tags), score

    def _select_by_tag(self, operations: List[Dict[str, Any]], tag: str) -> List[Dict[str, Any]]:
        selected = [item for item in operations if tag in item.get("tags", [])]
        return selected[:25]

    def _select_batch_candidates(self, operations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        selected = [
            item
            for item in operations
            if item.get("operation_type") == "query"
            and "batch-candidate" in item.get("tags", [])
            and item.get("operation")
        ]
        return selected[:25]

    def _count(self, operations: List[Dict[str, Any]], operation_type: str) -> int:
        return sum(1 for item in operations if item.get("operation_type") == operation_type)
