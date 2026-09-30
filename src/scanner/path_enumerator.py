"""GraphQL path enumeration over introspection schemas.

This is inspired by graphql-path-enum: it walks from GraphQL operation roots to
interesting object types so testers can quickly identify query paths that reach
sensitive resources.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


SENSITIVE_KEYWORDS = (
    "admin",
    "account",
    "apiKey",
    "credential",
    "customer",
    "debug",
    "email",
    "internal",
    "invoice",
    "owner",
    "password",
    "payment",
    "permission",
    "profile",
    "role",
    "secret",
    "session",
    "token",
    "user",
)


@dataclass
class TypeRef:
    kind: str
    name: Optional[str]
    wrappers: List[str] = field(default_factory=list)

    @property
    def is_list(self) -> bool:
        return "LIST" in self.wrappers


@dataclass
class PathSegment:
    field: str
    parent_type: str
    return_type: str
    return_kind: str
    wrappers: List[str] = field(default_factory=list)
    required_args: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class EnumeratedPath:
    operation_type: str
    root_type: str
    target_type: str
    path: str
    depth: int
    is_list_path: bool
    required_args: List[Dict[str, str]]
    score: int
    reasons: List[str]
    query_preview: str
    segments: List[PathSegment]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def normalize_schema(schema_data: Dict[str, Any]) -> Dict[str, Any]:
    """Return the introspection payload containing `__schema`."""
    if "data" in schema_data:
        schema_data = schema_data["data"]
    if "__schema" not in schema_data:
        raise ValueError("Schema data must contain __schema")
    return schema_data


def unwrap_type(type_ref: Optional[Dict[str, Any]]) -> TypeRef:
    """Unwrap NON_NULL/LIST wrappers and return the named type."""
    wrappers: List[str] = []
    current = type_ref or {}
    while current.get("kind") in {"NON_NULL", "LIST"}:
        wrappers.append(current.get("kind"))
        current = current.get("ofType") or {}
    return TypeRef(
        kind=current.get("kind", "UNKNOWN"),
        name=current.get("name"),
        wrappers=wrappers,
    )


def is_required(type_ref: Optional[Dict[str, Any]]) -> bool:
    return bool(type_ref and type_ref.get("kind") == "NON_NULL")


def type_ref_to_string(type_ref: Optional[Dict[str, Any]]) -> str:
    """Render a GraphQL type reference such as `[ID!]!`."""
    if not type_ref:
        return "Unknown"
    kind = type_ref.get("kind")
    if kind == "NON_NULL":
        return f"{type_ref_to_string(type_ref.get('ofType'))}!"
    if kind == "LIST":
        return f"[{type_ref_to_string(type_ref.get('ofType'))}]"
    return type_ref.get("name") or kind or "Unknown"


class GraphQLPathEnumerator:
    """Enumerate paths from operation roots to target object types."""

    def __init__(
        self,
        schema_data: Dict[str, Any],
        *,
        target_types: Optional[Iterable[str]] = None,
        max_depth: int = 6,
        include_mutations: bool = True,
        include_subscriptions: bool = False,
        all_types: bool = False,
    ):
        self.schema = normalize_schema(schema_data)
        self.type_map = {
            type_def["name"]: type_def
            for type_def in self.schema["__schema"].get("types", [])
            if type_def.get("name")
        }
        self.max_depth = max_depth
        self.include_mutations = include_mutations
        self.include_subscriptions = include_subscriptions
        self.all_types = all_types
        self.target_types = {name.lower() for name in target_types or []}

    def enumerate(self) -> Dict[str, Any]:
        """Enumerate matching paths and return a report dictionary."""
        paths: List[EnumeratedPath] = []

        for operation_type, root_type in self._operation_roots():
            root_def = self.type_map.get(root_type)
            if not root_def:
                continue
            for field_def in root_def.get("fields") or []:
                paths.extend(
                    self._walk_field(
                        operation_type=operation_type,
                        root_type=root_type,
                        parent_type=root_type,
                        field_def=field_def,
                        segments=[],
                        visited=(),
                    )
                )

        paths.sort(key=lambda item: (-item.score, item.depth, item.path))
        return {
            "summary": {
                "total_paths": len(paths),
                "target_types": sorted(self._effective_targets()),
                "max_depth": self.max_depth,
                "include_mutations": self.include_mutations,
                "include_subscriptions": self.include_subscriptions,
            },
            "paths": [path.to_dict() for path in paths],
        }

    def _operation_roots(self) -> List[Tuple[str, str]]:
        roots: List[Tuple[str, str]] = []
        schema = self.schema["__schema"]
        query = schema.get("queryType")
        mutation = schema.get("mutationType")
        subscription = schema.get("subscriptionType")
        if query and query.get("name"):
            roots.append(("query", query["name"]))
        if self.include_mutations and mutation and mutation.get("name"):
            roots.append(("mutation", mutation["name"]))
        if self.include_subscriptions and subscription and subscription.get("name"):
            roots.append(("subscription", subscription["name"]))
        return roots

    def _effective_targets(self) -> Set[str]:
        if self.all_types:
            return {
                type_def["name"]
                for type_def in self.type_map.values()
                if type_def.get("kind") in {"OBJECT", "INTERFACE", "UNION"}
                and not type_def["name"].startswith("__")
            }
        if self.target_types:
            return {
                type_def["name"]
                for type_def in self.type_map.values()
                if type_def.get("name", "").lower() in self.target_types
            }
        return {
            type_def["name"]
            for type_def in self.type_map.values()
            if type_def.get("kind") in {"OBJECT", "INTERFACE", "UNION"}
            and self._is_sensitive_name(type_def.get("name", ""))
            and not type_def["name"].startswith("__")
        }

    def _walk_field(
        self,
        *,
        operation_type: str,
        root_type: str,
        parent_type: str,
        field_def: Dict[str, Any],
        segments: List[PathSegment],
        visited: Tuple[str, ...],
    ) -> List[EnumeratedPath]:
        type_ref = unwrap_type(field_def.get("type"))
        if not type_ref.name:
            return []

        required_args = [
            {"name": arg.get("name", ""), "type": type_ref_to_string(arg.get("type"))}
            for arg in field_def.get("args") or []
            if is_required(arg.get("type"))
        ]
        segment = PathSegment(
            field=field_def.get("name", ""),
            parent_type=parent_type,
            return_type=type_ref.name,
            return_kind=type_ref.kind,
            wrappers=type_ref.wrappers,
            required_args=required_args,
        )
        next_segments = [*segments, segment]
        results: List[EnumeratedPath] = []

        if self._matches_target(type_ref.name):
            results.append(self._build_path(operation_type, root_type, next_segments, type_ref.name))

        if len(next_segments) >= self.max_depth:
            return results

        if type_ref.kind not in {"OBJECT", "INTERFACE", "UNION"}:
            return results

        next_visited = (*visited, type_ref.name)
        if next_visited.count(type_ref.name) > 1:
            return results

        for concrete_type in self._expandable_types(type_ref.name):
            type_def = self.type_map.get(concrete_type)
            if not type_def:
                continue
            for child_field in type_def.get("fields") or []:
                name = child_field.get("name", "")
                if name.startswith("__") or name == "pageInfo":
                    continue
                results.extend(
                    self._walk_field(
                        operation_type=operation_type,
                        root_type=root_type,
                        parent_type=concrete_type,
                        field_def=child_field,
                        segments=next_segments,
                        visited=next_visited,
                    )
                )

        return results

    def _expandable_types(self, type_name: str) -> List[str]:
        type_def = self.type_map.get(type_name) or {}
        if type_def.get("kind") == "UNION":
            return [item["name"] for item in type_def.get("possibleTypes") or [] if item.get("name")]
        if type_def.get("kind") == "INTERFACE":
            possibles = [item["name"] for item in type_def.get("possibleTypes") or [] if item.get("name")]
            return [type_name, *possibles]
        return [type_name]

    def _matches_target(self, type_name: str) -> bool:
        if self.all_types:
            return not type_name.startswith("__") and type_name not in {"Query", "Mutation", "Subscription"}
        if self.target_types:
            return type_name.lower() in self.target_types
        return self._is_sensitive_name(type_name)

    def _build_path(
        self,
        operation_type: str,
        root_type: str,
        segments: List[PathSegment],
        target_type: str,
    ) -> EnumeratedPath:
        path = ".".join([root_type, *[segment.field for segment in segments]])
        required_args = [
            {"field": f"{segment.parent_type}.{segment.field}", **arg}
            for segment in segments
            for arg in segment.required_args
        ]
        score, reasons = self._score_path(path, target_type, segments, required_args)
        return EnumeratedPath(
            operation_type=operation_type,
            root_type=root_type,
            target_type=target_type,
            path=path,
            depth=len(segments),
            is_list_path=any("LIST" in segment.wrappers for segment in segments),
            required_args=required_args,
            score=score,
            reasons=reasons,
            query_preview=self._render_query_preview(operation_type, segments, target_type),
            segments=segments,
        )

    def _score_path(
        self,
        path: str,
        target_type: str,
        segments: List[PathSegment],
        required_args: List[Dict[str, str]],
    ) -> Tuple[int, List[str]]:
        score = 0
        reasons: List[str] = []
        lower_path = path.lower()
        lower_target = target_type.lower()

        for keyword in SENSITIVE_KEYWORDS:
            lowered = keyword.lower()
            if lowered in lower_target:
                score += 40
                reasons.append(f"sensitive target type keyword: {keyword}")
                break

        matched_fields = sorted({keyword for keyword in SENSITIVE_KEYWORDS if keyword.lower() in lower_path})
        if matched_fields:
            score += min(30, 10 * len(matched_fields))
            reasons.append("sensitive path keyword(s): " + ", ".join(matched_fields[:4]))

        if any(segment.field.lower() in {"node", "nodes"} for segment in segments):
            score += 10
            reasons.append("Relay node-style traversal")
        if any("LIST" in segment.wrappers for segment in segments):
            score += 10
            reasons.append("list-returning path")
        if required_args:
            score += 5
            reasons.append("requires caller-controlled argument(s)")

        return score, reasons or ["reachable object path"]

    def _render_query_preview(
        self,
        operation_type: str,
        segments: List[PathSegment],
        target_type: str,
    ) -> str:
        selection = self._leaf_selection(target_type)
        for segment in reversed(segments):
            args = self._render_required_args(segment.required_args)
            selection = f"{segment.field}{args} {{ {selection} }}"
        return f"{operation_type} {{ {selection} }}"

    def _leaf_selection(self, target_type: str) -> str:
        type_def = self.type_map.get(target_type) or {}
        scalar_fields: List[str] = ["__typename"]
        for preferred in ("id", "uuid", "name", "email", "title"):
            if self._has_leaf_field(type_def, preferred):
                scalar_fields.append(preferred)
        for field_def in type_def.get("fields") or []:
            if len(scalar_fields) >= 6:
                break
            field_name = field_def.get("name", "")
            type_ref = unwrap_type(field_def.get("type"))
            if field_name not in scalar_fields and type_ref.kind in {"SCALAR", "ENUM"}:
                scalar_fields.append(field_name)
        return " ".join(scalar_fields)

    def _has_leaf_field(self, type_def: Dict[str, Any], field_name: str) -> bool:
        for field_def in type_def.get("fields") or []:
            if field_def.get("name") == field_name:
                return unwrap_type(field_def.get("type")).kind in {"SCALAR", "ENUM"}
        return False

    def _render_required_args(self, required_args: List[Dict[str, str]]) -> str:
        if not required_args:
            return ""
        rendered = []
        for arg in required_args:
            rendered.append(f'{arg["name"]}: "REPLACE_ME"')
        return "(" + ", ".join(rendered) + ")"

    def _is_sensitive_name(self, name: str) -> bool:
        lowered = (name or "").lower()
        return any(keyword.lower() in lowered for keyword in SENSITIVE_KEYWORDS)
