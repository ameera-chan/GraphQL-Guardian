"""Build executable GraphQL operations from introspection type metadata."""

import json
import random
import string
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set


WRAPPER_KINDS = {"NON_NULL", "LIST"}
LEAF_KINDS = {"SCALAR", "ENUM"}
ABSTRACT_KINDS = {"INTERFACE", "UNION"}


@dataclass(frozen=True)
class EnumLiteral:
    """GraphQL enum argument value that must be emitted without quotes."""

    name: str


class QueryBuilder:
    """Construct small, valid GraphQL query and mutation documents.

    The scanner intentionally generates inline argument literals instead of
    client variables because payload fuzzing needs exact values visible in the
    request body. The builder still treats GraphQL types precisely so generated
    operations resemble what a real typed client would send.
    """

    def __init__(self, type_map: Dict):
        self.type_map = type_map

    def _get_random_string(self, length: int = 8) -> str:
        return "".join(random.choices(string.ascii_letters, k=length))

    def unwrap_type(self, type_ref: Optional[Dict]) -> Optional[Dict]:
        """Return the underlying named type for NON_NULL/LIST wrappers."""
        current = type_ref
        while current and current.get("kind") in WRAPPER_KINDS:
            current = current.get("ofType")
        return current

    def is_required(self, type_ref: Dict) -> bool:
        """Return True when a GraphQL type reference is non-null."""
        return bool(type_ref and type_ref.get("kind") == "NON_NULL")

    def generate_value(self, type_ref: Dict) -> Any:
        """Generate a dummy literal value for a GraphQL input type reference."""
        if not type_ref:
            return None

        kind = type_ref.get("kind")

        if kind == "NON_NULL":
            return self.generate_value(type_ref.get("ofType"))

        if kind == "LIST":
            return [self.generate_value(type_ref.get("ofType"))]

        if kind == "ENUM":
            enum_type = self.type_map.get(type_ref.get("name"), {})
            enum_values = [
                value["name"]
                for value in enum_type.get("enumValues", [])
                if not value.get("isDeprecated")
            ]
            return EnumLiteral(enum_values[0] if enum_values else "UNKNOWN")

        if kind == "INPUT_OBJECT":
            type_name = type_ref.get("name")
            input_type = self.type_map.get(type_name, {})
            return {
                field["name"]: self.generate_value(field["type"])
                for field in input_type.get("inputFields", [])
            }

        if kind == "SCALAR":
            return self._generate_scalar_value(type_ref.get("name", "String"))

        return None

    def _generate_scalar_value(self, scalar_name: str) -> Any:
        """Generate plausible values for built-in and common custom scalars."""
        scalar_key = scalar_name.lower()
        if scalar_name == "String":
            return self._get_random_string()
        if scalar_name == "Int":
            return random.randint(1, 100)
        if scalar_name == "Boolean":
            return True
        if scalar_name == "Float":
            return 1.0
        if scalar_name == "ID":
            return "1"
        if scalar_key in {"date", "localdate"}:
            return "2026-01-01"
        if scalar_key in {"datetime", "timestamp", "naivedatetime"}:
            return "2026-01-01T00:00:00Z"
        if scalar_key in {"email", "emailaddress"}:
            return "test@example.com"
        if scalar_key in {"url", "uri", "urlscalar"}:
            return "https://example.com"
        if scalar_key in {"json", "map"}:
            return {}
        return "test"

    def build_args(
        self,
        args_def: List[Dict],
        overrides: Optional[Dict] = None,
        include_optional: bool = True,
    ) -> Dict:
        """Build argument values, honoring explicit overrides first."""
        args = {}
        overrides = overrides or {}

        for arg in args_def:
            name = arg["name"]
            if name in overrides:
                args[name] = overrides[name]
                continue

            if include_optional or self.is_required(arg["type"]):
                args[name] = self.generate_value(arg["type"])

        return args

    def format_arg_value(self, value: Any) -> str:
        """Format a Python value as a GraphQL input literal."""
        if isinstance(value, EnumLiteral):
            return value.name
        if isinstance(value, str):
            return json.dumps(value)
        if isinstance(value, bool):
            return str(value).lower()
        if value is None:
            return "null"
        if isinstance(value, dict):
            props = [f"{key}: {self.format_arg_value(item)}" for key, item in value.items()]
            return f"{{ {', '.join(props)} }}"
        if isinstance(value, list):
            return f"[{', '.join(self.format_arg_value(item) for item in value)}]"
        return str(value)

    def build_selection_set(
        self,
        type_def: Optional[Dict],
        depth: int = 0,
        max_depth: int = 2,
        visited: Optional[Set[str]] = None,
    ) -> str:
        """Build a compact selection set for object, interface, or union types."""
        if not type_def or depth > max_depth:
            return "__typename"

        kind = type_def.get("kind")
        if kind in ABSTRACT_KINDS:
            return self._build_abstract_selection(type_def, depth, max_depth, visited)

        if kind != "OBJECT" or not type_def.get("fields"):
            return "__typename"

        visited = set(visited or set())
        type_name = type_def.get("name")
        if type_name in visited:
            return "__typename"
        visited.add(type_name)

        fields = []
        for field in type_def.get("fields", []):
            field_type = self.unwrap_type(field.get("type"))
            if not field_type:
                continue

            field_kind = field_type.get("kind")
            if field_kind in LEAF_KINDS:
                fields.append(field["name"])
            elif field_kind == "OBJECT" and depth < max_depth:
                nested_type = self.type_map.get(field_type.get("name"))
                nested_selection = self.build_selection_set(
                    nested_type,
                    depth + 1,
                    max_depth,
                    visited,
                )
                fields.append(f"{field['name']} {{ {nested_selection} }}")
            elif field_kind in ABSTRACT_KINDS and depth < max_depth:
                abstract_type = self.type_map.get(field_type.get("name"))
                abstract_selection = self._build_abstract_selection(
                    abstract_type,
                    depth + 1,
                    max_depth,
                    visited,
                )
                fields.append(f"{field['name']} {{ {abstract_selection} }}")

        return "\n".join(fields[:5]) if fields else "__typename"

    def _build_abstract_selection(
        self,
        type_def: Optional[Dict],
        depth: int,
        max_depth: int,
        visited: Optional[Set[str]],
    ) -> str:
        """Build inline fragments for GraphQL interface and union return types."""
        if not type_def:
            return "__typename"

        fragments = ["__typename"]
        possible_types = type_def.get("possibleTypes", [])[:3]
        for possible_type in possible_types:
            concrete = self.type_map.get(possible_type.get("name"))
            if not concrete:
                continue
            selection = self.build_selection_set(concrete, depth, max_depth, visited)
            fragments.append(f"... on {concrete['name']} {{ {selection} }}")
        return "\n".join(fragments)

    def construct_operation(
        self,
        operation_type: str,
        field_name: str,
        args_overrides: Optional[Dict] = None,
        include_optional_args: bool = True,
    ) -> Optional[str]:
        """Construct a query, mutation, or subscription document."""
        root_type = self.type_map.get(operation_type)
        if not root_type:
            root_type = self.type_map.get(operation_type + "s")

        if not root_type:
            return None

        field_def = next((field for field in root_type.get("fields", []) if field["name"] == field_name), None)
        if not field_def:
            return None

        args = self.build_args(
            field_def.get("args", []),
            overrides=args_overrides,
            include_optional=include_optional_args,
        )
        args_str = ""
        if args:
            args_list = [f"{key}: {self.format_arg_value(value)}" for key, value in args.items()]
            args_str = f"({', '.join(args_list)})"

        return_type_ref = self.unwrap_type(field_def.get("type"))
        return_type = self.type_map.get(return_type_ref.get("name")) if return_type_ref else None

        selection = ""
        if return_type_ref and return_type_ref.get("kind") not in LEAF_KINDS:
            selection = f" {{ {self.build_selection_set(return_type)} }}"

        op_keyword = operation_type.lower()
        if op_keyword.startswith("mutation"):
            op_keyword = "mutation"
        elif op_keyword.startswith("subscription"):
            op_keyword = "subscription"
        else:
            op_keyword = "query"

        return f"{op_keyword} {{\n  {field_name}{args_str}{selection}\n}}"
