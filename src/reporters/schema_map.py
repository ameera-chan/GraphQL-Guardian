"""Build the schema relationship graph used by the web dashboard."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple


ROOT_LABELS = {
    "query": "Query",
    "mutation": "Mutation",
    "subscription": "Subscription",
}

NODE_STYLES = {
    "api": ("#111827", "#030712", "#FFFFFF", 230),
    "root": ("#DBEAFE", "#2563EB", "#1E3A8A", 190),
    "operation": ("#EFF6FF", "#60A5FA", "#1E3A8A", 230),
    "type": ("#EEF2FF", "#818CF8", "#312E81", 210),
    "field": ("#FFFBEB", "#F59E0B", "#78350F", 220),
    "argument": ("#F8FAFC", "#94A3B8", "#334155", 210),
    "finding": ("#FEF2F2", "#EF4444", "#7F1D1D", 240),
}

SEVERITY_COLORS = {
    "CRITICAL": ("#7F1D1D", "#450A0A", "#FFFFFF"),
    "HIGH": ("#FEE2E2", "#DC2626", "#991B1B"),
    "MEDIUM": ("#FEF3C7", "#F59E0B", "#92400E"),
    "LOW": ("#DBEAFE", "#3B82F6", "#1E40AF"),
    "INFO": ("#F1F5F9", "#94A3B8", "#334155"),
}


def extract_schema_structure(schema_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Reduce introspection data to the types, fields, and arguments needed by the UI."""
    if not schema_data:
        return {"roots": {}, "types": []}

    normalized = schema_data.get("data", schema_data)
    schema = normalized.get("__schema") or {}
    roots = {
        "query": (schema.get("queryType") or {}).get("name"),
        "mutation": (schema.get("mutationType") or {}).get("name"),
        "subscription": (schema.get("subscriptionType") or {}).get("name"),
    }

    types = []
    for type_def in schema.get("types") or []:
        name = type_def.get("name")
        if not name or name.startswith("__"):
            continue

        fields = []
        source_fields = type_def.get("fields") or type_def.get("inputFields") or []
        for field_def in source_fields:
            type_name, type_kind, wrappers = _unwrap_type(field_def.get("type"))
            fields.append(
                {
                    "name": field_def.get("name"),
                    "description": field_def.get("description"),
                    "type": _render_type(field_def.get("type")),
                    "return_type": type_name,
                    "return_kind": type_kind,
                    "wrappers": wrappers,
                    "arguments": [
                        {
                            "name": argument.get("name"),
                            "description": argument.get("description"),
                            "type": _render_type(argument.get("type")),
                            "input_type": _unwrap_type(argument.get("type"))[0],
                            "input_kind": _unwrap_type(argument.get("type"))[1],
                            "wrappers": _unwrap_type(argument.get("type"))[2],
                            "required": (argument.get("type") or {}).get("kind") == "NON_NULL",
                        }
                        for argument in field_def.get("args") or []
                        if argument.get("name")
                    ],
                }
            )

        types.append(
            {
                "name": name,
                "kind": type_def.get("kind", "UNKNOWN"),
                "description": type_def.get("description"),
                "fields": fields,
                "interfaces": [item.get("name") for item in type_def.get("interfaces") or [] if item.get("name")],
                "possible_types": [item.get("name") for item in type_def.get("possibleTypes") or [] if item.get("name")],
                "enum_values": [item.get("name") for item in type_def.get("enumValues") or [] if item.get("name")],
            }
        )

    return {"roots": roots, "types": types}


def build_schema_map(report: Dict[str, Any]) -> Dict[str, Any]:
    """Build endpoint, root, operation, type, field, argument, and finding nodes."""
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: Dict[str, Dict[str, Any]] = {}
    operation_nodes: Dict[str, str] = {}
    field_nodes: Dict[str, str] = {}
    argument_nodes: Dict[Tuple[str, str], str] = {}

    schema = report.get("schema") or {}
    schema_graph = schema.get("graph") or {"roots": {}, "types": []}
    overview = schema.get("overview") or {}
    endpoint = (report.get("metadata") or {}).get("endpoint") or (overview.get("target") or {}).get("endpoint") or "GraphQL endpoint"
    findings = list(report.get("findings") or [])
    operations = list((report.get("operation_pack") or {}).get("operations") or [])
    operation_details = {item.get("operation_name"): item for item in operations if item.get("operation_name")}

    _add_node(
        nodes,
        "api:endpoint",
        "api",
        endpoint,
        endpoint=endpoint,
        schemaSource=schema.get("source") or overview.get("schema_source"),
        schemaAvailable=bool(schema.get("available")),
        counts=overview.get("counts") or {},
        meta="GraphQL API",
    )

    roots = dict(schema_graph.get("roots") or overview.get("root_types") or {})
    for operation in operations:
        operation_type = operation.get("operation_type")
        if operation_type and operation.get("root_type"):
            roots.setdefault(operation_type, operation.get("root_type"))

    root_types = {name: kind for kind, name in roots.items() if name}
    for operation_type in ("query", "mutation", "subscription"):
        root_name = roots.get(operation_type)
        if not root_name:
            continue
        root_id = f"root:{root_name}"
        _add_node(
            nodes,
            root_id,
            "root",
            ROOT_LABELS[operation_type],
            rootType=root_name,
            operationType=operation_type,
            meta=root_name,
        )
        _add_edge(edges, "api:endpoint", root_id, "root")

    schema_types = list(schema_graph.get("types") or [])
    type_details = {item.get("name"): item for item in schema_types if item.get("name")}
    if not schema_types:
        schema_types = _fallback_types(report)
        type_details = {item.get("name"): item for item in schema_types if item.get("name")}

    for type_def in schema_types:
        type_name = type_def.get("name")
        if not type_name or type_name in root_types:
            continue
        _add_type_node(nodes, type_def)

    for type_def in schema_types:
        type_name = type_def.get("name")
        if not type_name:
            continue
        operation_type = root_types.get(type_name)
        for field_def in type_def.get("fields") or []:
            field_name = field_def.get("name")
            if not field_name:
                continue
            if operation_type:
                operation_name = f"{type_name}.{field_name}"
                detail = {**field_def, **(operation_details.get(operation_name) or {})}
                operation_id = _add_operation_node(nodes, edges, detail, operation_type, type_name)
                operation_nodes[operation_name] = operation_id
                _add_operation_arguments(nodes, edges, argument_nodes, operation_id, operation_name, detail, type_details)
                _link_return_type(nodes, edges, operation_id, detail, type_details)
            else:
                is_input_field = type_def.get("kind") == "INPUT_OBJECT"
                field_id = _add_field_node(
                    nodes,
                    edges,
                    type_name,
                    field_def,
                    type_details,
                    relationship="input field" if is_input_field else "field",
                    type_relationship="value type" if is_input_field else "returns",
                )
                field_nodes[f"{type_name}.{field_name}"] = field_id
                _add_field_arguments(nodes, edges, argument_nodes, field_id, f"{type_name}.{field_name}", field_def, type_details)

        for interface_name in type_def.get("interfaces") or []:
            _add_type_node(nodes, type_details.get(interface_name) or {"name": interface_name, "kind": "INTERFACE"})
            _add_edge(edges, f"type:{type_name}", f"type:{interface_name}", "implements")
        for possible_name in type_def.get("possible_types") or []:
            _add_type_node(nodes, type_details.get(possible_name) or {"name": possible_name, "kind": "OBJECT"})
            _add_edge(edges, f"type:{type_name}", f"type:{possible_name}", "possible type")

    for operation in operations:
        operation_name = operation.get("operation_name")
        if not operation_name:
            continue
        operation_type = operation.get("operation_type") or "query"
        root_type = operation.get("root_type") or roots.get(operation_type) or ROOT_LABELS.get(operation_type, "Query")
        operation_id = _add_operation_node(nodes, edges, operation, operation_type, root_type)
        operation_nodes[operation_name] = operation_id
        schema_operation = next(
            (
                field
                for field in (type_details.get(root_type) or {}).get("fields") or []
                if field.get("name") == operation.get("field")
            ),
            {},
        )
        argument_detail = {**schema_operation, **operation}
        _add_operation_arguments(nodes, edges, argument_nodes, operation_id, operation_name, argument_detail, type_details)
        _link_return_type(nodes, edges, operation_id, operation, type_details)

    _add_path_relationships(report, nodes, edges, operation_nodes, field_nodes, type_details)
    _add_sensitive_relationships(report, nodes, edges, operation_nodes, field_nodes, type_details)
    _add_findings(report, nodes, edges, operation_nodes, field_nodes, argument_nodes)
    _apply_layout(nodes)

    node_counts = defaultdict(int)
    for node in nodes.values():
        node_counts[node["data"]["nodeType"]] += 1

    return {
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "summary": {
            "schema_available": bool(schema.get("available")),
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "node_counts": dict(node_counts),
            "mapped_findings": node_counts.get("finding", 0),
        },
    }


def _add_operation_node(
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[str, Dict[str, Any]],
    operation: Dict[str, Any],
    operation_type: str,
    root_type: str,
) -> str:
    field_name = operation.get("field") or operation.get("name") or "unknown"
    operation_name = operation.get("operation_name") or f"{root_type}.{field_name}"
    operation_id = f"operation:{operation_name}"
    _add_node(
        nodes,
        operation_id,
        "operation",
        field_name,
        operationName=operation_name,
        operationType=operation_type,
        rootType=root_type,
        returnType=operation.get("return_type"),
        returnKind=operation.get("return_kind"),
        arguments=operation.get("all_args") or operation.get("arguments") or [],
        requiredArguments=operation.get("required_args") or [],
        tags=operation.get("tags") or [],
        riskScore=operation.get("risk_score", 0),
        operation=operation.get("operation"),
        fullOperation=operation.get("full_operation"),
        meta=operation_type,
    )
    root_id = f"root:{root_type}"
    if root_id not in nodes:
        _add_node(nodes, root_id, "root", ROOT_LABELS.get(operation_type, operation_type.title()), rootType=root_type, operationType=operation_type, meta=root_type)
        _add_edge(edges, "api:endpoint", root_id, "root")
    _add_edge(edges, root_id, operation_id, "operation")
    return operation_id


def _add_operation_arguments(
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[str, Dict[str, Any]],
    argument_nodes: Dict[Tuple[str, str], str],
    operation_id: str,
    operation_name: str,
    operation: Dict[str, Any],
    type_details: Dict[str, Dict[str, Any]],
) -> None:
    schema_arguments = {
        argument.get("name"): argument
        for argument in operation.get("arguments") or []
        if argument.get("name")
    }
    arguments = operation.get("all_args") or operation.get("arguments") or []
    for argument in arguments:
        argument = {**schema_arguments.get(argument.get("name"), {}), **argument}
        name = argument.get("name")
        if not name:
            continue
        argument_id = f"argument:{operation_name}:{name}"
        _add_node(
            nodes,
            argument_id,
            "argument",
            name,
            argumentName=name,
            argumentType=argument.get("type"),
            inputType=argument.get("input_type"),
            inputKind=argument.get("input_kind"),
            required=argument.get("required", str(argument.get("type") or "").endswith("!")),
            owner=operation_name,
            meta=argument.get("type") or "argument",
        )
        argument_nodes[(operation_name, name)] = argument_id
        _add_edge(edges, operation_id, argument_id, "accepts")
        _link_input_type(nodes, edges, argument_id, argument, type_details)


def _add_field_node(
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[str, Dict[str, Any]],
    parent_type: str,
    field_def: Dict[str, Any],
    type_details: Dict[str, Dict[str, Any]],
    *,
    relationship: str = "field",
    type_relationship: str = "returns",
) -> str:
    field_name = field_def.get("name") or field_def.get("field") or "unknown"
    field_path = f"{parent_type}.{field_name}"
    field_id = f"field:{field_path}"
    _add_type_node(nodes, type_details.get(parent_type) or {"name": parent_type, "kind": "OBJECT"})
    _add_node(
        nodes,
        field_id,
        "field",
        field_name,
        fullField=field_path,
        parentType=parent_type,
        fieldName=field_name,
        fieldType=field_def.get("type") or field_def.get("field_type"),
        returnType=field_def.get("return_type"),
        returnKind=field_def.get("return_kind"),
        arguments=field_def.get("arguments") or [],
        description=field_def.get("description"),
        meta=field_def.get("type") or field_def.get("field_type") or "field",
    )
    _add_edge(edges, f"type:{parent_type}", field_id, relationship)
    _link_return_type(nodes, edges, field_id, field_def, type_details, relationship=type_relationship)
    return field_id


def _add_field_arguments(
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[str, Dict[str, Any]],
    argument_nodes: Dict[Tuple[str, str], str],
    field_id: str,
    field_path: str,
    field_def: Dict[str, Any],
    type_details: Dict[str, Dict[str, Any]],
) -> None:
    for argument in field_def.get("arguments") or []:
        name = argument.get("name")
        if not name:
            continue
        argument_id = f"argument:{field_path}:{name}"
        _add_node(
            nodes,
            argument_id,
            "argument",
            name,
            argumentName=name,
            argumentType=argument.get("type"),
            inputType=argument.get("input_type"),
            inputKind=argument.get("input_kind"),
            required=argument.get("required", str(argument.get("type") or "").endswith("!")),
            owner=field_path,
            meta=argument.get("type") or "argument",
        )
        argument_nodes[(field_path, name)] = argument_id
        _add_edge(edges, field_id, argument_id, "accepts")
        _link_input_type(nodes, edges, argument_id, argument, type_details)


def _link_return_type(
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[str, Dict[str, Any]],
    source_id: str,
    detail: Dict[str, Any],
    type_details: Dict[str, Dict[str, Any]],
    *,
    relationship: str = "returns",
) -> None:
    return_type = detail.get("return_type")
    if not return_type:
        return
    type_def = type_details.get(return_type) or {"name": return_type, "kind": detail.get("return_kind") or "UNKNOWN"}
    _add_type_node(nodes, type_def)
    _add_edge(edges, source_id, f"type:{return_type}", relationship)


def _link_input_type(
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[str, Dict[str, Any]],
    argument_id: str,
    argument: Dict[str, Any],
    type_details: Dict[str, Dict[str, Any]],
) -> None:
    input_type = argument.get("input_type")
    if not input_type:
        rendered = str(argument.get("type") or "")
        input_type = rendered.replace("[", "").replace("]", "").replace("!", "") or None
    if not input_type:
        return
    type_def = type_details.get(input_type) or {
        "name": input_type,
        "kind": argument.get("input_kind") or "UNKNOWN",
    }
    _add_type_node(nodes, type_def)
    _add_edge(edges, argument_id, f"type:{input_type}", "input type")


def _add_type_node(nodes: Dict[str, Dict[str, Any]], type_def: Dict[str, Any]) -> None:
    type_name = type_def.get("name")
    if not type_name:
        return
    kind = type_def.get("kind", "UNKNOWN")
    _add_node(
        nodes,
        f"type:{type_name}",
        "type",
        type_name,
        typeKind=kind,
        fieldCount=len(type_def.get("fields") or []),
        enumValues=type_def.get("enum_values") or [],
        description=type_def.get("description"),
        meta=kind.lower(),
    )


def _add_path_relationships(
    report: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[str, Dict[str, Any]],
    operation_nodes: Dict[str, str],
    field_nodes: Dict[str, str],
    type_details: Dict[str, Dict[str, Any]],
) -> None:
    for path in (report.get("paths") or {}).get("paths") or []:
        segments = path.get("segments") or []
        for index, segment in enumerate(segments):
            parent = segment.get("parent_type")
            field_name = segment.get("field")
            if not parent or not field_name:
                continue
            if index == 0:
                operation_name = f"{parent}.{field_name}"
                operation_id = operation_nodes.get(operation_name)
                if not operation_id:
                    operation_id = _add_operation_node(nodes, edges, {**segment, "operation_name": operation_name}, path.get("operation_type") or "query", parent)
                    operation_nodes[operation_name] = operation_id
                _link_return_type(nodes, edges, operation_id, segment, type_details)
                continue
            field_id = _add_field_node(nodes, edges, parent, segment, type_details)
            field_nodes[f"{parent}.{field_name}"] = field_id


def _add_sensitive_relationships(
    report: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[str, Dict[str, Any]],
    operation_nodes: Dict[str, str],
    field_nodes: Dict[str, str],
    type_details: Dict[str, Dict[str, Any]],
) -> None:
    for item in (report.get("relationship_map") or {}).get("items") or []:
        location = item.get("location") or ""
        if "." not in location:
            continue
        parent_type, field_name = location.split(".", 1)
        field_id = field_nodes.get(location) or _add_field_node(
            nodes,
            edges,
            parent_type,
            {"name": field_name, "type": item.get("field_type"), "field_type": item.get("field_type")},
            type_details,
        )
        field_nodes[location] = field_id
        data = nodes[field_id]["data"]
        data.update(
            {
                "sensitive": True,
                "reviewScore": item.get("review_score"),
                "disposition": item.get("disposition"),
                "matchedKeywords": item.get("matched_keywords") or [],
                "recommendedFocus": item.get("recommended_focus"),
                "meta": f"sensitive · {item.get('field_type') or 'field'}",
            }
        )
        for operation in item.get("related_operations") or []:
            operation_name = operation.get("operation_name")
            if not operation_name:
                continue
            operation_id = operation_nodes.get(operation_name)
            if not operation_id:
                operation_id = _add_operation_node(nodes, edges, operation, operation.get("operation_type") or "query", operation.get("root_type") or "Query")
                operation_nodes[operation_name] = operation_id
            _add_edge(edges, operation_id, field_id, "reaches")


def _add_findings(
    report: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[str, Dict[str, Any]],
    operation_nodes: Dict[str, str],
    field_nodes: Dict[str, str],
    argument_nodes: Dict[Tuple[str, str], str],
) -> None:
    for index, finding in enumerate(report.get("findings") or []):
        finding_id = f"finding:{finding.get('id') or index}"
        severity = str(finding.get("severity") or "INFO").upper()
        _add_node(
            nodes,
            finding_id,
            "finding",
            finding.get("title") or "Untitled finding",
            severity=severity,
            category=finding.get("category") or "OTHER",
            description=finding.get("description"),
            operationName=finding.get("operation_name"),
            fullField=finding.get("field"),
            evidence=finding.get("evidence"),
            remediation=finding.get("remediation"),
            reproduction=finding.get("reproduction"),
            risk=finding.get("risk"),
            ruleId=finding.get("rule_id"),
            state=finding.get("state"),
            confidence=finding.get("confidence"),
            finding=finding,
            meta=f"{severity} · {finding.get('category') or 'OTHER'}",
        )
        anchors = _finding_anchors(finding, operation_nodes, field_nodes, argument_nodes)
        for anchor in anchors or ["api:endpoint"]:
            _add_edge(edges, anchor, finding_id, "finding", severity=severity)


def _finding_anchors(
    finding: Dict[str, Any],
    operation_nodes: Dict[str, str],
    field_nodes: Dict[str, str],
    argument_nodes: Dict[Tuple[str, str], str],
) -> List[str]:
    anchors = []
    operation_name = finding.get("operation_name")
    field = finding.get("field")
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}

    matched_operations = []
    if operation_name:
        if operation_name in operation_nodes:
            matched_operations.append(operation_name)
        elif "." not in str(operation_name):
            matches = [name for name in operation_nodes if name.endswith(f".{operation_name}")]
            if len(matches) == 1:
                matched_operations.extend(matches)

    evidence_field = evidence.get("field")
    if not matched_operations and evidence_field and "." not in str(evidence_field):
        matches = [name for name in operation_nodes if name.endswith(f".{evidence_field}")]
        if len(matches) == 1:
            matched_operations.extend(matches)

    argument_names = [field, evidence.get("argument")]
    for matched_operation in matched_operations:
        for argument_name in argument_names:
            key = (matched_operation, str(argument_name))
            if argument_name and key in argument_nodes:
                anchors.append(argument_nodes[key])
        anchors.append(operation_nodes[matched_operation])

    candidates = [field, evidence.get("location"), evidence.get("graphql_path")]
    for candidate in candidates:
        if not isinstance(candidate, str) or not candidate:
            continue
        if candidate in field_nodes:
            anchors.append(field_nodes[candidate])
        elif "." not in candidate:
            matches = [node_id for path, node_id in field_nodes.items() if path.endswith(f".{candidate}")]
            if len(matches) == 1:
                anchors.extend(matches)

    return list(dict.fromkeys(anchors))


def _fallback_types(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    schema = report.get("schema") or {}
    summary = schema.get("summary") or {}
    kinds = {
        "object_types": "OBJECT",
        "input_objects": "INPUT_OBJECT",
        "enums": "ENUM",
        "interfaces": "INTERFACE",
        "unions": "UNION",
        "custom_scalars": "SCALAR",
    }
    result = []
    seen = set()
    for key, kind in kinds.items():
        for name in summary.get(key) or []:
            if name and not name.startswith("__") and name not in seen:
                seen.add(name)
                result.append({"name": name, "kind": kind, "fields": []})
    return result


def _add_node(
    nodes: Dict[str, Dict[str, Any]],
    node_id: str,
    node_type: str,
    label: str,
    **data: Any,
) -> None:
    if node_id in nodes:
        existing = nodes[node_id]["data"]
        for key, value in data.items():
            if value not in (None, "", [], {}):
                existing[key] = value
        search_values = [existing.get("label", label), node_type, *[str(value) for value in existing.values() if isinstance(value, (str, int, float))]]
        existing["searchText"] = " ".join(search_values).lower()
        return

    background, border, color, width = NODE_STYLES[node_type]
    if node_type == "finding":
        background, border, color = SEVERITY_COLORS.get(str(data.get("severity") or "INFO").upper(), SEVERITY_COLORS["INFO"])
    search_values = [label, node_type, *[str(value) for value in data.values() if isinstance(value, (str, int, float))]]
    nodes[node_id] = {
        "id": node_id,
        "type": "custom",
        "data": {
            "label": label,
            "nodeType": node_type,
            "searchText": " ".join(search_values).lower(),
            **data,
        },
        "position": {"x": 0, "y": 0},
        "style": {
            "background": background,
            "border": f"2px solid {border}",
            "color": color,
            "borderRadius": "8px",
            "padding": "10px 12px",
            "width": width,
            "fontSize": "12px",
        },
    }


def _add_edge(
    edges: Dict[str, Dict[str, Any]],
    source: str,
    target: str,
    relationship: str,
    *,
    severity: Optional[str] = None,
) -> None:
    if source == target:
        return
    edge_id = f"edge:{source}:{relationship}:{target}"
    if edge_id in edges:
        return
    stroke = "#94A3B8"
    animated = False
    if relationship == "finding":
        stroke = SEVERITY_COLORS.get(severity or "INFO", SEVERITY_COLORS["INFO"])[1]
        animated = severity in {"CRITICAL", "HIGH"}
    elif relationship in {"returns", "reaches"}:
        stroke = "#6366F1"
    edges[edge_id] = {
        "id": edge_id,
        "source": source,
        "target": target,
        "animated": animated,
        "data": {"relationship": relationship},
        "style": {"stroke": stroke, "strokeWidth": 1.5},
    }


def _apply_layout(nodes: Dict[str, Dict[str, Any]]) -> None:
    columns = {
        "api": 0,
        "root": 1,
        "operation": 2,
        "type": 3,
        "field": 4,
        "argument": 4,
        "finding": 5,
    }
    x_positions = {0: 40, 1: 360, 2: 680, 3: 1030, 4: 1370, 5: 1960}
    groups: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for node in nodes.values():
        groups[columns[node["data"]["nodeType"]]].append(node)

    operation_order = {"query": 0, "mutation": 1, "subscription": 2}
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for column, column_nodes in groups.items():
        if column == 1:
            column_nodes.sort(key=lambda node: operation_order.get(node["data"].get("operationType"), 9))
        elif column == 2:
            column_nodes.sort(key=lambda node: (operation_order.get(node["data"].get("operationType"), 9), node["data"]["label"]))
        elif column == 5:
            column_nodes.sort(key=lambda node: (severity_order.get(node["data"].get("severity"), 9), node["data"].get("category", ""), node["data"]["label"]))
        else:
            column_nodes.sort(key=lambda node: (node["data"]["nodeType"], node["data"]["label"]))

        lanes = 3 if column == 5 else 2 if column == 4 else 1
        for index, node in enumerate(column_nodes):
            lane = index % lanes
            row = index // lanes
            node["position"] = {
                "x": x_positions[column] + lane * 270,
                "y": 40 + row * 125,
            }

    root_children = defaultdict(list)
    for node in groups.get(2, []):
        root_children[node["data"].get("rootType")].append(node["position"]["y"])
    for node in groups.get(1, []):
        child_positions = root_children.get(node["data"].get("rootType")) or []
        if child_positions:
            node["position"]["y"] = int(sum(child_positions) / len(child_positions))
    root_positions = [node["position"]["y"] for node in groups.get(1, [])]
    if groups.get(0):
        groups[0][0]["position"]["y"] = int(sum(root_positions) / len(root_positions)) if root_positions else 40


def _unwrap_type(type_ref: Optional[Dict[str, Any]]) -> Tuple[Optional[str], Optional[str], List[str]]:
    wrappers = []
    current = type_ref or {}
    while current.get("kind") in {"NON_NULL", "LIST"}:
        wrappers.append(current.get("kind"))
        current = current.get("ofType") or {}
    return current.get("name"), current.get("kind"), wrappers


def _render_type(type_ref: Optional[Dict[str, Any]]) -> str:
    if not type_ref:
        return "Unknown"
    kind = type_ref.get("kind")
    if kind == "NON_NULL":
        return f"{_render_type(type_ref.get('ofType'))}!"
    if kind == "LIST":
        return f"[{_render_type(type_ref.get('ofType'))}]"
    return type_ref.get("name") or kind or "Unknown"
