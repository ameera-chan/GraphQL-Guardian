from src.reporters.schema_map import build_schema_map, extract_schema_structure


def _type_ref(name, kind="SCALAR"):
    return {"kind": kind, "name": name, "ofType": None}


def test_extract_schema_structure_keeps_roots_fields_and_arguments():
    schema = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": None,
                "subscriptionType": None,
                "types": [
                    {
                        "kind": "OBJECT",
                        "name": "Query",
                        "fields": [
                            {
                                "name": "user",
                                "type": _type_ref("User", "OBJECT"),
                                "args": [
                                    {
                                        "name": "id",
                                        "type": {
                                            "kind": "NON_NULL",
                                            "name": None,
                                            "ofType": _type_ref("ID"),
                                        },
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "User",
                        "fields": [
                            {"name": "email", "type": _type_ref("String"), "args": []}
                        ],
                    },
                    {"kind": "SCALAR", "name": "String"},
                    {"kind": "OBJECT", "name": "__Type", "fields": []},
                ],
            }
        }
    }

    graph = extract_schema_structure(schema)

    assert graph["roots"]["query"] == "Query"
    assert [item["name"] for item in graph["types"]] == ["Query", "User", "String"]
    operation = graph["types"][0]["fields"][0]
    assert operation["return_type"] == "User"
    assert operation["arguments"][0] == {
        "name": "id",
        "description": None,
        "type": "ID!",
        "input_type": "ID",
        "input_kind": "SCALAR",
        "wrappers": ["NON_NULL"],
        "required": True,
    }


def test_build_schema_map_links_schema_and_findings():
    report = {
        "metadata": {"endpoint": "http://localhost/graphql"},
        "schema": {
            "available": True,
            "source": "introspection",
            "graph": {
                "roots": {"query": "Query", "mutation": None, "subscription": None},
                "types": [
                    {
                        "name": "Query",
                        "kind": "OBJECT",
                        "fields": [
                            {
                                "name": "user",
                                "type": "User",
                                "return_type": "User",
                                "return_kind": "OBJECT",
                                "arguments": [{"name": "id", "type": "ID!", "required": True}],
                            }
                        ],
                    },
                    {
                        "name": "User",
                        "kind": "OBJECT",
                        "fields": [
                            {
                                "name": "email",
                                "type": "String",
                                "return_type": "String",
                                "return_kind": "SCALAR",
                                "arguments": [],
                            }
                        ],
                    },
                    {"name": "String", "kind": "SCALAR", "fields": []},
                ],
            },
        },
        "operation_pack": {
            "operations": [
                {
                    "operation_name": "Query.user",
                    "operation_type": "query",
                    "root_type": "Query",
                    "field": "user",
                    "return_type": "User",
                    "return_kind": "OBJECT",
                    "all_args": [{"name": "id", "type": "ID!"}],
                    "tags": ["idor-candidate"],
                    "risk_score": 50,
                }
            ]
        },
        "findings": [
            {
                "id": "finding-1",
                "title": "Sensitive email exposed",
                "severity": "HIGH",
                "category": "AUTH",
                "operation_name": "Query.user",
                "field": "User.email",
            }
        ],
    }

    graph = build_schema_map(report)
    node_ids = {node["id"] for node in graph["nodes"]}
    edge_pairs = {(edge["source"], edge["target"]) for edge in graph["edges"]}

    assert {
        "api:endpoint",
        "root:Query",
        "operation:Query.user",
        "argument:Query.user:id",
        "type:User",
        "field:User.email",
        "type:String",
        "finding:finding-1",
        "type:ID",
    }.issubset(node_ids)
    assert ("root:Query", "operation:Query.user") in edge_pairs
    assert ("operation:Query.user", "type:User") in edge_pairs
    assert ("type:User", "field:User.email") in edge_pairs
    assert ("field:User.email", "type:String") in edge_pairs
    assert ("argument:Query.user:id", "type:ID") in edge_pairs
    assert ("field:User.email", "finding:finding-1") in edge_pairs
    assert graph["summary"]["node_counts"]["finding"] == 1

    argument = next(node for node in graph["nodes"] if node["id"] == "argument:Query.user:id")
    assert argument["data"]["required"] is True
    assert all(edge["source"] in node_ids and edge["target"] in node_ids for edge in graph["edges"])


def test_build_schema_map_links_arguments_and_input_object_fields_to_their_types():
    report = {
        "schema": {
            "available": True,
            "graph": {
                "roots": {"query": "RootQuery"},
                "types": [
                    {
                        "name": "RootQuery",
                        "kind": "OBJECT",
                        "fields": [
                            {
                                "name": "search",
                                "type": "String",
                                "return_type": "String",
                                "return_kind": "SCALAR",
                                "arguments": [
                                    {
                                        "name": "filter",
                                        "type": "FilterInput!",
                                        "input_type": "FilterInput",
                                        "input_kind": "INPUT_OBJECT",
                                        "required": True,
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "name": "FilterInput",
                        "kind": "INPUT_OBJECT",
                        "fields": [
                            {
                                "name": "keyword",
                                "type": "String!",
                                "return_type": "String",
                                "return_kind": "SCALAR",
                                "arguments": [],
                            }
                        ],
                    },
                    {"name": "String", "kind": "SCALAR", "fields": []},
                ],
            },
        },
        "operation_pack": {
            "operations": [
                {
                    "operation_name": "RootQuery.search",
                    "operation_type": "query",
                    "root_type": "RootQuery",
                    "field": "search",
                    "return_type": "String",
                    "return_kind": "SCALAR",
                    "all_args": [{"name": "filter", "type": "FilterInput!"}],
                }
            ]
        },
        "findings": [],
    }

    graph = build_schema_map(report)
    relationships = {
        (edge["source"], edge["target"], edge["data"]["relationship"])
        for edge in graph["edges"]
    }

    assert ("argument:RootQuery.search:filter", "type:FilterInput", "input type") in relationships
    assert ("type:FilterInput", "field:FilterInput.keyword", "input field") in relationships
    assert ("field:FilterInput.keyword", "type:String", "value type") in relationships


def test_finding_anchor_uses_unique_operation_argument_from_evidence():
    report = {
        "schema": {"available": False, "graph": {"roots": {"query": "Query"}, "types": []}},
        "operation_pack": {
            "operations": [
                {
                    "operation_name": "Query.pastes",
                    "operation_type": "query",
                    "root_type": "Query",
                    "field": "pastes",
                    "all_args": [{"name": "limit", "type": "Int"}],
                }
            ]
        },
        "findings": [
            {
                "id": "pagination",
                "title": "Pagination limit override",
                "category": "AUDIT",
                "evidence": {"field": "pastes", "argument": "limit"},
            }
        ],
    }

    graph = build_schema_map(report)
    finding_sources = {
        edge["source"]
        for edge in graph["edges"]
        if edge["target"] == "finding:pagination"
    }

    assert finding_sources == {"operation:Query.pastes", "argument:Query.pastes:limit"}


def test_ambiguous_short_field_name_does_not_create_false_relationships():
    report = {
        "schema": {
            "available": True,
            "graph": {
                "roots": {},
                "types": [
                    {"name": "User", "kind": "OBJECT", "fields": [{"name": "id", "type": "ID", "return_type": "ID", "return_kind": "SCALAR", "arguments": []}]},
                    {"name": "Post", "kind": "OBJECT", "fields": [{"name": "id", "type": "ID", "return_type": "ID", "return_kind": "SCALAR", "arguments": []}]},
                    {"name": "ID", "kind": "SCALAR", "fields": []},
                ],
            },
        },
        "findings": [{"id": "ambiguous", "title": "Ambiguous field", "field": "id"}],
    }

    graph = build_schema_map(report)
    finding_sources = {
        edge["source"]
        for edge in graph["edges"]
        if edge["target"] == "finding:ambiguous"
    }

    assert finding_sources == {"api:endpoint"}
