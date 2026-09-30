import pytest
from src.scanner.dependency_graph import DependencyGraphBuilder

# Mock Schema Data (Simplified Introspection Result)
MOCK_SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "subscriptionType": None,
            "types": [
                {
                    "kind": "OBJECT",
                    "name": "Query",
                    "fields": [
                        {
                            "name": "getUser",
                            "args": [],
                            "type": {"kind": "OBJECT", "name": "User", "ofType": None}
                        },
                        {
                            "name": "listProducts",
                            "args": [],
                            "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "Product"}}
                        }
                    ],
                    "interfaces": []
                },
                {
                    "kind": "OBJECT",
                    "name": "Mutation",
                    "fields": [
                        {
                            "name": "createUser",
                            "args": [],
                            "type": {"kind": "OBJECT", "name": "User", "ofType": None}
                        },
                        {
                            "name": "addProduct",
                            "args": [],
                            "type": {"kind": "OBJECT", "name": "Product", "ofType": None}
                        }
                    ],
                    "interfaces": []
                },
                {
                    "kind": "OBJECT",
                    "name": "User",
                    "fields": [
                        {
                            "name": "id", 
                            "args": [],
                            "type": {"kind": "SCALAR", "name": "ID"}
                        }
                    ],
                    "interfaces": []
                },
                {
                    "kind": "OBJECT",
                    "name": "Product",
                    "fields": [
                        {
                            "name": "id", 
                            "args": [],
                            "type": {"kind": "SCALAR", "name": "ID"}
                        }
                    ],
                    "interfaces": []
                },
                {"kind": "SCALAR", "name": "ID", "fields": None, "interfaces": None},
                {"kind": "SCALAR", "name": "String", "fields": None, "interfaces": None}
            ],
            "directives": []
        }
    }
}

def test_graph_construction():
    builder = DependencyGraphBuilder(MOCK_SCHEMA)
    graph = builder.build()
    
    # Check nodes
    assert "User" in graph.nodes
    assert "Product" in graph.nodes
    assert "Mutation.createUser" in graph.nodes
    
    # Check edges
    # createUser -> User (creator)
    assert graph.has_edge("Mutation.createUser", "User")
    assert graph.edges["Mutation.createUser", "User"]["type"] == "creator"
    
    # getUser -> User (accessor)
    assert graph.has_edge("Query.getUser", "User")
    assert graph.edges["Query.getUser", "User"]["type"] == "accessor"

    # Check field dependency (Query object -> Product object via listProducts field)
    # Note: Query is also an Object Type, so it gets processed in step 1 too.
    assert graph.has_edge("Query", "Product")
    assert graph.edges["Query", "Product"]["type"] == "field"
    assert graph.edges["Query", "Product"]["field"] == "listProducts"

def test_heuristics():
    builder = DependencyGraphBuilder(MOCK_SCHEMA)
    graph = builder.build()
    
    # Check if heuristics identified creators correctly
    creators = [n for n, d in graph.nodes(data=True) if d.get("type") == "mutation"]
    for creator in creators:
        # Check outgoing edges
        successors = list(graph.successors(creator))
        assert len(successors) > 0
