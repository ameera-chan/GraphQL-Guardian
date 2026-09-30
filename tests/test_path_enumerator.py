from src.scanner.path_enumerator import GraphQLPathEnumerator


SCHEMA = {
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
                            "name": "user",
                            "args": [
                                {
                                    "name": "id",
                                    "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}},
                                }
                            ],
                            "type": {"kind": "OBJECT", "name": "User"},
                        }
                    ],
                },
                {
                    "kind": "OBJECT",
                    "name": "Mutation",
                    "fields": [
                        {
                            "name": "createPost",
                            "args": [],
                            "type": {"kind": "OBJECT", "name": "Post"},
                        }
                    ],
                },
                {
                    "kind": "OBJECT",
                    "name": "User",
                    "fields": [
                        {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "ID"}},
                        {
                            "name": "posts",
                            "args": [],
                            "type": {"kind": "OBJECT", "name": "PostConnection"},
                        },
                    ],
                },
                {
                    "kind": "OBJECT",
                    "name": "PostConnection",
                    "fields": [
                        {
                            "name": "edges",
                            "args": [],
                            "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "PostEdge"}},
                        }
                    ],
                },
                {
                    "kind": "OBJECT",
                    "name": "PostEdge",
                    "fields": [
                        {"name": "node", "args": [], "type": {"kind": "OBJECT", "name": "Post"}}
                    ],
                },
                {
                    "kind": "OBJECT",
                    "name": "Post",
                    "fields": [
                        {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "ID"}},
                        {"name": "title", "args": [], "type": {"kind": "SCALAR", "name": "String"}},
                    ],
                },
                {"kind": "SCALAR", "name": "ID"},
                {"kind": "SCALAR", "name": "String"},
            ],
            "directives": [],
        }
    }
}


def test_enumerates_path_to_target_type_through_relay_connection():
    report = GraphQLPathEnumerator(SCHEMA, target_types=["Post"], max_depth=6).enumerate()

    paths = {item["path"]: item for item in report["paths"]}

    assert "Query.user.posts.edges.node" in paths
    assert paths["Query.user.posts.edges.node"]["target_type"] == "Post"
    assert paths["Query.user.posts.edges.node"]["required_args"][0]["name"] == "id"
    assert "query {" in paths["Query.user.posts.edges.node"]["query_preview"]


def test_all_types_includes_mutation_paths():
    report = GraphQLPathEnumerator(SCHEMA, all_types=True, max_depth=2).enumerate()

    assert any(item["path"] == "Mutation.createPost" for item in report["paths"])
