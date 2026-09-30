from src.scanner.points_of_interest import build_points_of_interest


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
                        {"name": "user", "args": [], "type": {"kind": "OBJECT", "name": "User"}}
                    ],
                },
                {
                    "kind": "OBJECT",
                    "name": "Mutation",
                    "fields": [
                        {"name": "updateUserRole", "args": [], "type": {"kind": "OBJECT", "name": "User"}}
                    ],
                },
                {
                    "kind": "OBJECT",
                    "name": "User",
                    "fields": [
                        {"name": "email", "args": [], "type": {"kind": "SCALAR", "name": "String"}},
                        {"name": "passwordHash", "args": [], "type": {"kind": "SCALAR", "name": "String"}},
                    ],
                },
                {"kind": "SCALAR", "name": "String"},
            ],
            "directives": [],
        }
    }
}


def test_points_of_interest_collects_sensitive_fields_and_paths():
    operation_pack = {
        "operations": [
            {
                "operation_name": "Mutation.updateUserRole",
                "operation_type": "mutation",
                "tags": ["idor-candidate", "input-fuzz-candidate"],
                "risk_score": 70,
                "required_args": [{"name": "id", "type": "ID!"}],
                "all_args": [{"name": "id", "type": "ID!"}],
                "return_type": "User",
            },
            {
                "operation_name": "Query.user",
                "operation_type": "query",
                "tags": ["idor-candidate"],
                "risk_score": 65,
                "required_args": [{"name": "id", "type": "ID!"}],
                "all_args": [{"name": "id", "type": "ID!"}],
                "return_type": "User",
            },
        ]
    }
    path_report = {
        "paths": [
            {
                "path": "Query.user",
                "target_type": "User",
                "score": 80,
                "reasons": ["sensitive target type keyword: user"],
                "required_args": [{"name": "id", "type": "ID!"}],
            }
        ]
    }
    dependency_graph = {
        "analysis": {
            "creators": [{"operation": "Mutation.updateUserRole", "resource": "User"}],
            "accessors": [{"operation": "Query.user", "resource": "User"}],
        }
    }

    report = build_points_of_interest(SCHEMA, operation_pack, path_report, dependency_graph)

    assert report["summary"]["sensitive_fields"] >= 2
    assert any(item["location"].startswith("User.") for item in report["sensitive_fields"])
    assert report["risky_mutations"][0]["operation_name"] == "Mutation.updateUserRole"
    assert report["id_arguments"][0]["argument"] == "id"
    assert report["auth_critical_paths"][0]["path"] == "Query.user"
