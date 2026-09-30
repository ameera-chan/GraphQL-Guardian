from src.scanner.operation_pack import OperationPackGenerator


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
                                    "type": {
                                        "kind": "NON_NULL",
                                        "ofType": {"kind": "SCALAR", "name": "ID"},
                                    },
                                }
                            ],
                            "type": {"kind": "OBJECT", "name": "User"},
                        },
                        {
                            "name": "users",
                            "args": [],
                            "type": {
                                "kind": "LIST",
                                "ofType": {"kind": "OBJECT", "name": "User"},
                            },
                        },
                    ],
                },
                {
                    "kind": "OBJECT",
                    "name": "Mutation",
                    "fields": [
                        {
                            "name": "updateUser",
                            "args": [
                                {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}},
                                {"name": "email", "type": {"kind": "SCALAR", "name": "String"}},
                            ],
                            "type": {"kind": "OBJECT", "name": "User"},
                        }
                    ],
                },
                {
                    "kind": "OBJECT",
                    "name": "User",
                    "fields": [
                        {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "ID"}},
                        {"name": "email", "args": [], "type": {"kind": "SCALAR", "name": "String"}},
                    ],
                },
                {"kind": "SCALAR", "name": "ID"},
                {"kind": "SCALAR", "name": "String"},
            ],
            "directives": [],
        }
    }
}


def test_operation_pack_generates_query_and_mutation_documents():
    report = OperationPackGenerator(SCHEMA).generate()

    operations = {item["operation_name"]: item for item in report["operations"]}

    assert report["summary"]["total_operations"] == 3
    assert "Query.user" in operations
    assert "Mutation.updateUser" in operations
    assert "query {" in operations["Query.user"]["operation"]
    assert "mutation {" in operations["Mutation.updateUser"]["operation"]


def test_operation_pack_tags_idor_injection_and_dos_candidates():
    report = OperationPackGenerator(SCHEMA).generate()
    operations = {item["operation_name"]: item for item in report["operations"]}

    assert "idor-candidate" in operations["Query.user"]["tags"]
    assert "input-fuzz-candidate" in operations["Mutation.updateUser"]["tags"]
    assert "list-response" in operations["Query.users"]["tags"]
    assert report["packs"]["access_control"]


def test_operation_pack_marks_authentication_surfaces():
    schema = {
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
                            {"name": "me", "args": [], "type": {"kind": "OBJECT", "name": "User"}},
                        ],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Mutation",
                        "fields": [
                            {
                                "name": "login",
                                "args": [
                                    {"name": "email", "type": {"kind": "SCALAR", "name": "String"}},
                                    {"name": "password", "type": {"kind": "SCALAR", "name": "String"}},
                                ],
                                "type": {"kind": "OBJECT", "name": "AuthPayload"},
                            }
                        ],
                    },
                    {"kind": "OBJECT", "name": "User", "fields": [{"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "ID"}}]},
                    {"kind": "OBJECT", "name": "AuthPayload", "fields": [{"name": "accessToken", "args": [], "type": {"kind": "SCALAR", "name": "String"}}]},
                    {"kind": "SCALAR", "name": "ID"},
                    {"kind": "SCALAR", "name": "String"},
                ],
                "directives": [],
            }
        }
    }

    report = OperationPackGenerator(schema).generate()
    operations = {item["operation_name"]: item for item in report["operations"]}

    assert "auth-surface" in operations["Query.me"]["tags"]
    assert "identity-query" in operations["Query.me"]["tags"]
    assert "auth-surface" in operations["Mutation.login"]["tags"]
    assert report["packs"]["authentication"]
