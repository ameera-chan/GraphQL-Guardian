from src.scanner.active_security import ActiveSecurityScanner
from src.utils.http_client import GraphQLResponse


def scalar(name, required=False):
    value = {"kind": "SCALAR", "name": name, "ofType": None}
    if required:
        return {"kind": "NON_NULL", "name": None, "ofType": value}
    return value


def object_ref(name):
    return {"kind": "OBJECT", "name": name, "ofType": None}


def make_schema(query_fields, mutation_fields=None, extra_types=None):
    types = [
        {
            "kind": "OBJECT",
            "name": "Query",
            "fields": query_fields,
        }
    ]
    mutation_type = None
    if mutation_fields:
        mutation_type = {"name": "Mutation"}
        types.append(
            {
                "kind": "OBJECT",
                "name": "Mutation",
                "fields": mutation_fields,
            }
        )
    types.extend(extra_types or [])
    return {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": mutation_type,
            "subscriptionType": None,
            "types": types,
        }
    }


def response(data=None, errors=None, raw_text=""):
    return GraphQLResponse(
        data=data,
        errors=errors,
        status_code=200,
        raw_text=raw_text,
        response_time=0.01,
    )


def test_active_scanner_finds_anonymous_sensitive_query():
    schema = make_schema(
        [{"name": "users", "args": [], "type": object_ref("User")}],
        extra_types=[
            {
                "kind": "OBJECT",
                "name": "User",
                "fields": [
                    {"name": "id", "args": [], "type": scalar("ID")},
                    {"name": "password", "args": [], "type": scalar("String")},
                ],
            }
        ],
    )
    scanner = ActiveSecurityScanner(
        "http://localhost/graphql",
        schema=schema,
        technique="A",
    )
    scanner._post = lambda query: response(
        {"users": {"id": "1", "password": "hash"}}
    )

    findings = scanner.run()

    assert any(
        item.rule_id == "GG-AUTH-ANONYMOUS-SENSITIVE-QUERY"
        for item in findings
    )


def test_active_scanner_finds_unbound_token_and_bola():
    schema = make_schema(
        [
            {
                "name": "auth",
                "args": [
                    {
                        "name": "veterinaryName",
                        "type": scalar("String", required=True),
                    }
                ],
                "type": scalar("String", required=True),
            },
            {
                "name": "myInfo",
                "args": [
                    {
                        "name": "accessToken",
                        "type": scalar("String", required=True),
                    },
                    {
                        "name": "veterinaryId",
                        "type": scalar("Int", required=True),
                    },
                ],
                "type": object_ref("Veterinary"),
            },
        ],
        extra_types=[
            {
                "kind": "OBJECT",
                "name": "Veterinary",
                "fields": [
                    {"name": "id", "args": [], "type": scalar("ID")},
                    {"name": "name", "args": [], "type": scalar("String")},
                ],
            }
        ],
    )
    scanner = ActiveSecurityScanner(
        "http://localhost/graphql",
        schema=schema,
        technique="A",
    )

    def fake_post(query):
        if "auth(" in query:
            return response({"auth": "signed-token"})
        if "myInfo(" in query:
            return response({"myInfo": {"id": "1", "name": "victim"}})
        return response({})

    scanner._post = fake_post
    findings = scanner.run()
    rule_ids = {item.rule_id for item in findings}

    assert "GG-AUTH-TOKEN-OBJECT-BINDING" in rule_ids
    assert "GG-AUTH-BOLA-TOKEN-BINDING" in rule_ids


def test_active_scanner_confirms_command_injection_with_canary():
    schema = make_schema(
        [
            {
                "name": "getCommandResult",
                "args": [
                    {
                        "name": "command",
                        "type": scalar("String", required=True),
                    }
                ],
                "type": scalar("String"),
            }
        ]
    )
    scanner = ActiveSecurityScanner(
        "http://localhost/graphql",
        schema=schema,
        technique="IA",
    )

    def fake_post(query):
        if "GG_CMD_CANARY_7F31" in query:
            return response(
                {"getCommandResult": "GG_CMD_CANARY_7F31"}
            )
        return response({})

    scanner._post = fake_post
    findings = scanner.run()
    rule_ids = {item.rule_id for item in findings}

    assert "GG-INJECTION-COMMAND-EXECUTION" in rule_ids
    assert "GG-AUTH-ANONYMOUS-COMMAND-EXECUTION" in rule_ids


def test_active_scanner_confirms_behavioural_sql_injection():
    schema = make_schema(
        [
            {
                "name": "dogs",
                "args": [
                    {
                        "name": "namePrefix",
                        "type": scalar("String"),
                    }
                ],
                "type": object_ref("Dog"),
            }
        ],
        extra_types=[
            {
                "kind": "OBJECT",
                "name": "Dog",
                "fields": [
                    {"name": "id", "args": [], "type": scalar("ID")},
                    {"name": "name", "args": [], "type": scalar("String")},
                ],
            }
        ],
    )
    scanner = ActiveSecurityScanner(
        "http://localhost/graphql",
        schema=schema,
        technique="I",
    )

    def fake_post(query):
        if "GG_NO_MATCH_7F31" in query:
            return response({"dogs": []})
        if "OR 1=1" in query:
            return response({"dogs": [{"id": "1", "name": "Rex"}]})
        return response({"dogs": []})

    scanner._post = fake_post
    findings = scanner.run()

    assert any(
        item.rule_id == "GG-INJECTION-SQL-BEHAVIOR"
        for item in findings
    )


def test_active_scanner_confirms_same_origin_ssrf():
    schema = make_schema(
        [],
        mutation_fields=[
            {
                "name": "importPaste",
                "args": [
                    {"name": "host", "type": scalar("String", required=True)},
                    {"name": "path", "type": scalar("String", required=True)},
                    {"name": "port", "type": scalar("Int", required=True)},
                    {"name": "scheme", "type": scalar("String", required=True)},
                ],
                "type": object_ref("Paste"),
            }
        ],
        extra_types=[
            {
                "kind": "OBJECT",
                "name": "Paste",
                "fields": [
                    {"name": "id", "args": [], "type": scalar("ID")},
                    {"name": "content", "args": [], "type": scalar("String")},
                ],
            }
        ],
    )
    scanner = ActiveSecurityScanner(
        "http://localhost:5013/graphql",
        schema=schema,
        profile="aggressive",
        technique="I",
    )
    scanner._post = lambda query: response(
        {"importPaste": {"id": "1", "content": "<title>GraphiQL</title>"}}
    )

    findings = scanner.run()

    assert any(
        item.rule_id == "GG-INJECTION-SSRF-SAME-ORIGIN"
        for item in findings
    )
