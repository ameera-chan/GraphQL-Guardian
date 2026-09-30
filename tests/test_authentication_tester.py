from src.scanner.authentication_tester import AuthenticationScanner
from src.utils.http_client import GraphQLResponse


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
                            "name": "me",
                            "args": [],
                            "type": {"kind": "OBJECT", "name": "User"},
                        }
                    ],
                },
                {
                    "kind": "OBJECT",
                    "name": "Mutation",
                    "fields": [
                        {
                            "name": "login",
                            "args": [
                                {"name": "email", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "String"}}},
                                {"name": "password", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "String"}}},
                            ],
                            "type": {"kind": "OBJECT", "name": "AuthPayload"},
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
                {
                    "kind": "OBJECT",
                    "name": "AuthPayload",
                    "fields": [
                        {"name": "accessToken", "args": [], "type": {"kind": "SCALAR", "name": "String"}},
                    ],
                },
                {"kind": "SCALAR", "name": "ID"},
                {"kind": "SCALAR", "name": "String"},
            ],
            "directives": [],
        }
    }
}


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)

    def post_graphql(self, query):
        response = self.responses.pop(0)
        response.request_body = {"query": query}
        return response


def _response(data=None, errors=None, status_code=200):
    return GraphQLResponse(
        data=data,
        errors=errors,
        status_code=status_code,
        raw_text="",
        response_time=0.1,
        request_method="POST",
        request_url="http://localhost/graphql",
        request_headers={"Content-Type": "application/json"},
        request_body=None,
        response_headers={"content-type": "application/json"},
    )


def test_authentication_scanner_flags_anonymous_identity_access_and_verbose_errors():
    operation_pack = {
        "operations": [
            {
                "operation_name": "Query.me",
                "operation_type": "query",
                "tags": ["auth-surface", "identity-query"],
                "operation": "query { me { id email } }",
            },
            {
                "operation_name": "Mutation.login",
                "operation_type": "mutation",
                "tags": ["auth-surface", "credential-flow", "credential-input"],
                "full_operation": 'mutation { login(email: "x", password: "y") { accessToken } }',
            },
        ]
    }
    scanner = AuthenticationScanner(
        "http://localhost/graphql",
        schema=SCHEMA,
        config={},
        operation_pack=operation_pack,
    )
    scanner.anonymous_client = FakeClient(
        [
            _response(data={"me": {"id": "1", "email": "user@example.com"}}),
            _response(errors=[{"message": "User not found"}]),
        ]
    )

    findings = scanner.run()
    titles = [finding.title for finding in findings]

    assert "Authentication Surface Identified" in titles
    assert "Anonymous Current-User Query Accessible" in titles
    assert "Verbose Authentication Error Disclosure" in titles
    assert scanner.report["summary"]["anonymous_identity_accesses"] == 1
    assert scanner.report["summary"]["verbose_auth_errors"] == 1


def test_authentication_scanner_flags_session_data_returned_for_synthetic_credentials():
    operation_pack = {
        "operations": [
            {
                "operation_name": "Mutation.login",
                "operation_type": "mutation",
                "tags": ["auth-surface", "credential-flow", "credential-input"],
                "full_operation": 'mutation { login(email: "x", password: "y") { accessToken } }',
            },
        ]
    }
    scanner = AuthenticationScanner(
        "http://localhost/graphql",
        schema=SCHEMA,
        config={},
        operation_pack=operation_pack,
    )
    scanner.anonymous_client = FakeClient(
        [
            _response(data={"login": {"accessToken": "jwt-token"}}),
        ]
    )

    findings = scanner.run()

    assert any(finding.title == "Authentication Bypass Candidate" for finding in findings)
    assert scanner.report["summary"]["credential_bypass_candidates"] == 1
