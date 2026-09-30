from unittest.mock import MagicMock

from src.scanner.introspection_bypass import IntrospectionBypassScanner
from src.utils.http_client import GraphQLResponse


def gql_response(data=None, errors=None, status_code=200):
    return GraphQLResponse(
        data=data,
        errors=errors,
        status_code=status_code,
        raw_text="",
        response_time=0.01,
    )


def test_introspection_bypass_detects_type_probe_and_suggestions():
    scanner = IntrospectionBypassScanner("http://localhost:5000/graphql")
    scanner.http_client.post_graphql = MagicMock(
        side_effect=[
            gql_response(errors=[{"message": "Introspection is not allowed"}]),
            gql_response(data={"__type": {"name": "Query", "fields": [{"name": "user"}]}}),
            gql_response(errors=[{"message": "Cannot query field 'typNonsenseGuardian' on type 'Query'. Did you mean 'type'?"}]),
        ]
    )

    findings = scanner.run()

    titles = {finding.title for finding in findings}
    assert "Type-Based Introspection Bypass" in titles
    assert "Error-Guided Schema Recovery Surface" in titles
    assert scanner.report["summary"]["schema_accessible"] is False
    assert scanner.report["summary"]["type_accessible"] is True
    assert scanner.report["summary"]["suggestion_leak"] is True

