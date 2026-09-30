from unittest.mock import MagicMock

import pytest

from src.scanner.config_checker import ConfigChecker
from src.utils.http_client import GraphQLResponse


def gql_response(data=None, errors=None, status_code=200, raw_text=None):
    return GraphQLResponse(
        data=data,
        errors=errors,
        status_code=status_code,
        raw_text=raw_text or "",
        response_time=0.01,
    )


@pytest.fixture
def checker():
    return ConfigChecker("http://localhost:5000/graphql")


def test_check_introspection_enabled(checker):
    checker.http_client.post_graphql = MagicMock(
        return_value=gql_response(data={"__schema": {"queryType": {"name": "Query"}}})
    )

    checker.check_introspection()

    result = checker.findings[0]
    assert result.title == "Introspection Enabled"
    assert result.severity == "MEDIUM"


def test_check_introspection_disabled(checker):
    checker.http_client.post_graphql = MagicMock(
        return_value=gql_response(errors=[{"message": "Introspection is not allowed"}])
    )

    checker.check_introspection()

    result = checker.findings[0]
    assert result.title == "Introspection Disabled"
    assert result.severity == "INFO"


def test_check_graphiql_found(checker):
    mock_response = MagicMock(status_code=200)
    mock_response.text = "<html><title>GraphiQL</title></html>"
    checker.http_client.get = MagicMock(return_value=mock_response)

    checker.check_graphiql()

    result = checker.findings[0]
    assert result.title == "Public GraphQL IDE Interface"
    assert result.severity == "MEDIUM"
    assert result.rule_id == "GG-CONFIG-PUBLIC-GRAPHQL-IDE"


def test_check_verbose_errors(checker):
    checker.http_client.post_graphql = MagicMock(
        return_value=gql_response(errors=[{"message": "Syntax Error: Stack Trace"}])
    )

    checker.check_verbose_errors()

    result = checker.findings[0]
    assert result.title == "Verbose Error Messages"
    assert result.severity == "LOW"


def test_check_query_complexity_safe(checker):
    checker.http_client.post_graphql = MagicMock(
        return_value=gql_response(errors=[{"message": "Query depth limit exceeded"}])
    )

    checker.check_query_complexity()

    result = checker.findings[0]
    assert result.title == "Query Complexity Limit Enforced"
    assert result.severity == "INFO"


def test_check_field_suggestions_uses_discovered_root_field(checker):
    checker.http_client.post_graphql = MagicMock(
        side_effect=[
            gql_response(
                data={
                    "__type": {
                        "fields": [{"name": "pastes"}],
                    }
                }
            ),
            gql_response(
                errors=[
                    {
                        "message": (
                            'Cannot query field "pastex" on type "Query". '
                            'Did you mean "pastes" or "paste"?'
                        )
                    }
                ]
            ),
        ]
    )

    checker.check_field_suggestions()

    assert checker.findings[0].title == "Field Suggestion Feature Enabled"
    assert "pastex" in checker.http_client.post_graphql.call_args_list[1].args[0]


def test_check_field_suggestions_preserves_protected_result(checker):
    checker.http_client.post_graphql = MagicMock(
        side_effect=[
            gql_response(
                data={
                    "__type": {
                        "fields": [{"name": "auth"}],
                    }
                }
            ),
            gql_response(
                errors=[
                    {
                        "message": (
                            "Validation error of type FieldUndefined: "
                            "Field 'autx' is undefined"
                        )
                    }
                ]
            ),
        ]
    )

    checker.check_field_suggestions()

    assert checker.findings[0].title == "Field Suggestions Disabled"


def test_query_complexity_probe_is_valid_recursive_type_query(checker):
    checker.http_client.post_graphql = MagicMock(
        return_value=gql_response(
            data={
                "__type": {
                    "fields": [
                        {
                            "type": {
                                "kind": "OBJECT",
                                "name": "User",
                            }
                        }
                    ]
                }
            }
        )
    )

    checker.check_query_complexity()

    query = checker.http_client.post_graphql.call_args.args[0]
    assert query.count("ofType") == 15
    assert "types { types" not in query
    assert checker.findings[0].title == "No Query Complexity Limit"
