from unittest.mock import MagicMock

import pytest

from src.scanner.dos_scanner import DoSScanner
from src.utils.http_client import GraphQLResponse


def gql_response(data=None, errors=None, status_code=200):
    return GraphQLResponse(
        data=data,
        errors=errors,
        status_code=status_code,
        raw_text="",
        response_time=0.01,
    )


@pytest.fixture
def mock_config():
    return {}


def test_dos_scanner_init(mock_config):
    scanner = DoSScanner("http://localhost/graphql", schema={}, config=mock_config)
    assert scanner.endpoint == "http://localhost/graphql"


def test_alias_overloading_vulnerable(mock_config):
    scanner = DoSScanner("http://localhost/graphql", schema={}, config=mock_config)
    scanner.http_client.post_graphql = MagicMock(
        return_value=gql_response(data={"alias1": "val", "alias100": "val"})
    )

    scanner.check_alias_overloading()

    assert scanner.findings[0].title == "Alias Overloading DoS Vulnerability"
    assert scanner.findings[0].severity == "HIGH"


def test_alias_overloading_safe(mock_config):
    scanner = DoSScanner("http://localhost/graphql", schema={}, config=mock_config)
    scanner.http_client.post_graphql = MagicMock(
        return_value=gql_response(errors=[{"message": "Too many aliases"}], status_code=400)
    )

    scanner.check_alias_overloading()

    assert scanner.findings[0].title == "Alias Overloading Protection"
    assert scanner.findings[0].severity == "INFO"


def test_batch_queries_vulnerable(mock_config):
    scanner = DoSScanner("http://localhost/graphql", schema={}, config=mock_config)
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = [{"data": {}}] * 10
    mock_response.elapsed.total_seconds.return_value = 0.01
    scanner.http_client.post_batch = MagicMock(return_value=mock_response)

    scanner.check_batch_query()

    assert scanner.findings[0].title == "Batch Query Support Detected"
    assert scanner.findings[0].severity == "HIGH"


def test_batch_queries_safe(mock_config):
    scanner = DoSScanner("http://localhost/graphql", schema={}, config=mock_config)
    mock_response = MagicMock(status_code=400)
    mock_response.json.return_value = {"errors": [{"message": "Batching not supported"}]}
    scanner.http_client.post_batch = MagicMock(return_value=mock_response)

    scanner.check_batch_query()

    assert scanner.findings[0].title == "No Batch Query Support"
    assert scanner.findings[0].severity == "INFO"


def test_batch_queries_use_universal_typename_canary(mock_config):
    scanner = DoSScanner(
        "http://localhost/graphql",
        schema={},
        config=mock_config,
        operation_pack={
            "packs": {
                "batching": [
                    {
                        "operation_type": "query",
                        "operation_name": "Query.users",
                        "operation": "query { users { id email } }",
                    }
                ]
            }
        },
    )
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = [{"data": {"__typename": "Query"}}] * 10
    mock_response.elapsed.total_seconds.return_value = 0.01
    scanner.http_client.post_batch = MagicMock(return_value=mock_response)

    scanner.check_batch_query()

    batch_payload = scanner.http_client.post_batch.call_args.args[0]
    assert len(batch_payload) == 10
    assert all(
        item["query"] == "query GuardianBatchCanary { __typename }"
        for item in batch_payload
    )
    assert scanner.findings[0].title == "Batch Query Support Detected"


def test_alias_queries_use_universal_typename_canary(mock_config):
    scanner = DoSScanner(
        "http://localhost/graphql",
        schema={},
        config=mock_config,
        operation_pack={
            "packs": {
                "access_control": [
                    {
                        "operation_type": "query",
                        "operation_name": "Query.user",
                        "operation": 'query { user(id: "1") { id } }',
                    }
                ]
            }
        },
    )

    query, candidates = scanner._build_alias_query(4)

    assert "alias0: __typename" in query
    assert "alias3: __typename" in query
    assert len(candidates) == 4
    assert all(candidate["role"] == "general" for candidate in candidates)
    assert all(
        candidate["operation_name"] == "Query.__typename"
        for candidate in candidates
    )


def test_field_duplication_uses_universal_typename_canary(mock_config):
    scanner = DoSScanner(
        "http://localhost/graphql",
        schema={},
        config=mock_config,
    )
    scanner.http_client.post_graphql = MagicMock(
        return_value=gql_response(data={"__typename": "Query"})
    )

    scanner.check_field_duplication()

    query = scanner.http_client.post_graphql.call_args.args[0]
    assert query.count("__typename") == 200
    assert "pastes" not in query
    assert scanner.findings[0].title == "Field Duplication DoS Vulnerability"
