from unittest.mock import MagicMock

import pytest

from src.scanner.injector import PayloadInjector
from src.utils.http_client import GraphQLResponse


@pytest.fixture
def mock_schema():
    return {
        "__schema": {
            "types": [
                {
                    "name": "Query",
                    "kind": "OBJECT",
                    "fields": [
                        {
                            "name": "user",
                            "args": [{"name": "id", "type": {"kind": "SCALAR", "name": "String"}}],
                            "type": {"kind": "SCALAR", "name": "String"},
                        }
                    ],
                },
                {
                    "name": "String",
                    "kind": "SCALAR",
                },
            ],
            "queryType": {"name": "Query"},
        }
    }


@pytest.fixture
def mock_config():
    return {}


def gql_response(data=None, errors=None, status_code=200, raw_text=""):
    return GraphQLResponse(
        data=data,
        errors=errors,
        status_code=status_code,
        raw_text=raw_text,
        response_time=0.01,
    )


def test_injector_init(mock_schema, mock_config):
    injector = PayloadInjector("http://localhost/graphql", mock_schema, mock_config)
    assert injector.endpoint == "http://localhost/graphql"


def test_injector_run_vulnerable(mock_schema, mock_config):
    injector = PayloadInjector("http://localhost/graphql", mock_schema, mock_config)
    reflected_payloads = " ".join(case["payload"] for case in injector.generate_fuzz_cases())
    injector.http_client.post_graphql = MagicMock(
        return_value=gql_response(data={"user": reflected_payloads}, raw_text=reflected_payloads)
    )

    results = injector.run()

    assert isinstance(results, list)
    assert any("Reflected Payload" in finding.title for finding in results)


def test_injector_run_sql_error(mock_schema, mock_config):
    injector = PayloadInjector("http://localhost/graphql", mock_schema, mock_config)
    raw_text = '{"errors": [{"message": "Syntax error in SQL statement"}]}'
    injector.http_client.post_graphql = MagicMock(
        return_value=gql_response(
            errors=[{"message": "Syntax error in SQL statement"}],
            raw_text=raw_text,
        )
    )

    results = injector.run()

    assert any("SQL Injection" in finding.title for finding in results)
