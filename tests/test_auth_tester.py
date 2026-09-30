import pytest
from unittest.mock import MagicMock, patch
from src.scanner.auth_tester import AuthTester
from src.reporters.converter import ResultConverter

@pytest.fixture
def mock_schema():
    return {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {
                    "name": "User",
                    "kind": "OBJECT",
                    "fields": [{"name": "id", "type": {"kind": "SCALAR", "name": "ID"}}]
                },
                {
                    "name": "String",
                    "kind": "SCALAR"
                },
                {
                    "name": "ID",
                    "kind": "SCALAR"
                },
                {
                    "name": "Query",
                    "kind": "OBJECT",
                    "fields": [
                        {
                            "name": "getUser",
                            "args": [{"name": "id", "type": {"kind": "SCALAR", "name": "ID"}}],
                            "type": {"kind": "OBJECT", "name": "User"}
                        }
                    ]
                },
                {
                    "name": "Mutation",
                    "kind": "OBJECT",
                    "fields": [
                        {
                            "name": "createUser",
                            "args": [{"name": "name", "type": {"kind": "SCALAR", "name": "String"}}],
                            "type": {"kind": "OBJECT", "name": "User"}
                        }
                    ]
                }
            ]
        }
    }

@pytest.fixture
def mock_graph():
    return {
        "analysis": {
            "creators": [
                {"operation": "Mutation.createUser", "resource": "User"}
            ],
            "accessors": [
                {"operation": "Query.getUser", "resource": "User"}
            ]
        }
    }

@pytest.fixture
def mock_config():
    return {
        "user_a": {"headers": {"Authorization": "Bearer A"}},
        "user_b": {"headers": {"Authorization": "Bearer B"}}
    }

def test_auth_tester_init(mock_schema, mock_graph, mock_config):
    tester = AuthTester("http://localhost/graphql", mock_config, mock_schema, mock_graph)
    assert tester.endpoint == "http://localhost/graphql"
    assert tester.config == mock_config

@patch('src.scanner.auth_tester.requests.post')
def test_auth_tester_run_idor_detected(mock_post, mock_schema, mock_graph, mock_config):
    tester = AuthTester("http://localhost/graphql", mock_config, mock_schema, mock_graph)
    
    # Mock responses
    mock_post.side_effect = [
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": {"id": "123"}}}),
        MagicMock(status_code=200, json=lambda: {"data": {"getUser": {"id": "123"}}}),  # anonymous
        MagicMock(status_code=200, json=lambda: {"data": {"getUser": {"id": "123"}}}),  # user_a
        MagicMock(status_code=200, json=lambda: {"data": {"getUser": {"id": "123"}}}),  # user_b
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": {"id": "anon-1"}}}),  # mutation anonymous
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": {"id": "owner-2"}}}),  # mutation owner
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": {"id": "userb-3"}}}),  # mutation user_b
    ]
    
    results = tester.run()
    
    assert len(results) == 1
    assert results[0]['idor_detected'] is True
    assert results[0]['anonymous_detected'] is True
    assert results[0]['resource'] == "User"
    assert tester.matrix_report["summary"]["resource_checks"] == 1
    assert tester.matrix_report["summary"]["mutation_checks"] == 1

@patch('src.scanner.auth_tester.requests.post')
def test_auth_tester_run_safe(mock_post, mock_schema, mock_graph, mock_config):
    tester = AuthTester("http://localhost/graphql", mock_config, mock_schema, mock_graph)
    
    mock_post.side_effect = [
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": {"id": "123"}}}),
        MagicMock(status_code=200, json=lambda: {"data": {"getUser": None}, "errors": [{"message": "Forbidden"}]}),  # anonymous
        MagicMock(status_code=200, json=lambda: {"data": {"getUser": {"id": "123"}}}),  # user_a
        MagicMock(status_code=200, json=lambda: {"data": {"getUser": None}, "errors": [{"message": "Forbidden"}]}),
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": None}, "errors": [{"message": "Forbidden"}]}),
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": {"id": "owner-2"}}}),
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": None}, "errors": [{"message": "Forbidden"}]}),
    ]
    
    results = tester.run()
    
    assert len(results) == 1
    assert results[0]['idor_detected'] is False
    assert results[0]['anonymous_detected'] is False


@patch('src.scanner.auth_tester.requests.post')
def test_auth_tester_attaches_path_candidates_to_idor_result(mock_post, mock_schema, mock_graph, mock_config):
    path_report = {
        "paths": [
            {
                "path": "Query.getUser",
                "target_type": "User",
                "score": 75,
                "depth": 1,
            }
        ]
    }
    tester = AuthTester(
        "http://localhost/graphql",
        mock_config,
        mock_schema,
        mock_graph,
        path_report=path_report,
    )

    mock_post.side_effect = [
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": {"id": "123"}}}),
        MagicMock(
            status_code=200,
            headers={"Content-Type": "application/json"},
            text='{"data":{"getUser":{"id":"123"}}}',
            json=lambda: {"data": {"getUser": {"id": "123"}}},
        ),
        MagicMock(
            status_code=200,
            headers={"Content-Type": "application/json"},
            text='{"data":{"getUser":{"id":"123"}}}',
            json=lambda: {"data": {"getUser": {"id": "123"}}},
        ),
        MagicMock(
            status_code=200,
            headers={"Content-Type": "application/json"},
            text='{"data":{"getUser":{"id":"123"}}}',
            json=lambda: {"data": {"getUser": {"id": "123"}}},
        ),
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": {"id": "anon-1"}}}),
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": {"id": "owner-2"}}}),
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": {"id": "userb-3"}}}),
    ]

    results = tester.run()

    assert results[0]["idor_detected"] is True
    assert results[0]["paths"][0]["path"] == "Query.getUser"
    assert results[0]["request"]["body"]["query"].startswith("query")
    assert results[0]["response"]["status_code"] == 200
    assert len(results[0]["role_results"]) == 3
    assert results[0]["flow_evidence"]["stateful_reuse"][0]["target_argument"] == "id"
    assert "Owner (User A) received data." in results[0]["flow_evidence"]["decision_summary"]


@patch('src.scanner.auth_tester.requests.post')
def test_auth_tester_matrix_flags_mutation_bola_and_admin(mock_post, mock_schema, mock_graph, mock_config):
    schema = json_clone(mock_schema)
    mutation_fields = next(
        t for t in schema["__schema"]["types"] if t["name"] == "Mutation"
    )["fields"]
    mutation_fields.append(
        {
            "name": "updateUser",
            "args": [
                {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}},
                {"name": "name", "type": {"kind": "SCALAR", "name": "String"}},
            ],
            "type": {"kind": "OBJECT", "name": "User"},
        }
    )
    config = {
        **mock_config,
        "admin": {"headers": {"Authorization": "Bearer ADMIN"}},
    }
    operation_pack = {
        "operations": [
            {
                "operation_type": "mutation",
                "operation_name": "Mutation.updateUser",
                "field": "updateUser",
                "tags": ["idor-candidate"],
                "return_type": "User",
                "all_args": [{"name": "id", "type": "ID"}, {"name": "name", "type": "String"}],
                "required_args": [],
                "risk_score": 90,
            }
        ]
    }

    tester = AuthTester(
        "http://localhost/graphql",
        config,
        schema,
        mock_graph,
        operation_pack=operation_pack,
    )

    mock_post.side_effect = [
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": {"id": "123"}}}),
        MagicMock(status_code=200, json=lambda: {"data": {"getUser": None}}),  # anonymous query
        MagicMock(status_code=200, json=lambda: {"data": {"getUser": {"id": "123"}}}),  # user_a query
        MagicMock(status_code=200, json=lambda: {"data": {"getUser": None}}),  # user_b query
        MagicMock(status_code=200, json=lambda: {"data": {"getUser": {"id": "123"}}}),  # admin query
        MagicMock(status_code=200, json=lambda: {"data": {"updateUser": None}, "errors": [{"message": "Forbidden"}]}),  # anonymous mutation
        MagicMock(status_code=200, json=lambda: {"data": {"updateUser": {"id": "123"}}}),  # owner mutation
        MagicMock(status_code=200, json=lambda: {"data": {"updateUser": {"id": "123"}}}),  # user_b mutation
        MagicMock(status_code=200, json=lambda: {"data": {"updateUser": {"id": "123"}}}),  # admin mutation
    ]

    tester.run()

    assert tester.matrix_report["summary"]["admin_configured"] is True
    assert tester.matrix_report["summary"]["mutation_vulnerabilities"] == 1
    assert tester.matrix_report["mutation_vulnerabilities"][0]["vulnerable_roles"] == ["user_b"]
    assert tester.matrix_report["mutation_vulnerabilities"][0]["stateful_reuse"][0]["target_argument"] == "id"


@patch('src.scanner.auth_tester.requests.post')
def test_auth_tester_matrix_flags_unauthenticated_subscription(mock_post, mock_schema, mock_graph, mock_config):
    schema = json_clone(mock_schema)
    schema["__schema"]["subscriptionType"] = {"name": "Subscription"}
    schema["__schema"]["types"].append(
        {
            "name": "Subscription",
            "kind": "OBJECT",
            "fields": [
                {
                    "name": "userUpdated",
                    "args": [],
                    "type": {"kind": "OBJECT", "name": "User"},
                }
            ],
        }
    )
    operation_pack = {
        "operations": [
            {
                "operation_type": "subscription",
                "operation_name": "Subscription.userUpdated",
                "field": "userUpdated",
                "tags": ["sensitive-surface"],
                "risk_score": 100,
            }
        ]
    }
    tester = AuthTester(
        "http://localhost/graphql",
        mock_config,
        schema,
        mock_graph,
        operation_pack=operation_pack,
    )

    mock_post.side_effect = [
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": {"id": "123"}}}),
        MagicMock(status_code=200, json=lambda: {"data": {"getUser": None}}),
        MagicMock(status_code=200, json=lambda: {"data": {"getUser": {"id": "123"}}}),
        MagicMock(status_code=200, json=lambda: {"data": {"getUser": None}}),
    ]
    tester._probe_subscription_role = MagicMock(side_effect=[
        {
            "role": "anonymous",
            "label": "Anonymous",
            "allowed": True,
            "request": {"method": "WEBSOCKET", "url": "ws://localhost/graphql", "headers": {}, "body": {"query": "subscription { userUpdated { id } }"}},
            "response": {"status_code": 101, "headers": {}, "body_sample": '{"type":"connection_ack"}'},
        },
        {
            "role": "user_a",
            "label": "Owner (User A)",
            "allowed": True,
            "request": {"method": "WEBSOCKET", "url": "ws://localhost/graphql", "headers": {"Authorization": "Bearer A"}, "body": {"query": "subscription { userUpdated { id } }"}},
            "response": {"status_code": 101, "headers": {}, "body_sample": '{"type":"connection_ack"}'},
        },
        {
            "role": "user_b",
            "label": "User B",
            "allowed": True,
            "request": {"method": "WEBSOCKET", "url": "ws://localhost/graphql", "headers": {"Authorization": "Bearer B"}, "body": {"query": "subscription { userUpdated { id } }"}},
            "response": {"status_code": 101, "headers": {}, "body_sample": '{"type":"connection_ack"}'},
        },
    ])

    tester.run()

    assert tester.matrix_report["summary"]["subscription_vulnerabilities"] == 1
    assert tester.matrix_report["subscription_vulnerabilities"][0]["vulnerable_roles"] == ["anonymous"]


def test_convert_auth_results_includes_matrix_findings():
    findings = ResultConverter.convert_auth_results(
        [],
        matrix_report={
            "resource_checks": [
                {
                    "creator": "Mutation.createUser",
                    "accessor": "Query.getUser",
                    "id": "123",
                    "paths": [],
                    "vulnerable_roles": ["anonymous"],
                    "role_results": [
                        {
                            "role": "anonymous",
                            "request": {"method": "POST", "url": "http://localhost/graphql", "headers": {}, "body": {"query": "query { getUser(id:\"123\") { id } }"}},
                            "response": {"status_code": 200, "headers": {}, "body_sample": '{"data":{"getUser":{"id":"123"}}}'},
                        }
                    ],
                }
            ],
            "mutation_vulnerabilities": [
                {
                    "operation_name": "Mutation.updateUser",
                    "resource": "User",
                    "resource_id": "123",
                    "id_argument": "id",
                    "tags": ["idor-candidate"],
                    "reasons": ["User B executed owner-linked mutation."],
                    "vulnerable_roles": ["user_b"],
                    "role_results": [
                        {
                            "role": "user_b",
                            "request": {"method": "POST", "url": "http://localhost/graphql", "headers": {"Authorization": "Bearer B"}, "body": {"query": "mutation { updateUser(id:\"123\") { id } }"}},
                            "response": {"status_code": 200, "headers": {}, "body_sample": '{"data":{"updateUser":{"id":"123"}}}'},
                        }
                    ],
                }
            ],
            "subscription_vulnerabilities": [
                {
                    "operation_name": "Subscription.userUpdated",
                    "endpoint": "ws://localhost/graphql",
                    "tags": ["sensitive-surface"],
                    "reasons": ["Anonymous role was able to initialize and start a sensitive subscription."],
                    "vulnerable_roles": ["anonymous"],
                    "role_results": [
                        {
                            "role": "anonymous",
                            "request": {"method": "WEBSOCKET", "url": "ws://localhost/graphql", "headers": {}, "body": {"query": "subscription { userUpdated { id } }"}},
                            "response": {"status_code": 101, "headers": {}, "body_sample": '{"type":"connection_ack"}'},
                        }
                    ],
                }
            ],
        },
    )

    titles = {finding.title for finding in findings}
    assert "Anonymous Resource Access" in titles
    assert "Mutation Authorization Bypass" in titles
    assert "Unauthenticated Subscription Access" in titles


@patch('src.scanner.auth_tester.requests.post')
def test_auth_tester_records_stateful_flow_report(mock_post, mock_schema, mock_graph, mock_config):
    tester = AuthTester("http://localhost/graphql", mock_config, mock_schema, mock_graph)

    mock_post.side_effect = [
        MagicMock(
            status_code=200,
            headers={"Content-Type": "application/json"},
            text='{"data":{"createUser":{"id":"123"}}}',
            json=lambda: {"data": {"createUser": {"id": "123"}}},
        ),
        MagicMock(
            status_code=200,
            headers={"Content-Type": "application/json"},
            text='{"data":{"getUser":null},"errors":[{"message":"Forbidden"}]}',
            json=lambda: {"data": {"getUser": None}, "errors": [{"message": "Forbidden"}]},
        ),
        MagicMock(
            status_code=200,
            headers={"Content-Type": "application/json"},
            text='{"data":{"getUser":{"id":"123"}}}',
            json=lambda: {"data": {"getUser": {"id": "123"}}},
        ),
        MagicMock(
            status_code=200,
            headers={"Content-Type": "application/json"},
            text='{"data":{"getUser":{"id":"123"}}}',
            json=lambda: {"data": {"getUser": {"id": "123"}}},
        ),
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": {"id": "anon-1"}}}),
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": {"id": "owner-2"}}}),
        MagicMock(status_code=200, json=lambda: {"data": {"createUser": {"id": "userb-3"}}}),
    ]

    tester.run()

    assert tester.matrix_report["summary"]["stateful_flows"] == 1
    flow = tester.matrix_report["stateful_flows"][0]
    assert flow["creator"] == "Mutation.createUser"
    assert flow["accessor"] == "Query.getUser"
    assert flow["creation_request"]["body"]["query"].startswith("mutation")
    assert flow["creation_response"]["status_code"] == 200
    assert flow["stateful_reuse"][0]["value"] == "123"


def json_clone(value):
    import json
    return json.loads(json.dumps(value))
