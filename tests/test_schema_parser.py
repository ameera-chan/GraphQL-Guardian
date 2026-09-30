import pytest
from unittest.mock import patch, MagicMock
import requests
from src.scanner.schema_parser import fetch_introspection, parse_schema_details

# Mock introspection response data
MOCK_INTROSPECTION_DATA = {
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
                        "name": "getUser",
                        "args": [],
                        "type": {"kind": "SCALAR", "name": "String", "ofType": None}
                    },
                    {
                        "name": "listUsers",
                        "args": [],
                        "type": {"kind": "SCALAR", "name": "String", "ofType": None}
                    }
                ],
                "interfaces": []
            },
            {
                "kind": "OBJECT", 
                "name": "Mutation", 
                "fields": [
                    {
                        "name": "createUser",
                        "args": [],
                        "type": {"kind": "SCALAR", "name": "String", "ofType": None}
                    }
                ],
                "interfaces": []
            },
            {
                "kind": "SCALAR", 
                "name": "String"
            },
            {
                "kind": "SCALAR", 
                "name": "Boolean"
            },
            {
                "kind": "INPUT_OBJECT",
                "name": "CreateUserInput",
                "inputFields": [
                    {
                        "name": "status",
                        "type": {"kind": "ENUM", "name": "Status", "ofType": None},
                        "defaultValue": None,
                    }
                ],
            },
            {
                "kind": "ENUM",
                "name": "Status",
                "enumValues": [
                    {"name": "ACTIVE", "isDeprecated": False, "deprecationReason": None}
                ],
            }
        ],
        "directives": []
    }
}

def test_fetch_introspection_success():
    with patch('src.scanner.schema_parser.requests.post') as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': MOCK_INTROSPECTION_DATA}
        mock_post.return_value = mock_response
        
        result = fetch_introspection('http://localhost/graphql')
        assert result == MOCK_INTROSPECTION_DATA

def test_fetch_introspection_failure():
    with patch('src.scanner.schema_parser.requests.post') as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 500
        # Simulate HTTPError which is a subclass of RequestException
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("500 Server Error")
        mock_post.return_value = mock_response
        
        with pytest.raises(Exception) as excinfo:
            fetch_introspection('http://localhost/graphql')
        assert "Network error" in str(excinfo.value)

def test_parse_schema_details():
    summary = parse_schema_details(MOCK_INTROSPECTION_DATA)
    
    assert "Query" in summary["types"]
    assert "Mutation" in summary["types"]
    assert "getUser" in summary["queries"]
    assert "createUser" in summary["mutations"]
    assert len(summary["subscriptions"]) == 0
    assert "CreateUserInput" in summary["input_objects"]
    assert "Status" in summary["enums"]
