import requests
import json
from graphql import (
    GraphQLEnumType,
    GraphQLInputObjectType,
    GraphQLInterfaceType,
    GraphQLObjectType,
    GraphQLScalarType,
    GraphQLUnionType,
    get_introspection_query,
    build_client_schema,
)
from graphql.utilities import print_schema
from src.utils.files import write_json

def fetch_introspection(endpoint):
    """
    Sends a standard GraphQL introspection query to the endpoint.
    Returns the introspection result (dict) or raises an exception.
    """
    query = get_introspection_query()
    headers = {'Content-Type': 'application/json'}
    
    try:
        response = requests.post(endpoint, json={'query': query}, headers=headers, timeout=10)
        response.raise_for_status()
        
        result = response.json()
        
        if 'errors' in result:
            raise Exception(f"GraphQL Errors: {result['errors']}")
            
        if 'data' not in result:
            raise Exception("Invalid GraphQL response: 'data' field missing.")
            
        return result['data']
        
    except requests.exceptions.RequestException as e:
        raise Exception(f"Network error connecting to {endpoint}: {str(e)}")
    except json.JSONDecodeError:
        raise Exception(f"Invalid JSON response from {endpoint}")

def save_schema(introspection_data, output_file):
    """
    Saves the introspection data to a JSON file.
    """
    write_json(output_file, introspection_data)

def parse_schema_details(introspection_data):
    """
    Parses the introspection data using graphql-core to extract high-level details.
    Returns a summary dict.
    """
    try:
        # build_client_schema expects the 'data' dictionary (containing __schema) 
        # or the full response dictionary. We passed 'data' from fetch_introspection.
        # However, build_client_schema expects the dict to contain {'__schema': ...}
        # fetch_introspection returns result['data'], which usually contains {'__schema': ...}
        
        client_schema = build_client_schema(introspection_data)
        
        summary = {
            "types": [],
            "queries": [],
            "mutations": [],
            "subscriptions": [],
            "object_types": [],
            "input_objects": [],
            "enums": [],
            "interfaces": [],
            "unions": [],
            "custom_scalars": [],
        }
        
        # Extract Types
        type_map = client_schema.type_map
        summary["types"] = list(type_map.keys())
        built_in_scalars = {"String", "Int", "Float", "Boolean", "ID"}

        for type_name, type_def in type_map.items():
            if type_name.startswith("__"):
                continue
            if isinstance(type_def, GraphQLObjectType):
                summary["object_types"].append(type_name)
            elif isinstance(type_def, GraphQLInputObjectType):
                summary["input_objects"].append(type_name)
            elif isinstance(type_def, GraphQLEnumType):
                summary["enums"].append(type_name)
            elif isinstance(type_def, GraphQLInterfaceType):
                summary["interfaces"].append(type_name)
            elif isinstance(type_def, GraphQLUnionType):
                summary["unions"].append(type_name)
            elif isinstance(type_def, GraphQLScalarType) and type_name not in built_in_scalars:
                summary["custom_scalars"].append(type_name)
        
        # Extract Queries
        query_type = client_schema.query_type
        if query_type:
            summary["queries"] = list(query_type.fields.keys())
            
        # Extract Mutations
        mutation_type = client_schema.mutation_type
        if mutation_type:
            summary["mutations"] = list(mutation_type.fields.keys())
            
        # Extract Subscriptions
        subscription_type = client_schema.subscription_type
        if subscription_type:
            summary["subscriptions"] = list(subscription_type.fields.keys())
            
        return summary
        
    except Exception as e:
        raise Exception(f"Failed to parse schema details: {str(e)}")
