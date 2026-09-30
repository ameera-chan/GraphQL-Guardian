import networkx as nx
import json
from graphql import build_client_schema, GraphQLObjectType, GraphQLList, GraphQLNonNull, GraphQLScalarType
from graphql.utilities import get_introspection_query
from src.utils.files import write_json

class DependencyGraphBuilder:
    def __init__(self, schema_data):
        # Unwrap 'data' if present, as build_client_schema expects the dict containing '__schema'
        if isinstance(schema_data, dict) and "data" in schema_data:
            schema_data = schema_data["data"]
            
        self.schema = build_client_schema(schema_data)
        self.graph = nx.DiGraph()
        self.resource_creators = []
        self.resource_accessors = []

    def _get_underlying_type(self, gql_type):
        """Recursively unwraps List and NonNull types to get the named type."""
        current = gql_type
        while isinstance(current, (GraphQLList, GraphQLNonNull)):
            current = current.of_type
        return current

    def _get_real_resource_type(self, gql_type):
        """
        If the type is a wrapper (e.g. CreateUserPayload), try to find the actual resource inside.
        Heuristic: If type has 1 field that is an Object, return that.
        """
        if not isinstance(gql_type, GraphQLObjectType):
            return gql_type
            
        # Check if it looks like a wrapper
        # e.g. CreatePaste -> paste: PasteObject
        if len(gql_type.fields) == 1:
            field = list(gql_type.fields.values())[0]
            inner_type = self._get_underlying_type(field.type)
            if isinstance(inner_type, GraphQLObjectType):
                return inner_type
        
        return gql_type

    def build(self):
        """Builds the dependency graph from the schema."""
        
        # 1. Add Object Types as nodes and their field dependencies
        for type_name, type_obj in self.schema.type_map.items():
            if isinstance(type_obj, GraphQLObjectType) and not type_name.startswith('__'):
                self.graph.add_node(type_name, type='object')
                
                # Add edges for fields
                for field_name, field_def in type_obj.fields.items():
                    field_type = self._get_underlying_type(field_def.type)
                    if hasattr(field_type, 'name') and not field_type.name.startswith('__'):
                        # We are interested in relationships between types
                        # If it's a scalar, we might skip it to avoid clutter, 
                        # unless we want to map data flow to scalars.
                        # For dependency graph, usually Object->Object is most interesting.
                        if isinstance(field_type, GraphQLObjectType):
                            self.graph.add_edge(type_name, field_type.name, type='field', field=field_name)

        # 2. Process Mutations (Potential Creators)
        mutation_type = self.schema.mutation_type
        if mutation_type:
            for name, field in mutation_type.fields.items():
                return_type = self._get_underlying_type(field.type)
                node_name = f"Mutation.{name}"
                
                # Add mutation node
                self.graph.add_node(node_name, type='mutation')
                
                # Determine edge type based on heuristics
                edge_type = 'dependency'
                if any(keyword in name.lower() for keyword in ['create', 'add', 'register', 'insert']):
                    edge_type = 'creator'
                    
                    # Try to unwrap resource
                    real_resource = self._get_real_resource_type(return_type)
                    
                    self.resource_creators.append({
                        'operation': node_name,
                        'resource': real_resource.name if hasattr(real_resource, 'name') else str(real_resource)
                    })
                
                # Add edge: Mutation -> Return Type
                if hasattr(return_type, 'name'):
                    self.graph.add_edge(node_name, return_type.name, type=edge_type)

        # 3. Process Queries (Potential Accessors)
        query_type = self.schema.query_type
        if query_type:
            for name, field in query_type.fields.items():
                return_type = self._get_underlying_type(field.type)
                node_name = f"Query.{name}"
                
                # Add query node
                self.graph.add_node(node_name, type='query')
                
                # Determine edge type based on heuristics
                edge_type = 'dependency'
                # Added 'paste', 'users', 'read' to keywords
                if any(keyword in name.lower() for keyword in ['get', 'find', 'list', 'search', 'fetch', 'paste', 'users', 'read']):
                    edge_type = 'accessor'
                    self.resource_accessors.append({
                        'operation': node_name,
                        'resource': return_type.name if hasattr(return_type, 'name') else str(return_type)
                    })
                
                # Add edge: Query -> Return Type
                if hasattr(return_type, 'name'):
                    self.graph.add_edge(node_name, return_type.name, type=edge_type)
        
        return self.graph

    def export_dict(self):
        """Exports the graph and analysis to a dictionary."""
        return {
            "graph": nx.node_link_data(self.graph),
            "analysis": {
                "creators": self.resource_creators,
                "accessors": self.resource_accessors
            }
        }

    def export_json(self, filepath):
        """Exports the graph and analysis to a JSON file."""
        data = self.export_dict()
        write_json(filepath, data)
        return data

    def get_stats(self):
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "creators": len(self.resource_creators),
            "accessors": len(self.resource_accessors)
        }
