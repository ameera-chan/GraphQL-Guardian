"""Utility methods for parsing and working with GraphQL schemas."""

from typing import Dict, List, Optional, Any
import random
import string


class SchemaUtils:
    """Utility class for parsing GraphQL schemas and generating test data."""
    
    def __init__(self, schema: Dict):
        """
        Initialize schema utilities.
        
        Args:
            schema: Introspection schema data
        """
        # Handle wrapped schema
        if 'data' in schema:
            schema = schema['data']
        self.schema = schema
        self.type_map = {t['name']: t for t in schema['__schema']['types']}
    
    def get_query_fields(self) -> List[Dict]:
        """
        Get all query fields.
        
        Returns:
            List of field definitions
        """
        query_type = self.schema['__schema'].get('queryType')
        if not query_type:
            return []
        query_type_def = self.type_map.get(query_type['name'])
        return query_type_def.get('fields', []) if query_type_def else []
    
    def get_mutation_fields(self) -> List[Dict]:
        """
        Get all mutation fields.
        
        Returns:
            List of field definitions
        """
        mutation_type = self.schema['__schema'].get('mutationType')
        if not mutation_type:
            return []
        mutation_type_def = self.type_map.get(mutation_type['name'])
        return mutation_type_def.get('fields', []) if mutation_type_def else []
    
    def get_subscription_fields(self) -> List[Dict]:
        """
        Get all subscription fields.
        
        Returns:
            List of field definitions
        """
        subscription_type = self.schema['__schema'].get('subscriptionType')
        if not subscription_type:
            return []
        subscription_type_def = self.type_map.get(subscription_type['name'])
        return subscription_type_def.get('fields', []) if subscription_type_def else []
    
    def get_scalar_type_name(self, type_ref: Dict) -> str:
        """
        Extract the scalar type name from a field type reference.
        
        Args:
            type_ref: Type reference dict with 'kind' and 'name'/'ofType'
            
        Returns:
            The underlying scalar type name
        """
        while type_ref and type_ref.get('kind') in ['NON_NULL', 'LIST']:
            type_ref = type_ref.get('ofType')
        return type_ref.get('name', 'Unknown') if type_ref else 'Unknown'
    
    def is_sensitive_type(self, type_name: str) -> bool:
        """
        Check if a type is user-defined (not built-in).
        
        Args:
            type_name: The type name to check
            
        Returns:
            True if user-defined, False if built-in
        """
        builtin_types = {'String', 'Int', 'Float', 'Boolean', 'ID'}
        return type_name not in builtin_types and not type_name.startswith('__')
    
    def generate_dummy_value(self, type_ref: Dict) -> Any:
        """
        Generate dummy values for GraphQL types.
        
        Args:
            type_ref: Type reference dict
            
        Returns:
            A dummy value appropriate for the type
        """
        if not type_ref:
            return None
        
        kind = type_ref.get('kind')
        
        if kind == 'NON_NULL':
            return self.generate_dummy_value(type_ref.get('ofType'))
        
        if kind == 'SCALAR':
            scalar_generators = {
                'String': lambda: self._random_string(8),
                'Int': lambda: random.randint(1, 100),
                'Float': lambda: round(random.uniform(1.0, 100.0), 2),
                'Boolean': lambda: random.choice([True, False]),
                'ID': lambda: str(random.randint(1, 1000))
            }
            type_name = type_ref.get('name', 'String')
            return scalar_generators.get(type_name, lambda: 'test')()
        
        if kind == 'INPUT_OBJECT':
            type_name = type_ref.get('name')
            input_type = self.type_map.get(type_name, {})
            obj = {}
            for field in input_type.get('inputFields', []):
                obj[field['name']] = self.generate_dummy_value(field['type'])
            return obj
        
        if kind == 'ENUM':
            type_name = type_ref.get('name')
            enum_type = self.type_map.get(type_name, {})
            enum_values = enum_type.get('enumValues', [])
            if enum_values:
                return enum_values[0]['name']
            return 'UNKNOWN'
        
        if kind == 'LIST':
            return [self.generate_dummy_value(type_ref.get('ofType'))]
        
        return None
    
    def _random_string(self, length: int = 8) -> str:
        """Generate a random string."""
        return ''.join(random.choices(string.ascii_letters, k=length))
    
    def build_selection_set(
        self, 
        type_def: Dict, 
        depth: int = 0, 
        max_depth: int = 2
    ) -> str:
        """
        Build a selection set for a type (recursively).
        
        Args:
            type_def: Type definition dict
            depth: Current recursion depth
            max_depth: Maximum recursion depth
            
        Returns:
            Selection set string
        """
        if depth > max_depth or not type_def or 'fields' not in type_def:
            return ""
        
        fields = []
        for field in type_def.get('fields', []):
            field_type = field['type']
            
            # Unwrap NON_NULL and LIST
            while field_type.get('kind') in ['NON_NULL', 'LIST']:
                field_type = field_type.get('ofType', {})
            
            if field_type.get('kind') == 'SCALAR':
                fields.append(field['name'])
            elif field_type.get('kind') == 'OBJECT' and depth < max_depth:
                # Recurse for nested objects
                nested_type = self.type_map.get(field_type.get('name'))
                if nested_type:
                    nested_selection = self.build_selection_set(
                        nested_type, 
                        depth + 1, 
                        max_depth
                    )
                    if nested_selection:
                        fields.append(f"{field['name']} {{ {nested_selection} }}")
                    else:
                        fields.append(field['name'])
        
        return " ".join(fields[:10])  # Limit to 10 fields to keep queries manageable
