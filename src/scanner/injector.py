import json
import time
import click
from typing import Dict, List
from src.payloads.matcher import select_payloads
from src.scanner.query_builder import QueryBuilder
from src.scanner.base_scanner import BaseScanner
from src.reporters.models import Finding
from src.config import SEVERITY_HIGH, SEVERITY_MEDIUM, CATEGORY_INJECTION

class PayloadInjector(BaseScanner):
    def __init__(self, endpoint: str, schema: Dict, config: Dict = None, graph: Dict = None):
        super().__init__(endpoint, schema, config, graph)
        self.builder = QueryBuilder(self.get_type_map())

    def _get_scalar_type_name(self, type_ref):
        while type_ref['kind'] in ['NON_NULL', 'LIST']:
            type_ref = type_ref['ofType']
        return type_ref['name']

    def generate_fuzz_cases(self):
        """
        Generates a list of fuzz cases.
        Each case is a dict: {
            'operation_type': 'Query'|'Mutation',
            'field': field_name,
            'arg': arg_name,
            'payload': payload_string,
            'category': payload_category
        }
        """
        cases = []
        
        # Fuzz Mutations
        type_map = self.get_type_map()
        mutation_type = type_map.get('Mutations') or type_map.get('Mutation')
        if mutation_type:
            for field in mutation_type['fields']:
                for arg in field['args']:
                    type_name = self._get_scalar_type_name(arg['type'])
                    payloads = select_payloads(arg['name'], type_name)
                    
                    for p in payloads:
                        cases.append({
                            'operation_type': mutation_type['name'], # Use actual name from schema
                            'field': field['name'],
                            'arg': arg['name'],
                            'payload': p
                        })

        # Fuzz Queries
        query_type = type_map.get('Query')
        if query_type:
            for field in query_type['fields']:
                for arg in field['args']:
                    type_name = self._get_scalar_type_name(arg['type'])
                    payloads = select_payloads(arg['name'], type_name)
                    
                    for p in payloads:
                        cases.append({
                            'operation_type': query_type['name'],
                            'field': field['name'],
                            'arg': arg['name'],
                            'payload': p
                        })
                        
        return cases

    def _extract_id(self, data: Dict, op_name: str) -> str:
        """Extracts ID from the response data for a given operation."""
        if not data or 'data' not in data:
            return None
        
        op_data = data['data'].get(op_name)
        if not op_data:
            return None
            
        # If it returns a list (e.g. createMany), take the first
        if isinstance(op_data, list) and len(op_data) > 0:
            op_data = op_data[0]
            
        if isinstance(op_data, dict):
            return op_data.get('id')
            
        return None

    def _check_stored_xss(self, case, response_json, headers):
        """
        Checks if the injected payload is stored and returned by an accessor query.
        """
        if not self.graph or not response_json:
            return None

        op_name = case['field']
        
        # Only check if this operation is a known Creator
        if op_name not in self.graph.get('creators', {}):
            return None
            
        # Extract the ID of the created resource
        resource_id = self._extract_id(response_json, op_name)
        if not resource_id:
            return None
            
        # Find a suitable Accessor
        creator_info = self.graph['creators'][op_name]
        accessors = creator_info.get('accessors', [])
        
        if not accessors:
            return None
            
        # Try the first accessor
        accessor_name = accessors[0]
        
        # Build query: query { accessor(id: "123") { field_we_injected } }
        # Note: We need to ask for the field we injected to see if it comes back.
        # But QueryBuilder usually asks for all scalar fields. That's fine.
        
        query = self.builder.construct_operation(
            'Query',
            accessor_name,
            args_overrides={'id': resource_id}
        )
        
        if not query:
            return None
            
        try:
            # Send the accessor query
            resp = self.http_client.post_graphql(query, headers=headers)
            
            if resp.is_success() and case['payload'] in resp.raw_text:
                return {
                    'type': 'Stored XSS',
                    'details': f"Payload stored via {op_name} and retrieved via {accessor_name}"
                }
        except:
            pass
            
        return None

    def analyze_response(self, response, case):
        """
        Analyzes the response for signs of vulnerability.
        """
        issues = []
        
        # 1. Reflected XSS / Payload Reflection
        # If the payload appears in the response body exactly as sent
        if case['payload'] in response.raw_text:
            # Exclude simple echo if it's just the query parameter reflection in error message
            # But if it's in 'data', it's interesting.
            if response.has_data() and case['payload'] in json.dumps(response.data):
                 issues.append({
                    'type': 'Reflected Payload',
                    'details': f"Payload reflected in data: {case['payload']}"
                })
        
        # 2. SQL Injection Errors
        # Check for SQL syntax errors
        sql_errors = ["syntax error", "sql", "database", "ora-", "mysql", "postgres"]
        if any(e in response.raw_text.lower() for e in sql_errors):
             issues.append({
                'type': 'SQL Injection Error',
                'details': f"Potential SQL error detected."
            })
            
        # 3. Server Errors (500)
        if response.status_code == 500:
             issues.append({
                'type': 'Server Error',
                'details': f"Internal Server Error (500) triggered."
            })
            
        return issues

    def run(self) -> List[Finding]:
        """Execute injection fuzzing and return findings."""
        self.logger.info("Starting injection fuzzing")
        
        cases = self.generate_fuzz_cases()
        self.logger.info(f"Generated {len(cases)} fuzz cases")
        
        unique_vulns = set()
        
        with click.progressbar(cases, label='      Fuzzing ', fill_char=click.style('\u2588', fg='cyan'), empty_char='\u2591') as bar:
            for case in bar:
                # Construct query with payload
                query = self.builder.construct_operation(
                    case['operation_type'], 
                    case['field'], 
                    args_overrides={case['arg']: case['payload']}
                )
                
                if not query:
                    continue
                    
                try:
                    # Send request
                    # Use user_a headers if available, or none
                    headers = {}
                    if self.config and 'user_a' in self.config:
                        headers = self.config['user_a'].get('headers', {})
                        
                    resp = self.http_client.post_graphql(query, headers=headers)
                    
                    # Check for Reflected XSS / SQLi
                    issues = self.analyze_response(resp, case)
                    
                    # Check for Stored XSS (if applicable)
                    try:
                        stored_issue = self._check_stored_xss(case, resp.data, headers)
                        if stored_issue:
                            issues.append(stored_issue)
                    except:
                        pass

                    if issues:
                        for issue in issues:
                            # Determine severity based on vulnerability type
                            severity = SEVERITY_HIGH if issue['type'] in ['SQL Injection Error', 'Stored XSS'] else SEVERITY_MEDIUM
                            
                            self.add_finding(
                                title=f"{issue['type']} in {case['field']}",
                                description=issue['details'],
                                severity=severity,
                                category=CATEGORY_INJECTION,
                                operation_name=f"{case['operation_type']}.{case['field']}",
                                field=case['arg'],
                                evidence={
                                    "payload": case["payload"],
                                    "issue_type": issue["type"],
                                    "operation_type": case["operation_type"],
                                    "operation_field": case["field"],
                                    "argument": case["arg"],
                                },
                                response=resp,
                            )
                            
                            # Deduplicate console output
                            vuln_key = f"{issue['type']}:{case['field']}:{case['arg']}"
                            if vuln_key not in unique_vulns:
                                click.echo("") # Newline to break progress bar
                                click.secho(f"      \u2718  FOUND: {issue['type']} in {case['field']}({case['arg']})", fg='red', bold=True)
                                unique_vulns.add(vuln_key)
                            
                except Exception as e:
                    # click.echo(f"    [-] Error executing case: {e}")
                    pass
        
        self.logger.info(f"Injection fuzzing complete: {len(self.findings)} findings")
        return self.findings
