"""Configuration security checker for GraphQL endpoints."""

from typing import List
from urllib.parse import urljoin, urlparse
from src.scanner.base_scanner import BaseScanner
from src.reporters.models import Finding
from src.utils.graphql_ide import detect_graphql_ide
from src.config import (
    MAX_QUERY_DEPTH,
    GRAPHIQL_PATHS,
    VERBOSE_ERROR_KEYWORDS,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
    CATEGORY_CONFIG
)


class ConfigChecker(BaseScanner):
    """Scanner for GraphQL endpoint configuration and security settings."""

    def run(self) -> List[Finding]:
        """
        Execute all configuration security checks.
        
        Returns:
            List of Finding objects
        """
        self.logger.info("Starting configuration security checks")
        
        self.check_introspection()
        self.check_graphiql()
        self.check_verbose_errors()
        self.check_query_complexity()
        self.check_get_method_support()
        self.check_field_suggestions()
        
        self.logger.info(f"Configuration scan complete: {len(self.findings)} findings")
        return self.findings
    
    def check_introspection(self) -> None:
        """Test if GraphQL introspection is enabled."""
        query = """
        query {
            __schema {
                queryType {
                    name
                }
            }
        }
        """
        
        response = self.http_client.post_graphql(query)
        
        if response.is_success() and response.has_data() and response.data.get('__schema'):
            self.add_finding(
                title="Introspection Enabled",
                description="GraphQL introspection is enabled, allowing full schema discovery. "
                           "While useful in development, this exposes your API structure to attackers.",
                severity=SEVERITY_MEDIUM,
                category=CATEGORY_CONFIG,
                rule_id="GG-CONFIG-INTROSPECTION-ENABLED",
                response=response,
                evidence={"query": "__schema.queryType.name"},
                remediation="Disable introspection in production or implement authentication."
            )
            self.logger.warning("Introspection is enabled")
        elif response.has_errors():
            error_msg = str(response.errors).lower()
            if 'introspection' in error_msg and 'not allowed' in error_msg:
                self.add_finding(
                    title="Introspection Disabled",
                    description="Introspection is properly disabled.",
                    severity=SEVERITY_INFO,
                    category=CATEGORY_CONFIG,
                    rule_id="GG-CONFIG-INTROSPECTION-DISABLED",
                    response=response,
                )
                self.logger.info("Introspection is disabled")
            else:
                self.logger.debug(f"Introspection check returned errors: {response.errors}")
        else:
            self.add_finding(
                title="Introspection Check Inconclusive",
                description="Could not determine introspection status.",
                severity=SEVERITY_INFO,
                category=CATEGORY_CONFIG,
                rule_id="GG-CONFIG-INTROSPECTION-INCONCLUSIVE",
                response=response,
            )
            self.logger.warning("Introspection check inconclusive")

    def check_graphiql(self) -> None:
        """Test for publicly accessible GraphiQL/Playground interfaces."""
        parsed = urlparse(self.endpoint)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        found = []
        first_response = None
        for path in GRAPHIQL_PATHS:
            target = urljoin(base, path)
            
            try:
                response = self.http_client.get(path, headers={'Accept': 'text/html'})
                if response and response.status_code == 200:
                    content = response.text.lower()
                    ide_name = detect_graphql_ide(content)
                    if ide_name:
                        found.append({
                            "url": target,
                            "tool": ide_name,
                            "status_code": response.status_code,
                        })
                        first_response = first_response or response
                        self.logger.debug(f"Found {ide_name} interface at: {target}")
            except Exception as e:
                self.logger.debug(f"Error checking {target}: {e}")
        
        if found:
            first = found[0]
            self.add_finding(
                title="Public GraphQL IDE Interface",
                description="Publicly accessible GraphQL IDE interfaces were found. These tools can expose schemas, headers, saved operations, and allow query testing.",
                severity=SEVERITY_MEDIUM,
                category=CATEGORY_CONFIG,
                rule_id="GG-CONFIG-PUBLIC-GRAPHQL-IDE",
                confidence="high",
                state="confirmed",
                evidence={
                    "interfaces_found": found,
                },
                request={
                    "method": "GET",
                    "url": first["url"],
                    "headers": {"Accept": "text/html"},
                },
                response={
                    "status_code": first.get("status_code", 0),
                    "headers": dict(getattr(first_response, "headers", {}) or {}),
                    "body_sample": getattr(first_response, "text", "")[:1200] if first_response else None,
                },
                remediation="Disable or restrict access to GraphiQL/Playground in production."
            )
            self.logger.warning(f"Public GraphQL IDE interfaces found: {', '.join(item['url'] for item in found)}")
        else:
            self.add_finding(
                title="No Public GraphQL IDE Interface",
                description="No common GraphQL IDE interfaces detected.",
                severity=SEVERITY_INFO,
                category=CATEGORY_CONFIG,
                rule_id="GG-CONFIG-NO-PUBLIC-GRAPHQL-IDE",
                confidence="medium",
                state="informational",
            )
            self.logger.info("No public GraphiQL interfaces found")

    def check_verbose_errors(self) -> None:
        """Test if server returns verbose error messages that leak information."""
        query = "query { nonExistentField12345 }"
        
        response = self.http_client.post_graphql(query)
        
        if response.has_errors():
            import json
            errors_text = json.dumps(response.errors).lower()
            found_keywords = [k for k in VERBOSE_ERROR_KEYWORDS if k in errors_text]
            
            if found_keywords:
                self.add_finding(
                    title="Verbose Error Messages",
                    description=f"Server returns verbose error messages that may leak internal information.",
                    severity=SEVERITY_LOW,
                    category=CATEGORY_CONFIG,
                    rule_id="GG-CONFIG-VERBOSE-ERRORS",
                    response=response,
                    evidence={"keywords_found": found_keywords, "sample_error": str(response.errors[0]) if response.errors else None},
                    remediation="Configure server to return sanitized error messages in production."
                )
                self.logger.warning(f"Verbose errors detected with keywords: {', '.join(found_keywords)}")
            else:
                self.add_finding(
                    title="Error Messages Sanitized",
                    description="Errors are returned but appear to be sanitized.",
                    severity=SEVERITY_INFO,
                    category=CATEGORY_CONFIG,
                    rule_id="GG-CONFIG-SANITIZED-ERRORS",
                    response=response,
                )
                self.logger.info("Error messages appear sanitized")
        else:
            # Check raw text for verbose errors in HTTP body
            found_keywords = [k for k in VERBOSE_ERROR_KEYWORDS if k in response.raw_text.lower()]
            if found_keywords:
                self.add_finding(
                    title="Verbose Error Messages in Response Body",
                    description="Verbose error information detected in HTTP response body.",
                    severity=SEVERITY_LOW,
                    category=CATEGORY_CONFIG,
                    rule_id="GG-CONFIG-VERBOSE-ERROR-BODY",
                    response=response,
                    evidence={"keywords_found": found_keywords},
                    remediation="Configure server to return sanitized error messages."
                )
                self.logger.warning(f"Verbose errors in response body: {', '.join(found_keywords)}")
            else:
                self.logger.info("No verbose errors detected")

    def check_query_complexity(self) -> None:
        """Test whether the server enforces query-depth or complexity limits."""
        selection = "name kind"
        for _ in range(MAX_QUERY_DEPTH):
            selection = f"ofType {{ {selection} }}"

        query = (
            'query GuardianDepthCanary { '
            '__type(name: "Query") { fields { type { '
            f"{selection}"
            " } } } }"
        )
        response = self.http_client.post_graphql(query)
        if response.is_success() and response.has_data():
            self.add_finding(
                title="No Query Complexity Limit",
                description=f"Server accepted a deeply nested query (depth {MAX_QUERY_DEPTH}) without rejection. "
                           f"This could be exploited for DoS attacks.",
                severity=SEVERITY_MEDIUM,
                category=CATEGORY_CONFIG,
                rule_id="GG-CONFIG-NO-QUERY-COMPLEXITY-LIMIT",
                response=response,
                evidence={"max_depth_tested": MAX_QUERY_DEPTH},
                remediation="Implement query depth/complexity analysis and limits."
            )
            self.logger.warning(f"No query complexity limit detected (depth {MAX_QUERY_DEPTH} accepted)")
        elif response.has_errors():
            errors_text = str(response.errors).lower()
            if any(keyword in errors_text for keyword in ['depth', 'complexity', 'too deep', 'too complex']):
                self.add_finding(
                    title="Query Complexity Limit Enforced",
                    description="Server rejected deeply nested query, indicating complexity limits are in place.",
                    severity=SEVERITY_INFO,
                    category=CATEGORY_CONFIG,
                    rule_id="GG-CONFIG-QUERY-COMPLEXITY-LIMIT",
                    response=response,
                )
                self.logger.info("Query complexity limit detected")
            else:
                self.logger.debug(f"Query rejected but not explicitly for complexity: {response.errors}")
        else:
            self.logger.debug(f"Query complexity check returned status {response.status_code}")

    def check_get_method_support(self) -> None:
        """Test if server accepts mutations via GET requests (CSRF vulnerability)."""
        query = "mutation { __typename }"
        
        try:
            import requests
            response = requests.get(
                self.endpoint, 
                params={'query': query}, 
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('data') is not None:
                    self.add_finding(
                        title="GET-based Mutations Allowed (CSRF Risk)",
                        description="Server accepts mutations via GET requests, making it vulnerable to CSRF attacks. "
                                   "Mutations should only be accepted via POST.",
                        severity=SEVERITY_HIGH,
                        category=CATEGORY_CONFIG,
                        rule_id="GG-CONFIG-GET-MUTATION-CSRF",
                        request={
                            "method": "GET",
                            "url": response.url,
                            "headers": {},
                        },
                        response={
                            "status_code": response.status_code,
                            "headers": dict(response.headers),
                            "body_sample": response.text[:1200],
                        },
                        remediation="Configure server to reject mutations sent via GET method."
                    )
                    self.logger.warning("GET-based mutations are allowed (CSRF risk)")
                    return
        except Exception as e:
            self.logger.debug(f"GET method check error: {e}")
        
        self.add_finding(
            title="GET-based Mutations Blocked",
            description="Server does not execute mutations via GET requests.",
            severity=SEVERITY_INFO,
            category=CATEGORY_CONFIG,
            rule_id="GG-CONFIG-GET-MUTATION-BLOCKED",
            confidence="medium",
            state="informational",
        )
        self.logger.info("GET-based mutations are blocked")

    def check_field_suggestions(self) -> None:
        """Test field suggestions using real root fields when available."""
        discovery = self.http_client.post_graphql(
            'query GuardianSuggestionFields { '
            '__type(name: "Query") { fields { name } } }'
        )

        fields = []
        if isinstance(discovery.data, dict):
            query_type = discovery.data.get("__type") or {}
            fields = [
                item.get("name")
                for item in query_type.get("fields", [])
                if isinstance(item, dict) and item.get("name")
            ]

        candidates = fields[:5] or ["users", "products", "pastes", "viewer"]
        last_response = discovery

        for field_name in candidates:
            typo = (
                f"{field_name[:-1]}x"
                if len(field_name) > 1
                else f"{field_name}x"
            )
            response = self.http_client.post_graphql(
                f"query GuardianSuggestionProbe {{ {typo} }}"
            )
            last_response = response
            errors_text = str(response.errors or "")

            if "did you mean" not in errors_text.lower():
                continue

            self.add_finding(
                title="Field Suggestion Feature Enabled",
                description=(
                    "The server returned field-name suggestions for an invalid "
                    "root query field, which can assist schema enumeration."
                ),
                severity=SEVERITY_LOW,
                category=CATEGORY_CONFIG,
                rule_id="GG-CONFIG-FIELD-SUGGESTIONS",
                response=response,
                evidence={
                    "valid_field": field_name,
                    "invalid_field": typo,
                    "sample_error": errors_text[:500],
                },
                remediation="Disable field suggestions in production error responses."
            )
            self.logger.warning(
                f"Field suggestions are enabled for the invalid field {typo}"
            )
            return

        self.add_finding(
            title="Field Suggestions Disabled",
            description="The tested invalid fields did not disclose field suggestions.",
            severity=SEVERITY_INFO,
            category=CATEGORY_CONFIG,
            rule_id="GG-CONFIG-FIELD-SUGGESTIONS-DISABLED",
            response=last_response,
        )
        self.logger.info("Field suggestions not detected")
