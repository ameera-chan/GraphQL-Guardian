"""Rule-based schema auditor for sensitive field detection."""

from typing import List
from src.scanner.base_scanner import BaseScanner
from src.reporters.models import Finding
from src.config import (
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
    CATEGORY_AUDIT,
    DOS_PAGINATION_OVERRIDE_LIMIT,
)


class SchemaAuditor(BaseScanner):
    """
    Audits a GraphQL schema for security issues using rule-based pattern matching.
    
    Checks for:
    1. Sensitive Information Exposure (passwords, tokens, keys)
    2. PII Exposure (email, phone, SSN)
    3. Dangerous Arguments (isAdmin, debug)
    4. Private/Hidden Fields (underscore prefix)
    """

    # Rule Definitions
    SENSITIVE_KEYWORDS = [
        'password', 'secret', 'token', 'key', 'auth', 'credential', 
        'hash', 'salt', 'private', 'admin', 'otp', 'pin', 'access_token',
        'refresh_token', 'api_key', 'session'
    ]
    
    PII_KEYWORDS = [
        'email', 'phone', 'mobile', 'address', 'dob', 'birthdate', 
        'ssn', 'social_security', 'credit_card', 'passport', 'national_id',
        'driver_license', 'tax_id'
    ]
    
    DANGEROUS_ARGS = [
        'isadmin', 'is_admin', 'role', 'debug', 'test', 'privilege', 
        'group', 'bypass', 'sudo', 'root'
    ]

    def run(self) -> List[Finding]:
        """
        Execute schema audit and return findings.
        
        Returns:
            List of Finding objects
        """
        self.logger.info("Starting rule-based schema audit")
        
        type_map = self.get_type_map()
        
        for type_name, type_def in type_map.items():
            # Skip standard GraphQL introspection types
            if type_name.startswith('__'):
                continue
                
            self._check_type_fields(type_name, type_def)

        # Structural / exposure checks
        self.check_bidirectional_relationships()
        self.check_subscription_exposure()
        self.check_pagination_override()
        
        self.logger.info(f"Schema audit complete: {len(self.findings)} findings")
        return self.findings

    def _check_type_fields(self, type_name: str, type_def: dict) -> None:
        """Check fields of a specific type for security issues."""
        if not type_def.get('fields'):
            return

        for field in type_def['fields']:
            field_name = field['name']
            field_lower = field_name.lower()
            
            # 1. Check for Sensitive Keywords in Field Name
            for keyword in self.SENSITIVE_KEYWORDS:
                if keyword in field_lower:
                    self.add_finding(
                        title=f"Sensitive Field Exposed: {type_name}.{field_name}",
                        description=f"The field '{field_name}' in type '{type_name}' contains the sensitive keyword '{keyword}'. "
                                   f"This may expose credentials, tokens, or secrets to unauthorized users.",
                        severity=SEVERITY_HIGH,
                        category=CATEGORY_AUDIT,
                        field=f"{type_name}.{field_name}",
                        evidence={
                            "candidate_source": "rule",
                            "candidate_kind": "sensitive_field",
                            "location": f"{type_name}.{field_name}",
                            "matched_keyword": keyword,
                            "matched_keywords": [keyword],
                            "field_type": self._get_field_type_name(field),
                            "rule_strength": "high",
                        },
                        remediation=f"1. Add authentication/authorization checks\n"
                                   f"2. Consider renaming to avoid obvious sensitive naming\n"
                                   f"3. Implement field-level permissions"
                    )
                    self.logger.warning(f"Sensitive field detected: {type_name}.{field_name} (keyword: {keyword})")
                    break  # Only report once per field
                    
            # 2. Check for PII Keywords in Field Name
            for keyword in self.PII_KEYWORDS:
                if keyword in field_lower:
                    self.add_finding(
                        title=f"PII Field Detected: {type_name}.{field_name}",
                        description=f"The field '{field_name}' in type '{type_name}' contains the PII keyword '{keyword}'. "
                                   f"Ensure this personal data is properly protected and complies with privacy regulations (GDPR, CCPA).",
                        severity=SEVERITY_MEDIUM,
                        category=CATEGORY_AUDIT,
                        field=f"{type_name}.{field_name}",
                        evidence={
                            "candidate_source": "rule",
                            "candidate_kind": "pii_field",
                            "location": f"{type_name}.{field_name}",
                            "matched_keyword": keyword,
                            "matched_keywords": [keyword],
                            "field_type": self._get_field_type_name(field),
                            "rule_strength": "medium",
                        },
                        remediation=f"1. Implement data access controls\n"
                                   f"2. Add data masking for unauthorized users\n"
                                   f"3. Ensure GDPR/CCPA compliance"
                    )
                    self.logger.info(f"PII field detected: {type_name}.{field_name} (keyword: {keyword})")
                    break  # Only report once per field

            # 3. Check for Private Fields (Underscore prefix)
            if field_name.startswith('_') and not field_name.startswith('__'):
                self.add_finding(
                    title=f"Private Field Potentially Exposed: {type_name}.{field_name}",
                    description=f"The field '{field_name}' in type '{type_name}' starts with an underscore, "
                               f"suggesting it might be an internal or private field accidentally exposed in the public schema.",
                    severity=SEVERITY_LOW,
                    category=CATEGORY_AUDIT,
                    field=f"{type_name}.{field_name}",
                    evidence={"field_type": self._get_field_type_name(field)},
                    remediation="Review if this field should be private. Remove from public schema or rename without underscore prefix."
                )
                self.logger.debug(f"Private field detected: {type_name}.{field_name}")

            # 4. Check Arguments for Dangerous Patterns
            if field.get('args'):
                for arg in field['args']:
                    arg_name = arg['name']
                    arg_lower = arg_name.lower()
                    
                    for keyword in self.DANGEROUS_ARGS:
                        if keyword == arg_lower or f"_{keyword}" in arg_lower or keyword in arg_lower:
                            self.add_finding(
                                title=f"Dangerous Argument: {type_name}.{field_name}({arg_name})",
                                description=f"The argument '{arg_name}' in field '{type_name}.{field_name}' suggests potential "
                                           f"privilege escalation, debug access, or administrative functionality.",
                                severity=SEVERITY_HIGH,
                                category=CATEGORY_AUDIT,
                                field=f"{type_name}.{field_name}",
                                evidence={
                                    "argument": arg_name, 
                                    "matched_keyword": keyword,
                                    "arg_type": self._get_arg_type_name(arg)
                                },
                                remediation=f"1. Implement strict authorization checks\n"
                                           f"2. Add rate limiting\n"
                                           f"3. Log all uses of this argument\n"
                                           f"4. Consider removing from public API"
                            )
                            self.logger.warning(f"Dangerous argument detected: {type_name}.{field_name}({arg_name}) (keyword: {keyword})")
                            break  # Only report once per argument

    def _get_field_type_name(self, field: dict) -> str:
        """Extract the type name from a field definition."""
        from src.scanner.schema_utils import SchemaUtils
        schema_utils = SchemaUtils(self.schema)
        return schema_utils.get_scalar_type_name(field['type'])
    
    def _get_arg_type_name(self, arg: dict) -> str:
        """Extract the type name from an argument definition."""
        from src.scanner.schema_utils import SchemaUtils
        schema_utils = SchemaUtils(self.schema)
        return schema_utils.get_scalar_type_name(arg['type'])

    # ── Structural / Exposure Checks ─────────────────────────────────────────

    def _resolve_object_type(self, type_ref: dict) -> str:
        """Resolve the underlying OBJECT type name from a type reference."""
        if not type_ref:
            return None
        kind = type_ref.get('kind')
        if kind in ('NON_NULL', 'LIST'):
            return self._resolve_object_type(type_ref.get('ofType'))
        if kind == 'OBJECT':
            return type_ref.get('name')
        return None

    def _resolve_scalar_type(self, type_ref: dict) -> str:
        """Resolve the underlying SCALAR type name from a type reference."""
        if not type_ref:
            return None
        kind = type_ref.get('kind')
        if kind in ('NON_NULL', 'LIST'):
            return self._resolve_scalar_type(type_ref.get('ofType'))
        if kind == 'SCALAR':
            return type_ref.get('name')
        return None

    def check_bidirectional_relationships(self) -> None:
        """Analyze schema for bidirectional type relationships (circular query risk).

        Checklist: DoS – Review the API\u2019s SDL file for bidirectional relationships.
        Types that reference each other (e.g. User -> Posts -> User) create
        circular query paths exploitable for recursive DoS attacks.
        """
        type_map = self.get_type_map()

        # Build adjacency: type A -> type B if A has a field returning type B
        adjacency = {}
        for type_name, type_def in type_map.items():
            if type_name.startswith('__') or not type_def.get('fields'):
                continue
            for field in type_def['fields']:
                target = self._resolve_object_type(field['type'])
                if target and target in type_map and not target.startswith('__'):
                    adjacency.setdefault(type_name, set()).add(target)

        # Find bidirectional pairs: A -> B and B -> A
        found_pairs = set()
        for a, targets in adjacency.items():
            for b in targets:
                if b in adjacency and a in adjacency[b] and a != b:
                    found_pairs.add(tuple(sorted([a, b])))

        if found_pairs:
            pairs_str = ', '.join(f'{a} <-> {b}' for a, b in list(found_pairs)[:10])
            self.add_finding(
                title="Bidirectional Type Relationships Detected",
                description=(
                    f"Found {len(found_pairs)} bidirectional relationship(s): {pairs_str}. "
                    f"These create circular query paths that attackers can exploit "
                    f"for recursive query DoS attacks."
                ),
                severity=SEVERITY_MEDIUM,
                category=CATEGORY_AUDIT,
                evidence={'pairs': [list(p) for p in found_pairs]},
                remediation=(
                    "Implement query-depth limiting and query-cost analysis. "
                    "Consider limiting one direction of bidirectional relationships."
                ),
            )
            self.logger.warning(f"Bidirectional relationships: {pairs_str}")
        else:
            self.logger.info("No bidirectional type relationships found")

    def check_subscription_exposure(self) -> None:
        """Check if the schema exposes GraphQL subscriptions (WebSocket attack surface).

        Checklist: Hijacking Requests – Identify whether the server supports
        subscriptions.  Subscriptions typically use WebSocket and may be
        vulnerable to Cross-Site WebSocket Hijacking (CSWSH) if Origin
        headers are not validated.
        """
        try:
            schema_root = self.schema.get('__schema', self.schema) if isinstance(self.schema, dict) else self.schema
            sub_type = schema_root.get('subscriptionType')
            if sub_type:
                sub_type_name = sub_type.get('name', 'Subscription')
                type_def = self.get_type_map().get(sub_type_name, {})
                sub_fields = [f['name'] for f in type_def.get('fields', [])]

                self.add_finding(
                    title="GraphQL Subscriptions Exposed",
                    description=(
                        f"Schema defines {len(sub_fields)} subscription(s): "
                        f"{', '.join(sub_fields[:5])}"
                        f"{'...' if len(sub_fields) > 5 else ''}.  "
                        f"Subscriptions use WebSocket connections and may be vulnerable "
                        f"to Cross-Site WebSocket Hijacking (CSWSH) if Origin headers "
                        f"are not validated during the handshake."
                    ),
                    severity=SEVERITY_MEDIUM,
                    category=CATEGORY_AUDIT,
                    evidence={'subscriptions': sub_fields},
                    remediation=(
                        "1. Validate the Origin header during WebSocket handshake\n"
                        "2. Require authentication for all subscriptions\n"
                        "3. Implement subscription rate limiting"
                    ),
                )
                self.logger.warning(f"Subscriptions exposed: {sub_fields}")
        except Exception as e:
            self.logger.debug(f"Subscription check error: {e}")

    def check_pagination_override(self) -> None:
        """Test if pagination arguments accept very large values (data exfiltration / DoS).

        Checklist: DoS – Object limit overriding in API pagination arguments
        such as filter, max, limit, and total.
        """
        type_map = self.get_type_map()
        query_type = type_map.get('Query')
        if not query_type or not query_type.get('fields'):
            return

        pagination_keywords = {
            'limit', 'first', 'last', 'max', 'count', 'size',
            'pagesize', 'per_page', 'offset', 'total', 'filter',
        }
        tested = False

        for field in query_type['fields']:
            if tested:
                break
            for arg in field.get('args', []):
                if arg['name'].lower() in pagination_keywords:
                    arg_scalar = self._resolve_scalar_type(arg['type'])
                    if arg_scalar not in ('Int', 'Float', 'ID'):
                        continue

                    query = (
                        f'{{ {field["name"]}({arg["name"]}: '
                        f'{DOS_PAGINATION_OVERRIDE_LIMIT}) {{ __typename }} }}'
                    )
                    response = self.http_client.post_graphql(query)

                    if response.is_success() and response.has_data():
                        self.add_finding(
                            title=f"Pagination Limit Override: {field['name']}({arg['name']})",
                            description=(
                                f"Server accepted {arg['name']}={DOS_PAGINATION_OVERRIDE_LIMIT} "
                                f"for query '{field['name']}'.  An attacker can exfiltrate "
                                f"large amounts of data or exhaust server resources."
                            ),
                            severity=SEVERITY_MEDIUM,
                            category=CATEGORY_AUDIT,
                            evidence={
                                'field': field['name'],
                                'argument': arg['name'],
                                'value': DOS_PAGINATION_OVERRIDE_LIMIT,
                                'response_time': response.response_time,
                            },
                            remediation=(
                                "Enforce maximum pagination limits server-side "
                                "(e.g., max 100 records per request)."
                            ),
                        )
                        self.logger.warning(
                            f"Pagination override accepted: {field['name']}({arg['name']}={DOS_PAGINATION_OVERRIDE_LIMIT})"
                        )
                        tested = True
                        break

        if not tested:
            self.logger.info("No exploitable pagination arguments found")
