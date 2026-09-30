"""Denial of Service (DoS) vulnerability scanner."""

from typing import Any, Dict, List, Optional
from src.scanner.base_scanner import BaseScanner
from src.scanner.operation_pack import OperationPackGenerator
from src.reporters.models import Finding
from src.config import (
    DOS_ALIAS_COUNT, 
    DOS_BATCH_SIZE, 
    DOS_DIRECTIVE_COUNT,
    DOS_FIELD_DUPLICATION_COUNT,
    DOS_CIRCULAR_DEPTH,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_INFO,
    CATEGORY_DOS,
    PROFILE_DEFAULT,
    PROFILE_AGGRESSIVE,
    profile_allows,
)


class DoSScanner(BaseScanner):
    """Scanner for Denial of Service vulnerabilities in GraphQL endpoints."""

    ROLE_PRIORITY = (
        "access_control",
        "injection",
        "dos",
        "batching",
        "reconnaissance",
        "general",
    )

    def __init__(
        self,
        endpoint: str,
        schema: Dict,
        config: Dict = None,
        graph: Dict = None,
        operation_pack: Optional[Dict] = None,
    ):
        super().__init__(endpoint, schema, config, graph)
        self.operation_pack = operation_pack or self._build_operation_pack()

    def _build_operation_pack(self) -> Dict:
        if not self.schema:
            return {}
        try:
            return OperationPackGenerator(self.schema).generate()
        except Exception:
            return {}

    def _query_candidates_by_role(self) -> Dict[str, List[Dict[str, Any]]]:
        packs = self.operation_pack.get("packs", {})
        grouped: Dict[str, List[Dict[str, Any]]] = {}

        for role in self.ROLE_PRIORITY:
            if role == "general":
                continue
            candidates = []
            seen = set()
            for item in packs.get(role, []):
                operation = item.get("operation")
                if item.get("operation_type") != "query" or not operation:
                    continue
                selection = self._extract_root_selection(operation)
                signature = item.get("operation_name") or selection
                if not selection or signature in seen:
                    continue
                seen.add(signature)
                candidates.append(
                    {
                        "role": role,
                        "operation_name": item.get("operation_name") or item.get("field") or "query",
                        "query": operation,
                        "selection": selection,
                        "tags": item.get("tags", []),
                    }
                )
            if candidates:
                grouped[role] = candidates

        if grouped:
            return grouped

        fallback_candidates = []
        seen = set()
        for item in self.operation_pack.get("operations", []):
            operation = item.get("operation")
            if item.get("operation_type") != "query" or not operation:
                continue
            selection = self._extract_root_selection(operation)
            signature = item.get("operation_name") or selection
            if not selection or signature in seen:
                continue
            seen.add(signature)
            fallback_candidates.append(
                {
                    "role": "general",
                    "operation_name": item.get("operation_name") or "query",
                    "query": operation,
                    "selection": selection,
                    "tags": item.get("tags", []),
                }
            )

        if fallback_candidates:
            return {"general": fallback_candidates}

        return {
            "general": [
                {
                    "role": "general",
                    "operation_name": "Query.__typename",
                    "query": "query { __typename }",
                    "selection": "__typename",
                    "tags": ["fallback"],
                }
            ]
        }

    def _extract_root_selection(self, query_document: str) -> str:
        document = (query_document or "").strip()
        start = document.find("{")
        if start == -1:
            return document

        depth = 0
        content_start = None
        for index in range(start, len(document)):
            token = document[index]
            if token == "{":
                depth += 1
                if depth == 1:
                    content_start = index + 1
            elif token == "}":
                depth -= 1
                if depth == 0 and content_start is not None:
                    return document[content_start:index].strip()

        return document[start + 1 :].rstrip("}").strip()

    def _indent_block(self, block: str, spaces: int = 2) -> str:
        prefix = " " * spaces
        return "\n".join(f"{prefix}{line}" if line else line for line in block.splitlines())

    def _mixed_role_candidates(self, total: int) -> List[Dict[str, Any]]:
        grouped = self._query_candidates_by_role()
        roles = [role for role in self.ROLE_PRIORITY if role in grouped]
        if not roles:
            return []

        indexes = {role: 0 for role in roles}
        selected: List[Dict[str, Any]] = []

        while len(selected) < total:
            progressed = False
            for role in roles:
                pool = grouped.get(role) or []
                if not pool:
                    continue
                candidate = pool[indexes[role] % len(pool)]
                indexes[role] += 1
                selected.append(candidate)
                progressed = True
                if len(selected) >= total:
                    break
            if not progressed:
                break

        return selected

    def _batch_operations(self, batch_size: int) -> tuple[List[Dict[str, str]], List[Dict[str, Any]]]:
        candidate = {
            "role": "general",
            "operation_name": "Query.__typename",
            "query": "query GuardianBatchCanary { __typename }",
            "selection": "__typename",
            "tags": ["universal-canary"],
        }
        candidates = [dict(candidate) for _ in range(batch_size)]
        batch = [{"query": candidate["query"]} for candidate in candidates]
        return batch, candidates

    def _build_alias_query(
        self,
        alias_count: int,
        *,
        alias_prefix: str = "alias",
    ) -> tuple[str, List[Dict[str, Any]]]:
        candidates = [
            {
                "role": "general",
                "operation_name": "Query.__typename",
                "query": "query { __typename }",
                "selection": "__typename",
                "tags": ["universal-canary"],
            }
            for _ in range(alias_count)
        ]
        aliased_fields = [
            f"  {alias_prefix}{index}: __typename"
            for index in range(alias_count)
        ]
        query = (
            "query GuardianAliasCanary {\n"
            + "\n".join(aliased_fields)
            + "\n}"
        )
        return query, candidates

    def _candidate_summary(self, candidates: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        operation_names = []
        seen = set()
        for item in candidates:
            label = f"{item.get('role', 'general')}:{item.get('operation_name', 'query')}"
            if label in seen:
                continue
            seen.add(label)
            operation_names.append(label)
        return {
            "roles_tested": sorted({item.get("role", "general") for item in candidates}),
            "operations_tested": operation_names[:25],
            "operation_mix_size": len(candidates),
        }
    
    def run(self, profile: str = PROFILE_AGGRESSIVE) -> List[Finding]:
        """
        Execute DoS vulnerability checks filtered by scan profile.

        Profiles:
          passive    →  Skip ALL DoS checks (no attack traffic)
          default    →  Safe probes only (alias, batch, directive, rate-limit)
          aggressive →  Full DoS suite including destructive checks

        Args:
            profile: One of 'passive', 'default', 'aggressive'

        Returns:
            List of Finding objects
        """
        self.logger.info(f"Starting DoS checks (profile={profile})")

        # ── default-level checks (moderate, non-destructive) ─────────────
        if profile_allows(profile, PROFILE_DEFAULT):
            self.check_alias_overloading()
            self.check_batch_query()
            self.check_directive_overloading()
            self.check_alias_rate_limit_bypass()
            self.check_field_duplication()
        else:
            self.logger.info("Skipping DoS checks (passive profile)")

        # ── aggressive-level checks (can crash / degrade target) ─────────
        if profile_allows(profile, PROFILE_AGGRESSIVE):
            self.check_circular_query_depth()
            self.check_circular_fragments()
        else:
            self.logger.info("Skipping destructive DoS checks (requires aggressive profile)")

        self.logger.info(f"DoS scan complete: {len(self.findings)} findings")
        return self.findings

    def check_alias_overloading(self) -> None:
        """Test if server accepts excessive query aliases (potential DoS vector)."""
        query, candidates = self._build_alias_query(DOS_ALIAS_COUNT + 1, alias_prefix="alias")
        candidate_summary = self._candidate_summary(candidates)
        
        response = self.http_client.post_graphql(query)
        
        if response.is_success() and response.has_data():
            # Check if we got back the last alias
            if f'alias{DOS_ALIAS_COUNT}' in response.data:
                self.add_finding(
                    title="Alias Overloading DoS Vulnerability",
                    description=f"Server processed {DOS_ALIAS_COUNT + 1} aliases without rejection or rate limiting. "
                               f"An attacker could exploit this to cause resource exhaustion.",
                    severity=SEVERITY_HIGH,
                    category=CATEGORY_DOS,
                    rule_id="GG-DOS-ALIAS-OVERLOADING",
                    response=response,
                    evidence={
                        "alias_count": DOS_ALIAS_COUNT + 1,
                        "response_time": response.response_time,
                        **candidate_summary,
                    },
                    remediation="Implement query complexity limits or alias count restrictions (e.g., max 10 aliases per query)."
                )
                self.logger.warning(f"Alias overloading vulnerability detected ({DOS_ALIAS_COUNT + 1} aliases accepted)")
            else:
                self.add_finding(
                    title="Alias Overloading Protection",
                    description="Server appears to have protection against alias overloading attacks.",
                    severity=SEVERITY_INFO,
                    category=CATEGORY_DOS,
                    rule_id="GG-DOS-ALIAS-OVERLOADING-PROTECTED",
                    response=response,
                )
                self.logger.info("Alias overloading check: Protected")
        else:
            self.add_finding(
                title="Alias Overloading Protection",
                description="Server rejected excessive aliases.",
                severity=SEVERITY_INFO,
                category=CATEGORY_DOS,
                rule_id="GG-DOS-ALIAS-OVERLOADING-PROTECTED",
                response=response,
            )
            self.logger.info("Alias overloading check: Rejected by server")

    def check_batch_query(self) -> None:
        """Test if server accepts array-based batch queries using generated operations."""
        batch, candidates = self._batch_operations(DOS_BATCH_SIZE)
        candidate_summary = self._candidate_summary(candidates)
        
        try:
            response = self.http_client.post_batch(batch)
            
            if response and response.status_code == 200:
                result = response.json()
                if isinstance(result, list) and len(result) == DOS_BATCH_SIZE:
                    response_headers = dict(getattr(response, "headers", {}) or {})
                    response_text = getattr(response, "text", "") or ""
                    if not isinstance(response_text, str):
                        response_text = str(response_text)
                    self.add_finding(
                        title="Batch Query Support Detected",
                        description=f"Server accepts array-based batch queries built from Guardian's generated operation pack "
                                   f"(tested with {DOS_BATCH_SIZE} operations). This mirrors a BatchQL-style abuse path for "
                                   f"rate-limit bypass and bulk enumeration.",
                        severity=SEVERITY_HIGH,
                        category=CATEGORY_DOS,
                        rule_id="GG-DOS-BATCH-QUERY-SUPPORT",
                        request={
                            "method": "POST",
                            "url": self.endpoint,
                            "headers": self.http_client.default_headers,
                            "body": batch,
                        },
                        response={
                            "status_code": response.status_code,
                            "response_time_ms": round(response.elapsed.total_seconds() * 1000, 2),
                            "headers": response_headers,
                            "body_sample": response_text[:1200],
                        },
                        evidence={
                            "batch_size": DOS_BATCH_SIZE,
                            "response_time": response.elapsed.total_seconds(),
                            **candidate_summary,
                            "batch_preview": batch[:3],
                        },
                        remediation="Implement per-batch rate limiting or disable batch query support if not needed."
                    )
                    self.logger.warning(f"Batch query support detected (tested {DOS_BATCH_SIZE} queries)")
                    return
        except Exception as e:
            self.logger.debug(f"Batch query check error: {e}")
        
        self.add_finding(
            title="No Batch Query Support",
            description="Server does not appear to support array-based batch queries using generated GraphQL operations.",
            severity=SEVERITY_INFO,
            category=CATEGORY_DOS,
            rule_id="GG-DOS-NO-BATCH-QUERY-SUPPORT",
            confidence="medium",
            state="informational",
        )
        self.logger.info("Batch query check: Not supported")

    def check_directive_overloading(self) -> None:
        """Test if server accepts queries with excessive directives (potential DoS vector)."""
        directives = "@include(if: true) " * DOS_DIRECTIVE_COUNT
        query = f"query {{ __typename {directives} }}"
        
        response = self.http_client.post_graphql(query)
        
        if response.is_success() and response.has_data():
            self.add_finding(
                title="Directive Overloading DoS Vulnerability",
                description=f"Server processed a query with {DOS_DIRECTIVE_COUNT} directives without rejection. "
                           f"This could be exploited to cause resource exhaustion.",
                severity=SEVERITY_HIGH,
                category=CATEGORY_DOS,
                rule_id="GG-DOS-DIRECTIVE-OVERLOADING",
                response=response,
                evidence={
                    "directive_count": DOS_DIRECTIVE_COUNT,
                    "response_time": response.response_time
                },
                remediation="Implement limits on the number of directives per query (e.g., max 10 directives)."
            )
            self.logger.warning(f"Directive overloading vulnerability detected ({DOS_DIRECTIVE_COUNT} directives accepted)")
        else:
            self.add_finding(
                title="Directive Overloading Protection",
                description="Server rejected or failed to process excessive directives.",
                severity=SEVERITY_INFO,
                category=CATEGORY_DOS,
                rule_id="GG-DOS-DIRECTIVE-OVERLOADING-PROTECTED",
                response=response,
            )
            self.logger.info("Directive overloading check: Protected")

    def check_field_duplication(self) -> None:
        """Test if server accepts queries with massively duplicated fields.

        Technique from Black-Hat-GraphQL Ch5 (field-duplication.graphql).
        A query that repeats the same field hundreds of times can exhaust
        server resources even though the result is logically identical.
        """
        fields = " ".join(
            "__typename" for _ in range(DOS_FIELD_DUPLICATION_COUNT)
        )
        query = f"query GuardianRepeatedFieldCanary {{ {fields} }}"
        response = self.http_client.post_graphql(query)

        if response.is_success() and response.has_data():
            self.add_finding(
                title="Field Duplication DoS Vulnerability",
                description=(
                    f"Server processed a query with {DOS_FIELD_DUPLICATION_COUNT} "
                    f"duplicated fields without rejection.  An attacker can exploit "
                    f"this to amplify response processing cost."
                ),
                severity=SEVERITY_HIGH,
                category=CATEGORY_DOS,
                rule_id="GG-DOS-FIELD-DUPLICATION",
                response=response,
                evidence={
                    'duplicated_fields': DOS_FIELD_DUPLICATION_COUNT,
                    'response_time': response.response_time,
                },
                remediation=(
                    "Implement query-complexity analysis that de-duplicates or "
                    "limits repeated field selections."
                ),
            )
            self.logger.warning(
                f"Field duplication vulnerability detected ({DOS_FIELD_DUPLICATION_COUNT} fields accepted)"
            )
        else:
            self.add_finding(
                title="Field Duplication Protection",
                description="Server rejected or limited queries with excessive duplicated fields.",
                severity=SEVERITY_INFO,
                category=CATEGORY_DOS,
                rule_id="GG-DOS-FIELD-DUPLICATION-PROTECTED",
                response=response,
            )
            self.logger.info("Field duplication check: Protected")

    def check_circular_query_depth(self) -> None:
        """Test if server allows deeply nested circular queries.

        Technique from Black-Hat-GraphQL Ch5 (unsafe-circular-query.graphql).
        Types that reference each other (e.g. Paste->Owner->Pastes->Owner...)
        allow an attacker to craft arbitrarily deep queries that can cause
        exponential processing time on the server.
        """
        # Build a deeply nested circular query:
        #   { pastes { owner { pastes { owner { ... __typename } } } } }
        depth = DOS_CIRCULAR_DEPTH
        opening = 'query { pastes { '
        for _ in range(depth):
            opening += 'owner { pastes { '
        closing = '__typename ' + '} } ' * depth + '} }'
        query = opening + closing

        response = self.http_client.post_graphql(query)

        total_depth = depth * 2 + 2  # each iteration adds 2 nesting levels
        error_text = str(response.errors).lower() if response.has_errors() else ''
        timed_out = 'timed out' in error_text or 'timeout' in error_text

        if timed_out:
            # Server hung on the query — strongest DoS proof
            self.add_finding(
                title="Deep Recursive Query DoS Vulnerability",
                description=(
                    f"Server timed out processing a circular query {total_depth} "
                    f"levels deep (>{response.response_time:.0f}s).  Attackers can "
                    f"exploit circular type references to hang the server."
                ),
                severity=SEVERITY_HIGH,
                category=CATEGORY_DOS,
                rule_id="GG-DOS-DEEP-RECURSIVE-QUERY",
                response=response,
                evidence={
                    'query_depth': total_depth,
                    'response_time': response.response_time,
                    'timed_out': True,
                },
                remediation=(
                    "Implement query-depth limiting (recommended max: 10 levels) "
                    "and query-cost analysis to reject overly complex queries."
                ),
            )
            self.logger.warning(
                f"Circular query depth vulnerability detected (depth={total_depth}, server timed out)"
            )
        elif response.is_success() and response.has_data():
            severity = SEVERITY_HIGH if response.response_time > 2.0 else SEVERITY_MEDIUM
            self.add_finding(
                title="Deep Recursive Query DoS Vulnerability",
                description=(
                    f"Server processed a circular query {total_depth} levels deep "
                    f"in {response.response_time:.2f}s.  Attackers can exploit "
                    f"circular type references to amplify server workload exponentially."
                ),
                severity=severity,
                category=CATEGORY_DOS,
                rule_id="GG-DOS-DEEP-RECURSIVE-QUERY",
                response=response,
                evidence={
                    'query_depth': total_depth,
                    'response_time': response.response_time,
                },
                remediation=(
                    "Implement query-depth limiting (recommended max: 10 levels) "
                    "and query-cost analysis to reject overly complex queries."
                ),
            )
            self.logger.warning(
                f"Circular query depth vulnerability detected (depth={total_depth}, time={response.response_time:.2f}s)"
            )
        elif response.has_errors():
            # Server rejected — check if it was a depth limit
            if 'depth' in error_text or 'complex' in error_text:
                self.add_finding(
                    title="Query Depth Limiting Enabled",
                    description=(
                        f"Server rejected a circular query of depth {total_depth} "
                        f"with a depth/complexity error.  This is a good defense."
                    ),
                    severity=SEVERITY_INFO,
                    category=CATEGORY_DOS,
                    rule_id="GG-DOS-QUERY-DEPTH-LIMITING",
                    response=response,
                )
                self.logger.info("Circular query depth check: Depth limit enforced")
            else:
                self.add_finding(
                    title="Circular Query Depth Check Inconclusive",
                    description=(
                        f"Server returned an error for a circular query of depth "
                        f"{total_depth}, but the error doesn't clearly indicate "
                        f"a depth limit."
                    ),
                    severity=SEVERITY_INFO,
                    category=CATEGORY_DOS,
                    rule_id="GG-DOS-CIRCULAR-QUERY-INCONCLUSIVE",
                    response=response,
                )
                self.logger.info("Circular query depth check: Inconclusive")
        else:
            self.add_finding(
                title="Circular Query Depth Protection",
                description="Server rejected deeply nested circular queries.",
                severity=SEVERITY_INFO,
                category=CATEGORY_DOS,
                rule_id="GG-DOS-CIRCULAR-QUERY-PROTECTED",
                response=response,
            )
            self.logger.info("Circular query depth check: Protected")

    def check_circular_fragments(self) -> None:
        """Test if server allows circular fragment spreads (DoS vector).

        Checklist: DoS – Circular fragments.
        If Fragment A spreads Fragment B and B spreads A, a na\u00efve server may
        enter an infinite expansion loop during validation or execution.
        Well-configured servers reject them at the validation stage.
        """
        query = """
        query {
            __typename
            ...FragA
        }
        fragment FragA on Query {
            __typename
            ...FragB
        }
        fragment FragB on Query {
            __typename
            ...FragA
        }
        """

        response = self.http_client.post_graphql(query)

        error_text = str(response.errors).lower() if response.has_errors() else ''
        timed_out = 'timed out' in error_text or 'timeout' in error_text

        if timed_out:
            self.add_finding(
                title="Circular Fragment DoS Vulnerability",
                description=(
                    "Server timed out processing a query with circular fragment spreads. "
                    "Attackers can exploit this to cause infinite processing loops."
                ),
                severity=SEVERITY_HIGH,
                category=CATEGORY_DOS,
                rule_id="GG-DOS-CIRCULAR-FRAGMENT",
                response=response,
                evidence={'response_time': response.response_time, 'timed_out': True},
                remediation="Implement fragment-cycle detection in query validation."
            )
            self.logger.warning("Circular fragment vulnerability: server timed out")
        elif response.is_success() and response.has_data():
            self.add_finding(
                title="Circular Fragment DoS Vulnerability",
                description=(
                    "Server processed a query with circular fragment spreads without "
                    "rejection.  This can be exploited for DoS via infinite fragment expansion."
                ),
                severity=SEVERITY_HIGH,
                category=CATEGORY_DOS,
                rule_id="GG-DOS-CIRCULAR-FRAGMENT",
                response=response,
                evidence={'response_time': response.response_time},
                remediation="Implement fragment-cycle detection in query validation."
            )
            self.logger.warning("Circular fragment vulnerability: processed without rejection")
        elif response.has_errors():
            if any(kw in error_text for kw in ['cycle', 'circular', 'recursive', 'fragment spread', 'infinite']):
                self.add_finding(
                    title="Circular Fragment Protection",
                    description="Server correctly rejects circular fragment spreads (cycle detection in place).",
                    severity=SEVERITY_INFO,
                    category=CATEGORY_DOS,
                    rule_id="GG-DOS-CIRCULAR-FRAGMENT-PROTECTED",
                    response=response,
                )
                self.logger.info("Circular fragment check: Protected (cycle detection)")
            else:
                self.add_finding(
                    title="Circular Fragment Protection",
                    description="Server rejected the circular fragment query.",
                    severity=SEVERITY_INFO,
                    category=CATEGORY_DOS,
                    rule_id="GG-DOS-CIRCULAR-FRAGMENT-PROTECTED",
                    response=response,
                )
                self.logger.info("Circular fragment check: Rejected")
        else:
            self.add_finding(
                title="Circular Fragment Protection",
                description="Server rejected the circular fragment query.",
                severity=SEVERITY_INFO,
                category=CATEGORY_DOS,
                rule_id="GG-DOS-CIRCULAR-FRAGMENT-PROTECTED",
                response=response,
            )
            self.logger.info("Circular fragment check: Protected")
    def check_alias_rate_limit_bypass(self) -> None:
        """Test if alias-based batching can bypass rate limiting (CrackQL-style).

        CrackQL demonstrated that GraphQL's alias feature lets an attacker
        pack many distinct operations (e.g. login attempts) into a single HTTP
        request, evading per-request rate limits.  This check sends a single
        request containing 50 aliased operations and verifies whether ALL of
        them are processed — indicating that the server does not count
        individual aliased operations toward any rate or cost budget.
        """
        BATCH_COUNT = 50

        query, candidates = self._build_alias_query(BATCH_COUNT, alias_prefix="op")
        candidate_summary = self._candidate_summary(candidates)

        response = self.http_client.post_graphql(query)

        if response.is_success() and response.has_data():
            returned = sum(1 for k in response.data if k.startswith("op"))
            if returned >= BATCH_COUNT:
                self.add_finding(
                    title="Alias-Based Rate-Limit Bypass",
                    description=(
                        f"Server processed {BATCH_COUNT} aliased operations in a single "
                        "HTTP request without throttling.  Attackers can use this to "
                        "perform credential stuffing, OTP brute-force, or enumeration "
                        "attacks while bypassing per-request rate limits (CrackQL technique)."
                    ),
                    severity=SEVERITY_HIGH,
                    category=CATEGORY_DOS,
                    rule_id="GG-DOS-ALIAS-RATE-LIMIT-BYPASS",
                    response=response,
                    evidence={
                        "aliases_sent": BATCH_COUNT,
                        "aliases_returned": returned,
                        "response_time": response.response_time,
                        **candidate_summary,
                    },
                    remediation=(
                        "Implement operation-level (not request-level) rate limiting. "
                        "Use query cost analysis to count each alias as a separate operation."
                    ),
                )
                self.logger.warning(
                    f"Alias rate-limit bypass: {returned}/{BATCH_COUNT} aliases processed"
                )
            else:
                self.add_finding(
                    title="Partial Alias Rate-Limit Protection",
                    description=(
                        f"Server processed only {returned}/{BATCH_COUNT} aliased operations, "
                        "suggesting partial throttling or cost analysis is in place."
                    ),
                    severity=SEVERITY_MEDIUM,
                    category=CATEGORY_DOS,
                    rule_id="GG-DOS-PARTIAL-ALIAS-RATE-LIMIT",
                    response=response,
                    evidence={
                        "aliases_sent": BATCH_COUNT,
                        "aliases_returned": returned,
                        **candidate_summary,
                    },
                    remediation="Verify that operation-level rate limiting fully covers aliased queries.",
                )
                self.logger.info(f"Partial alias rate protection: {returned}/{BATCH_COUNT}")
        elif response.has_errors():
            error_text = str(response.errors).lower()
            if any(kw in error_text for kw in ['rate', 'limit', 'throttl', 'cost', 'complexity']):
                self.add_finding(
                    title="Alias Rate-Limit Protection",
                    description="Server rejected batched aliased operations, indicating rate/cost controls.",
                    severity=SEVERITY_INFO,
                    category=CATEGORY_DOS,
                    rule_id="GG-DOS-ALIAS-RATE-LIMIT-PROTECTED",
                    response=response,
                )
                self.logger.info("Alias rate-limit bypass: Protected (rate/cost controls)")
            else:
                self.add_finding(
                    title="Alias Rate-Limit Check Inconclusive",
                    description="Server returned errors for batched aliases but not explicitly rate-related.",
                    severity=SEVERITY_INFO,
                    category=CATEGORY_DOS,
                    rule_id="GG-DOS-ALIAS-RATE-LIMIT-INCONCLUSIVE",
                    response=response,
                )
                self.logger.info("Alias rate-limit bypass: Inconclusive")
        else:
            self.add_finding(
                title="Alias Rate-Limit Check Inconclusive",
                description="Could not determine alias-based rate-limit bypass status.",
                severity=SEVERITY_INFO,
                category=CATEGORY_DOS,
                rule_id="GG-DOS-ALIAS-RATE-LIMIT-INCONCLUSIVE",
                response=response,
            )
            self.logger.info("Alias rate-limit bypass check: Inconclusive")
