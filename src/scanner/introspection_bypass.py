"""Focused tests for partial or bypassed GraphQL introspection exposure."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.config import CATEGORY_RECON, SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM
from src.scanner.base_scanner import BaseScanner


class IntrospectionBypassScanner(BaseScanner):
    """Probe for partial schema disclosure when full introspection is blocked."""

    def __init__(self, endpoint: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(endpoint, config=config or {})
        self.report: Dict[str, Any] = {
            "summary": {
                "schema_accessible": False,
                "type_accessible": False,
                "suggestion_leak": False,
                "root_type_leak": False,
            },
            "canary": {},
            "type_probe": {},
            "suggestion_probe": {},
        }

    def run(self) -> List:
        schema_response = self.http_client.post_graphql(
            "query GuardianIntrospectionCanary { __schema { queryType { name } } }"
        )
        type_response = self.http_client.post_graphql(
            'query GuardianTypeProbe { __type(name: "Query") { name fields { name } } }'
        )
        suggestion_response = self.http_client.post_graphql(
            "query GuardianSuggestionProbe { typNonsenseGuardian }"
        )

        schema_accessible = bool(
            schema_response.is_success()
            and schema_response.has_data()
            and (schema_response.data or {}).get("__schema")
        )
        type_accessible = bool(
            type_response.is_success()
            and type_response.has_data()
            and (type_response.data or {}).get("__type")
        )

        suggestion_text = self._errors_to_text(suggestion_response.errors)
        suggestion_leak = "did you mean" in suggestion_text.lower()
        root_type_leak = " on type " in suggestion_text.lower()

        self.report = {
            "summary": {
                "schema_accessible": schema_accessible,
                "type_accessible": type_accessible,
                "suggestion_leak": suggestion_leak,
                "root_type_leak": root_type_leak,
            },
            "canary": self._response_summary(schema_response),
            "type_probe": self._response_summary(type_response),
            "suggestion_probe": self._response_summary(suggestion_response),
        }

        if not schema_accessible and type_accessible:
            self.add_finding(
                title="Type-Based Introspection Bypass",
                description=(
                    "Full introspection looked blocked, but Guardian still retrieved schema data through "
                    "__type(name: \"Query\"). This is a classic partial-introspection bypass that still "
                    "gives attackers field discovery and schema reconstruction material."
                ),
                severity=SEVERITY_MEDIUM,
                category=CATEGORY_RECON,
                rule_id="GG-RECON-TYPE-INTROSPECTION-BYPASS",
                response=type_response,
                evidence={
                    "schema_canary": self.report["canary"],
                    "type_probe": self.report["type_probe"],
                },
                remediation="Disable or gate all introspection meta-fields, not only __schema, in production.",
            )

        if not schema_accessible and (suggestion_leak or root_type_leak):
            self.add_finding(
                title="Error-Guided Schema Recovery Surface",
                description=(
                    "Even with full introspection unavailable, error responses still expose schema hints such as "
                    "field suggestions or root type names. Attackers can combine these signals with blind "
                    "introspection tooling to rebuild the API surface."
                ),
                severity=SEVERITY_LOW,
                category=CATEGORY_RECON,
                rule_id="GG-RECON-ERROR-GUIDED-SCHEMA-RECOVERY",
                response=suggestion_response,
                evidence={
                    "suggestion_leak": suggestion_leak,
                    "root_type_leak": root_type_leak,
                    "sample_error": suggestion_text[:500],
                },
                remediation="Reduce field suggestions and verbose schema hints in production error messages.",
            )

        if not self.findings:
            self.add_finding(
                title="No Partial Introspection Bypass Detected",
                description="Guardian did not identify a type-level or error-guided introspection bypass beyond the main canary result.",
                severity=SEVERITY_INFO,
                category=CATEGORY_RECON,
                rule_id="GG-RECON-NO-INTROSPECTION-BYPASS",
                confidence="medium",
                state="informational",
                evidence=self.report,
            )

        return self.findings

    def _errors_to_text(self, errors: Optional[List[Any]]) -> str:
        parts = []
        for error in errors or []:
            if isinstance(error, dict):
                parts.append(str(error.get("message", "")))
            else:
                parts.append(str(error))
        return " | ".join(part for part in parts if part)

    def _response_summary(self, response: Any) -> Dict[str, Any]:
        errors = self._errors_to_text(getattr(response, "errors", None))
        return {
            "status_code": getattr(response, "status_code", 0),
            "has_data": bool(getattr(response, "data", None)),
            "has_errors": bool(getattr(response, "errors", None)),
            "errors": errors[:500],
        }
