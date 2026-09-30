"""Authentication-focused schema-aware checks for GraphQL Guardian."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from src.config import CATEGORY_AUTH, SEVERITY_HIGH, SEVERITY_INFO, SEVERITY_LOW
from src.scanner.base_scanner import BaseScanner
from src.scanner.path_enumerator import normalize_schema
from src.scanner.query_builder import QueryBuilder
from src.utils.http_client import HTTPClient


AUTH_ERROR_DISCLOSURE_KEYWORDS = (
    "password",
    "invalid password",
    "user not found",
    "email not found",
    "unknown user",
    "account does not exist",
    "account locked",
    "too many attempts",
    "mfa required",
    "otp",
)
TOKEN_LIKE_KEYS = {
    "token",
    "accessToken",
    "access_token",
    "refreshToken",
    "refresh_token",
    "session",
    "jwt",
}


class AuthenticationScanner(BaseScanner):
    """Check authentication surfaces and a few high-signal auth behaviors."""

    def __init__(
        self,
        endpoint: str,
        *,
        schema: Optional[Dict[str, Any]] = None,
        config: Optional[Dict[str, Any]] = None,
        operation_pack: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(endpoint, schema=schema or {}, config=config or {})
        self.schema = normalize_schema(schema or {})
        self.type_map = {
            item["name"]: item
            for item in self.schema.get("__schema", {}).get("types", [])
            if item.get("name")
        }
        self.builder = QueryBuilder(self.type_map)
        self.operation_pack = operation_pack or {}
        self.anonymous_client = HTTPClient(
            endpoint,
            default_headers=self._anonymous_headers(),
            timeout=self.http_client.timeout,
            proxy=self.config.get("proxy"),
        )
        self.report: Dict[str, Any] = {
            "summary": {
                "auth_queries": 0,
                "auth_mutations": 0,
                "identity_queries_tested": 0,
                "anonymous_identity_accesses": 0,
                "credential_probes": 0,
                "credential_bypass_candidates": 0,
                "verbose_auth_errors": 0,
            },
            "auth_queries": [],
            "auth_mutations": [],
            "identity_query_checks": [],
            "credential_probe_checks": [],
        }

    def run(self) -> List:
        auth_queries = self._auth_queries()
        auth_mutations = self._auth_mutations()
        self.report["auth_queries"] = auth_queries
        self.report["auth_mutations"] = auth_mutations
        self.report["summary"]["auth_queries"] = len(auth_queries)
        self.report["summary"]["auth_mutations"] = len(auth_mutations)

        if auth_queries or auth_mutations:
            self.add_finding(
                title="Authentication Surface Identified",
                description=(
                    "Guardian identified GraphQL operations that appear to participate in authentication "
                    "or session handling. These are the primary entry points for authentication-focused testing."
                ),
                severity=SEVERITY_INFO,
                category=CATEGORY_AUTH,
                rule_id="GG-AUTH-AUTHENTICATION-SURFACE",
                state="informational",
                confidence="medium",
                evidence={
                    "queries": auth_queries,
                    "mutations": auth_mutations,
                },
                remediation=(
                    "Document the intended authentication flow for these operations and verify they enforce "
                    "consistent identity, session, and credential handling."
                ),
            )

        for item in auth_queries:
            if "identity-query" not in item.get("tags", []):
                continue
            self._probe_identity_query(item)

        for item in auth_mutations:
            self._probe_credential_mutation(item)

        return self.findings

    def _anonymous_headers(self) -> Dict[str, str]:
        headers = {}
        for key, value in (self.config.get("headers") or {}).items():
            lowered = key.lower()
            if lowered in {"authorization", "cookie", "x-api-key", "api-key", "proxy-authorization"}:
                continue
            headers[key] = value
        headers.setdefault("Content-Type", "application/json")
        headers.setdefault("Accept", "application/json")
        return headers

    def _auth_queries(self) -> List[Dict[str, Any]]:
        return [
            item for item in self.operation_pack.get("operations", [])
            if item.get("operation_type") == "query" and "auth-surface" in item.get("tags", [])
        ]

    def _auth_mutations(self) -> List[Dict[str, Any]]:
        return [
            item for item in self.operation_pack.get("operations", [])
            if item.get("operation_type") == "mutation" and "auth-surface" in item.get("tags", [])
        ]

    def _probe_identity_query(self, item: Dict[str, Any]) -> None:
        document = item.get("operation") or item.get("full_operation")
        if not document:
            return
        response = self.anonymous_client.post_graphql(document)
        allowed = response.is_success() and self._meaningful_data(response.data)
        entry = {
            "operation_name": item.get("operation_name"),
            "allowed": allowed,
            "status_code": response.status_code,
            "error_messages": self._error_messages(response.errors),
            "response_preview": self._body_preview(response.data, response.errors),
        }
        self.report["identity_query_checks"].append(entry)
        self.report["summary"]["identity_queries_tested"] += 1
        if not allowed:
            return

        self.report["summary"]["anonymous_identity_accesses"] += 1
        self.add_finding(
            title="Anonymous Current-User Query Accessible",
            description=(
                f"Guardian retrieved data from {item.get('operation_name')} without authentication. "
                "Current-user and session-oriented queries should normally require an authenticated identity."
            ),
            severity=SEVERITY_HIGH,
            category=CATEGORY_AUTH,
            operation_name=item.get("operation_name"),
            rule_id="GG-AUTH-ANONYMOUS-IDENTITY-QUERY",
            request={
                "method": response.request_method or "POST",
                "url": response.request_url or self.endpoint,
                "headers": response.request_headers or self._anonymous_headers(),
                "body": response.request_body,
            },
            response=response,
            evidence={
                "operation_tags": item.get("tags", []),
                "response_preview": self._body_preview(response.data, response.errors),
            },
            remediation=(
                "Require authentication before resolving current-user, viewer, session, or identity-oriented queries."
            ),
        )

    def _probe_credential_mutation(self, item: Dict[str, Any]) -> None:
        document = self._build_auth_mutation_document(item)
        if not document:
            return
        response = self.anonymous_client.post_graphql(document)
        errors = self._error_messages(response.errors)
        bypass = response.is_success() and self._payload_contains_session(response.data)
        verbose = any(keyword in " ".join(errors).lower() for keyword in AUTH_ERROR_DISCLOSURE_KEYWORDS)
        entry = {
            "operation_name": item.get("operation_name"),
            "status_code": response.status_code,
            "bypass": bypass,
            "verbose_error": verbose,
            "error_messages": errors,
            "response_preview": self._body_preview(response.data, response.errors),
        }
        self.report["credential_probe_checks"].append(entry)
        self.report["summary"]["credential_probes"] += 1

        if bypass:
            self.report["summary"]["credential_bypass_candidates"] += 1
            self.add_finding(
                title="Authentication Bypass Candidate",
                description=(
                    f"Guardian sent clearly invalid or synthetic credential input to {item.get('operation_name')} "
                    "and still received session-like data. That is a strong indicator of broken authentication logic."
                ),
                severity=SEVERITY_HIGH,
                category=CATEGORY_AUTH,
                operation_name=item.get("operation_name"),
                rule_id="GG-AUTH-CREDENTIAL-BYPASS-CANDIDATE",
                request={
                    "method": response.request_method or "POST",
                    "url": response.request_url or self.endpoint,
                    "headers": response.request_headers or self._anonymous_headers(),
                    "body": response.request_body,
                },
                response=response,
                evidence={
                    "operation_tags": item.get("tags", []),
                    "response_preview": self._body_preview(response.data, response.errors),
                },
                remediation=(
                    "Verify the authentication resolver validates credentials, refresh tokens, and session state before issuing any authenticated response."
                ),
            )

        if verbose:
            self.report["summary"]["verbose_auth_errors"] += 1
            self.add_finding(
                title="Verbose Authentication Error Disclosure",
                description=(
                    f"Guardian observed authentication-specific error detail from {item.get('operation_name')} "
                    "while using synthetic credential input. Overly specific auth errors can help attackers enumerate users or tune brute-force attempts."
                ),
                severity=SEVERITY_LOW,
                category=CATEGORY_AUTH,
                operation_name=item.get("operation_name"),
                rule_id="GG-AUTH-VERBOSE-AUTH-ERROR",
                request={
                    "method": response.request_method or "POST",
                    "url": response.request_url or self.endpoint,
                    "headers": response.request_headers or self._anonymous_headers(),
                    "body": response.request_body,
                },
                response=response,
                evidence={
                    "error_messages": errors,
                    "operation_tags": item.get("tags", []),
                },
                remediation=(
                    "Return generic authentication failure messages and avoid revealing whether the username, email, token, or password was the invalid component."
                ),
            )

    def _build_auth_mutation_document(self, item: Dict[str, Any]) -> Optional[str]:
        operation_name = item.get("operation_name", "")
        if "." not in operation_name:
            return item.get("full_operation") or item.get("operation")
        root_type, field_name = operation_name.split(".", 1)
        root_def = self.type_map.get(root_type)
        if not root_def:
            return item.get("full_operation") or item.get("operation")
        field_def = next((field for field in root_def.get("fields", []) if field.get("name") == field_name), None)
        if not field_def:
            return item.get("full_operation") or item.get("operation")

        overrides = {}
        for arg in field_def.get("args", []) or []:
            overrides[arg["name"]] = self._auth_probe_value(arg["name"], arg.get("type"))
        return self.builder.construct_operation(
            root_type,
            field_name,
            args_overrides=overrides,
            include_optional_args=True,
        )

    def _auth_probe_value(self, arg_name: str, type_ref: Optional[Dict[str, Any]]) -> Any:
        normalized = (arg_name or "").lower()
        if any(token in normalized for token in ("email", "username", "login", "user")):
            return "guardian-invalid@example.com" if "email" in normalized else "guardian_invalid_user"
        if any(token in normalized for token in ("password", "passwd", "passcode", "pin")):
            return "GuardianWrongPass123!"
        if "otp" in normalized or "code" in normalized:
            return "000000"
        if "refresh" in normalized or "token" in normalized or "session" in normalized:
            return "guardian-invalid-token"
        return self.builder.generate_value(type_ref or {"kind": "SCALAR", "name": "String"})

    def _meaningful_data(self, data: Any) -> bool:
        if not data:
            return False
        if isinstance(data, dict):
            return any(self._meaningful_data(value) for value in data.values())
        if isinstance(data, list):
            return any(self._meaningful_data(value) for value in data)
        return data not in ("", 0, False)

    def _payload_contains_session(self, data: Any) -> bool:
        if not data:
            return False
        if isinstance(data, dict):
            for key, value in data.items():
                if key in TOKEN_LIKE_KEYS and self._meaningful_data(value):
                    return True
                if self._payload_contains_session(value):
                    return True
        if isinstance(data, list):
            return any(self._payload_contains_session(value) for value in data)
        return False

    def _error_messages(self, errors: Any) -> List[str]:
        messages: List[str] = []
        for error in errors or []:
            if isinstance(error, dict):
                message = error.get("message")
                if message:
                    messages.append(str(message))
            elif error:
                messages.append(str(error))
        return messages

    def _body_preview(self, data: Any, errors: Any) -> str:
        payload = {}
        if data is not None:
            payload["data"] = data
        if errors:
            payload["errors"] = errors
        return json.dumps(payload, default=str)[:1200] if payload else ""
