"""Bounded active checks for live GraphQL security controls."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from src.config import (
    CATEGORY_AUTH,
    CATEGORY_CONFIG,
    CATEGORY_INJECTION,
    PROFILE_AGGRESSIVE,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)
from src.scanner.base_scanner import BaseScanner
from src.scanner.query_builder import QueryBuilder
from src.utils.http_client import HTTPClient, GraphQLResponse


AUTH_HEADER_NAMES = {
    "authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "proxy-authorization",
}

BACKEND_ERROR_MARKERS = {
    "sqlstate",
    "sqlite",
    "postgres",
    "mysql",
    "mariadb",
    "sequelize",
    "database error",
    "syntax error",
    "unterminated",
    "traceback",
    "stack trace",
    "exception:",
}

SENSITIVE_TERMS = {
    "admin",
    "account",
    "audit",
    "credential",
    "debug",
    "password",
    "private",
    "profile",
    "secret",
    "system",
    "user",
    "users",
}

COMMAND_TERMS = {
    "cmd",
    "command",
    "debug",
    "exec",
    "execute",
    "shell",
    "system",
}

SQL_ARGUMENT_TERMS = {
    "filter",
    "name",
    "nameprefix",
    "query",
    "search",
    "term",
    "where",
}


class ActiveSecurityScanner(BaseScanner):
    """Confirm selected live issues with small, non-destructive canaries."""

    def __init__(
        self,
        endpoint: str,
        *,
        schema: Optional[Dict[str, Any]] = None,
        config: Optional[Dict[str, Any]] = None,
        profile: str = "default",
        technique: str = "IDAC",
    ):
        super().__init__(endpoint, schema=schema or {}, config=config or {})
        self.profile = profile
        self.technique = technique or "IDAC"
        self.type_map = self.get_type_map()
        self.builder = QueryBuilder(self.type_map)

        anonymous_headers = {
            key: value
            for key, value in (self.config.get("headers") or {}).items()
            if key.lower() not in AUTH_HEADER_NAMES
        }
        anonymous_headers.setdefault("Content-Type", "application/json")
        self.anonymous_client = HTTPClient(
            endpoint,
            default_headers=anonymous_headers,
            proxy=self.config.get("proxy"),
        )
        self.report: Dict[str, Any] = {
            "summary": {
                "checks_sent": 0,
                "anonymous_sensitive_access": 0,
                "token_binding_failures": 0,
                "command_injection": 0,
                "sql_injection": 0,
                "verbose_backend_errors": 0,
                "same_origin_ssrf": 0,
            }
        }

    def run(self) -> List:
        if "A" in self.technique:
            self._check_anonymous_sensitive_queries()
            self._check_token_object_binding()

        if "I" in self.technique:
            self._check_sql_injection()
            self._check_command_injection()
            if self.profile == PROFILE_AGGRESSIVE:
                self._check_same_origin_ssrf()

        return self.findings

    def _post(self, query: str) -> GraphQLResponse:
        self.report["summary"]["checks_sent"] += 1
        return self.anonymous_client.post_graphql(query)

    def _schema_root(self) -> Dict[str, Any]:
        root = self.schema.get("data", self.schema)
        return root.get("__schema", {})

    def _root_name(self, kind: str) -> Optional[str]:
        root = self._schema_root()
        reference = root.get(f"{kind}Type") or {}
        return reference.get("name")

    def _fields(self, kind: str):
        root_name = self._root_name(kind)
        root_type = self.type_map.get(root_name or "", {})
        for field in root_type.get("fields", []) or []:
            yield root_name, field

    def _named_type(self, type_ref: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        current = type_ref
        while current and current.get("kind") in {"NON_NULL", "LIST"}:
            current = current.get("ofType")
        return current

    def _type_name(self, type_ref: Optional[Dict[str, Any]]) -> str:
        named = self._named_type(type_ref)
        return str((named or {}).get("name") or "")

    def _is_string(self, type_ref: Optional[Dict[str, Any]]) -> bool:
        return self._type_name(type_ref).lower() in {
            "string",
            "url",
            "uri",
            "urlscalar",
        }

    def _operation(
        self,
        root_name: str,
        field_name: str,
        overrides: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        return self.builder.construct_operation(
            root_name,
            field_name,
            args_overrides=overrides,
            include_optional_args=False,
        )

    def _top_value(self, response: GraphQLResponse, field_name: str) -> Any:
        if not isinstance(response.data, dict):
            return None
        return response.data.get(field_name)

    def _meaningful(self, value: Any) -> bool:
        if value is None or value is False:
            return False
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, (list, tuple, set)):
            return any(self._meaningful(item) for item in value)
        if isinstance(value, dict):
            return any(self._meaningful(item) for item in value.values())
        return True

    def _weight(self, value: Any) -> int:
        if value is None or value is False:
            return 0
        if isinstance(value, str):
            return 1 if value.strip() else 0
        if isinstance(value, (list, tuple, set)):
            return sum(self._weight(item) for item in value)
        if isinstance(value, dict):
            return sum(self._weight(item) for item in value.values())
        return 1

    def _data_text(self, response: GraphQLResponse) -> str:
        return json.dumps(response.data, default=str).lower()

    def _response_text(self, response: GraphQLResponse) -> str:
        errors = json.dumps(response.errors or [], default=str)
        return f"{response.raw_text}\n{errors}".lower()

    def _backend_markers(self, response: GraphQLResponse) -> List[str]:
        text = self._response_text(response)
        return sorted(marker for marker in BACKEND_ERROR_MARKERS if marker in text)

    def _output_field_names(self, field: Dict[str, Any]) -> List[str]:
        named = self._named_type(field.get("type"))
        output_type = self.type_map.get((named or {}).get("name") or "", {})
        return [
            str(item.get("name") or "").lower()
            for item in output_type.get("fields", []) or []
        ]

    def _check_anonymous_sensitive_queries(self) -> None:
        excluded = {
            "auth",
            "authenticate",
            "login",
            "token",
            "issuetoken",
            "gettoken",
        }

        for root_name, field in self._fields("query"):
            name = str(field.get("name") or "")
            lowered = name.lower()
            if lowered in excluded:
                continue

            searchable = {lowered, *self._output_field_names(field)}
            if not any(
                term in item
                for item in searchable
                for term in SENSITIVE_TERMS
            ):
                continue

            query = self._operation(root_name, name)
            if not query:
                continue

            response = self._post(query)
            value = self._top_value(response, name)
            if not self._meaningful(value):
                continue

            self.add_finding(
                title="Anonymous Sensitive GraphQL Query Accessible",
                description=(
                    f"The query '{name}' returned sensitive data without authentication. "
                    "The server should reject anonymous access before the resolver returns data."
                ),
                severity=SEVERITY_HIGH,
                category=CATEGORY_AUTH,
                rule_id="GG-AUTH-ANONYMOUS-SENSITIVE-QUERY",
                field=name,
                response=response,
                evidence={
                    "operation": query,
                    "returned_data": True,
                },
                remediation=(
                    "Require authentication and apply field-level authorization before "
                    "returning sensitive records."
                ),
            )
            self.report["summary"]["anonymous_sensitive_access"] += 1

    def _check_token_object_binding(self) -> None:
        issuers = []
        protected_queries = []

        for root_name, field in self._fields("query"):
            name = str(field.get("name") or "")
            lowered = name.lower()
            args = field.get("args", []) or []

            identity_args = [
                arg
                for arg in args
                if self._is_string(arg.get("type"))
                and any(
                    term in str(arg.get("name") or "").lower()
                    for term in ("email", "name", "user", "veterinary")
                )
            ]
            if (
                any(term in lowered for term in ("auth", "token"))
                and self._type_name(field.get("type")).lower() == "string"
                and identity_args
            ):
                issuers.append((root_name, field, identity_args[0]))

            token_args = [
                arg for arg in args
                if "token" in str(arg.get("name") or "").lower()
            ]
            id_args = [
                arg for arg in args
                if str(arg.get("name") or "").lower() == "id"
                or str(arg.get("name") or "").lower().endswith("id")
            ]
            if token_args and id_args:
                protected_queries.append(
                    (root_name, field, token_args[0], id_args[0])
                )

        for issuer_root, issuer, identity_arg in issuers[:2]:
            issuer_name = issuer["name"]
            issuer_query = self._operation(
                issuer_root,
                issuer_name,
                {identity_arg["name"]: "guardian_unowned_identity"},
            )
            if not issuer_query:
                continue

            issuer_response = self._post(issuer_query)
            token = self._top_value(issuer_response, issuer_name)
            if not isinstance(token, str) or not token.strip():
                continue

            for query_root, field, token_arg, id_arg in protected_queries[:4]:
                field_name = field["name"]
                id_type = self._type_name(id_arg.get("type")).lower()

                for candidate_id in (1, 2, 3):
                    id_value = candidate_id if id_type in {"int", "float"} else str(candidate_id)
                    query = self._operation(
                        query_root,
                        field_name,
                        {
                            token_arg["name"]: token,
                            id_arg["name"]: id_value,
                        },
                    )
                    if not query:
                        continue

                    response = self._post(query)
                    value = self._top_value(response, field_name)
                    if not self._meaningful(value):
                        continue

                    evidence = {
                        "token_issuer": issuer_name,
                        "tested_operation": field_name,
                        "tested_object_id": candidate_id,
                        "issuer_identity": "guardian_unowned_identity",
                    }
                    self.add_finding(
                        title="Authentication Token Not Bound to Requested Object",
                        description=(
                            f"A token issued for one identity accessed '{field_name}' "
                            f"with object identifier {candidate_id}. The resolver trusted "
                            "the supplied identifier without proving ownership."
                        ),
                        severity=SEVERITY_HIGH,
                        category=CATEGORY_AUTH,
                        rule_id="GG-AUTH-TOKEN-OBJECT-BINDING",
                        field=field_name,
                        response=response,
                        evidence=evidence,
                        remediation=(
                            "Read the subject identity from the verified token and enforce "
                            "ownership on every requested object."
                        ),
                    )
                    self.add_finding(
                        title="BOLA Through Unbound Identity Token",
                        description=(
                            f"The '{field_name}' resolver accepted a separately supplied "
                            "object identifier that was not bound to the token subject."
                        ),
                        severity=SEVERITY_HIGH,
                        category=CATEGORY_AUTH,
                        rule_id="GG-AUTH-BOLA-TOKEN-BINDING",
                        field=field_name,
                        response=response,
                        evidence=evidence,
                        remediation=(
                            "Derive object ownership from the authenticated principal and "
                            "reject identifiers belonging to another principal."
                        ),
                    )
                    self.report["summary"]["token_binding_failures"] += 1
                    return

    def _check_command_injection(self) -> None:
        marker = "GG_CMD_CANARY_7F31"

        for kind in ("query", "mutation"):
            for root_name, field in self._fields(kind):
                field_name = str(field.get("name") or "")
                for arg in field.get("args", []) or []:
                    arg_name = str(arg.get("name") or "")
                    searchable = f"{field_name} {arg_name}".lower()
                    if not self._is_string(arg.get("type")):
                        continue
                    if not any(term in searchable for term in COMMAND_TERMS):
                        continue

                    payloads = [
                        f"printf {marker}",
                        f"; printf {marker}",
                    ]
                    if arg_name.lower() not in {"cmd", "command"}:
                        payloads.reverse()

                    for payload in payloads:
                        query = self._operation(
                            root_name,
                            field_name,
                            {arg_name: payload},
                        )
                        if not query:
                            continue

                        response = self._post(query)
                        if marker.lower() not in self._data_text(response):
                            continue

                        evidence = {
                            "operation": field_name,
                            "argument": arg_name,
                            "canary": marker,
                            "payload": payload,
                        }
                        self.add_finding(
                            title="GraphQL Command Injection Confirmed",
                            description=(
                                f"The '{field_name}' resolver executed a harmless printf "
                                "canary supplied through a GraphQL argument."
                            ),
                            severity=SEVERITY_HIGH,
                            category=CATEGORY_INJECTION,
                            rule_id="GG-INJECTION-COMMAND-EXECUTION",
                            field=field_name,
                            response=response,
                            evidence=evidence,
                            remediation=(
                                "Do not pass GraphQL input to a shell. Use fixed commands, "
                                "strict allowlists, and argument arrays without shell parsing."
                            ),
                        )
                        if "A" in self.technique:
                            self.add_finding(
                                title="Anonymous Command Execution Accessible",
                                description=(
                                    f"The command-capable resolver '{field_name}' executed "
                                    "the canary without authentication."
                                ),
                                severity=SEVERITY_HIGH,
                                category=CATEGORY_AUTH,
                                rule_id="GG-AUTH-ANONYMOUS-COMMAND-EXECUTION",
                                field=field_name,
                                response=response,
                                evidence=evidence,
                                remediation=(
                                    "Remove the command resolver or require strong "
                                    "authentication and explicit administrative authorization."
                                ),
                            )
                        self.report["summary"]["command_injection"] += 1
                        return

    def _check_sql_injection(self) -> None:
        control = "GG_NO_MATCH_7F31"
        attack = "%' OR 1=1 -- "
        malformed = "'"

        for root_name, field in self._fields("query"):
            field_name = str(field.get("name") or "")
            for arg in field.get("args", []) or []:
                arg_name = str(arg.get("name") or "")
                if not self._is_string(arg.get("type")):
                    continue
                if not any(term in arg_name.lower() for term in SQL_ARGUMENT_TERMS):
                    continue

                control_query = self._operation(
                    root_name,
                    field_name,
                    {arg_name: control},
                )
                attack_query = self._operation(
                    root_name,
                    field_name,
                    {arg_name: attack},
                )
                malformed_query = self._operation(
                    root_name,
                    field_name,
                    {arg_name: malformed},
                )
                if not control_query or not attack_query or not malformed_query:
                    continue

                control_response = self._post(control_query)
                attack_response = self._post(attack_query)
                malformed_response = self._post(malformed_query)

                control_weight = self._weight(
                    self._top_value(control_response, field_name)
                )
                attack_weight = self._weight(
                    self._top_value(attack_response, field_name)
                )
                backend_markers = sorted(
                    set(self._backend_markers(attack_response))
                    | set(self._backend_markers(malformed_response))
                )
                behavioural_match = control_weight == 0 and attack_weight > 0

                if not behavioural_match and not backend_markers:
                    continue

                evidence = {
                    "operation": field_name,
                    "argument": arg_name,
                    "control_weight": control_weight,
                    "attack_weight": attack_weight,
                    "backend_error_markers": backend_markers,
                    "confirmation": (
                        "backend-error"
                        if backend_markers
                        else "control-versus-attack"
                    ),
                }
                proof_response = (
                    malformed_response if backend_markers else attack_response
                )
                self.add_finding(
                    title="GraphQL SQL Injection Confirmed",
                    description=(
                        f"The '{field_name}' resolver showed SQL injection evidence "
                        f"through the '{arg_name}' argument."
                    ),
                    severity=SEVERITY_HIGH,
                    category=CATEGORY_INJECTION,
                    rule_id="GG-INJECTION-SQL-BEHAVIOR",
                    field=field_name,
                    response=proof_response,
                    evidence=evidence,
                    remediation=(
                        "Use parameterized database queries and validate GraphQL input "
                        "before it reaches the data layer."
                    ),
                )
                self.report["summary"]["sql_injection"] += 1

                if backend_markers:
                    self.add_finding(
                        title="Verbose Backend Error Disclosed",
                        description=(
                            f"The '{field_name}' resolver returned database or backend "
                            "implementation details after malformed input."
                        ),
                        severity=SEVERITY_MEDIUM,
                        category=CATEGORY_CONFIG,
                        rule_id="GG-CONFIG-VERBOSE-BACKEND-ERROR",
                        field=field_name,
                        response=proof_response,
                        evidence=evidence,
                        remediation=(
                            "Return a generic GraphQL error to clients and keep stack, "
                            "database, and framework details in server-side logs."
                        ),
                    )
                    self.report["summary"]["verbose_backend_errors"] += 1
                return

    def _check_same_origin_ssrf(self) -> None:
        parsed = urlparse(self.endpoint)
        if not parsed.hostname:
            return

        scheme = parsed.scheme or "http"
        port = parsed.port or (443 if scheme == "https" else 80)
        safe_path = "/graphiql"
        safe_url = f"{scheme}://{parsed.hostname}:{port}{safe_path}"

        for kind in ("query", "mutation"):
            for root_name, field in self._fields(kind):
                field_name = str(field.get("name") or "")
                args = field.get("args", []) or []
                names = {
                    str(arg.get("name") or "").lower(): arg
                    for arg in args
                }
                overrides: Dict[str, Any] = {}

                url_arg = next(
                    (
                        arg
                        for arg in args
                        if str(arg.get("name") or "").lower()
                        in {"url", "uri", "endpoint"}
                    ),
                    None,
                )
                if url_arg and self._is_string(url_arg.get("type")):
                    overrides[url_arg["name"]] = safe_url
                elif {"host", "path"}.issubset(names):
                    host_arg = names["host"]
                    path_arg = names["path"]
                    if not (
                        self._is_string(host_arg.get("type"))
                        and self._is_string(path_arg.get("type"))
                    ):
                        continue

                    overrides[host_arg["name"]] = parsed.hostname
                    overrides[path_arg["name"]] = safe_path
                    if "scheme" in names:
                        overrides[names["scheme"]["name"]] = scheme
                    if "port" in names:
                        port_type = self._type_name(
                            names["port"].get("type")
                        ).lower()
                        overrides[names["port"]["name"]] = (
                            port if port_type in {"int", "float"} else str(port)
                        )
                else:
                    continue

                query = self._operation(root_name, field_name, overrides)
                if not query:
                    continue

                response = self._post(query)
                text = self._data_text(response)
                if "graphiql" not in text and "graphql ide" not in text:
                    continue

                self.add_finding(
                    title="GraphQL Server-Side Request Forgery Confirmed",
                    description=(
                        f"The '{field_name}' resolver fetched the application's own "
                        "GraphiQL page using attacker-controlled destination input."
                    ),
                    severity=SEVERITY_HIGH,
                    category=CATEGORY_INJECTION,
                    rule_id="GG-INJECTION-SSRF-SAME-ORIGIN",
                    field=field_name,
                    response=response,
                    evidence={
                        "operation": field_name,
                        "safe_canary_url": safe_url,
                        "same_origin_only": True,
                    },
                    remediation=(
                        "Allow only required outbound destinations, block private and "
                        "loopback ranges, and validate redirects after DNS resolution."
                    ),
                )
                self.report["summary"]["same_origin_ssrf"] += 1
                return
