"""GraphQL request-forgery transport checks inspired by Black Hat GraphQL."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import requests

from src.config import (
    CATEGORY_CONFIG,
    PROFILE_PASSIVE,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
from src.scanner.base_scanner import BaseScanner


TRANSPORT_REJECTION_KEYWORDS = [
    "only supports post",
    "must use post",
    "get support disabled",
    "unsupported media type",
    "must provide query string",
    "must provide an operation",
    "persistedquerynotfound",
]


class RequestForgeryScanner(BaseScanner):
    """Exercise browser-friendly transport variants that often enable CSRF/CSWSH style abuse."""

    def __init__(
        self,
        endpoint: str,
        *,
        config: Optional[Dict[str, Any]] = None,
        operation_pack: Optional[Dict[str, Any]] = None,
        profile: str = PROFILE_PASSIVE,
    ):
        super().__init__(endpoint, config=config or {})
        self.operation_pack = operation_pack or {}
        self.profile = profile
        self.report: Dict[str, Any] = {
            "summary": {
                "variants_tested": 0,
                "variants_accepted": 0,
                "query_variants_accepted": 0,
                "mutation_variants_accepted": 0,
            },
            "variants": [],
        }

    def run(self) -> List:
        query_doc, query_source = self._candidate_operation("query")
        mutation_doc, mutation_source = self._candidate_operation("mutation")

        self._test_variant(
            name="GET query",
            operation_type="query",
            method="GET",
            query=query_doc,
            query_source=query_source,
        )
        self._test_variant(
            name="URL-encoded POST query",
            operation_type="query",
            method="POST",
            query=query_doc,
            query_source=query_source,
            content_mode="form",
        )
        self._test_variant(
            name="Multipart POST query",
            operation_type="query",
            method="POST",
            query=query_doc,
            query_source=query_source,
            content_mode="multipart",
        )

        if self.profile != PROFILE_PASSIVE:
            self._test_variant(
                name="GET mutation",
                operation_type="mutation",
                method="GET",
                query=mutation_doc,
                query_source=mutation_source,
            )
            self._test_variant(
                name="URL-encoded POST mutation",
                operation_type="mutation",
                method="POST",
                query=mutation_doc,
                query_source=mutation_source,
                content_mode="form",
            )
            self._test_variant(
                name="Multipart POST mutation",
                operation_type="mutation",
                method="POST",
                query=mutation_doc,
                query_source=mutation_source,
                content_mode="multipart",
            )

        if not self.findings:
            self.add_finding(
                title="Request Forgery Transport Checks Passed",
                description="Guardian did not find a browser-friendly GraphQL transport variant that executed outside the normal JSON POST flow.",
                severity=SEVERITY_INFO,
                category=CATEGORY_CONFIG,
                rule_id="GG-CONFIG-REQUEST-FORGERY-CHECKS-PASSED",
                confidence="medium",
                state="informational",
                evidence=self.report,
            )

        return self.findings

    def _candidate_operation(self, operation_type: str) -> tuple[str, str]:
        operations = self.operation_pack.get("operations", [])
        for item in operations:
            if item.get("operation_type") != operation_type:
                continue
            doc = item.get("full_operation") or item.get("operation")
            if doc:
                return doc, item.get("operation_name", f"generated-{operation_type}")
        if operation_type == "mutation":
            return "mutation GuardianRequestForgery { __typename }", "syntactic-canary"
        return "query GuardianRequestForgery { __typename }", "syntactic-canary"

    def _request_headers(self) -> Dict[str, str]:
        headers = {
            key: value
            for key, value in (self.config.get("headers") or {}).items()
            if key.lower() != "content-type"
        }
        headers.setdefault("Accept", "application/json")
        return headers

    def _send_variant(
        self,
        *,
        method: str,
        query: str,
        content_mode: str = "json",
    ) -> Optional[requests.Response]:
        headers = self._request_headers()
        try:
            if method == "GET":
                return requests.get(
                    self.endpoint,
                    params={"query": query},
                    headers=headers,
                    timeout=5,
                    proxies=self.http_client.proxies,
                    verify=not bool(self.http_client.proxies),
                )
            if content_mode == "form":
                return requests.post(
                    self.endpoint,
                    data={"query": query},
                    headers=headers,
                    timeout=5,
                    proxies=self.http_client.proxies,
                    verify=not bool(self.http_client.proxies),
                )
            if content_mode == "multipart":
                return requests.post(
                    self.endpoint,
                    files={"query": (None, query)},
                    headers=headers,
                    timeout=5,
                    proxies=self.http_client.proxies,
                    verify=not bool(self.http_client.proxies),
                )
        except requests.RequestException:
            return None
        return None

    def _response_payload(self, response: Optional[requests.Response]) -> Dict[str, Any]:
        if not response:
            return {"data": None, "errors": ["request_failed"]}
        try:
            payload = response.json()
            return {
                "data": payload.get("data"),
                "errors": payload.get("errors"),
            }
        except ValueError:
            return {"data": None, "errors": None}

    def _transport_accepted(self, response: Optional[requests.Response], payload: Dict[str, Any]) -> bool:
        if not response:
            return False
        if response.status_code >= 500:
            return False
        if payload.get("data") is not None:
            return True
        errors = payload.get("errors")
        if errors:
            errors_text = json.dumps(errors).lower()
            return not any(keyword in errors_text for keyword in TRANSPORT_REJECTION_KEYWORDS)
        return False

    def _response_time_ms(self, response: Optional[requests.Response]) -> Optional[float]:
        if not response or not getattr(response, "elapsed", None):
            return None
        return round(response.elapsed.total_seconds() * 1000, 2)

    def _severity_for(self, operation_type: str, content_mode: str) -> str:
        if operation_type == "mutation":
            return SEVERITY_HIGH
        if content_mode == "form":
            return SEVERITY_MEDIUM
        return SEVERITY_LOW

    def _test_variant(
        self,
        *,
        name: str,
        operation_type: str,
        method: str,
        query: str,
        query_source: str,
        content_mode: str = "json",
    ) -> None:
        response = self._send_variant(method=method, query=query, content_mode=content_mode)
        payload = self._response_payload(response)
        accepted = self._transport_accepted(response, payload)

        variant = {
            "name": name,
            "operation_type": operation_type,
            "transport": "multipart/form-data" if content_mode == "multipart" else (
                "application/x-www-form-urlencoded" if content_mode == "form" else method
            ),
            "accepted": accepted,
            "status_code": getattr(response, "status_code", 0) if response else 0,
            "query_source": query_source,
            "response_time_ms": self._response_time_ms(response),
            "response_excerpt": (getattr(response, "text", "") or "")[:400] if response else "",
        }
        self.report["variants"].append(variant)
        self.report["summary"]["variants_tested"] += 1
        if accepted:
            self.report["summary"]["variants_accepted"] += 1
            summary_key = (
                "mutation_variants_accepted"
                if operation_type == "mutation"
                else "query_variants_accepted"
            )
            self.report["summary"][summary_key] += 1

            self.add_finding(
                title=f"{name} Accepted",
                description=(
                    f"The endpoint processed a {name.lower()} request outside the standard JSON POST flow. "
                    f"That broadens the request-forgery surface for browser-based attacks and makes manual "
                    f"replay easier during testing."
                ),
                severity=self._severity_for(operation_type, content_mode),
                category=CATEGORY_CONFIG,
                rule_id=f"GG-CONFIG-{name.upper().replace(' ', '-').replace('/', '-')}",
                request={
                    "method": method,
                    "url": getattr(response, "url", self.endpoint) if response else self.endpoint,
                    "headers": self._request_headers(),
                    "body": (
                        None
                        if method == "GET"
                        else {"query": query, "encoding": content_mode}
                    ),
                },
                response={
                    "status_code": getattr(response, "status_code", 0) if response else 0,
                    "response_time_ms": self._response_time_ms(response),
                    "headers": dict(getattr(response, "headers", {}) or {}) if response else {},
                    "body_sample": (getattr(response, "text", "") or "")[:1200] if response else "",
                },
                evidence={
                    "query_source": query_source,
                    "operation_type": operation_type,
                    "graphql_data_present": payload.get("data") is not None,
                    "graphql_errors_present": bool(payload.get("errors")),
                },
                remediation=(
                    "Restrict GraphQL execution to the intended content types, reject browser-form transports "
                    "for authenticated operations, and enforce CSRF protections on any state-changing flows."
                ),
            )
