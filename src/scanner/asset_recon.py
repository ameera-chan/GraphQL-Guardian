"""Passive HTML and JavaScript asset reconnaissance for GraphQL targets."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from src.config import (
    ASSET_RECON_MAX_DOCUMENTS,
    ASSET_RECON_MAX_SCRIPT_FETCHES,
    CATEGORY_RECON,
    GRAPHQL_ENDPOINT_PATHS,
    GRAPHQL_WEBSOCKET_PATHS,
    SEVERITY_INFO,
    SEVERITY_LOW,
)
from src.scanner.base_scanner import BaseScanner


SCRIPT_SRC_PATTERN = re.compile(r"""<script[^>]+src=['"](?P<src>[^'"]+)['"]""", re.IGNORECASE)
GRAPHQL_OPERATION_PATTERN = re.compile(
    r"""\b(?P<kind>query|mutation|subscription)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"""
)
ABSOLUTE_URL_PATTERN = re.compile(r"""(?P<url>(?:https?|wss?)://[^\s"'<>]+)""")
PATH_PATTERN = re.compile(
    r"""(?P<path>/(?:[A-Za-z0-9_.-]+/)*(?:graphql|graphiql|playground|explorer|altair|voyager|sandbox|subscriptions|socket|ws)(?:[A-Za-z0-9_./?=&%-]*)?)""",
    re.IGNORECASE,
)
SHA256_HASH_PATTERN = re.compile(
    r"""sha256Hash["']?\s*[:=]\s*["'](?P<hash>[A-Fa-f0-9]{32,128})["']"""
)

KNOWN_AUTH_HEADERS = [
    "Authorization",
    "X-API-Key",
    "Api-Key",
    "X-CSRF-Token",
    "X-Auth-Token",
    "X-Hasura-Admin-Secret",
    "Apollo-Require-Preflight",
]
ENVIRONMENT_MARKERS = ["localhost", "127.0.0.1", "staging", "dev", "internal", "test"]


class AssetReconScanner(BaseScanner):
    """Mine HTML and JavaScript for GraphQL attack surface clues."""

    def __init__(self, endpoint: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(endpoint, config=config or {})
        self.report: Dict[str, Any] = {
            "summary": {
                "documents_scanned": 0,
                "graphql_endpoints": 0,
                "subscription_endpoints": 0,
                "operations": 0,
                "persisted_query_hashes": 0,
                "auth_headers": 0,
                "environment_urls": 0,
            },
            "documents": [],
            "graphql_endpoints": [],
            "subscription_endpoints": [],
            "operations": [],
            "persisted_query_hashes": [],
            "auth_headers": [],
            "environment_urls": [],
        }
        self._document_index: Dict[str, Dict[str, Any]] = {}
        self._graphql_hits: Dict[str, Dict[str, Any]] = {}
        self._subscription_hits: Dict[str, Dict[str, Any]] = {}
        self._operation_hits: Dict[tuple[str, str], Dict[str, Any]] = {}
        self._persisted_hash_hits: Dict[str, Dict[str, Any]] = {}
        self._auth_header_hits: Dict[str, Dict[str, Any]] = {}
        self._environment_hits: Dict[str, Dict[str, Any]] = {}

    def run(self) -> List:
        base_url = self._base_url()
        queue = [base_url, self.endpoint]
        visited = set()
        script_fetches = 0

        while queue and len(self._document_index) < ASSET_RECON_MAX_DOCUMENTS:
            target = queue.pop(0)
            if target in visited:
                continue
            visited.add(target)

            response = self._fetch_document(target)
            if not response:
                continue

            doc = self._store_document(target, response)
            self._analyze_document(target, response.text)

            if (
                "html" in doc["content_type"]
                and script_fetches < ASSET_RECON_MAX_SCRIPT_FETCHES
            ):
                for script_url in self._extract_script_urls(response.text, target):
                    if script_url in visited or script_url in queue:
                        continue
                    if not self._same_origin(script_url, base_url):
                        continue
                    queue.append(script_url)
                    script_fetches += 1
                    if script_fetches >= ASSET_RECON_MAX_SCRIPT_FETCHES:
                        break

        self._finalize_report()
        self._emit_findings()
        return self.findings

    def _base_url(self) -> str:
        parsed = urlparse(self.endpoint)
        return f"{parsed.scheme}://{parsed.netloc}/"

    def _same_origin(self, url: str, base_url: str) -> bool:
        return urlparse(url).netloc == urlparse(base_url).netloc

    def _request_headers(self) -> Dict[str, str]:
        headers = {
            key: value
            for key, value in (self.config.get("headers") or {}).items()
            if key.lower() != "content-type"
        }
        headers.setdefault(
            "Accept",
            "text/html,application/javascript,text/javascript,*/*;q=0.1",
        )
        return headers

    def _fetch_document(self, url: str) -> Optional[requests.Response]:
        try:
            return requests.get(
                url,
                headers=self._request_headers(),
                timeout=5,
                proxies=self.http_client.proxies,
                verify=not bool(self.http_client.proxies),
            )
        except requests.RequestException:
            return None

    def _store_document(self, url: str, response: requests.Response) -> Dict[str, Any]:
        doc = {
            "url": url,
            "status_code": response.status_code,
            "content_type": (response.headers.get("content-type") or "").lower(),
            "body_sample": response.text[:1200],
        }
        self._document_index[url] = doc
        return doc

    def _extract_script_urls(self, html: str, source_url: str) -> List[str]:
        urls = []
        for match in SCRIPT_SRC_PATTERN.finditer(html):
            resolved = urljoin(source_url, match.group("src"))
            urls.append(resolved)
        return urls

    def _normalize_candidate_url(self, candidate: str, source_url: str) -> str:
        if candidate.startswith("http://") or candidate.startswith("https://"):
            return candidate
        if candidate.startswith("ws://") or candidate.startswith("wss://"):
            return candidate
        return urljoin(self._base_url(), candidate.lstrip("/"))

    def _snippet(self, text: str, value: str, limit: int = 140) -> str:
        idx = text.find(value)
        if idx == -1:
            return value[:limit]
        start = max(0, idx - 40)
        end = min(len(text), idx + len(value) + 60)
        return text[start:end].strip()

    def _record_hit(self, bucket: Dict[str, Dict[str, Any]], key: str, hit: Dict[str, Any]) -> None:
        bucket.setdefault(key, hit)

    def _analyze_document(self, source_url: str, text: str) -> None:
        lowered = text.lower()

        for match in ABSOLUTE_URL_PATTERN.finditer(text):
            url = match.group("url")
            self._classify_url_hit(url, source_url, text)

        for match in PATH_PATTERN.finditer(text):
            start = match.start("path")
            prefix_window = text[max(0, start - 8):start]
            if "://" in prefix_window:
                continue
            path = match.group("path")
            first_segment = path.lstrip("/").split("/", 1)[0]
            if "." in first_segment:
                continue
            url = self._normalize_candidate_url(path, source_url)
            self._classify_url_hit(url, source_url, text)

        for operation_match in GRAPHQL_OPERATION_PATTERN.finditer(text):
            kind = operation_match.group("kind")
            name = operation_match.group("name")
            self._record_hit(
                self._operation_hits,
                (kind, name),
                {
                    "kind": kind,
                    "name": name,
                    "source": source_url,
                    "snippet": self._snippet(text, operation_match.group(0)),
                },
            )

        for hash_match in SHA256_HASH_PATTERN.finditer(text):
            digest = hash_match.group("hash")
            self._record_hit(
                self._persisted_hash_hits,
                digest,
                {
                    "hash": digest,
                    "source": source_url,
                    "snippet": self._snippet(text, hash_match.group(0)),
                },
            )

        for header_name in KNOWN_AUTH_HEADERS:
            if header_name.lower() in lowered:
                self._record_hit(
                    self._auth_header_hits,
                    header_name,
                    {
                        "name": header_name,
                        "source": source_url,
                        "snippet": self._snippet(text, header_name),
                    },
                )

    def _classify_url_hit(self, url: str, source_url: str, text: str) -> None:
        lowered = url.lower()
        hit = {
            "url": url,
            "source": source_url,
            "snippet": self._snippet(text, url),
        }

        if any(marker in lowered for marker in ENVIRONMENT_MARKERS):
            self._record_hit(self._environment_hits, url, hit)

        if any(path.strip("/").lower() in lowered for path in GRAPHQL_ENDPOINT_PATHS):
            self._record_hit(self._graphql_hits, url, hit)
        elif "graphql" in lowered or "graphiql" in lowered or "playground" in lowered:
            self._record_hit(self._graphql_hits, url, hit)

        if any(path.strip("/").lower() in lowered for path in GRAPHQL_WEBSOCKET_PATHS):
            if lowered.startswith("ws://") or lowered.startswith("wss://") or "subscription" in lowered or "/ws" in lowered or "/socket" in lowered:
                self._record_hit(self._subscription_hits, url, hit)
        elif lowered.startswith("ws://") or lowered.startswith("wss://") or "subscription" in lowered:
            self._record_hit(self._subscription_hits, url, hit)

    def _finalize_report(self) -> None:
        self.report["documents"] = list(self._document_index.values())
        self.report["graphql_endpoints"] = sorted(self._graphql_hits.values(), key=lambda item: item["url"])
        self.report["subscription_endpoints"] = sorted(
            self._subscription_hits.values(),
            key=lambda item: item["url"],
        )
        self.report["operations"] = sorted(
            self._operation_hits.values(),
            key=lambda item: (item["kind"], item["name"]),
        )
        self.report["persisted_query_hashes"] = sorted(
            self._persisted_hash_hits.values(),
            key=lambda item: item["hash"],
        )
        self.report["auth_headers"] = sorted(
            self._auth_header_hits.values(),
            key=lambda item: item["name"],
        )
        self.report["environment_urls"] = sorted(
            self._environment_hits.values(),
            key=lambda item: item["url"],
        )
        self.report["summary"] = {
            "documents_scanned": len(self.report["documents"]),
            "graphql_endpoints": len(self.report["graphql_endpoints"]),
            "subscription_endpoints": len(self.report["subscription_endpoints"]),
            "operations": len(self.report["operations"]),
            "persisted_query_hashes": len(self.report["persisted_query_hashes"]),
            "auth_headers": len(self.report["auth_headers"]),
            "environment_urls": len(self.report["environment_urls"]),
        }

    def _doc_for_source(self, source_url: str) -> Optional[Dict[str, Any]]:
        return self._document_index.get(source_url)

    def _emit_findings(self) -> None:
        endpoint_hits = self.report["graphql_endpoints"]
        operation_hits = self.report["operations"]
        persisted_hits = self.report["persisted_query_hashes"]
        auth_headers = self.report["auth_headers"]

        if endpoint_hits or self.report["environment_urls"]:
            first = endpoint_hits[0] if endpoint_hits else self.report["environment_urls"][0]
            first_doc = self._doc_for_source(first["source"]) or {}
            severity = SEVERITY_LOW if self.report["environment_urls"] else SEVERITY_INFO
            self.add_finding(
                title="Client Assets Leak GraphQL Endpoints",
                description=(
                    "Guardian found GraphQL-related endpoints or environment URLs in HTML/JavaScript "
                    "assets. Public client bundles often reveal non-obvious targets for reconnaissance, "
                    "alternate environments, or subscription endpoints."
                ),
                severity=severity,
                category=CATEGORY_RECON,
                rule_id="GG-RECON-ASSET-ENDPOINT-LEAKS",
                evidence={
                    "graphql_endpoints": endpoint_hits[:20],
                    "subscription_endpoints": self.report["subscription_endpoints"][:20],
                    "environment_urls": self.report["environment_urls"][:20],
                },
                request={
                    "method": "GET",
                    "url": first["source"],
                    "headers": self._request_headers(),
                },
                response=first_doc,
                remediation=(
                    "Review public bundles for environment leakage. Remove unused endpoint references, "
                    "lock down non-production GraphQL services, and avoid exposing internal hostnames."
                ),
            )

        if operation_hits:
            first = operation_hits[0]
            first_doc = self._doc_for_source(first["source"]) or {}
            self.add_finding(
                title="Client Assets Expose Named GraphQL Operations",
                description=(
                    "JavaScript or HTML assets include named GraphQL operations. These operation names "
                    "help testers and attackers rebuild real client workflows, target high-value mutations, "
                    "and discover subscription names without introspection."
                ),
                severity=SEVERITY_INFO,
                category=CATEGORY_RECON,
                rule_id="GG-RECON-ASSET-OPERATIONS",
                evidence={"operations": operation_hits[:30]},
                request={
                    "method": "GET",
                    "url": first["source"],
                    "headers": self._request_headers(),
                },
                response=first_doc,
                remediation="Minimize exposed development operations in public bundles and review persisted-operation publishing workflows.",
            )

        if persisted_hits or auth_headers:
            first = (persisted_hits or auth_headers)[0]
            first_doc = self._doc_for_source(first["source"]) or {}
            self.add_finding(
                title="Client Assets Expose GraphQL Client Metadata",
                description=(
                    "Guardian found persisted-query hashes or GraphQL auth-header hints in public assets. "
                    "These clues make replay, APQ enumeration, and manual request construction easier during testing."
                ),
                severity=SEVERITY_INFO,
                category=CATEGORY_RECON,
                rule_id="GG-RECON-ASSET-CLIENT-METADATA",
                evidence={
                    "persisted_query_hashes": persisted_hits[:20],
                    "auth_headers": auth_headers[:20],
                },
                request={
                    "method": "GET",
                    "url": first["source"],
                    "headers": self._request_headers(),
                },
                response=first_doc,
                remediation="Avoid leaking unnecessary client metadata in production bundles and rotate secrets or sensitive header schemes when exposed.",
            )
