"""Active GraphQL subscription and WebSocket security probes."""

from __future__ import annotations

import asyncio
import inspect
import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
import websockets

from src.config import CATEGORY_RECON, GRAPHQL_WEBSOCKET_PATHS, SEVERITY_HIGH, SEVERITY_INFO
from src.scanner.base_scanner import BaseScanner


ACK_TYPES = {"connection_ack", "ka", "ping", "pong"}


class SubscriptionSecurityScanner(BaseScanner):
    """Probe for active GraphQL WebSocket endpoints and weak handshake controls."""

    def __init__(
        self,
        endpoint: str,
        *,
        schema: Optional[Dict[str, Any]] = None,
        config: Optional[Dict[str, Any]] = None,
        asset_recon: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(endpoint, schema=schema or {}, config=config or {})
        self.asset_recon = asset_recon or {}
        self.safe_origin = self._http_origin(self.endpoint)
        self.evil_origin = "https://evil.example"
        self.report: Dict[str, Any] = {
            "summary": {
                "subscription_fields": 0,
                "candidate_endpoints": 0,
                "active_endpoints": 0,
                "unauthenticated_handshakes": 0,
                "unauthenticated_acks": 0,
                "evil_origin_accepted": 0,
            },
            "subscription_fields": [],
            "candidates": [],
        }

    def run(self) -> List:
        subscription_fields = self._subscription_fields()
        candidates = self._candidate_endpoints()
        self.report["subscription_fields"] = subscription_fields
        self.report["summary"]["subscription_fields"] = len(subscription_fields)
        self.report["summary"]["candidate_endpoints"] = len(candidates)

        active = []
        unauthenticated = []
        unauthenticated_acks = []
        evil_origin = []

        for candidate in candidates[:6]:
            probe = self._probe_candidate(candidate)
            self.report["candidates"].append(probe)
            if probe["upgrade_ok"] or probe["protocol_ack"]:
                active.append(probe)
                unauthenticated.append(probe)
            if probe["protocol_ack"]:
                unauthenticated_acks.append(probe)
            if probe["evil_origin_upgrade"] or probe["evil_origin_ack"]:
                evil_origin.append(probe)

        self.report["summary"]["active_endpoints"] = len(active)
        self.report["summary"]["unauthenticated_handshakes"] = len(unauthenticated)
        self.report["summary"]["unauthenticated_acks"] = len(unauthenticated_acks)
        self.report["summary"]["evil_origin_accepted"] = len(evil_origin)

        if active:
            self.add_finding(
                title="GraphQL WebSocket Endpoint Active",
                description=(
                    "Guardian identified an active WebSocket endpoint that appears to support GraphQL "
                    "subscription traffic. This extends the attack surface beyond HTTP and should be "
                    "reviewed for Origin validation, auth-on-connect, and event authorization."
                ),
                severity=SEVERITY_INFO,
                category=CATEGORY_RECON,
                rule_id="GG-RECON-ACTIVE-GRAPHQL-WS-ENDPOINT",
                evidence={
                    "subscription_fields": subscription_fields,
                    "active_candidates": active[:10],
                },
            )

        if unauthenticated:
            self.add_finding(
                title="Unauthenticated GraphQL WebSocket Handshake Accepted",
                description=(
                    "Guardian received a WebSocket upgrade or GraphQL protocol acknowledgement without "
                    "presenting authentication headers. An HTTP 101 upgrade confirms an unauthenticated "
                    "WebSocket handshake, but does not by itself prove access to subscription events."
                ),
                severity=SEVERITY_HIGH,
                category=CATEGORY_RECON,
                rule_id="GG-RECON-UNAUTHENTICATED-GRAPHQL-WS",
                evidence={
                    "subscription_fields": subscription_fields,
                    "candidates": unauthenticated[:10],
                },
                remediation=(
                    "Require authentication during the WebSocket handshake or connection_init phase and "
                    "authorize every subscription resolver independently."
                ),
            )

        if evil_origin:
            self.add_finding(
                title="WebSocket Origin Validation Missing",
                description=(
                    "Guardian accepted a WebSocket upgrade or protocol handshake from a malicious Origin. "
                    "That is a strong indicator of Cross-Site WebSocket Hijacking risk for GraphQL "
                    "subscriptions."
                ),
                severity=SEVERITY_HIGH,
                category=CATEGORY_RECON,
                rule_id="GG-RECON-GRAPHQL-WS-ORIGIN-VALIDATION",
                evidence={
                    "subscription_fields": subscription_fields,
                    "candidates": evil_origin[:10],
                },
                remediation="Validate Origin on the WebSocket handshake and reject cross-site subscription connections by default.",
            )

        return self.findings

    def _subscription_fields(self) -> List[str]:
        if not isinstance(self.schema, dict):
            return []
        schema_root = self.schema.get("data", self.schema)
        schema = schema_root.get("__schema", {})
        subscription_type = schema.get("subscriptionType") or {}
        name = subscription_type.get("name")
        if not name:
            return []
        type_map = {
            item["name"]: item
            for item in schema.get("types", [])
            if item.get("name")
        }
        type_def = type_map.get(name, {})
        return [field["name"] for field in type_def.get("fields", [])]

    def _candidate_endpoints(self) -> List[str]:
        parsed = urlparse(self.endpoint)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        base_ws = f"{ws_scheme}://{parsed.netloc}"
        seeds = [f"{base_ws}{parsed.path or '/graphql'}"]
        for path in GRAPHQL_WEBSOCKET_PATHS:
            seeds.append(f"{base_ws}{path}")

        for bucket_name in ("subscription_endpoints", "graphql_endpoints"):
            for item in self.asset_recon.get(bucket_name, []) or []:
                url = item.get("url") if isinstance(item, dict) else item
                if not url:
                    continue
                seeds.append(self._ws_url(url))

        deduped = []
        seen = set()
        for candidate in seeds:
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            deduped.append(candidate)
        return deduped

    def _ws_url(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme in {"ws", "wss"}:
            return url
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        return f"{ws_scheme}://{parsed.netloc}{parsed.path or '/graphql'}"

    def _http_origin(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _http_url(self, ws_url: str) -> str:
        parsed = urlparse(ws_url)
        http_scheme = "https" if parsed.scheme == "wss" else "http"
        return f"{http_scheme}://{parsed.netloc}{parsed.path or '/graphql'}"

    def _upgrade_headers(self, origin: str) -> Dict[str, str]:
        return {
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Origin": origin,
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "+onQ3ZxjWlkNa0na6ydhNg==",
            "Sec-WebSocket-Protocol": "graphql-transport-ws, graphql-ws",
        }

    def _http_upgrade_probe(self, ws_url: str, origin: str) -> Dict[str, Any]:
        http_url = self._http_url(ws_url)
        try:
            response = requests.get(
                http_url,
                headers=self._upgrade_headers(origin),
                timeout=5,
                proxies=self.http_client.proxies,
                verify=not bool(self.http_client.proxies),
            )
        except requests.RequestException as exc:
            return {
                "accepted": False,
                "status_code": 0,
                "headers": {},
                "error": str(exc),
            }

        upgrade_header = (response.headers.get("Upgrade") or "").lower()
        connection_header = (response.headers.get("Connection") or "").lower()
        accepted = response.status_code == 101 and "websocket" in upgrade_header and "upgrade" in connection_header
        return {
            "accepted": accepted,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "error": None,
        }

    async def _graphql_ws_probe_async(self, ws_url: str, origin: str) -> Dict[str, Any]:
        connect_kwargs: Dict[str, Any] = {
            "subprotocols": ["graphql-transport-ws", "graphql-ws"],
            "open_timeout": 3,
            "close_timeout": 1,
            "origin": origin,
        }
        signature = inspect.signature(websockets.connect)
        header_param = "additional_headers" if "additional_headers" in signature.parameters else "extra_headers"
        connect_kwargs[header_param] = {}

        try:
            async with websockets.connect(ws_url, **connect_kwargs) as websocket:
                await websocket.send(json.dumps({"type": "connection_init", "payload": {}}))
                message_types = []
                raw_messages = []
                for _ in range(2):
                    try:
                        reply = await asyncio.wait_for(websocket.recv(), timeout=2)
                    except asyncio.TimeoutError:
                        break
                    raw_messages.append(reply if isinstance(reply, str) else str(reply))
                    try:
                        parsed = json.loads(reply)
                        message_types.append(parsed.get("type"))
                    except (TypeError, ValueError):
                        continue

                ack = any(item in ACK_TYPES for item in message_types)
                return {
                    "connected": True,
                    "ack": ack,
                    "message_types": message_types,
                    "message_sample": raw_messages[:2],
                    "subprotocol": websocket.subprotocol,
                    "error": None,
                }
        except Exception as exc:
            return {
                "connected": False,
                "ack": False,
                "message_types": [],
                "message_sample": [],
                "subprotocol": None,
                "error": str(exc),
            }

    def _graphql_ws_probe(self, ws_url: str, origin: str) -> Dict[str, Any]:
        try:
            return asyncio.run(self._graphql_ws_probe_async(ws_url, origin))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(self._graphql_ws_probe_async(ws_url, origin))
            finally:
                loop.close()

    def _probe_candidate(self, ws_url: str) -> Dict[str, Any]:
        baseline_upgrade = self._http_upgrade_probe(ws_url, self.safe_origin)
        evil_upgrade = self._http_upgrade_probe(ws_url, self.evil_origin)
        baseline_protocol = self._graphql_ws_probe(ws_url, self.safe_origin)
        evil_protocol = self._graphql_ws_probe(ws_url, self.evil_origin)
        return {
            "url": ws_url,
            "upgrade_ok": baseline_upgrade["accepted"],
            "upgrade_status_code": baseline_upgrade["status_code"],
            "protocol_ack": baseline_protocol["ack"],
            "subprotocol": baseline_protocol.get("subprotocol"),
            "message_types": baseline_protocol.get("message_types", []),
            "evil_origin_upgrade": evil_upgrade["accepted"],
            "evil_origin_ack": evil_protocol["ack"],
            "errors": {
                "baseline_upgrade": baseline_upgrade.get("error"),
                "baseline_protocol": baseline_protocol.get("error"),
                "evil_upgrade": evil_upgrade.get("error"),
                "evil_protocol": evil_protocol.get("error"),
            },
        }
