import asyncio
import inspect
import json
import requests
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import websockets

from src.config import GRAPHQL_WEBSOCKET_PATHS
from src.scanner.query_builder import QueryBuilder


ID_ARGUMENT_NAMES = {"id", "uuid", "key", "nodeid", "node_id", "objectid", "object_id"}
SENSITIVE_OPERATION_KEYWORDS = {
    "admin",
    "approve",
    "ban",
    "delete",
    "disable",
    "grant",
    "invite",
    "manage",
    "permission",
    "promote",
    "publish",
    "reset",
    "revoke",
    "role",
    "secret",
    "suspend",
    "token",
    "update",
}
DESTRUCTIVE_MUTATION_KEYWORDS = {"delete", "remove", "destroy", "purge", "revoke"}
ACK_TYPES = {"connection_ack", "ka", "ping", "pong"}


class AuthTester:
    def __init__(
        self,
        endpoint: str,
        config_data: Dict,
        schema_data: Dict,
        graph_data: Dict,
        path_report: Dict = None,
        operation_pack: Dict = None,
        asset_recon: Dict = None,
    ):
        self.endpoint = endpoint
        self.config = config_data or {}
        self.schema = schema_data
        self.graph = graph_data
        self.path_report = path_report or {}
        self.operation_pack = operation_pack or {}
        self.asset_recon = asset_recon or {}
        if "data" in self.schema:
            self.schema = self.schema["data"]

        self.type_map = {t["name"]: t for t in self.schema["__schema"]["types"]}
        self.builder = QueryBuilder(self.type_map)
        self.paths_by_target = self._index_paths_by_target()
        self.roles = self._build_roles()
        self.matrix_report = {
            "summary": {
                "roles_available": 0,
                "resource_checks": 0,
                "resource_vulnerabilities": 0,
                "anonymous_resource_vulnerabilities": 0,
                "stateful_flows": 0,
                "connected_path_flows": 0,
                "mutation_checks": 0,
                "mutation_vulnerabilities": 0,
                "subscription_checks": 0,
                "subscription_vulnerabilities": 0,
                "admin_configured": False,
            },
            "roles": self._role_report(),
            "resource_checks": [],
            "stateful_flows": [],
            "mutation_checks": [],
            "subscription_checks": [],
            "mutation_vulnerabilities": [],
            "subscription_vulnerabilities": [],
        }

    def _build_roles(self) -> List[Dict[str, Any]]:
        base_headers = dict(self.config.get("headers") or {})
        roles = [
            {
                "key": "anonymous",
                "label": "Anonymous",
                "configured": True,
                "headers": dict(base_headers),
                "username": None,
            }
        ]

        for key, label in (
            ("user_a", "Owner (User A)"),
            ("user_b", "User B"),
            ("admin", "Admin"),
        ):
            role_config = self.config.get(key) or {}
            headers = role_config.get("headers") or {}
            configured = bool(headers)
            roles.append(
                {
                    "key": key,
                    "label": label,
                    "configured": configured,
                    "headers": {**base_headers, **headers} if configured else dict(base_headers),
                    "username": role_config.get("username"),
                }
            )
        return roles

    def _role_report(self) -> List[Dict[str, Any]]:
        return [
            {
                "role": role["key"],
                "label": role["label"],
                "configured": role["configured"],
                "username": role.get("username"),
            }
            for role in self.roles
        ]

    def _configured_roles(self) -> List[Dict[str, Any]]:
        return [role for role in self.roles if role["configured"]]

    def _role(self, key: str) -> Optional[Dict[str, Any]]:
        return next((role for role in self.roles if role["key"] == key), None)

    def _role_result(self, role_results: List[Dict[str, Any]], key: str) -> Optional[Dict[str, Any]]:
        return next((item for item in role_results if item["role"] == key), None)

    def _top_level_field(self, operation_name: str) -> str:
        return operation_name.split(".")[-1]

    def _index_paths_by_target(self) -> Dict[str, List[Dict]]:
        paths_by_target: Dict[str, List[Dict]] = {}
        for path in self.path_report.get("paths", []):
            target = (path.get("target_type") or "").lower()
            if not target:
                continue
            paths_by_target.setdefault(target, []).append(path)
        return paths_by_target

    def _matching_paths(self, resource: str, accessor_operation: str = None) -> List[Dict]:
        paths = list(self.paths_by_target.get((resource or "").lower(), []))
        if not accessor_operation:
            return paths[:5]

        accessor_name = accessor_operation.split(".")[-1].lower()

        def rank(path: Dict) -> tuple:
            path_parts = [part.lower() for part in (path.get("path") or "").split(".")]
            first_field = path_parts[1] if len(path_parts) > 1 else ""
            exact_accessor = first_field == accessor_name
            score = path.get("score", 0)
            return (0 if exact_accessor else 1, -score, path.get("depth", 99))

        return sorted(paths, key=rank)[:5]

    def _accessor_rank(self, resource: str, accessor: Dict) -> tuple:
        matches = self._matching_paths(resource, accessor.get("operation"))
        if not matches:
            return (1, 0)
        return (0, -max(path.get("score", 0) for path in matches))

    def _request_evidence(self, query: str, headers: Dict) -> Dict:
        return {
            "method": "POST",
            "url": self.endpoint,
            "headers": headers or {},
            "body": {"query": query},
        }

    def _response_evidence(self, response: requests.Response) -> Dict:
        body_text = getattr(response, "text", "") or ""
        if not isinstance(body_text, str):
            body_text = str(body_text)
        return {
            "status_code": getattr(response, "status_code", 0),
            "headers": dict(getattr(response, "headers", {}) or {}),
            "body_sample": body_text[:1200],
        }

    def _safe_json(self, response: requests.Response) -> Dict[str, Any]:
        try:
            payload = response.json()
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}

    def _id_argument_name(self, operation_name: str) -> Optional[str]:
        field_def = self._field_definition(operation_name)
        if not field_def:
            return None
        arg = next(
            (item for item in field_def.get("args", []) if item["name"].lower() in ID_ARGUMENT_NAMES),
            None,
        )
        return arg["name"] if arg else None

    def _stateful_reuse(self, source_value: Any, target_argument: Optional[str]) -> List[Dict[str, Any]]:
        if target_argument is None or source_value is None:
            return []
        return [
            {
                "source": "creator_response",
                "source_field": "id",
                "target_argument": target_argument,
                "value": source_value,
            }
        ]

    def _role_decision_summary(self, role_results: List[Dict[str, Any]]) -> str:
        labels = []
        for role_key in ("user_a", "user_b", "anonymous", "admin"):
            result = self._role_result(role_results, role_key)
            if not result:
                continue
            label = result.get("label") or role_key
            if result.get("allowed"):
                labels.append(f"{label} received data.")
            elif result.get("errors"):
                labels.append(f"{label} was blocked with GraphQL errors.")
            else:
                labels.append(f"{label} did not receive data.")
        return " ".join(labels)

    def _extract_id(self, data):
        if isinstance(data, dict):
            if "id" in data:
                return data["id"]
            for value in data.values():
                res = self._extract_id(value)
                if res:
                    return res
        elif isinstance(data, list):
            for item in data:
                res = self._extract_id(item)
                if res:
                    return res
        return None

    def _construct_operation(
        self,
        operation_name: str,
        overrides: Optional[Dict[str, Any]] = None,
        include_optional_args: bool = True,
    ) -> Optional[str]:
        root_type_name, clean_name = operation_name.split(".", 1)
        return self.builder.construct_operation(
            root_type_name,
            clean_name,
            args_overrides=overrides or {},
            include_optional_args=include_optional_args,
        )

    def _field_definition(self, operation_name: str) -> Optional[Dict[str, Any]]:
        root_type_name, clean_name = operation_name.split(".", 1)
        root_type = self.type_map.get(root_type_name) or self.type_map.get(root_type_name + "s")
        if not root_type:
            return None
        return next((field for field in root_type.get("fields", []) if field["name"] == clean_name), None)

    def _construct_mutation(self, operation_name: str) -> Optional[str]:
        field_def = self._field_definition(operation_name)
        if not field_def:
            return None

        overrides = {}
        for arg in field_def.get("args", []):
            arg_type = self.builder.unwrap_type(arg.get("type"))
            if arg["name"] == "public" and arg_type and arg_type.get("name") == "Boolean":
                overrides[arg["name"]] = False

        return self._construct_operation(
            operation_name,
            overrides=overrides,
            include_optional_args=True,
        )

    def _normalize_arg_value(self, arg_type: Optional[Dict[str, Any]], value: Any) -> Any:
        if not arg_type:
            return value
        if arg_type.get("name") == "Int":
            try:
                return int(value)
            except Exception:
                return value
        return value

    def _construct_query(self, operation_name: str, resource_id: Any) -> Optional[str]:
        field_def = self._field_definition(operation_name)
        if not field_def:
            return None

        id_arg = next(
            (arg for arg in field_def.get("args", []) if arg["name"].lower() in ID_ARGUMENT_NAMES),
            None,
        )
        if not id_arg:
            return None

        arg_type = self.builder.unwrap_type(id_arg["type"])
        resource_id = self._normalize_arg_value(arg_type, resource_id)
        return self._construct_operation(
            operation_name,
            overrides={id_arg["name"]: resource_id},
            include_optional_args=False,
        )

    def _meaningful_value(self, value: Any) -> bool:
        return value not in (None, {}, [], False)

    def _response_allowed(self, response: requests.Response, operation_name: str) -> bool:
        payload = self._safe_json(response)
        field_name = self._top_level_field(operation_name)
        value = (payload.get("data") or {}).get(field_name)
        return response.status_code == 200 and self._meaningful_value(value)

    def _http_role_probe(self, role: Dict[str, Any], operation_name: str, query: str) -> Dict[str, Any]:
        try:
            response = requests.post(
                self.endpoint,
                json={"query": query},
                headers=role["headers"],
            )
        except Exception as exc:
            return {
                "role": role["key"],
                "label": role["label"],
                "allowed": False,
                "error": str(exc),
                "request": self._request_evidence(query, role["headers"]),
                "response": {"status_code": 0, "headers": {}, "body_sample": ""},
            }

        payload = self._safe_json(response)
        field_name = self._top_level_field(operation_name)
        value = (payload.get("data") or {}).get(field_name)
        return {
            "role": role["key"],
            "label": role["label"],
            "allowed": self._response_allowed(response, operation_name),
            "status_code": response.status_code,
            "errors": payload.get("errors"),
            "data_present": self._meaningful_value(value),
            "request": self._request_evidence(query, role["headers"]),
            "response": self._response_evidence(response),
        }

    def _candidate_mutations(self) -> List[Dict[str, Any]]:
        candidates = []
        operations = self.operation_pack.get("operations") or []
        if operations:
            for item in operations:
                if item.get("operation_type") != "mutation":
                    continue
                operation_name = item.get("operation_name")
                if not operation_name:
                    continue
                candidates.append(
                    {
                        "operation_name": operation_name,
                        "field": item.get("field") or self._top_level_field(operation_name),
                        "tags": item.get("tags", []),
                        "return_type": item.get("return_type"),
                        "required_args": item.get("required_args", []),
                        "all_args": item.get("all_args", []),
                        "risk_score": item.get("risk_score", 0),
                    }
                )
        else:
            mutation_type = self.schema["__schema"].get("mutationType")
            mutation_def = self.type_map.get((mutation_type or {}).get("name", ""))
            for field in mutation_def.get("fields", []) if mutation_def else []:
                return_type = self.builder.unwrap_type(field.get("type")) or {}
                args = [
                    {"name": arg["name"], "type": "unknown"}
                    for arg in field.get("args", [])
                ]
                candidates.append(
                    {
                        "operation_name": f"{mutation_def['name']}.{field['name']}",
                        "field": field["name"],
                        "tags": [],
                        "return_type": return_type.get("name"),
                        "required_args": args,
                        "all_args": args,
                        "risk_score": 0,
                    }
                )

        ranked = []
        seen = set()
        for candidate in candidates:
            name = candidate["operation_name"]
            if name in seen:
                continue
            seen.add(name)
            field_name = candidate["field"].lower()
            if any(keyword in field_name for keyword in DESTRUCTIVE_MUTATION_KEYWORDS):
                continue
            id_arg_bonus = 20 if any(arg["name"].lower() in ID_ARGUMENT_NAMES for arg in candidate["all_args"]) else 0
            sensitivity_bonus = 20 if self._is_sensitive_operation(name, candidate.get("tags", [])) else 0
            candidate["score"] = candidate.get("risk_score", 0) + id_arg_bonus + sensitivity_bonus
            ranked.append(candidate)

        ranked.sort(key=lambda item: (-item["score"], item["operation_name"]))
        return ranked[:8]

    def _candidate_subscriptions(self) -> List[Dict[str, Any]]:
        candidates = []
        operations = self.operation_pack.get("operations") or []
        if operations:
            for item in operations:
                if item.get("operation_type") != "subscription":
                    continue
                operation_name = item.get("operation_name")
                if not operation_name:
                    continue
                candidates.append(
                    {
                        "operation_name": operation_name,
                        "field": item.get("field") or self._top_level_field(operation_name),
                        "tags": item.get("tags", []),
                        "risk_score": item.get("risk_score", 0),
                    }
                )
        else:
            subscription_type = self.schema["__schema"].get("subscriptionType")
            subscription_def = self.type_map.get((subscription_type or {}).get("name", ""))
            for field in subscription_def.get("fields", []) if subscription_def else []:
                candidates.append(
                    {
                        "operation_name": f"{subscription_def['name']}.{field['name']}",
                        "field": field["name"],
                        "tags": [],
                        "risk_score": 0,
                    }
                )

        for candidate in candidates:
            candidate["score"] = candidate.get("risk_score", 0) + (
                20 if self._is_sensitive_operation(candidate["operation_name"], candidate.get("tags", [])) else 0
            )
        candidates.sort(key=lambda item: (-item["score"], item["operation_name"]))
        return candidates[:5]

    def _resource_context_for_candidate(
        self,
        candidate: Dict[str, Any],
        resource_contexts: List[Dict[str, Any]],
    ) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
        id_arg = next(
            (arg for arg in candidate.get("all_args", []) if arg["name"].lower() in ID_ARGUMENT_NAMES),
            None,
        )
        if not id_arg:
            return None, None

        field_name = candidate["field"].lower()
        return_type = (candidate.get("return_type") or "").lower()
        for context in resource_contexts:
            resource = context["resource"].lower()
            singular = resource[:-1] if resource.endswith("s") else resource
            if return_type == resource or resource in field_name or singular in field_name:
                return context, id_arg["name"]
        return None, id_arg["name"]

    def _is_sensitive_operation(self, operation_name: str, tags: List[str]) -> bool:
        if any(tag in {"sensitive-surface", "idor-candidate"} for tag in tags or []):
            return True
        lowered = operation_name.lower()
        return any(keyword in lowered for keyword in SENSITIVE_OPERATION_KEYWORDS)

    def _subscription_endpoints(self) -> List[str]:
        parsed = urlparse(self.endpoint)
        scheme = "wss" if parsed.scheme == "https" else "ws"
        seeds = [f"{scheme}://{parsed.netloc}{parsed.path or '/graphql'}"]

        for path in GRAPHQL_WEBSOCKET_PATHS:
            seeds.append(f"{scheme}://{parsed.netloc}{path}")

        for bucket_name in ("subscription_endpoints", "graphql_endpoints"):
            for item in self.asset_recon.get(bucket_name, []) or []:
                url = item.get("url") if isinstance(item, dict) else item
                if not url:
                    continue
                seeds.append(self._to_ws_url(url))

        deduped = []
        seen = set()
        for candidate in seeds:
            if candidate in seen:
                continue
            seen.add(candidate)
            deduped.append(candidate)
        return deduped[:5]

    def _to_ws_url(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme in {"ws", "wss"}:
            return url
        scheme = "wss" if parsed.scheme == "https" else "ws"
        return f"{scheme}://{parsed.netloc}{parsed.path or '/graphql'}"

    def _connect_kwargs(self, role_headers: Dict[str, Any], origin: str) -> Dict[str, Any]:
        connect_kwargs: Dict[str, Any] = {
            "subprotocols": ["graphql-transport-ws", "graphql-ws"],
            "open_timeout": 3,
            "close_timeout": 1,
            "origin": origin,
        }
        headers = {
            key: value
            for key, value in (role_headers or {}).items()
            if key.lower() != "content-type"
        }
        signature = inspect.signature(websockets.connect)
        header_param = "additional_headers" if "additional_headers" in signature.parameters else "extra_headers"
        connect_kwargs[header_param] = headers
        return connect_kwargs

    async def _probe_subscription_async(
        self,
        ws_url: str,
        role: Dict[str, Any],
        operation_name: str,
        query: str,
    ) -> Dict[str, Any]:
        origin = f"{urlparse(self.endpoint).scheme}://{urlparse(self.endpoint).netloc}"
        try:
            async with websockets.connect(ws_url, **self._connect_kwargs(role["headers"], origin)) as websocket:
                await websocket.send(json.dumps({"type": "connection_init", "payload": {}}))

                ack = False
                message_types = []
                message_sample = []
                subscribe_error = None

                for _ in range(2):
                    try:
                        reply = await asyncio.wait_for(websocket.recv(), timeout=2)
                    except asyncio.TimeoutError:
                        break
                    message_sample.append(reply if isinstance(reply, str) else str(reply))
                    try:
                        parsed = json.loads(reply)
                    except Exception:
                        continue
                    msg_type = parsed.get("type")
                    message_types.append(msg_type)
                    if msg_type in ACK_TYPES:
                        ack = True
                    if msg_type in {"connection_error", "error"}:
                        subscribe_error = parsed

                if ack:
                    outbound_type = "subscribe" if websocket.subprotocol == "graphql-transport-ws" else "start"
                    await websocket.send(
                        json.dumps(
                            {
                                "id": "guardian-authz-matrix",
                                "type": outbound_type,
                                "payload": {"query": query},
                            }
                        )
                    )
                    for _ in range(2):
                        try:
                            reply = await asyncio.wait_for(websocket.recv(), timeout=2)
                        except asyncio.TimeoutError:
                            break
                        message_sample.append(reply if isinstance(reply, str) else str(reply))
                        try:
                            parsed = json.loads(reply)
                        except Exception:
                            continue
                        msg_type = parsed.get("type")
                        message_types.append(msg_type)
                        if msg_type in {"error", "connection_error"}:
                            subscribe_error = parsed
                        if msg_type == "complete":
                            break
                    stop_type = "complete" if websocket.subprotocol == "graphql-transport-ws" else "stop"
                    try:
                        await websocket.send(
                            json.dumps({"id": "guardian-authz-matrix", "type": stop_type})
                        )
                    except Exception:
                        pass

                return {
                    "role": role["key"],
                    "label": role["label"],
                    "allowed": bool(ack and not subscribe_error),
                    "ack": ack,
                    "subprotocol": websocket.subprotocol,
                    "message_types": message_types,
                    "message_sample": message_sample[:3],
                    "error": subscribe_error,
                    "request": {
                        "method": "WEBSOCKET",
                        "url": ws_url,
                        "headers": role["headers"],
                        "body": {"query": query},
                    },
                    "response": {
                        "status_code": 101 if ack else 0,
                        "headers": {"Sec-WebSocket-Protocol": websocket.subprotocol or ""},
                        "body_sample": "\n".join(message_sample[:3])[:1200],
                    },
                }
        except Exception as exc:
            return {
                "role": role["key"],
                "label": role["label"],
                "allowed": False,
                "ack": False,
                "subprotocol": None,
                "message_types": [],
                "message_sample": [],
                "error": str(exc),
                "request": {
                    "method": "WEBSOCKET",
                    "url": ws_url,
                    "headers": role["headers"],
                    "body": {"query": query},
                },
                "response": {
                    "status_code": 0,
                    "headers": {},
                    "body_sample": str(exc)[:1200],
                },
            }

    def _probe_subscription_role(
        self,
        ws_url: str,
        role: Dict[str, Any],
        operation_name: str,
        query: str,
    ) -> Dict[str, Any]:
        try:
            return asyncio.run(self._probe_subscription_async(ws_url, role, operation_name, query))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(
                    self._probe_subscription_async(ws_url, role, operation_name, query)
                )
            finally:
                loop.close()

    def _evaluate_resource_access(
        self,
        context: Dict[str, Any],
        accessors: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        results = []
        for accessor in accessors:
            query = self._construct_query(accessor["operation"], context["id"])
            if not query:
                print(f"    [-] Could not construct query for {accessor['operation']}", file=sys.stderr)
                continue

            role_results = [
                self._http_role_probe(role, accessor["operation"], query)
                for role in self._configured_roles()
            ]
            owner_result = self._role_result(role_results, "user_a")
            user_b_result = self._role_result(role_results, "user_b")
            vulnerable_roles = [
                item["role"]
                for item in role_results
                if item["role"] in {"anonymous", "user_b"} and item["allowed"]
            ]
            id_argument = self._id_argument_name(accessor["operation"])
            stateful_reuse = self._stateful_reuse(context["id"], id_argument)
            decision_summary = self._role_decision_summary(role_results)

            entry = {
                "resource": context["resource"],
                "creator": context["creator"],
                "accessor": accessor["operation"],
                "id": context["id"],
                "id_argument": id_argument,
                "paths": self._matching_paths(context["resource"], accessor["operation"]),
                "owner_access": bool(owner_result and owner_result["allowed"]),
                "role_results": role_results,
                "vulnerable_roles": vulnerable_roles,
                "creation_request": context.get("creation_request"),
                "creation_response": context.get("creation_response"),
                "created_object_sample": context.get("created_object_sample"),
                "stateful_reuse": stateful_reuse,
                "decision_summary": decision_summary,
            }
            self.matrix_report["resource_checks"].append(entry)
            self.matrix_report["stateful_flows"].append(
                {
                    "resource": context["resource"],
                    "creator": context["creator"],
                    "accessor": accessor["operation"],
                    "resource_id": context["id"],
                    "id_argument": id_argument,
                    "path_candidates": entry["paths"],
                    "creation_request": context.get("creation_request"),
                    "creation_response": context.get("creation_response"),
                    "stateful_reuse": stateful_reuse,
                    "role_results": role_results,
                    "vulnerable_roles": vulnerable_roles,
                    "decision_summary": decision_summary,
                }
            )

            results.append(
                {
                    "resource": context["resource"],
                    "creator": context["creator"],
                    "accessor": accessor["operation"],
                    "id": context["id"],
                    "idor_detected": bool(user_b_result and user_b_result["allowed"]),
                    "anonymous_detected": "anonymous" in vulnerable_roles,
                    "paths": entry["paths"],
                    "request": user_b_result["request"] if user_b_result else None,
                    "response": user_b_result["response"] if user_b_result else None,
                    "role_results": role_results,
                    "flow_evidence": {
                        "creator": context["creator"],
                        "accessor": accessor["operation"],
                        "id_argument": id_argument,
                        "stateful_reuse": stateful_reuse,
                        "creation_request": context.get("creation_request"),
                        "creation_response": context.get("creation_response"),
                        "decision_summary": decision_summary,
                    },
                }
            )
        return results

    def _evaluate_mutation_matrix(self, resource_contexts: List[Dict[str, Any]]) -> None:
        for candidate in self._candidate_mutations():
            context, id_arg = self._resource_context_for_candidate(candidate, resource_contexts)
            overrides = {}
            if context and id_arg:
                field_def = self._field_definition(candidate["operation_name"])
                arg_def = next(
                    (arg for arg in field_def.get("args", []) if arg["name"] == id_arg),
                    None,
                ) if field_def else None
                overrides[id_arg] = self._normalize_arg_value(
                    self.builder.unwrap_type((arg_def or {}).get("type")),
                    context["id"],
                )

            query = self._construct_operation(
                candidate["operation_name"],
                overrides=overrides,
                include_optional_args=True,
            )
            if not query:
                continue

            role_results = [
                self._http_role_probe(role, candidate["operation_name"], query)
                for role in self._configured_roles()
            ]
            owner_result = self._role_result(role_results, "user_a")
            user_b_result = self._role_result(role_results, "user_b")
            anonymous_result = self._role_result(role_results, "anonymous")

            vulnerable_roles = []
            reasons = []
            sensitive = self._is_sensitive_operation(
                candidate["operation_name"],
                candidate.get("tags", []),
            )

            if sensitive and anonymous_result and anonymous_result["allowed"]:
                vulnerable_roles.append("anonymous")
                reasons.append("Anonymous role executed a sensitive mutation.")

            if (
                context
                and id_arg
                and owner_result
                and owner_result["allowed"]
                and user_b_result
                and user_b_result["allowed"]
            ):
                vulnerable_roles.append("user_b")
                reasons.append(
                    f"User B executed a mutation against an owner-owned resource using {id_arg}={context['id']}."
                )

            entry = {
                "operation_name": candidate["operation_name"],
                "resource": context["resource"] if context else None,
                "resource_id": context["id"] if context else None,
                "id_argument": id_arg,
                "tags": candidate.get("tags", []),
                "sensitive": sensitive,
                "role_results": role_results,
                "vulnerable_roles": vulnerable_roles,
                "reasons": reasons,
                "creator": context.get("creator") if context else None,
                "creation_request": context.get("creation_request") if context else None,
                "creation_response": context.get("creation_response") if context else None,
                "stateful_reuse": self._stateful_reuse(context["id"], id_arg) if context and id_arg else [],
            }
            self.matrix_report["mutation_checks"].append(entry)
            if vulnerable_roles:
                self.matrix_report["mutation_vulnerabilities"].append(entry)

    def _evaluate_subscription_matrix(self) -> None:
        endpoints = self._subscription_endpoints()
        if not endpoints:
            return

        for candidate in self._candidate_subscriptions():
            query = self._construct_operation(candidate["operation_name"], include_optional_args=True)
            if not query:
                continue

            selected_endpoint = endpoints[0]
            role_results = [
                self._probe_subscription_role(selected_endpoint, role, candidate["operation_name"], query)
                for role in self._configured_roles()
            ]
            anonymous_result = self._role_result(role_results, "anonymous")
            sensitive = self._is_sensitive_operation(
                candidate["operation_name"],
                candidate.get("tags", []),
            )
            vulnerable_roles = []
            reasons = []

            if sensitive and anonymous_result and anonymous_result["allowed"]:
                vulnerable_roles.append("anonymous")
                reasons.append("Anonymous role was able to initialize and start a sensitive subscription.")

            entry = {
                "operation_name": candidate["operation_name"],
                "endpoint": selected_endpoint,
                "tags": candidate.get("tags", []),
                "sensitive": sensitive,
                "role_results": role_results,
                "vulnerable_roles": vulnerable_roles,
                "reasons": reasons,
            }
            self.matrix_report["subscription_checks"].append(entry)
            if vulnerable_roles:
                self.matrix_report["subscription_vulnerabilities"].append(entry)

    def _finalize_matrix_summary(self) -> None:
        summary = self.matrix_report["summary"]
        summary["roles_available"] = len([role for role in self.roles if role["configured"]])
        summary["admin_configured"] = bool(self._role("admin") and self._role("admin")["configured"])
        summary["resource_checks"] = len(self.matrix_report["resource_checks"])
        summary["resource_vulnerabilities"] = sum(
            1 for item in self.matrix_report["resource_checks"] if "user_b" in item["vulnerable_roles"]
        )
        summary["anonymous_resource_vulnerabilities"] = sum(
            1 for item in self.matrix_report["resource_checks"] if "anonymous" in item["vulnerable_roles"]
        )
        summary["stateful_flows"] = len(self.matrix_report["stateful_flows"])
        summary["connected_path_flows"] = sum(
            1 for item in self.matrix_report["stateful_flows"] if item.get("path_candidates")
        )
        summary["mutation_checks"] = len(self.matrix_report["mutation_checks"])
        summary["mutation_vulnerabilities"] = len(self.matrix_report["mutation_vulnerabilities"])
        summary["subscription_checks"] = len(self.matrix_report["subscription_checks"])
        summary["subscription_vulnerabilities"] = len(self.matrix_report["subscription_vulnerabilities"])

    def run(self):
        creators = self.graph["analysis"]["creators"]
        accessors = self.graph["analysis"]["accessors"]

        results = []
        resource_map = {}
        resource_contexts = []

        for acc in accessors:
            res = acc["resource"]
            resource_map.setdefault(res, []).append(acc)

        print(f"[*] Found {len(creators)} creators and {len(accessors)} accessors.", file=sys.stderr)

        owner_role = self._role("user_a")
        if not owner_role or not owner_role["configured"]:
            self._finalize_matrix_summary()
            return results

        for creator in creators:
            resource = creator["resource"]
            mutation = self._construct_mutation(creator["operation"])
            if not mutation:
                print(f"[-] Could not construct mutation for {creator['operation']}", file=sys.stderr)
                continue

            print(f"[*] Testing resource: {resource} (Created by {creator['operation']})", file=sys.stderr)
            print("    [Owner] Creating resource...", file=sys.stderr)
            resp_owner = requests.post(
                self.endpoint,
                json={"query": mutation},
                headers=owner_role["headers"],
            )
            payload = self._safe_json(resp_owner)
            if resp_owner.status_code != 200 or payload.get("errors"):
                print(f"    [-] Creation failed: {getattr(resp_owner, 'text', '')}", file=sys.stderr)
                continue

            created_obj = (payload.get("data") or {}).get(self._top_level_field(creator["operation"]))
            if not created_obj:
                print("    [-] No data returned.", file=sys.stderr)
                continue

            resource_id = self._extract_id(created_obj)
            if not resource_id:
                print("    [-] Could not extract ID from response.", file=sys.stderr)
                continue

            print(f"    [+] Created Resource ID: {resource_id}", file=sys.stderr)
            context = {
                "resource": resource,
                "creator": creator["operation"],
                "id": resource_id,
                "creation_request": self._request_evidence(mutation, owner_role["headers"]),
                "creation_response": self._response_evidence(resp_owner),
                "created_object_sample": created_obj,
            }
            resource_contexts.append(context)

            resource_accessors = sorted(
                resource_map.get(resource, []),
                key=lambda item: self._accessor_rank(resource, item),
            )
            results.extend(self._evaluate_resource_access(context, resource_accessors))

        self._evaluate_mutation_matrix(resource_contexts)
        self._evaluate_subscription_matrix()
        self._finalize_matrix_summary()
        return results
