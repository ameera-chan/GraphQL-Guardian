from typing import List, Dict
from .models import Finding
from src.utils.evidence import build_evidence

class ResultConverter:
    @staticmethod
    def convert_config_results(results: List[Dict]) -> List[Finding]:
        findings = []
        for res in results:
            if res['status'] == 'SAFE':
                continue
                
            severity = "INFO"
            if res['status'] == 'VULNERABLE':
                # Introspection is usually Low/Medium, but Public GraphiQL is Low.
                # Let's map based on check name if needed, or default to MEDIUM for VULNERABLE
                if "Introspection" in res['check']: severity = "LOW"
                elif "GraphiQL" in res['check']: severity = "LOW"
                elif "GET Method" in res['check']: severity = "MEDIUM"
                else: severity = "MEDIUM"
            elif res['status'] == 'WARNING':
                severity = "LOW"
            elif res['status'] == 'ERROR':
                severity = "INFO"

            findings.append(Finding(
                title=res['check'],
                description=res['message'],
                severity=severity,
                category="CONFIG"
            ))
        return findings

    @staticmethod
    def convert_dos_results(results: List[Dict]) -> List[Finding]:
        findings = []
        for res in results:
            if res['status'] == 'SAFE':
                continue
                
            severity = "HIGH" if res['status'] == 'VULNERABLE' else "LOW"
            
            findings.append(Finding(
                title=res['check'],
                description=res['message'],
                severity=severity,
                category="DOS"
            ))
        return findings

    @staticmethod
    def convert_audit_results(results: List[Dict]) -> List[Finding]:
        findings = []
        for res in results:
            findings.append(Finding(
                title=res['title'],
                description=res['description'],
                severity=res['severity'].upper(),
                category="SCHEMA",
                field=res.get('location', 'Unknown')
            ))
        return findings

    @staticmethod
    def convert_injection_results(results: List[Dict]) -> List[Finding]:
        findings = []
        for res in results:
            severity = "HIGH"
            if "Reflected Payload" in res['vulnerability']:
                severity = "MEDIUM" # Reflected XSS is usually Medium/High
            elif "SQL" in res['vulnerability']:
                severity = "HIGH"
            
            findings.append(Finding(
                title=res['vulnerability'],
                description=f"Found {res['vulnerability']} in {res['operation']}",
                severity=severity,
                category="INJECTION",
                operation_name=res['operation'],
                field=res['argument'],
                evidence=res.get('payload')
            ))
        return findings

    @staticmethod
    def convert_auth_results(results: List[Dict], matrix_report: Dict = None) -> List[Finding]:
        findings = []
        for res in results:
            if not res['idor_detected']:
                if not res.get("anonymous_detected"):
                    continue
            else:
                rule_id = "GG-AUTH-IDOR-BOLA"
                evidence = build_evidence(
                    rule_id=rule_id,
                    confidence="high",
                    state="confirmed",
                    details={
                        "creator": res["creator"],
                        "accessor": res["accessor"],
                        "resource_id": res["id"],
                        "path_candidates": res.get("paths", []),
                        "role_results": res.get("role_results", []),
                        "stateful_flow": res.get("flow_evidence"),
                    },
                    request=res.get("request"),
                    response=res.get("response"),
                )

                findings.append(Finding(
                    title="IDOR Vulnerability",
                    description=f"User B was able to access User A's resource via {res['accessor']}",
                    severity="HIGH",
                    category="AUTH",
                    operation_name=res['accessor'],
                    field=f"Resource ID: {res['id']}",
                    evidence=evidence,
                    rule_id=rule_id,
                    confidence="high",
                    state="confirmed",
                    reproduction=evidence.reproduction,
                    remediation="Implement object-level authorization checks on every resolver that can return this resource."
                ))

        if not matrix_report:
            return findings

        for item in matrix_report.get("resource_checks", []):
            if "anonymous" not in item.get("vulnerable_roles", []):
                continue
            anonymous_result = next(
                (result for result in item.get("role_results", []) if result.get("role") == "anonymous"),
                None,
            )
            if not anonymous_result:
                continue

            rule_id = "GG-AUTH-ANONYMOUS-RESOURCE-ACCESS"
            evidence = build_evidence(
                rule_id=rule_id,
                confidence="high",
                state="confirmed",
                details={
                    "creator": item["creator"],
                    "accessor": item["accessor"],
                    "resource_id": item["id"],
                    "path_candidates": item.get("paths", []),
                    "role_results": item.get("role_results", []),
                    "decision_summary": item.get("decision_summary"),
                    "stateful_reuse": item.get("stateful_reuse", []),
                    "creation_request": item.get("creation_request"),
                    "creation_response": item.get("creation_response"),
                },
                request=anonymous_result.get("request"),
                response=anonymous_result.get("response"),
            )
            findings.append(Finding(
                title="Anonymous Resource Access",
                description=f"Anonymous access was able to retrieve owner-linked data via {item['accessor']}.",
                severity="HIGH",
                category="AUTH",
                operation_name=item["accessor"],
                field=f"Resource ID: {item['id']}",
                evidence=evidence,
                rule_id=rule_id,
                confidence="high",
                state="confirmed",
                reproduction=evidence.reproduction,
                remediation="Require authentication and object-level authorization checks before returning owner-linked resources.",
            ))

        for item in matrix_report.get("mutation_vulnerabilities", []):
            role_order = ["anonymous", "user_b"]
            for role_name in role_order:
                if role_name not in item.get("vulnerable_roles", []):
                    continue
                role_result = next(
                    (result for result in item.get("role_results", []) if result.get("role") == role_name),
                    None,
                )
                if not role_result:
                    continue
                rule_id = (
                    "GG-AUTH-ANONYMOUS-MUTATION-ACCESS"
                    if role_name == "anonymous"
                    else "GG-AUTH-MUTATION-BOLA"
                )
                description = (
                    f"Anonymous access executed sensitive mutation {item['operation_name']}."
                    if role_name == "anonymous"
                    else f"User B executed owner-linked mutation {item['operation_name']} against resource {item.get('resource_id')}."
                )
                confidence = "high" if role_name == "anonymous" or item.get("resource_id") else "medium"
                evidence = build_evidence(
                    rule_id=rule_id,
                    confidence=confidence,
                    state="confirmed" if confidence == "high" else "possible",
                    details={
                        "resource": item.get("resource"),
                        "resource_id": item.get("resource_id"),
                        "id_argument": item.get("id_argument"),
                        "tags": item.get("tags", []),
                        "reasons": item.get("reasons", []),
                        "role_results": item.get("role_results", []),
                        "creator": item.get("creator"),
                        "stateful_reuse": item.get("stateful_reuse", []),
                        "creation_request": item.get("creation_request"),
                        "creation_response": item.get("creation_response"),
                    },
                    request=role_result.get("request"),
                    response=role_result.get("response"),
                )
                findings.append(Finding(
                    title="Mutation Authorization Bypass",
                    description=description,
                    severity="HIGH",
                    category="AUTH",
                    operation_name=item["operation_name"],
                    field=item.get("id_argument"),
                    evidence=evidence,
                    rule_id=rule_id,
                    confidence=confidence,
                    state="confirmed" if confidence == "high" else "possible",
                    reproduction=evidence.reproduction,
                    remediation="Enforce object-level authorization on state-changing mutations and validate privilege requirements per role.",
                ))

        for item in matrix_report.get("subscription_vulnerabilities", []):
            if "anonymous" not in item.get("vulnerable_roles", []):
                continue
            role_result = next(
                (result for result in item.get("role_results", []) if result.get("role") == "anonymous"),
                None,
            )
            if not role_result:
                continue
            rule_id = "GG-AUTH-ANONYMOUS-SUBSCRIPTION-ACCESS"
            evidence = build_evidence(
                rule_id=rule_id,
                confidence="medium",
                state="possible",
                details={
                    "endpoint": item.get("endpoint"),
                    "tags": item.get("tags", []),
                    "reasons": item.get("reasons", []),
                    "role_results": item.get("role_results", []),
                },
                request=role_result.get("request"),
                response=role_result.get("response"),
            )
            findings.append(Finding(
                title="Unauthenticated Subscription Access",
                description=f"Anonymous access was able to initialize subscription {item['operation_name']} on {item.get('endpoint')}.",
                severity="HIGH",
                category="AUTH",
                operation_name=item["operation_name"],
                evidence=evidence,
                rule_id=rule_id,
                confidence="medium",
                state="possible",
                reproduction=evidence.reproduction,
                remediation="Require authentication and per-subscription authorization before accepting WebSocket subscription requests.",
            ))
        return findings
