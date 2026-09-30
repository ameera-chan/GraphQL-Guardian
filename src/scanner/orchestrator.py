"""Unified scan orchestration for GraphQL Guardian."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import yaml

from src.config import PROFILE_AGGRESSIVE, PROFILE_DEFAULT, PROFILE_PASSIVE
from src.reporters.converter import ResultConverter
from src.reporters.finding_enricher import enrich_findings
from src.reporters.relationship_map import build_relationship_map_from_parts
from src.reporters.schema_map import extract_schema_structure
from src.reporters.models import Finding
from src.scanner.active_security import ActiveSecurityScanner
from src.scanner.asset_recon import AssetReconScanner
from src.scanner.authentication_tester import AuthenticationScanner
from src.scanner.auth_tester import AuthTester
from src.scanner.blind_introspector import BlindIntrospector
from src.scanner.config_checker import ConfigChecker
from src.scanner.dependency_graph import DependencyGraphBuilder
from src.scanner.dos_scanner import DoSScanner
from src.scanner.fingerprinter import GraphQLFingerprinter
from src.scanner.introspection_bypass import IntrospectionBypassScanner
from src.scanner.injector import PayloadInjector
from src.scanner.operation_pack import OperationPackGenerator
from src.scanner.path_enumerator import GraphQLPathEnumerator, normalize_schema
from src.scanner.points_of_interest import build_points_of_interest
from src.scanner.request_forgery import RequestForgeryScanner
from src.scanner.schema_auditor import SchemaAuditor
from src.scanner.schema_overview import build_schema_overview
from src.scanner.schema_parser import fetch_introspection, parse_schema_details
from src.scanner.sensitive_field_review import review_sensitive_candidates, split_sensitive_candidates
from src.scanner.subscription_tester import SubscriptionSecurityScanner


ProgressCallback = Callable[[str, float, str], None]


@dataclass
class ScanPhase:
    name: str
    status: str = "pending"
    summary: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    started_at: Optional[float] = None
    ended_at: Optional[float] = None

    def start(self) -> None:
        self.status = "running"
        self.started_at = time.time()

    def complete(self, summary: Optional[Dict[str, Any]] = None) -> None:
        self.status = "completed"
        self.summary = summary or {}
        self.ended_at = time.time()

    def fail(self, error: Exception) -> None:
        self.status = "failed"
        self.error = str(error)
        self.ended_at = time.time()

    def skip(self, reason: str) -> None:
        self.status = "skipped"
        self.summary = {"reason": reason}
        self.ended_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.started_at and self.ended_at:
            data["duration_seconds"] = round(self.ended_at - self.started_at, 2)
        return data


class ScanOrchestrator:
    """Run Guardian as one integrated GraphQL pentesting workflow."""

    def __init__(
        self,
        endpoint: str,
        *,
        config_data: Optional[Dict[str, Any]] = None,
        profile: Optional[str] = None,
        risk_level: int = 1,
        technique: str = "IDAC",
        enable_ml: bool = False,
        enable_llm: bool = False,
        llm_provider: Optional[str] = None,
        llm_model: Optional[str] = None,
        progress_callback: Optional[ProgressCallback] = None,
    ):
        self.endpoint = endpoint
        self.config = config_data if config_data is not None else self._load_default_config()
        self.profile = profile or self._profile_from_risk(risk_level)
        self.risk_level = risk_level
        self.technique = technique or "IDAC"
        self.enable_ml = enable_ml
        self.enable_llm = enable_llm
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self.progress_callback = progress_callback

        self.findings: List[Finding] = []
        self.workflow: List[ScanPhase] = []
        self.schema_data: Optional[Dict[str, Any]] = None
        self.schema_summary: Dict[str, Any] = {}
        self.dependency_graph: Optional[Dict[str, Any]] = None
        self.path_report: Dict[str, Any] = {"summary": {"total_paths": 0}, "paths": []}
        self.operation_pack: Dict[str, Any] = {
            "summary": {"total_operations": 0},
            "operations": [],
            "packs": {},
        }
        self.asset_recon: Dict[str, Any] = {"summary": {"documents_scanned": 0}}
        self.introspection_bypass: Dict[str, Any] = {
            "summary": {
                "schema_accessible": False,
                "type_accessible": False,
                "suggestion_leak": False,
                "root_type_leak": False,
            }
        }
        self.request_forgery: Dict[str, Any] = {"summary": {"variants_tested": 0}}
        self.subscription_security: Dict[str, Any] = {
            "summary": {"candidate_endpoints": 0, "active_endpoints": 0}
        }
        self.authorization_matrix: Dict[str, Any] = {"summary": {"roles_available": 0}}
        self.authentication_review: Dict[str, Any] = {"summary": {"auth_queries": 0, "auth_mutations": 0}}
        self.active_security_validation: Dict[str, Any] = {"summary": {"checks_sent": 0}}
        self.sensitive_field_review: Dict[str, Any] = {"summary": {"reported_sensitive_fields": 0}}
        self.points_of_interest: Dict[str, Any] = {
            "summary": {
                "sensitive_fields": 0,
                "risky_mutations": 0,
                "id_arguments": 0,
                "auth_critical_paths": 0,
            }
        }
        self.fingerprint: Dict[str, Any] = {}
        self.relationship_map: Dict[str, Any] = {"summary": {"sensitive_fields_mapped": 0}}
        self._pending_sensitive_rule_candidates: List[Finding] = []

    def run(self) -> Dict[str, Any]:
        started = time.time()

        # These early phases identify the target and check what GraphQL features are exposed.
        self._run_phase("Fingerprint", 0.08, self._fingerprint)
        self._run_phase("Asset Recon", 0.14, self._asset_recon)
        self._run_phase("Configuration", 0.18, self._configuration)
        self._run_phase("Introspection Bypass", 0.24, self._introspection_bypass)
        self._run_phase("Schema Acquisition", 0.30, self._schema_acquisition)

        if self.schema_data:
            # Schema-based phases need GraphQL types, fields, arguments, and operation paths.
            self._run_phase("Schema Audit", 0.42, self._schema_audit)
            self._run_phase("Dependency Graph", 0.52, self._dependency_graph)
            self._run_phase("Path Enumeration", 0.62, self._path_enumeration)
            self._run_phase("Operation Packs", 0.68, self._operation_packs)
            self._run_phase("Points of Interest", 0.72, self._points_of_interest)
            self._run_phase("Request Forgery", 0.76, self._request_forgery)
            self._run_phase("Subscription Security", 0.79, self._subscription_security)
            self._run_phase("Authentication", 0.83, self._authentication)
            self._run_phase("ML Analysis", 0.86, self._ml_analysis)
            self._run_phase("Authorization", 0.9, self._authorization)
            self._run_phase("Injection", 0.94, self._injection)
            self._run_phase(
                "Active Security Validation",
                0.95,
                self._active_security,
            )
        else:
            # When schema recovery fails, keep only checks that can run from endpoint evidence.
            self._skip_phase("Schema Audit", "No schema was available.")
            self._skip_phase("Dependency Graph", "No schema was available.")
            self._skip_phase("Path Enumeration", "No schema was available.")
            self._skip_phase("Operation Packs", "No schema was available.")
            self._skip_phase("Points of Interest", "No schema was available.")
            self._run_phase("Request Forgery", 0.76, self._request_forgery)
            self._run_phase("Subscription Security", 0.79, self._subscription_security)
            self._skip_phase("Authentication", "No schema was available.")
            self._skip_phase("ML Analysis", "No schema was available.")
            self._skip_phase("Authorization", "No schema was available.")
            self._skip_phase("Injection", "No schema was available.")
            self._skip_phase(
                "Active Security Validation",
                "No schema was available.",
            )

        # DoS and LLM validation run near the end after other findings are available.
        self._run_phase("Denial of Service", 0.96, self._dos)
        self._run_phase("LLM Validation", 0.99, self._llm_validation)
        enrich_findings(self.findings)

        duration = round(time.time() - started, 2)
        # Build graph links for schema map and connected finding views.
        self.relationship_map = build_relationship_map_from_parts(
            sensitive_field_review=self.sensitive_field_review,
            points_of_interest=self.points_of_interest,
            path_report=self.path_report,
            operation_pack=self.operation_pack,
            authorization_matrix=self.authorization_matrix,
        )
        if self.progress_callback:
            self.progress_callback("Completed", 1.0, "Scan complete")

        return {
            "summary": self._summary(),
            "findings": [finding.to_dict() for finding in self.findings],
            "workflow": [phase.to_dict() for phase in self.workflow],
            "schema": {
                "available": bool(self.schema_data),
                "source": self.schema_summary.get("_source"),
                "summary": self.schema_summary,
                "graph": extract_schema_structure(self.schema_data),
                "overview": build_schema_overview(
                    self.schema_data,
                    endpoint=self.endpoint,
                    source=self.schema_summary.get("_source"),
                    verified_graphql=self.fingerprint.get("verified_graphql"),
                    fingerprint=self.fingerprint,
                    path_report=self.path_report,
                    operation_pack=self.operation_pack,
                    dependency_graph=self.dependency_graph,
                ) if self.schema_data else {},
            },
            "paths": self.path_report,
            "operation_pack": self.operation_pack,
            "asset_recon": self.asset_recon,
            "introspection_bypass": self.introspection_bypass,
            "request_forgery": self.request_forgery,
            "subscription_security": self.subscription_security,
            "authentication_review": self.authentication_review,
            "active_security_validation": self.active_security_validation,
            "authorization_matrix": self.authorization_matrix,
            "sensitive_field_review": self.sensitive_field_review,
            "relationship_map": self.relationship_map,
            "points_of_interest": self.points_of_interest,
            "dependency_graph": self.dependency_graph,
            "fingerprint": self.fingerprint,
            "metadata": {
                "endpoint": self.endpoint,
                "profile": self.profile,
                "risk_level": self.risk_level,
                "technique": self.technique,
                "duration_seconds": duration,
            },
        }

    def _run_phase(self, name: str, progress: float, fn: Callable[[], Dict[str, Any]]) -> None:
        phase = ScanPhase(name=name)
        phase.start()
        self.workflow.append(phase)
        if self.progress_callback:
            self.progress_callback(name, progress, "running")
        try:
            summary = fn()
            phase.complete(summary)
        except Exception as exc:
            phase.fail(exc)
        if self.progress_callback:
            self.progress_callback(name, progress, phase.status)

    def _skip_phase(self, name: str, reason: str) -> None:
        phase = ScanPhase(name=name)
        phase.skip(reason)
        self.workflow.append(phase)

    def _fingerprint(self) -> Dict[str, Any]:
        fingerprinter = GraphQLFingerprinter(
            self.endpoint,
            headers=self.config.get("headers") or None,
            proxy=self.config.get("proxy"),
        )
        verified = fingerprinter.verify_graphql()
        result = fingerprinter.run() if verified else None
        self.fingerprint = asdict(result) if result else {"detected": False}
        self.fingerprint["verified_graphql"] = verified
        return {
            "verified_graphql": verified,
            "engine": self.fingerprint.get("engine_name") or "Unknown",
        }

    def _configuration(self) -> Dict[str, Any]:
        config = {
            **self.config,
        }
        findings = ConfigChecker(self.endpoint, config=config).run()
        self.findings.extend(findings)
        return self._phase_finding_summary(findings)

    def _asset_recon(self) -> Dict[str, Any]:
        scanner = AssetReconScanner(self.endpoint, config=self.config)
        findings = scanner.run()
        self.asset_recon = scanner.report
        self.findings.extend(findings)
        return self.asset_recon.get("summary", {})

    def _introspection_bypass(self) -> Dict[str, Any]:
        scanner = IntrospectionBypassScanner(self.endpoint, config=self.config)
        findings = scanner.run()
        self.introspection_bypass = scanner.report
        self.findings.extend(findings)
        return self.introspection_bypass.get("summary", {})

    def _schema_acquisition(self) -> Dict[str, Any]:
        source = "introspection"
        try:
            self.schema_data = fetch_introspection(self.endpoint)
        except Exception:
            source = "blind"
            blind = BlindIntrospector(
                self.endpoint,
                headers=self.config.get("headers") or None,
                proxy=self.config.get("proxy"),
            )
            self.schema_data = blind.run()

        normalized = normalize_schema(self.schema_data)
        self.schema_summary = parse_schema_details(normalized)
        self.schema_summary["_source"] = source
        return {
            "source": source,
            "types": len(self.schema_summary.get("types", [])),
            "queries": len(self.schema_summary.get("queries", [])),
            "mutations": len(self.schema_summary.get("mutations", [])),
            "subscriptions": len(self.schema_summary.get("subscriptions", [])),
        }

    def _schema_audit(self) -> Dict[str, Any]:
        findings = SchemaAuditor(self.endpoint, self.schema_data, self.config).run()
        non_sensitive_findings, candidate_findings = split_sensitive_candidates(findings)
        self.findings.extend(non_sensitive_findings)

        if self.enable_ml:
            self._pending_sensitive_rule_candidates = candidate_findings
            raw_report = {
                "summary": {
                    "raw_rule_candidates": len(candidate_findings),
                    "reported_sensitive_fields": 0,
                }
            }
            self.sensitive_field_review = raw_report
            return {
                **self._phase_finding_summary(non_sensitive_findings),
                "raw_sensitive_candidates": len(candidate_findings),
            }

        reviewed_findings, review_report = review_sensitive_candidates(candidate_findings, [])
        self.findings.extend(reviewed_findings)
        self.sensitive_field_review = review_report
        phase_findings = non_sensitive_findings + reviewed_findings
        return {
            **self._phase_finding_summary(phase_findings),
            **review_report.get("summary", {}),
        }

    def _dependency_graph(self) -> Dict[str, Any]:
        builder = DependencyGraphBuilder(self.schema_data)
        graph = builder.build()
        self.dependency_graph = builder.export_dict()
        return {
            "nodes": graph.number_of_nodes(),
            "edges": graph.number_of_edges(),
            "creators": len(self.dependency_graph["analysis"]["creators"]),
            "accessors": len(self.dependency_graph["analysis"]["accessors"]),
        }

    def _path_enumeration(self) -> Dict[str, Any]:
        self.path_report = GraphQLPathEnumerator(
            self.schema_data,
            max_depth=6,
            include_mutations=True,
            all_types=False,
        ).enumerate()
        return self.path_report.get("summary", {})

    def _operation_packs(self) -> Dict[str, Any]:
        self.operation_pack = OperationPackGenerator(self.schema_data).generate()
        return self.operation_pack.get("summary", {})

    def _points_of_interest(self) -> Dict[str, Any]:
        self.points_of_interest = build_points_of_interest(
            self.schema_data,
            self.operation_pack,
            self.path_report,
            self.dependency_graph,
        )
        return self.points_of_interest.get("summary", {})

    def _request_forgery(self) -> Dict[str, Any]:
        if "C" not in self.technique:
            self.request_forgery = {"summary": {"skipped": "Technique excludes configuration checks."}}
            return self.request_forgery["summary"]

        scanner = RequestForgeryScanner(
            self.endpoint,
            config=self.config,
            operation_pack=self.operation_pack,
            profile=self.profile,
        )
        findings = scanner.run()
        self.request_forgery = scanner.report
        self.findings.extend(findings)
        return self.request_forgery.get("summary", {})

    def _subscription_security(self) -> Dict[str, Any]:
        scanner = SubscriptionSecurityScanner(
            self.endpoint,
            schema=self.schema_data or {},
            config=self.config,
            asset_recon=self.asset_recon,
        )
        findings = scanner.run()
        self.subscription_security = scanner.report
        self.findings.extend(findings)
        return self.subscription_security.get("summary", {})

    def _authentication(self) -> Dict[str, Any]:
        scanner = AuthenticationScanner(
            self.endpoint,
            schema=self.schema_data or {},
            config=self.config,
            operation_pack=self.operation_pack,
        )
        findings = scanner.run()
        self.authentication_review = scanner.report
        self.findings.extend(findings)
        return self.authentication_review.get("summary", {})

    def _authorization(self) -> Dict[str, Any]:
        if "A" not in self.technique:
            return {"skipped": "Technique excludes authorization checks."}
        if self.profile == PROFILE_PASSIVE:
            return {"skipped": "Passive profile does not send state-changing auth probes."}
        if not self.dependency_graph:
            return {"skipped": "Dependency graph was unavailable."}
        if not self.config.get("user_a") or not self.config.get("user_b"):
            return {"skipped": "user_a and user_b credentials are required."}

        tester = AuthTester(
            self.endpoint,
            self.config,
            self.schema_data,
            self.dependency_graph,
            path_report=self.path_report,
            operation_pack=self.operation_pack,
            asset_recon=self.asset_recon,
        )
        results = tester.run()
        self.authorization_matrix = tester.matrix_report
        findings = ResultConverter.convert_auth_results(results, matrix_report=self.authorization_matrix)
        self.findings.extend(findings)
        return {
            "tests": len(results),
            "vulnerable": sum(1 for item in results if item.get("idor_detected")),
            "anonymous_exposures": sum(1 for item in results if item.get("anonymous_detected")),
            "mutation_vulnerabilities": self.authorization_matrix.get("summary", {}).get("mutation_vulnerabilities", 0),
            "subscription_vulnerabilities": self.authorization_matrix.get("summary", {}).get("subscription_vulnerabilities", 0),
            "path_guided_tests": sum(1 for item in results if item.get("paths")),
        }

    def _ml_analysis(self) -> Dict[str, Any]:
        if not self.enable_ml:
            return {"skipped": "ML analysis disabled."}

        from src.scanner.ml_analyzer import MLSemanticAnalyzer

        # Merge ML candidates with rule candidates before reporting sensitive fields.
        findings = MLSemanticAnalyzer(self.endpoint, self.schema_data, config=self.config).run()
        reviewed_findings, review_report = review_sensitive_candidates(
            self._pending_sensitive_rule_candidates,
            findings,
        )
        self.findings.extend(reviewed_findings)
        self.sensitive_field_review = review_report
        self._pending_sensitive_rule_candidates = []
        return {
            "raw_ml_candidates": len(findings),
            **review_report.get("summary", {}),
        }

    def _injection(self) -> Dict[str, Any]:
        if "I" not in self.technique:
            return {"skipped": "Technique excludes injection checks."}
        if self.profile == PROFILE_PASSIVE:
            return {"skipped": "Passive profile does not send injection payloads."}

        findings = PayloadInjector(
            self.endpoint,
            self.schema_data,
            self.config,
            graph=self.dependency_graph,
        ).run()
        self.findings.extend(findings)
        return self._phase_finding_summary(findings)

    def _active_security(self) -> Dict[str, Any]:
        if self.profile == PROFILE_PASSIVE:
            return {"skipped": "Passive profile does not send active validation probes."}

        scanner = ActiveSecurityScanner(
            self.endpoint,
            schema=self.schema_data or {},
            config=self.config,
            profile=self.profile,
            technique=self.technique,
        )
        findings = scanner.run()
        self.active_security_validation = scanner.report
        self.findings.extend(findings)
        return {
            **scanner.report.get("summary", {}),
            **self._phase_finding_summary(findings),
        }

    def _dos(self) -> Dict[str, Any]:
        if "D" not in self.technique:
            return {"skipped": "Technique excludes DoS checks."}
        if self.profile == PROFILE_PASSIVE:
            return {"skipped": "Passive profile does not send DoS probes."}

        findings = DoSScanner(
            self.endpoint,
            schema=self.schema_data or {},
            config=self.config,
            operation_pack=self.operation_pack,
        ).run(profile=self.profile)
        self.findings.extend(findings)
        return self._phase_finding_summary(findings)

    def _llm_validation(self) -> Dict[str, Any]:
        if not self.enable_llm:
            return {"skipped": "LLM validation disabled."}
        if not self.findings:
            return {"skipped": "No findings to validate."}

        from src.scanner.llm_validator import LLMValidator

        validator = LLMValidator(provider=self.llm_provider, model_name=self.llm_model)
        validation_results = validator.batch_validate_findings(
            self.findings,
            self.schema_data if self.schema_data else {},
        )
        kept = []
        filtered = 0
        filtered_findings = []
        for item in validation_results:
            finding = item["finding"]
            validation = item["validation"]
            finding.ai_validation = validation
            # Filter only high-confidence false positives; weak AI decisions stay for review.
            if validation.get("is_false_positive", False) and validation.get("confidence", 0) >= 0.65:
                filtered += 1
                filtered_findings.append(
                    {
                        "title": finding.title,
                        "field": finding.field,
                        "decision": validation.get("decision"),
                        "confidence": validation.get("confidence"),
                        "reason": validation.get("reason") or validation.get("reasoning"),
                        "manual_check": validation.get("manual_check"),
                    }
                )
            else:
                kept.append(finding)
        self.findings = kept
        return {"kept": len(kept), "filtered": filtered, "filtered_findings": filtered_findings[:20]}

    def _summary(self) -> Dict[str, Any]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        categories: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
            categories[finding.category] = categories.get(finding.category, 0) + 1
        return {
            "total": len(self.findings),
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "info": counts["INFO"],
            "category_counts": categories,
        }

    def _phase_finding_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return {"findings": len(findings), "severity": counts}

    def _load_default_config(self) -> Dict[str, Any]:
        config_path = Path("users.yaml")
        if not config_path.exists():
            return {}
        with config_path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}

    def _profile_from_risk(self, risk_level: int) -> str:
        if risk_level <= 0:
            return PROFILE_PASSIVE
        if risk_level >= 2:
            return PROFILE_AGGRESSIVE
        return PROFILE_DEFAULT
