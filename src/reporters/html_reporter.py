from datetime import datetime
import json
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, List, Dict
from jinja2 import Environment, FileSystemLoader, select_autoescape
from .models import Finding, normalize_state
from .summary import (
    build_evidence_summary,
    build_remediation_summary,
    evidence_level,
    sort_findings_for_report,
)
from src.utils.files import write_text

class HTMLReporter:
    def __init__(self, output_path: str = "report.html"):
        self.output_path = output_path
        self.template_dir = Path(__file__).parent / 'templates'
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self.env.filters['pretty_json'] = self._pretty_json
        self.env.filters['short_json'] = self._short_json

    def generate(self, findings: List[Finding], report_context=None):
        """
        Generates an HTML report from the list of findings.
        """
        template = self.env.get_template('report.html')
        findings = sort_findings_for_report(findings)
        
        summary = self._calculate_summary(findings)
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        context = report_context if isinstance(report_context, dict) else {}
        target_profile = context.get("target_profile", {})
        fingerprint = target_profile.get("fingerprint", {}) if isinstance(target_profile, dict) else {}
        finding_views = [
            {
                "finding": finding,
                "item": finding.to_dict(),
                "evidence": self._evidence_view(finding.evidence),
                "evidence_level": evidence_level(finding),
            }
            for finding in findings
        ]
        
        html_content = template.render(
            findings=findings,
            finding_views=finding_views,
            summary=summary,
            scan_date=scan_date,
            report_context=context,
            metadata=context.get("metadata", {}),
            fingerprint=fingerprint,
            llm_validation=context.get("llm_validation", {}),
            remediation_summary=build_remediation_summary(findings),
            evidence_summary=build_evidence_summary(findings),
        )
        
        write_text(self.output_path, html_content)
        if self.output_path != "-":
            print(f"HTML report generated at: {self.output_path}", file=sys.stderr)

    def _calculate_summary(self, findings: List[Finding]) -> Dict[str, int]:
        summary = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "confirmed": 0,
            "possible": 0,
            "informational": 0,
        }
        
        for f in findings:
            sev = f.severity.lower()
            if sev == "informational":
                sev = "info"
            if sev in summary:
                summary[sev] += 1
            else:
                # Fallback for unknown severities
                summary["info"] += 1
            status = normalize_state(f.state, f.severity)
            summary[status] = summary.get(status, 0) + 1
                
        return summary

    @staticmethod
    def _pretty_json(value) -> str:
        if isinstance(value, str):
            return value
        if is_dataclass(value):
            value = asdict(value)
        return json.dumps(value, indent=2, default=str)

    @classmethod
    def _short_json(cls, value, limit: int = 1600) -> str:
        text = cls._pretty_json(cls._compact_value(value))
        if len(text) <= limit:
            return text
        return text[:limit] + "\n...<truncated>"

    @classmethod
    def _evidence_view(cls, evidence: Any) -> Dict[str, Any]:
        data = cls._to_plain(evidence)
        if not data:
            return {"details": None, "request": None, "response": None, "artifacts": [], "raw": None}

        if isinstance(data, dict) and any(key in data for key in ("details", "request", "response", "artifacts")):
            details = cls._clean_details(data.get("details"))
            return {
                "details": details,
                "request": cls._compact_value(data.get("request")),
                "response": cls._compact_response(data.get("response")),
                "artifacts": data.get("artifacts") or [],
                "raw": None,
            }

        return {
            "details": cls._clean_details(data),
            "request": None,
            "response": None,
            "artifacts": [],
            "raw": None,
        }

    @classmethod
    def _to_plain(cls, value: Any) -> Any:
        if is_dataclass(value):
            return asdict(value)
        if isinstance(value, dict):
            return {key: cls._to_plain(nested) for key, nested in value.items()}
        if isinstance(value, list):
            return [cls._to_plain(item) for item in value]
        return value

    @classmethod
    def _clean_details(cls, value: Any) -> Any:
        cleaned = cls._to_plain(value)
        if isinstance(cleaned, dict):
            for key in (
                "why_it_matters",
                "verification_guidance",
                "verification_status",
                "verification_reason",
            ):
                cleaned.pop(key, None)
            if not cleaned:
                return None
        return cls._compact_value(cleaned)

    @classmethod
    def _compact_response(cls, value: Any) -> Any:
        response = cls._compact_value(cls._to_plain(value))
        if isinstance(response, dict) and isinstance(response.get("body_sample"), str):
            body = response["body_sample"].strip()
            response["body_sample"] = body if len(body) <= 1200 else body[:1200] + "...<truncated>"
        return response

    @classmethod
    def _compact_value(cls, value: Any, *, max_items: int = 8) -> Any:
        value = cls._to_plain(value)
        if isinstance(value, dict):
            return {key: cls._compact_value(nested, max_items=max_items) for key, nested in value.items()}
        if isinstance(value, list):
            compacted = [cls._compact_value(item, max_items=max_items) for item in value[:max_items]]
            if len(value) > max_items:
                compacted.append({"omitted": len(value) - max_items})
            return compacted
        if isinstance(value, str) and len(value) > 1200:
            return value[:1200] + "...<truncated>"
        return value
