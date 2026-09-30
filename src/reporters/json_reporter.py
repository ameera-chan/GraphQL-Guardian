from typing import List
from .models import Finding, normalize_state
from .summary import build_evidence_summary, build_remediation_summary, sort_findings_for_report
from src.utils.files import write_json

class JSONReporter:
    @staticmethod
    def generate(findings: List[Finding], output_path: str, report_context=None):
        findings = sort_findings_for_report(findings)
        status_counts = {"confirmed": 0, "possible": 0, "informational": 0}
        for finding in findings:
            status = normalize_state(finding.state, finding.severity)
            status_counts[status] = status_counts.get(status, 0) + 1

        data = {
            "summary": {
                "total": len(findings),
                "critical": len([f for f in findings if f.severity == "CRITICAL"]),
                "high": len([f for f in findings if f.severity == "HIGH"]),
                "medium": len([f for f in findings if f.severity == "MEDIUM"]),
                "low": len([f for f in findings if f.severity == "LOW"]),
                "info": len([f for f in findings if f.severity == "INFO"]),
                "confirmed": status_counts.get("confirmed", 0),
                "possible": status_counts.get("possible", 0),
                "informational": status_counts.get("informational", 0),
            },
            "remediation_summary": build_remediation_summary(findings),
            "evidence_summary": build_evidence_summary(findings),
            "findings": [f.to_dict() for f in findings]
        }

        if isinstance(report_context, dict):
            for key, value in report_context.items():
                if key in {"summary", "findings"}:
                    continue
                data[key] = value
        
        write_json(output_path, data)
