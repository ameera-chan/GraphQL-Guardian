import csv
import sys
from typing import List
from .models import Finding, normalize_state
from .summary import evidence_level, sort_findings_for_report
from src.utils.files import ensure_parent_dir, is_stdout_path

class CSVReporter:
    @staticmethod
    def generate(findings: List[Finding], output_path: str):
        findings = sort_findings_for_report(findings)
        fieldnames = [
            'timestamp', 'severity', 'category', 'rule_id', 'confidence', 'state', 'verification_status',
            'evidence_level', 'title', 'endpoint', 'operation_name', 'field', 'description',
            'reproduction', 'evidence', 'remediation'
        ]
        
        stream = sys.__stdout__ if is_stdout_path(output_path) else ensure_parent_dir(output_path).open('w', newline='', encoding='utf-8')
        try:
            writer = csv.DictWriter(stream, fieldnames=fieldnames)
            writer.writeheader()
            
            for finding in findings:
                d = finding.to_dict()
                d['verification_status'] = normalize_state(finding.state, finding.severity)
                d['evidence_level'] = evidence_level(finding)
                # Filter to only include fields we want in CSV
                row = {k: d.get(k, '') for k in fieldnames}
                writer.writerow(row)
            stream.flush()
        finally:
            if stream is not sys.__stdout__:
                stream.close()
