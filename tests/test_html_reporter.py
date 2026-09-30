import os
import pytest
from src.reporters.models import Finding
from src.reporters.html_reporter import HTMLReporter

def test_html_reporter_generation(tmp_path):
    # Create dummy findings
    findings = [
        Finding(
            title="Test High Vulnerability",
            category="Injection",
            severity="HIGH",
            description="This is a test high severity finding.",
            remediation="Fix it immediately.",
            endpoint="http://localhost/graphql",
            operation_name="testOp",
            field="testField",
            evidence="payload"
        ),
        Finding(
            title="Test Low Vulnerability",
            category="Config",
            severity="LOW",
            description="This is a test low severity finding.",
            remediation="Fix it later."
        )
    ]
    
    output_file = tmp_path / "test_report.html"
    reporter = HTMLReporter(str(output_file))
    reporter.generate(
        findings,
        report_context={
            "metadata": {"endpoint": "http://localhost/graphql", "profile": "passive"},
            "target_profile": {"fingerprint": {"engine_name": "Graphene", "technologies": ["Python"]}},
        },
    )
    
    assert output_file.exists()
    
    content = output_file.read_text(encoding='utf-8')
    
    # Check for title
    assert "GraphQL Guardian Security Assessment Report" in content
    
    # Check for findings
    assert "Test High Vulnerability" in content
    assert "Test Low Vulnerability" in content
    assert "Evidence Summary" in content
    assert "Remediation Summary" in content
    assert "Fix it immediately." in content
    assert "Evidence Level" in content
    
    # Check for severity counts
    # We expect 1 High and 1 Low. Total 2.
    assert '<span class="value high">1</span>' in content
    assert '<span class="value low">1</span>' in content
    assert "http://localhost/graphql" in content
    assert "Graphene" in content

def test_html_reporter_empty(tmp_path):
    findings = []
    output_file = tmp_path / "test_empty_report.html"
    reporter = HTMLReporter(str(output_file))
    reporter.generate(findings)
    
    assert output_file.exists()
    content = output_file.read_text(encoding='utf-8')
    
    assert "Detailed Findings" in content
    assert '<span class="value high">0</span>' in content
    assert "No findings were reported." in content
