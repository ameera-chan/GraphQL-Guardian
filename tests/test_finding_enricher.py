from src.reporters.finding_enricher import enrich_findings
from src.reporters.models import Finding


def test_finding_enricher_adds_why_verify_and_default_remediation():
    finding = Finding(
        title="Anonymous Current-User Query Accessible",
        description="Anonymous access returned current-user data.",
        severity="HIGH",
        category="AUTH",
        evidence={"request": {"method": "POST"}, "response": {"status_code": 200}},
        remediation=None,
    )

    enrich_findings([finding])

    assert finding.risk["method"] == "OWASP Risk Rating Methodology"
    assert finding.severity == finding.risk["severity"]
    assert finding.remediation is not None
    assert finding.evidence["details"]["why_it_matters"]
    assert len(finding.evidence["details"]["verification_guidance"]) >= 2
    assert finding.state == "confirmed"
    assert finding.evidence["details"]["verification_status"] == "confirmed"
    assert finding.evidence["details"]["verification_reason"]


def test_finding_enricher_normalizes_plain_string_evidence():
    finding = Finding(
        title="GraphQL WebSocket Endpoint Active",
        description="A WebSocket endpoint was identified.",
        severity="INFO",
        category="RECON",
        evidence="ws://localhost/graphql",
    )

    enrich_findings([finding])

    assert isinstance(finding.evidence, dict)
    assert finding.evidence["details"]["raw"] == "ws://localhost/graphql"
    assert finding.evidence["details"]["why_it_matters"]
    assert finding.state == "informational"


def test_finding_enricher_marks_reflected_payload_as_possible():
    finding = Finding(
        title="Reflected Payload in createPaste",
        description="Payload was reflected in the response.",
        severity="MEDIUM",
        category="INJECTION",
        confidence="high",
        state="confirmed",
        evidence={
            "request": {"method": "POST"},
            "response": {"status_code": 200},
        },
    )

    enrich_findings([finding])

    assert finding.state == "possible"
    assert "manual proof" in finding.evidence["details"]["verification_reason"]


def test_finding_enricher_marks_sql_error_with_response_as_confirmed():
    finding = Finding(
        title="SQL Injection Error in pastes",
        description="Database error appeared after payload injection.",
        severity="HIGH",
        category="INJECTION",
        confidence="high",
        evidence={
            "request": {"method": "POST"},
            "response": {"status_code": 200, "body_sample": "SQL syntax error"},
        },
    )

    enrich_findings([finding])

    assert finding.state == "confirmed"
