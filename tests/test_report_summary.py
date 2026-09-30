from src.reporters.models import Finding
from src.reporters.summary import build_evidence_summary, build_remediation_summary, sort_findings_for_report


def test_report_summary_sorts_by_severity_and_state():
    findings = [
        Finding(title="Low", description="low", severity="LOW", category="CONFIG"),
        Finding(title="High possible", description="high", severity="HIGH", category="AUTH"),
        Finding(title="High confirmed", description="high", severity="HIGH", category="AUTH", state="confirmed"),
    ]

    ordered = sort_findings_for_report(findings)

    assert [finding.title for finding in ordered] == ["High confirmed", "High possible", "Low"]


def test_remediation_summary_groups_repeated_fixes_by_priority():
    findings = [
        Finding(
            title="Anon query",
            description="auth",
            severity="HIGH",
            category="AUTH",
            remediation="Enforce resolver authorization.",
        ),
        Finding(
            title="Anon mutation",
            description="auth",
            severity="MEDIUM",
            category="AUTH",
            remediation="Enforce resolver authorization.",
        ),
        Finding(
            title="Field suggestion",
            description="recon",
            severity="LOW",
            category="RECON",
            remediation="Disable production hints.",
        ),
    ]

    summary = build_remediation_summary(findings)

    assert summary[0]["remediation"] == "Enforce resolver authorization."
    assert summary[0]["count"] == 2
    assert summary[0]["highest_severity"] == "HIGH"
    assert summary[0]["categories"] == ["AUTH"]


def test_evidence_summary_counts_replayable_and_request_response_findings():
    findings = [
        Finding(
            title="Replayable",
            description="proof",
            severity="HIGH",
            category="AUTH",
            evidence={"request": {"method": "POST"}, "response": {"status_code": 200}},
            reproduction="curl http://example.test/graphql",
            ai_validation={"decision": "valid"},
        ),
        Finding(
            title="Context",
            description="schema",
            severity="LOW",
            category="RECON",
            evidence={"details": {"field": "User.email"}},
        ),
    ]

    summary = build_evidence_summary(findings)

    assert summary["levels"]["replayable"] == 1
    assert summary["levels"]["context_only"] == 1
    assert summary["request_response_findings"] == 1
    assert summary["replayable_findings"] == 1
    assert summary["ai_reviewed_findings"] == 1
