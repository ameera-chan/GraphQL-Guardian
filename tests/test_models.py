from src.reporters.models import Finding, normalize_state
from src.utils.evidence import build_curl_command


def test_finding_generates_unique_runtime_defaults():
    first = Finding(title="One", description="First", severity="INFO", category="TEST")
    second = Finding(title="Two", description="Second", severity="INFO", category="TEST")

    assert first.id != second.id
    assert first.timestamp <= second.timestamp


def test_finding_normalizes_verification_status():
    finding = Finding(title="One", description="First", severity="HIGH", category="TEST", state="probable")

    assert normalize_state("probable", "HIGH") == "possible"
    assert finding.to_dict()["verification_status"] == "possible"


def test_curl_command_redacts_sensitive_headers_and_body():
    command = build_curl_command(
        "POST",
        "http://localhost/graphql",
        {"Authorization": "Bearer secret", "Content-Type": "application/json"},
        {"query": "query { me { id } }", "variables": {"password": "secret"}},
    )

    assert "Bearer secret" not in command
    assert '\\"password\\":\\"<redacted>\\"' in command
    assert "-X POST" in command
