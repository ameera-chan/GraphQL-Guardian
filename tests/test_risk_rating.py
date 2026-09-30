from src.risk.rating import rate_finding, severity_from_matrix


def test_risk_matrix_matches_calculator_outcomes():
    assert severity_from_matrix("HIGH", "HIGH") == "CRITICAL"
    assert severity_from_matrix("HIGH", "MEDIUM") == "HIGH"
    assert severity_from_matrix("MEDIUM", "MEDIUM") == "MEDIUM"
    assert severity_from_matrix("MEDIUM", "LOW") == "LOW"
    assert severity_from_matrix("LOW", "LOW") == "INFO"


def test_auth_high_defaults_to_critical_rating():
    risk = rate_finding(category="AUTH", severity="HIGH")

    assert risk["severity"] == "CRITICAL"
    assert risk["likelihood_level"] == "HIGH"
    assert risk["impact_level"] == "HIGH"
    assert risk["vector"].startswith("(")
