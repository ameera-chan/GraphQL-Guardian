import pytest

from src.scanner.ml_analyzer import MLSemanticAnalyzer, RANDOM_FOREST_AVAILABLE


def _type_ref(name):
    return {"kind": "SCALAR", "name": name, "ofType": None}


def _schema(type_name, fields):
    return {
        "__schema": {
            "queryType": {"name": type_name},
            "types": [
                {
                    "kind": "OBJECT",
                    "name": type_name,
                    "fields": [
                        {"name": name, "type": _type_ref(field_type), "args": []}
                        for name, field_type in fields
                    ],
                },
                {"kind": "SCALAR", "name": "String", "fields": None},
                {"kind": "SCALAR", "name": "ID", "fields": None},
                {"kind": "SCALAR", "name": "Int", "fields": None},
                {"kind": "SCALAR", "name": "Boolean", "fields": None},
            ],
        }
    }


@pytest.mark.skipif(not RANDOM_FOREST_AVAILABLE, reason="scikit-learn is required")
def test_random_forest_flags_token_fields():
    analyzer = MLSemanticAnalyzer(
        "http://target/graphql",
        _schema("Login", [("accessToken", "String"), ("refreshToken", "String")]),
    )

    findings = analyzer.run()
    locations = {finding.evidence["location"] for finding in findings}

    assert locations == {"Login.accessToken", "Login.refreshToken"}
    assert all(finding.evidence["ml_model"] == "random_forest_sensitive_field_classifier" for finding in findings)
    assert all(finding.evidence["ml_components"]["random_forest"] >= 0.7 for finding in findings)


@pytest.mark.skipif(not RANDOM_FOREST_AVAILABLE, reason="scikit-learn is required")
def test_random_forest_reduces_config_policy_false_positive():
    analyzer = MLSemanticAnalyzer(
        "http://target/graphql",
        _schema(
            "Config",
            [
                ("id", "ID"),
                ("status", "String"),
                ("tokenCount", "Int"),
                ("passwordPolicy", "String"),
            ],
        ),
    )

    findings = analyzer.run()

    assert findings == []


@pytest.mark.skipif(not RANDOM_FOREST_AVAILABLE, reason="scikit-learn is required")
def test_random_forest_handles_compound_sensitive_names_without_broad_substring_false_positive():
    analyzer = MLSemanticAnalyzer(
        "http://target/graphql",
        _schema(
            "Payment",
            [
                ("creditCardNumber", "String"),
                ("privateKey", "String"),
                ("monkeyType", "String"),
                ("publicKeyId", "ID"),
            ],
        ),
    )

    findings = analyzer.run()
    locations = {finding.evidence["location"] for finding in findings}

    assert "Payment.creditCardNumber" in locations
    assert "Payment.privateKey" in locations
    assert "Payment.monkeyType" not in locations
    assert "Payment.publicKeyId" not in locations
