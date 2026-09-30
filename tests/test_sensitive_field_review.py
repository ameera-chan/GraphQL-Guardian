from src.reporters.models import Finding
from src.scanner.sensitive_field_review import (
    review_sensitive_candidates,
    split_sensitive_candidates,
)


def test_sensitive_field_review_merges_rule_and_ml_candidates():
    rule_candidate = Finding(
        title="Sensitive Field Exposed: User.passwordHash",
        description="Rule-based keyword match.",
        severity="HIGH",
        category="AUDIT",
        field="User.passwordHash",
        evidence={
            "candidate_source": "rule",
            "candidate_kind": "sensitive_field",
            "location": "User.passwordHash",
            "matched_keywords": ["password", "hash"],
            "field_type": "String",
        },
    )
    ml_candidate = Finding(
        title="ML-Detected Sensitive Field: User.passwordHash",
        description="ML semantic score indicates sensitivity.",
        severity="MEDIUM",
        category="AUDIT",
        field="User.passwordHash",
        evidence={
            "candidate_source": "ml",
            "candidate_kind": "ml_sensitive_field",
            "location": "User.passwordHash",
            "matched_keywords": ["password"],
            "field_type": "String",
            "ml_score": 0.84,
            "ml_components": {"embedding": 0.82, "final": 0.84},
        },
    )

    findings, report = review_sensitive_candidates([rule_candidate], [ml_candidate])

    assert len(findings) == 1
    assert findings[0].title == "Reviewed Sensitive Field: User.passwordHash"
    assert findings[0].severity == "HIGH"
    assert findings[0].confidence == "high"
    assert report["summary"]["raw_rule_candidates"] == 1
    assert report["summary"]["raw_ml_candidates"] == 1
    assert report["summary"]["corroborated_candidates"] == 1
    assert report["summary"]["likely_true"] == 1
    assert report["summary"]["reported_sensitive_fields"] == 1


def test_sensitive_field_review_filters_weak_identifier_like_match():
    weak_rule_candidate = Finding(
        title="PII Field Detected: User.emailId",
        description="Weak PII naming match.",
        severity="MEDIUM",
        category="AUDIT",
        field="User.emailId",
        evidence={
            "candidate_source": "rule",
            "candidate_kind": "pii_field",
            "location": "User.emailId",
            "matched_keywords": ["email"],
            "field_type": "ID",
        },
    )

    findings, report = review_sensitive_candidates([weak_rule_candidate], [])

    assert findings == []
    assert report["summary"]["reported_sensitive_fields"] == 0
    assert report["summary"]["filtered_candidates"] == 1
    assert report["filtered"][0]["location"] == "User.emailId"


def test_split_sensitive_candidates_preserves_non_sensitive_audit_findings():
    structural_finding = Finding(
        title="Bidirectional Type Relationships Detected",
        description="Structural DoS risk.",
        severity="MEDIUM",
        category="AUDIT",
        evidence={"pairs": [["User", "Post"]]},
    )
    sensitive_candidate = Finding(
        title="Sensitive Field Exposed: User.refreshToken",
        description="Rule-based keyword match.",
        severity="HIGH",
        category="AUDIT",
        field="User.refreshToken",
        evidence={
            "candidate_source": "rule",
            "candidate_kind": "sensitive_field",
            "location": "User.refreshToken",
            "matched_keywords": ["refresh_token", "token"],
            "field_type": "String",
        },
    )

    other_findings, candidates = split_sensitive_candidates([structural_finding, sensitive_candidate])

    assert other_findings == [structural_finding]
    assert candidates == [sensitive_candidate]
