"""Sensitive-field review and false-positive reduction helpers.

This module turns raw rule-based and ML-based sensitive-field candidates into a
cleaner, proposal-aligned result set:
1. likely true sensitive findings
2. weaker reviewed candidates
3. filtered-out noise
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from src.config import CATEGORY_AUDIT, SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_MEDIUM
from src.reporters.models import Finding


SENSITIVE_RULE_KINDS = {"sensitive_field", "pii_field", "ml_sensitive_field"}
STRONG_KEYWORDS = {
    "password",
    "secret",
    "token",
    "credential",
    "access_token",
    "refresh_token",
    "api_key",
    "ssn",
    "social_security",
    "credit_card",
    "card_number",
    "cvv",
    "passport",
    "otp",
    "pin",
    "private",
}
SAFE_SUFFIXES = ("Id", "ID", "Count", "Total", "Status", "Type", "Date")
SAFE_PARENT_NAMES = ("Config", "Settings", "Metadata", "Status")
SAFE_TYPES = {
    "ID": 0.36,
    "Boolean": 0.22,
    "Int": 0.14,
    "Float": 0.12,
    "DateTime": 0.18,
}


@dataclass
class CandidateAggregate:
    location: str
    parent_type: str
    field_name: str
    field_type: str = "Unknown"
    sources: set[str] = field(default_factory=set)
    rule_kinds: set[str] = field(default_factory=set)
    matched_keywords: set[str] = field(default_factory=set)
    original_titles: List[str] = field(default_factory=list)
    original_findings: List[Finding] = field(default_factory=list)
    ml_score: Optional[float] = None
    ml_components: Optional[Dict[str, float]] = None


def split_sensitive_candidates(findings: Iterable[Finding]) -> Tuple[List[Finding], List[Finding]]:
    """Split raw findings into non-sensitive findings and sensitive candidates."""
    other_findings: List[Finding] = []
    candidates: List[Finding] = []

    for finding in findings:
        if extract_sensitive_candidate(finding):
            candidates.append(finding)
        else:
            other_findings.append(finding)

    return other_findings, candidates


def review_sensitive_candidates(
    rule_candidates: Iterable[Finding] | None = None,
    ml_candidates: Iterable[Finding] | None = None,
) -> Tuple[List[Finding], Dict[str, Any]]:
    """Merge and review sensitive-field candidates before reporting."""
    grouped: Dict[str, CandidateAggregate] = {}
    raw_rule_candidates = 0
    raw_ml_candidates = 0

    # Collect rule-based candidates first because they are deterministic scanner signals.
    for finding in rule_candidates or []:
        candidate = extract_sensitive_candidate(finding)
        if not candidate:
            continue
        raw_rule_candidates += 1
        _merge_candidate(grouped, finding, candidate)

    # Merge ML candidates into the same field groups so both signals can support one finding.
    for finding in ml_candidates or []:
        candidate = extract_sensitive_candidate(finding)
        if not candidate:
            continue
        raw_ml_candidates += 1
        _merge_candidate(grouped, finding, candidate)

    reviewed_findings: List[Finding] = []
    reviewed_entries: List[Dict[str, Any]] = []
    filtered_entries: List[Dict[str, Any]] = []
    corroborated_candidates = 0

    for aggregate in sorted(grouped.values(), key=lambda item: item.location.lower()):
        # Review each grouped field once to avoid duplicate sensitive-field findings.
        review = _review_candidate_group(aggregate)
        if review["corroborated"]:
            corroborated_candidates += 1

        entry = {
            "location": aggregate.location,
            "field_type": aggregate.field_type,
            "matched_keywords": sorted(aggregate.matched_keywords),
            "sources": sorted(aggregate.sources),
            "rule_kinds": sorted(aggregate.rule_kinds),
            "review_score": review["score"],
            "disposition": review["disposition"],
            "corroborated": review["corroborated"],
            "reasons": review["reasons"],
            "adjustments": review["adjustments"],
            "ml_score": round(aggregate.ml_score, 2) if aggregate.ml_score is not None else None,
        }

        if review["disposition"] == "filtered_out":
            # Weak candidates are kept in the review report but not added as findings.
            filtered_entries.append(entry)
            continue

        # Strong or review-worthy candidates become reportable findings.
        reviewed_entries.append(entry)
        reviewed_findings.append(_build_reviewed_finding(aggregate, review))

    likely_true = sum(1 for item in reviewed_entries if item["disposition"] == "likely_true")
    reviewed_candidates = sum(1 for item in reviewed_entries if item["disposition"] == "reviewed_candidate")

    report = {
        "summary": {
            "raw_rule_candidates": raw_rule_candidates,
            "raw_ml_candidates": raw_ml_candidates,
            "corroborated_candidates": corroborated_candidates,
            "likely_true": likely_true,
            "reviewed_candidates": reviewed_candidates,
            "filtered_candidates": len(filtered_entries),
            "reported_sensitive_fields": len(reviewed_findings),
        },
        "reported": reviewed_entries[:20],
        "filtered": filtered_entries[:20],
    }

    return reviewed_findings, report


def extract_sensitive_candidate(finding: Finding) -> Optional[Dict[str, Any]]:
    """Extract structured sensitive-field candidate metadata from a finding."""
    if finding.category != CATEGORY_AUDIT:
        return None

    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    candidate_kind = evidence.get("candidate_kind")
    if not candidate_kind:
        title = finding.title.lower()
        if title.startswith("sensitive field exposed:"):
            candidate_kind = "sensitive_field"
        elif title.startswith("pii field detected:"):
            candidate_kind = "pii_field"
        elif title.startswith("ml-detected sensitive field:"):
            candidate_kind = "ml_sensitive_field"

    if candidate_kind not in SENSITIVE_RULE_KINDS:
        return None

    location = finding.field or evidence.get("location")
    if not location or "." not in location:
        return None

    parent_type, field_name = location.split(".", 1)
    ml_score = evidence.get("ml_score")
    try:
        if ml_score is not None:
            ml_score = float(ml_score)
    except (TypeError, ValueError):
        ml_score = None

    matched_keywords = evidence.get("matched_keywords") or []
    if not matched_keywords and evidence.get("matched_keyword"):
        matched_keywords = [evidence["matched_keyword"]]

    return {
        "location": location,
        "parent_type": parent_type,
        "field_name": field_name,
        "field_type": evidence.get("field_type") or "Unknown",
        "candidate_kind": candidate_kind,
        "candidate_source": evidence.get("candidate_source") or ("ml" if candidate_kind == "ml_sensitive_field" else "rule"),
        "matched_keywords": [str(item) for item in matched_keywords if item],
        "ml_score": ml_score,
        "ml_components": evidence.get("ml_components"),
    }


def _merge_candidate(
    grouped: Dict[str, CandidateAggregate],
    finding: Finding,
    candidate: Dict[str, Any],
) -> None:
    aggregate = grouped.setdefault(
        candidate["location"],
        CandidateAggregate(
            location=candidate["location"],
            parent_type=candidate["parent_type"],
            field_name=candidate["field_name"],
            field_type=candidate["field_type"],
        ),
    )

    aggregate.sources.add(candidate["candidate_source"])
    aggregate.rule_kinds.add(candidate["candidate_kind"])
    aggregate.matched_keywords.update(candidate["matched_keywords"])
    aggregate.original_titles.append(finding.title)
    aggregate.original_findings.append(finding)

    if candidate["field_type"] != "Unknown":
        aggregate.field_type = candidate["field_type"]

    ml_score = candidate.get("ml_score")
    if ml_score is not None and (aggregate.ml_score is None or ml_score > aggregate.ml_score):
        aggregate.ml_score = ml_score
        aggregate.ml_components = candidate.get("ml_components")


def _review_candidate_group(aggregate: CandidateAggregate) -> Dict[str, Any]:
    score = 0.0
    reasons: List[str] = []
    adjustments: List[str] = []

    if "sensitive_field" in aggregate.rule_kinds:
        score += 0.62
        reasons.append("Matched a high-risk sensitive naming rule.")
    if "pii_field" in aggregate.rule_kinds:
        score += 0.46
        reasons.append("Matched a personal-data naming rule.")
    if aggregate.ml_score is not None:
        score += min(aggregate.ml_score, 1.0) * 0.55
        reasons.append(f"ML semantic score contributed {aggregate.ml_score:.2f}.")

    corroborated = bool({"rule", "ml"}.issubset(aggregate.sources))
    if corroborated:
        score += 0.22
        reasons.append("Rule-based and ML analysis agree on this field.")

    strong_keywords = sorted(
        keyword for keyword in aggregate.matched_keywords if keyword.lower() in STRONG_KEYWORDS
    )
    if strong_keywords:
        score += 0.26
        reasons.append(f"High-risk keyword(s): {', '.join(strong_keywords[:3])}.")
    elif len(aggregate.matched_keywords) >= 2:
        score += 0.1
        reasons.append("Multiple weaker sensitive indicators were present.")

    safe_suffix = next(
        (suffix for suffix in SAFE_SUFFIXES if aggregate.field_name.endswith(suffix)),
        None,
    )
    if safe_suffix:
        penalty = 0.24 if safe_suffix in {"Id", "ID"} else 0.16
        score -= penalty
        adjustments.append(f"Reduced score because the field ends with '{safe_suffix}'.")

    safe_parent = next(
        (name for name in SAFE_PARENT_NAMES if name.lower() in aggregate.parent_type.lower()),
        None,
    )
    if safe_parent:
        score -= 0.14
        adjustments.append(f"Reduced score because parent type '{aggregate.parent_type}' looks metadata-oriented.")

    field_type_penalty = SAFE_TYPES.get(aggregate.field_type)
    if field_type_penalty:
        score -= field_type_penalty
        adjustments.append(f"Reduced score because field type '{aggregate.field_type}' is commonly non-sensitive.")

    score = round(max(0.0, min(score, 1.4)), 2)

    if (
        score >= 0.88
        or ("sensitive_field" in aggregate.rule_kinds and strong_keywords and score >= 0.72)
        or (corroborated and score >= 0.7)
    ):
        disposition = "likely_true"
    elif score >= 0.5:
        disposition = "reviewed_candidate"
    else:
        disposition = "filtered_out"

    return {
        "score": score,
        "disposition": disposition,
        "corroborated": corroborated,
        "reasons": reasons or ["Matched one weak sensitivity signal."],
        "adjustments": adjustments,
        "strong_keywords": strong_keywords,
    }


def _build_reviewed_finding(aggregate: CandidateAggregate, review: Dict[str, Any]) -> Finding:
    strong_signal = bool(review["strong_keywords"]) or "sensitive_field" in aggregate.rule_kinds
    if review["disposition"] == "likely_true":
        title = f"Reviewed Sensitive Field: {aggregate.location}"
        description = (
            f"Guardian reviewed this field through the sensitive-field false-positive reduction stage "
            f"and kept it as a likely true sensitive exposure candidate."
        )
        severity = SEVERITY_HIGH if strong_signal else SEVERITY_MEDIUM
        confidence = "high" if review["corroborated"] or review["score"] >= 0.9 else "medium"
        state = "reviewed"
        remediation = (
            "1. Verify that this field is only available to authorized roles.\n"
            "2. Apply field-level authorization or masking where appropriate.\n"
            "3. Remove or redesign the field if the value should never be client-visible."
        )
        rule_id = "GG-AUDIT-SENSITIVE-FIELD-REVIEWED"
    else:
        title = f"Sensitive Field Candidate: {aggregate.location}"
        description = (
            f"Guardian detected sensitivity signals for this field, but the false-positive reduction stage "
            f"lowered confidence. Treat it as a candidate that still needs manual verification."
        )
        severity = SEVERITY_LOW
        confidence = "medium"
        state = "needs-review"
        remediation = (
            "Manually verify whether this field can expose secrets or personal data across roles. "
            "If it is benign metadata, document that in the assessment to close the loop."
        )
        rule_id = "GG-AUDIT-SENSITIVE-FIELD-CANDIDATE"

    evidence = {
        "candidate_source": "review",
        "candidate_kind": "reviewed_sensitive_field",
        "location": aggregate.location,
        "field_type": aggregate.field_type,
        "matched_keywords": sorted(aggregate.matched_keywords),
        "sources": sorted(aggregate.sources),
        "rule_kinds": sorted(aggregate.rule_kinds),
        "ml_score": round(aggregate.ml_score, 2) if aggregate.ml_score is not None else None,
        "ml_components": aggregate.ml_components,
        "review_disposition": review["disposition"],
        "review_score": review["score"],
        "corroborated": review["corroborated"],
        "review_reasons": review["reasons"],
        "review_adjustments": review["adjustments"],
        "original_titles": aggregate.original_titles,
    }

    return Finding(
        title=title,
        description=description,
        severity=severity,
        category=CATEGORY_AUDIT,
        endpoint=aggregate.original_findings[0].endpoint if aggregate.original_findings else None,
        field=aggregate.location,
        evidence=evidence,
        remediation=remediation,
        rule_id=rule_id,
        confidence=confidence,
        state=state,
    )
