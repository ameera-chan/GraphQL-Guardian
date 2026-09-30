"""OWASP-style risk rating for findings."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict


SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

DEFAULT_FACTORS = {
    "threat_agent": {
        "skill_level": 3,
        "motive": 4,
        "opportunity": 7,
        "size": 6,
    },
    "vulnerability": {
        "ease_of_discovery": 7,
        "ease_of_exploit": 5,
        "awareness": 6,
        "intrusion_detection": 8,
    },
    "technical_impact": {
        "loss_of_confidentiality": 2,
        "loss_of_integrity": 1,
        "loss_of_availability": 1,
        "loss_of_accountability": 1,
    },
    "business_impact": {
        "financial_damage": 1,
        "reputation_damage": 1,
        "non_compliance": 2,
        "privacy_violation": 3,
    },
}

CATEGORY_DEFAULTS = {
    "AUTH": {
        "technical_impact": {
            "loss_of_confidentiality": 7,
            "loss_of_integrity": 7,
            "loss_of_accountability": 7,
        },
        "business_impact": {
            "reputation_damage": 5,
            "privacy_violation": 5,
        },
    },
    "INJECTION": {
        "technical_impact": {
            "loss_of_confidentiality": 7,
            "loss_of_integrity": 7,
            "loss_of_availability": 5,
        },
        "business_impact": {
            "financial_damage": 7,
            "reputation_damage": 5,
            "privacy_violation": 5,
        },
    },
    "DOS": {
        "technical_impact": {
            "loss_of_availability": 7,
        },
        "business_impact": {
            "financial_damage": 3,
            "reputation_damage": 4,
        },
    },
    "CONFIG": {
        "technical_impact": {
            "loss_of_confidentiality": 6,
            "loss_of_accountability": 7,
        },
        "business_impact": {
            "reputation_damage": 4,
        },
    },
    "AUDIT": {
        "technical_impact": {
            "loss_of_confidentiality": 6,
        },
        "business_impact": {
            "privacy_violation": 5,
        },
    },
    "RECON": {
        "vulnerability": {
            "ease_of_discovery": 7,
            "ease_of_exploit": 3,
            "awareness": 6,
            "intrusion_detection": 3,
        },
        "technical_impact": {
            "loss_of_confidentiality": 2,
        },
    },
}

SEVERITY_DEFAULTS = {
    "CRITICAL": {
        "threat_agent": {"opportunity": 9, "size": 9},
        "vulnerability": {"ease_of_discovery": 9, "ease_of_exploit": 9},
        "technical_impact": {
            "loss_of_confidentiality": 9,
            "loss_of_integrity": 9,
            "loss_of_availability": 7,
        },
        "business_impact": {
            "financial_damage": 7,
            "reputation_damage": 9,
            "privacy_violation": 7,
        },
    },
    "HIGH": {
        "vulnerability": {"ease_of_discovery": 7, "ease_of_exploit": 7},
        "technical_impact": {
            "loss_of_confidentiality": 7,
            "loss_of_integrity": 5,
            "loss_of_availability": 5,
        },
    },
    "MEDIUM": {
        "vulnerability": {"ease_of_discovery": 7, "ease_of_exploit": 5},
        "technical_impact": {
            "loss_of_confidentiality": 6,
            "loss_of_integrity": 3,
            "loss_of_availability": 1,
        },
    },
    "LOW": {
        "vulnerability": {"ease_of_discovery": 3, "ease_of_exploit": 3},
        "technical_impact": {
            "loss_of_confidentiality": 2,
            "loss_of_integrity": 1,
            "loss_of_availability": 1,
        },
        "business_impact": {
            "financial_damage": 1,
            "reputation_damage": 1,
            "privacy_violation": 3,
        },
    },
    "INFO": {
        "threat_agent": {"motive": 1, "opportunity": 4, "size": 4},
        "vulnerability": {
            "ease_of_discovery": 3,
            "ease_of_exploit": 1,
            "awareness": 4,
            "intrusion_detection": 1,
        },
        "technical_impact": {
            "loss_of_confidentiality": 0,
            "loss_of_integrity": 0,
            "loss_of_availability": 0,
            "loss_of_accountability": 1,
        },
        "business_impact": {
            "financial_damage": 0,
            "reputation_damage": 1,
            "non_compliance": 0,
            "privacy_violation": 0,
        },
    },
}

CATEGORY_SEVERITY_DEFAULTS = {
    ("AUTH", "HIGH"): {
        "technical_impact": {
            "loss_of_confidentiality": 7,
            "loss_of_integrity": 7,
            "loss_of_availability": 5,
            "loss_of_accountability": 7,
        },
        "business_impact": {
            "financial_damage": 7,
            "reputation_damage": 9,
            "non_compliance": 5,
            "privacy_violation": 7,
        },
    },
    ("INJECTION", "HIGH"): {
        "technical_impact": {
            "loss_of_confidentiality": 7,
            "loss_of_integrity": 7,
            "loss_of_availability": 7,
            "loss_of_accountability": 7,
        },
        "business_impact": {
            "financial_damage": 7,
            "reputation_damage": 9,
            "non_compliance": 5,
            "privacy_violation": 7,
        },
    },
}


def rate_finding(
    *,
    category: str,
    severity: str,
    risk: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    base_severity = normalize_severity(severity)
    factors = deepcopy(DEFAULT_FACTORS)
    _merge_factors(factors, CATEGORY_DEFAULTS.get(str(category or "").upper(), {}))
    _merge_factors(factors, SEVERITY_DEFAULTS.get(base_severity, {}))
    _merge_factors(factors, CATEGORY_SEVERITY_DEFAULTS.get((str(category or "").upper(), base_severity), {}))

    manual = risk or {}
    _merge_factors(factors, manual.get("factors") or {})

    likelihood_score = _score(
        factors["threat_agent"],
        factors["vulnerability"],
    )
    impact_score = _score(
        factors["technical_impact"],
        factors["business_impact"],
    )
    likelihood_level = score_level(likelihood_score)
    impact_level = score_level(impact_score)
    final_severity = severity_from_matrix(likelihood_level, impact_level)

    return {
        "method": "OWASP Risk Rating Methodology",
        "base_severity": base_severity,
        "severity": final_severity,
        "likelihood_score": likelihood_score,
        "impact_score": impact_score,
        "likelihood_level": likelihood_level,
        "impact_level": impact_level,
        "factors": factors,
        "vector": vector_from_factors(factors),
    }


def normalize_severity(value: str | None) -> str:
    severity = str(value or "INFO").upper()
    if severity == "INFORMATIONAL":
        return "INFO"
    return severity if severity in SEVERITY_ORDER else "INFO"


def score_level(score: float) -> str:
    if score < 3:
        return "LOW"
    if score < 6:
        return "MEDIUM"
    return "HIGH"


def severity_from_matrix(likelihood: str, impact: str) -> str:
    matrix = {
        ("HIGH", "HIGH"): "CRITICAL",
        ("HIGH", "MEDIUM"): "HIGH",
        ("HIGH", "LOW"): "MEDIUM",
        ("MEDIUM", "HIGH"): "HIGH",
        ("MEDIUM", "MEDIUM"): "MEDIUM",
        ("MEDIUM", "LOW"): "LOW",
        ("LOW", "HIGH"): "MEDIUM",
        ("LOW", "MEDIUM"): "LOW",
        ("LOW", "LOW"): "INFO",
    }
    return matrix[(likelihood, impact)]


def vector_from_factors(factors: Dict[str, Dict[str, float]]) -> str:
    aliases = (
        ("SL", "threat_agent", "skill_level"),
        ("M", "threat_agent", "motive"),
        ("O", "threat_agent", "opportunity"),
        ("S", "threat_agent", "size"),
        ("ED", "vulnerability", "ease_of_discovery"),
        ("EE", "vulnerability", "ease_of_exploit"),
        ("A", "vulnerability", "awareness"),
        ("ID", "vulnerability", "intrusion_detection"),
        ("LC", "technical_impact", "loss_of_confidentiality"),
        ("LI", "technical_impact", "loss_of_integrity"),
        ("LAV", "technical_impact", "loss_of_availability"),
        ("LAC", "technical_impact", "loss_of_accountability"),
        ("FD", "business_impact", "financial_damage"),
        ("RD", "business_impact", "reputation_damage"),
        ("NC", "business_impact", "non_compliance"),
        ("PV", "business_impact", "privacy_violation"),
    )
    return "(" + "/".join(
        f"{alias}:{_format_factor(factors.get(group, {}).get(key, 0))}"
        for alias, group, key in aliases
    ) + ")"


def _merge_factors(target: Dict[str, Dict[str, Any]], source: Dict[str, Dict[str, Any]]) -> None:
    for group, values in source.items():
        if not isinstance(values, dict):
            continue
        target.setdefault(group, {})
        for key, value in values.items():
            target[group][key] = _bound_factor(value)


def _score(*groups: Dict[str, Any]) -> float:
    values = [
        _bound_factor(value)
        for group in groups
        for value in group.values()
    ]
    if not values:
        return 0.0
    return round(sum(values) / len(values), 2)


def _bound_factor(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = 0.0
    return max(0.0, min(9.0, number))


def _format_factor(value: Any) -> str:
    number = _bound_factor(value)
    return str(int(number)) if number.is_integer() else str(number)
