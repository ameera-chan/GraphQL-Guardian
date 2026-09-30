"""DVGA benchmark mode for measuring Guardian accuracy."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

from src.scanner.orchestrator import ScanOrchestrator
from src.reporters.models import normalize_state
from src.utils.files import write_json, write_text


ROLE_LABELS = {
    "recon": "Reconnaissance",
    "auth": "Authentication / Access Control",
    "injection": "Injection",
    "dos": "Denial of Service",
    "other": "Other",
}

CATEGORY_TO_ROLE = {
    "CONFIG": "recon",
    "AUTH": "auth",
    "INJECTION": "injection",
    "DOS": "dos",
}

ROLE_TO_MODULE = {
    "recon": {"name": "ConfigChecker", "file": "src/scanner/config_checker.py"},
    "auth": {"name": "AuthTester", "file": "src/scanner/auth_tester.py"},
    "injection": {"name": "PayloadInjector", "file": "src/scanner/injector.py"},
    "dos": {"name": "DoSScanner", "file": "src/scanner/dos_scanner.py"},
    "other": {"name": "ScanOrchestrator", "file": "src/scanner/orchestrator.py"},
}

DVGA_GROUND_TRUTH = [
    {"id": "CONF-1", "category": "CONFIG", "role": "recon", "match": "Introspection", "desc": "Introspection Enabled"},
    {"id": "CONF-2", "category": "CONFIG", "role": "recon", "match": "GraphQL IDE", "desc": "Public GraphQL IDE Interface"},
    {"id": "DOS-1", "category": "DOS", "role": "dos", "match": "Alias Overloading", "desc": "Alias Overloading"},
    {"id": "DOS-2", "category": "DOS", "role": "dos", "match": "Batch Query", "desc": "Batch Queries"},
    {"id": "AUTH-1", "category": "AUTH", "role": "auth", "match": "readAndBurn", "desc": "IDOR: createPaste -> readAndBurn"},
    {"id": "AUTH-2", "category": "AUTH", "role": "auth", "match": "users", "desc": "IDOR: createUser -> users"},
    {"id": "INJ-1", "category": "INJECTION", "role": "injection", "match": "createPaste", "field": "content", "desc": "XSS in createPaste(content)"},
    {"id": "INJ-2", "category": "INJECTION", "role": "injection", "match": "createPaste", "field": "title", "desc": "XSS in createPaste(title)"},
    {"id": "INJ-3", "category": "INJECTION", "role": "injection", "match": "editPaste", "field": "content", "desc": "XSS in editPaste(content)"},
    {"id": "INJ-4", "category": "INJECTION", "role": "injection", "match": "editPaste", "field": "title", "desc": "XSS in editPaste(title)"},
    {"id": "INJ-5", "category": "INJECTION", "role": "injection", "match": "uploadPaste", "field": "content", "desc": "XSS in uploadPaste(content)"},
    {"id": "INJ-6", "category": "INJECTION", "role": "injection", "match": "uploadPaste", "field": "filename", "desc": "XSS in uploadPaste(filename)"},
    {"id": "INJ-7", "category": "INJECTION", "role": "injection", "match": "importPaste", "field": "path", "desc": "SQLi/Cmd Injection in importPaste(path)"},
    {"id": "INJ-8", "category": "INJECTION", "role": "injection", "match": "pastes", "field": "filter", "desc": "SQLi in pastes(filter)"},
    {"id": "INJ-9", "category": "INJECTION", "role": "injection", "match": "paste", "field": "title", "desc": "XSS in paste(title)"},
]


def evaluate_dvga_report(report: Dict[str, Any]) -> Dict[str, Any]:
    findings = _normalize_findings(report.get("findings", []))
    scoreable_findings = [finding for finding in findings if _is_scoreable_finding(finding)]
    ignored_findings = [finding for finding in findings if not _is_scoreable_finding(finding)]
    used_finding_indexes = set()
    coverage = []
    tp = 0
    fn = 0
    role_counts = _initialize_role_breakdown()

    for truth in DVGA_GROUND_TRUTH:
        role = truth.get("role") or CATEGORY_TO_ROLE.get(truth["category"], "other")
        matched_index = _match_truth(truth, scoreable_findings)
        detected = matched_index is not None
        if detected:
            used_finding_indexes.add(matched_index)
            tp += 1
            role_counts[role]["true_positives"] += 1
        else:
            fn += 1
            role_counts[role]["false_negatives"] += 1

        role_counts[role]["truth_count"] += 1

        coverage.append(
            {
                "id": truth["id"],
                "category": truth["category"],
                "role": role,
                "vulnerability": truth["desc"],
                "status": "detected" if detected else "missed",
                "module": ROLE_TO_MODULE.get(role, ROLE_TO_MODULE["other"]),
                "matched_finding": _finding_snapshot(scoreable_findings[matched_index]) if detected else None,
                "recommendation": None
                if detected
                else f"Investigate {ROLE_TO_MODULE.get(role, ROLE_TO_MODULE['other'])['name']} for {truth['desc']}.",
            }
        )

    fp = max(0, len(scoreable_findings) - len(used_finding_indexes))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    unmatched = [
        scoreable_findings[index]
        for index in range(len(scoreable_findings))
        if index not in used_finding_indexes
    ]

    for finding in unmatched:
        role = _finding_role(finding)
        role_counts[role]["false_positives"] += 1

    role_breakdown = _finalize_role_breakdown(role_counts)
    module_attribution = _build_module_attribution(coverage, unmatched)

    return {
        "target": report.get("metadata", {}).get("endpoint"),
        "evaluated_at": datetime.now().isoformat(),
        "metrics": {
            "true_positives": tp,
            "false_negatives": fn,
            "false_positives": fp,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
        },
        "coverage": coverage,
        "role_breakdown": role_breakdown,
        "module_attribution": module_attribution,
        "unmatched_findings": unmatched,
        "ignored_findings": ignored_findings,
        "ignored_findings_count": len(ignored_findings),
        "scan_summary": report.get("summary", {}),
    }


def run_dvga_benchmark(
    endpoint: str,
    *,
    config_data: Dict[str, Any] | None = None,
    profile: str = "default",
    enable_ml: bool = False,
    enable_llm: bool = False,
    progress_callback=None,
) -> Dict[str, Any]:
    report = ScanOrchestrator(
        endpoint,
        config_data=config_data,
        profile=profile,
        enable_ml=enable_ml,
        enable_llm=enable_llm,
        progress_callback=progress_callback,
    ).run()
    benchmark = evaluate_dvga_report(report)
    return {
        "report": report,
        "benchmark": benchmark,
    }


def save_benchmark_outputs(
    benchmark_result: Dict[str, Any],
    *,
    json_path: str,
    markdown_path: str | None = None,
) -> None:
    write_json(json_path, benchmark_result)
    if markdown_path:
        write_text(markdown_path, render_benchmark_markdown(benchmark_result["benchmark"]))


def render_benchmark_markdown(benchmark: Dict[str, Any]) -> str:
    metrics = benchmark["metrics"]
    coverage_rows = "\n".join(
        f"| {row['id']} | {row['category']} | {ROLE_LABELS.get(row.get('role'), row.get('role', 'other').title())} | {row['vulnerability']} | {'Detected' if row['status'] == 'detected' else 'Missed'} |"
        for row in benchmark["coverage"]
    )
    role_rows = "\n".join(
        f"| {item['label']} | {item['truth_count']} | {item['metrics']['true_positives']} | {item['metrics']['false_negatives']} | {item['metrics']['false_positives']} | {item['metrics']['precision']:.2f} | {item['metrics']['recall']:.2f} | {item['metrics']['f1_score']:.2f} |"
        for item in benchmark.get("role_breakdown", {}).values()
        if item.get("truth_count") or item.get("metrics", {}).get("false_positives")
    ) or "| None | 0 | 0 | 0 | 0 | 0.00 | 0.00 | 0.00 |"
    module_rows = "\n".join(
        f"| {item['module']['name']} | {item['module']['file']} | {item['missed_count']} | {item['false_positive_count']} | {', '.join(item['missed_truth_ids']) or '-'} |"
        for item in benchmark.get("module_attribution", {}).values()
        if item.get("missed_count") or item.get("false_positive_count")
    ) or "| None | - | 0 | 0 | - |"
    unmatched = benchmark.get("unmatched_findings", [])
    ignored_count = benchmark.get("ignored_findings_count", 0)
    unmatched_lines = "\n".join(
        f"* **[{item.get('category', 'UNKNOWN')}] {item.get('title', 'Untitled')}**: {item.get('description', '')}"
        for item in unmatched
    ) or "* None"

    return f"""# DVGA Coverage Analysis

**Date:** {benchmark.get('evaluated_at', 'N/A')}
**Target:** {benchmark.get('target', 'N/A')}
**Label:** {benchmark.get('label', 'N/A')}
**Group:** {benchmark.get('group', 'N/A')}

## Metrics

| Metric | Value |
|--------|-------|
| True Positives | {metrics['true_positives']} |
| False Negatives | {metrics['false_negatives']} |
| False Positives | {metrics['false_positives']} |
| Precision | {metrics['precision']:.2f} |
| Recall | {metrics['recall']:.2f} |
| F1 Score | {metrics['f1_score']:.2f} |
| Ignored Possible/Informational Findings | {ignored_count} |

## Detailed Coverage

| ID | Category | Role | Vulnerability | Status |
|----|----------|------|---------------|--------|
{coverage_rows}

## Role Breakdown

| Role | Truth Count | TP | FN | FP | Precision | Recall | F1 |
|------|-------------|----|----|----|-----------|--------|----|
{role_rows}

## Module Attribution

| Module | File | Missed Truths | False Positives | IDs |
|--------|------|---------------|-----------------|-----|
{module_rows}

## Unmatched Findings

{unmatched_lines}
"""


def load_report(path: str) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _normalize_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [dict(item) for item in findings]


def _is_scoreable_finding(finding: Dict[str, Any]) -> bool:
    return normalize_state(finding.get("state"), finding.get("severity")) == "confirmed"


def _initialize_role_breakdown() -> Dict[str, Dict[str, Any]]:
    return {
        role: {
            "label": label,
            "truth_count": 0,
            "true_positives": 0,
            "false_negatives": 0,
            "false_positives": 0,
        }
        for role, label in ROLE_LABELS.items()
    }


def _finalize_role_breakdown(role_counts: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    breakdown = {}
    for role, data in role_counts.items():
        tp = data["true_positives"]
        fn = data["false_negatives"]
        fp = data["false_positives"]
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        breakdown[role] = {
            **data,
            "metrics": {
                "true_positives": tp,
                "false_negatives": fn,
                "false_positives": fp,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1_score, 4),
            },
        }
    return breakdown


def _finding_role(finding: Dict[str, Any]) -> str:
    return CATEGORY_TO_ROLE.get(finding.get("category", "").upper(), "other")


def _finding_snapshot(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "title": finding.get("title"),
        "rule_id": finding.get("rule_id"),
        "category": finding.get("category"),
        "operation_name": finding.get("operation_name"),
        "field": finding.get("field"),
        "verification_status": normalize_state(finding.get("state"), finding.get("severity")),
    }


def _build_module_attribution(
    coverage: List[Dict[str, Any]],
    unmatched_findings: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    attribution = {
        module["name"]: {
            "module": module,
            "missed_count": 0,
            "detected_count": 0,
            "false_positive_count": 0,
            "missed_truth_ids": [],
            "missed_truths": [],
            "detected_truth_ids": [],
            "false_positive_titles": [],
        }
        for module in ROLE_TO_MODULE.values()
    }

    for item in coverage:
        module = item["module"]
        bucket = attribution[module["name"]]
        if item["status"] == "detected":
            bucket["detected_count"] += 1
            bucket["detected_truth_ids"].append(item["id"])
        else:
            bucket["missed_count"] += 1
            bucket["missed_truth_ids"].append(item["id"])
            bucket["missed_truths"].append(item["vulnerability"])

    for finding in unmatched_findings:
        role = _finding_role(finding)
        module = ROLE_TO_MODULE.get(role, ROLE_TO_MODULE["other"])
        bucket = attribution[module["name"]]
        bucket["false_positive_count"] += 1
        bucket["false_positive_titles"].append(finding.get("title", "Untitled"))

    return attribution


def _match_truth(truth: Dict[str, Any], findings: List[Dict[str, Any]]) -> int | None:
    for index, finding in enumerate(findings):
        if finding.get("category") != truth["category"]:
            continue
        text_blob = " ".join(
            str(part)
            for part in (
                finding.get("title"),
                finding.get("operation_name"),
                finding.get("description"),
                finding.get("field"),
            )
            if part is not None
        )
        if truth["match"] not in text_blob:
            continue
        field = truth.get("field")
        if field and field not in text_blob:
            continue
        return index
    return None
