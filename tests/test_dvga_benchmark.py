from src.scanner.dvga_benchmark import evaluate_dvga_report


def test_dvga_benchmark_scores_detected_and_missed_findings():
    report = {
        "metadata": {"endpoint": "http://localhost:5000/graphql"},
        "summary": {"total": 3, "high": 2, "medium": 1, "low": 0, "info": 0},
        "findings": [
            {
                "category": "CONFIG",
                "title": "Introspection Enabled",
                "description": "Introspection enabled on the endpoint.",
                "operation_name": "",
                "field": "",
                "state": "confirmed",
            },
            {
                "category": "DOS",
                "title": "Batch Query Support Detected",
                "description": "Server accepts array-based batch queries.",
                "operation_name": "",
                "field": "",
                "state": "confirmed",
            },
            {
                "category": "INJECTION",
                "title": "Stored XSS in createPaste",
                "description": "XSS in createPaste(content)",
                "operation_name": "Mutation.createPaste",
                "field": "content",
                "state": "confirmed",
            },
        ],
    }

    benchmark = evaluate_dvga_report(report)

    assert benchmark["metrics"]["true_positives"] == 3
    assert benchmark["metrics"]["false_negatives"] == 12
    assert benchmark["metrics"]["false_positives"] == 0
    assert benchmark["coverage"][0]["status"] == "detected"
    assert benchmark["role_breakdown"]["recon"]["metrics"]["true_positives"] == 1
    assert benchmark["role_breakdown"]["dos"]["metrics"]["true_positives"] == 1
    assert benchmark["role_breakdown"]["injection"]["metrics"]["true_positives"] == 1
    assert benchmark["role_breakdown"]["auth"]["metrics"]["false_negatives"] == 2
    assert benchmark["coverage"][0]["module"]["name"] == "ConfigChecker"
    assert benchmark["module_attribution"]["AuthTester"]["missed_count"] == 2
    assert benchmark["module_attribution"]["PayloadInjector"]["detected_count"] == 1


def test_dvga_benchmark_ignores_possible_findings_for_precision():
    report = {
        "metadata": {"endpoint": "http://localhost:5000/graphql"},
        "summary": {"total": 1},
        "findings": [
            {
                "category": "INJECTION",
                "title": "Reflected Payload in createPaste",
                "description": "Payload was reflected but execution was not proven.",
                "operation_name": "Mutation.createPaste",
                "field": "content",
                "state": "possible",
            }
        ],
    }

    benchmark = evaluate_dvga_report(report)

    assert benchmark["metrics"]["true_positives"] == 0
    assert benchmark["metrics"]["false_positives"] == 0
    assert benchmark["ignored_findings_count"] == 1
