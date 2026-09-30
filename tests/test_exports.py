import json

from src.api.exports import (
    build_finding_dossier,
    build_repeater_collection,
    render_finding_dossier_text,
    render_intruder_payloads,
    render_relationship_map_text,
    render_manual_finding_provenance_text,
    render_operation_pack_http,
)


REPORT = {
    "metadata": {"endpoint": "https://example.com/graphql"},
    "findings": [
        {
            "id": "finding-1",
            "title": "Reviewed Sensitive Field: User.email",
            "description": "Likely true sensitive exposure.",
            "severity": "HIGH",
            "category": "AUDIT",
            "field": "User.email",
            "state": "reviewed",
            "confidence": "high",
            "evidence": {"reproduction": "curl ..."},
            "reproduction": "curl ...",
        }
    ],
    "operation_pack": {
        "packs": {
            "reconnaissance": [
                {
                    "operation_name": "Query.users",
                    "operation": "query { users { id email } }",
                    "tags": ["recon"],
                }
            ],
            "access_control": [
                {
                    "operation_name": "Query.user",
                    "full_operation": 'query { user(id: "1") { id email } }',
                    "tags": ["idor-candidate"],
                }
            ],
        }
    },
    "relationship_map": {
        "summary": {"sensitive_fields_mapped": 1},
        "items": [
            {
                "location": "User.email",
                "review_score": 0.91,
                "disposition": "likely_true",
                "recommended_focus": "Follow Query.user first.",
                "related_paths": [{"path": "Query.user"}],
                "related_operations": [{"operation_name": "Query.user"}],
                "related_resource_checks": [{"accessor": "Query.user", "vulnerable_roles": ["user_b"]}],
                "related_mutation_checks": [],
                "related_subscription_checks": [],
            }
        ],
    },
}


def test_render_operation_pack_http_includes_raw_request_details():
    export_text = render_operation_pack_http(REPORT)

    assert "POST /graphql HTTP/1.1" in export_text
    assert "Host: example.com" in export_text
    assert '"query":"query { users { id email } }"' in export_text


def test_render_intruder_payloads_outputs_compact_json_lines():
    payload_text = render_intruder_payloads(REPORT)
    lines = payload_text.splitlines()

    assert len(lines) == 2
    assert lines[0] == '{"query":"query { users { id email } }","variables":{}}'
    assert '"query":"query { user(id: \\"1\\") { id email } }"' in lines[1]


def test_build_repeater_collection_contains_named_requests():
    collection = build_repeater_collection(REPORT)

    assert collection["format"] == "guardian-burp-repeater/v1"
    assert len(collection["items"]) == 2
    assert collection["items"][0]["role"] == "reconnaissance"
    assert collection["items"][1]["name"] == "Query.user"
    assert json.loads(json.dumps(collection))["items"][0]["method"] == "POST"


def test_render_manual_finding_provenance_text_includes_note_and_replays():
    export_text = render_manual_finding_provenance_text(
        {
            "scan_id": "scan-1",
            "endpoint": "https://example.com/graphql",
            "items": [
                {
                    "finding_id": "MANUAL-1",
                    "operation_name": "Query.user",
                    "finding": {
                        "title": "Manual validation: Query.user",
                        "severity": "HIGH",
                        "category": "AUTH",
                        "description": "Confirmed BOLA on user query.",
                    },
                    "note": {
                        "status": "confirmed",
                        "observations": "Changed id from 1 to 2.",
                    },
                    "request_override": {
                        "query": 'query { user(id: "2") { id } }',
                        "variables": {},
                    },
                    "replay_history": [
                        {
                            "id": 3,
                            "replay_result": {"status_code": 200, "body": {"data": {"user": {"id": "2"}}}},
                        }
                    ],
                    "promotion": {
                        "promoted_at": "2026-04-24T18:00:00",
                        "note_status": "confirmed",
                    },
                }
            ],
        }
    )

    assert "Manual validation: Query.user" in export_text
    assert '"status": "confirmed"' in export_text
    assert '"query": "query { user(id: \\"2\\") { id } }"' in export_text
    assert '"status_code": 200' in export_text


def test_build_finding_dossier_includes_relationship_context():
    payload = build_finding_dossier(REPORT, scan_id="scan-1")

    assert payload["summary"]["total_items"] == 1
    assert payload["items"][0]["finding"]["id"] == "finding-1"
    assert payload["items"][0]["relationship_context"]["location"] == "User.email"


def test_render_finding_dossier_and_relationship_map_text_are_human_readable():
    dossier_text = render_finding_dossier_text(build_finding_dossier(REPORT, scan_id="scan-1"))
    relationship_text = render_relationship_map_text(REPORT)

    assert "Reviewed Sensitive Field: User.email" in dossier_text
    assert "### relationship_context" in dossier_text
    assert "## User.email" in relationship_text
    assert "Query.user" in relationship_text
