from src.reporters.relationship_map import build_relationship_map


def test_relationship_map_links_sensitive_field_to_paths_operations_and_auth_signals():
    report = {
        "sensitive_field_review": {
            "reported": [
                {
                    "location": "User.email",
                    "disposition": "likely_true",
                    "review_score": 0.91,
                    "matched_keywords": ["email"],
                    "sources": ["rule", "ml"],
                }
            ]
        },
        "points_of_interest": {
            "auth_critical_paths": [
                {
                    "path": "Query.user",
                    "target_type": "User",
                    "score": 80,
                }
            ]
        },
        "operation_pack": {
            "operations": [
                {
                    "operation_name": "Query.user",
                    "return_type": "User",
                    "risk_score": 70,
                    "tags": ["idor-candidate", "object-accessor"],
                    "all_args": [{"name": "id"}],
                }
            ]
        },
        "authorization_matrix": {
            "resource_checks": [
                {
                    "resource": "User",
                    "accessor": "Query.user",
                    "id": "2",
                    "vulnerable_roles": ["user_b"],
                }
            ],
            "mutation_vulnerabilities": [],
            "subscription_vulnerabilities": [],
        },
    }

    relationship_map = build_relationship_map(report)

    assert relationship_map["summary"]["sensitive_fields_mapped"] == 1
    assert relationship_map["summary"]["fields_with_paths"] == 1
    assert relationship_map["summary"]["fields_with_operations"] == 1
    assert relationship_map["summary"]["fields_with_auth_signals"] == 1
    assert relationship_map["items"][0]["location"] == "User.email"
    assert relationship_map["items"][0]["related_paths"][0]["path"] == "Query.user"
    assert relationship_map["items"][0]["related_operations"][0]["operation_name"] == "Query.user"
    assert "Query.user" in relationship_map["items"][0]["recommended_focus"]
