from src.api.database import Database


def test_default_database_uses_guardql_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDQL_DATA_DIR", str(tmp_path / "guardql-data"))
    monkeypatch.delenv("GUARDQL_DB_PATH", raising=False)

    db = Database()

    assert db.db_path == tmp_path / "guardql-data" / "guardian.db"
    assert db.db_path.exists()


def test_statistics_include_critical_findings(tmp_path):
    db = Database(str(tmp_path / "guardian.db"))
    db.create_scan("scan-1", "http://localhost/graphql", {"profile": "default"})
    db.update_scan_status("scan-1", "completed")
    db.save_scan_results(
        "scan-1",
        {
            "summary": {"total": 3, "critical": 1, "high": 1, "medium": 0, "low": 0, "info": 1},
            "findings": [],
        },
    )

    stats = db.get_statistics()

    assert stats["total_findings"]["critical"] == 1
    assert stats["total_findings"]["high"] == 1
    assert stats["total_findings"]["info"] == 1


def test_statistics_recalculate_old_findings_with_risk_engine(tmp_path):
    db = Database(str(tmp_path / "guardian.db"))
    db.create_scan("scan-1", "http://localhost/graphql", {"profile": "default"})
    db.update_scan_status("scan-1", "completed")
    db.save_scan_results(
        "scan-1",
        {
            "summary": {"total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "findings": [
                {
                    "category": "AUTH",
                    "severity": "HIGH",
                    "title": "Old auth finding",
                    "description": "Stored before risk data existed.",
                }
            ],
        },
    )

    stats = db.get_statistics()

    assert stats["total_findings"]["critical"] == 1
    assert stats["total_findings"]["high"] == 0


def test_manual_notes_can_be_saved_and_listed(tmp_path):
    db = Database(str(tmp_path / "guardian.db"))
    db.create_scan("scan-1", "http://localhost/graphql", {"profile": "default"})

    saved = db.save_manual_note(
        scan_id="scan-1",
        operation_name="Query.user",
        status="testing",
        observations="User 2 can still access user 1 record.",
        payload_tweaks="Changed id from 1 to 2",
        request_override={"query": 'query { user(id: "2") { id } }', "variables": {}},
    )

    notes = db.list_manual_notes("scan-1")

    assert saved["operation_name"] == "Query.user"
    assert len(notes) == 1
    assert notes[0]["status"] == "testing"
    assert notes[0]["request_override"]["query"] == 'query { user(id: "2") { id } }'


def test_manual_notes_can_store_replay_snapshots(tmp_path):
    db = Database(str(tmp_path / "guardian.db"))
    db.create_scan("scan-1", "http://localhost/graphql", {"profile": "default"})

    saved = db.save_manual_note(
        scan_id="scan-1",
        operation_name="Query.user",
        status="retested",
        observations="Replay captured user 2 details.",
        payload_tweaks="Changed id from 1 to 2",
        request_override={"query": 'query { user(id: "2") { id } }', "variables": {}},
        last_replay={
            "status_code": 200,
            "ok": True,
            "headers": {"content-type": "application/json"},
            "body": {"data": {"user": {"id": "2"}}},
            "elapsed_ms": 42.5,
            "recorded_at": "2026-04-24T16:00:00",
        },
    )

    note = db.get_manual_note("scan-1", "Query.user")

    assert saved["last_replay"]["status_code"] == 200
    assert note["last_replay"]["body"]["data"]["user"]["id"] == "2"


def test_manual_replay_history_is_saved(tmp_path):
    db = Database(str(tmp_path / "guardian.db"))
    db.create_scan("scan-1", "http://localhost/graphql", {"profile": "default"})

    db.save_manual_replay(
        scan_id="scan-1",
        operation_name="Query.user",
        request_override={"query": 'query { user(id: "1") { id } }', "variables": {}},
        replay_result={"status_code": 200, "ok": True, "body": {"data": {"user": {"id": "1"}}}},
    )
    db.save_manual_replay(
        scan_id="scan-1",
        operation_name="Query.user",
        request_override={"query": 'query { user(id: "2") { id } }', "variables": {}},
        replay_result={"status_code": 403, "ok": False, "body": {"errors": ["Forbidden"]}},
    )

    replays = db.list_manual_replays("scan-1", "Query.user", limit=5)

    assert len(replays) == 2
    assert replays[0]["request_override"]["query"] == 'query { user(id: "2") { id } }'
    assert replays[1]["replay_result"]["body"]["data"]["user"]["id"] == "1"


def test_promote_manual_note_updates_scan_results(tmp_path):
    db = Database(str(tmp_path / "guardian.db"))
    db.create_scan("scan-1", "http://localhost/graphql", {"profile": "default"})
    db.save_scan_results(
        "scan-1",
        {
            "summary": {"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "findings": [],
            "metadata": {"endpoint": "http://localhost/graphql"},
        },
    )
    db.save_manual_note(
        scan_id="scan-1",
        operation_name="Query.user",
        status="confirmed",
        observations="Confirmed BOLA on user query.",
        payload_tweaks="Changed id from 1 to 2",
        request_override={"query": 'query { user(id: "2") { id } }', "variables": {}},
    )

    result = db.promote_manual_note_to_finding(
        "scan-1",
        "Query.user",
        {
            "category": "AUTH",
            "severity": "HIGH",
            "title": "Manual validation: Query.user",
            "description": "Confirmed BOLA on user query.",
        },
    )

    report = db.get_scan_results("scan-1")

    assert result["finding"]["id"].startswith("MANUAL-")
    assert report["summary"]["critical"] == 1
    assert report["findings"][0]["severity"] == "CRITICAL"
    assert report["findings"][0]["risk"]["likelihood_level"] == "HIGH"
    assert report["findings"][0]["risk"]["impact_level"] == "HIGH"
    assert report["findings"][0]["source"] == "manual"
    assert report["findings"][0]["provenance"]["operation_name"] == "Query.user"
    assert report["findings"][0]["provenance"]["request_override"]["query"] == 'query { user(id: "2") { id } }'
    assert db.get_manual_note("scan-1", "Query.user")["promoted_finding_id"] == result["finding"]["id"]


def test_benchmark_list_supports_label_filter(tmp_path):
    db = Database(str(tmp_path / "guardian.db"))
    db.create_benchmark(
        benchmark_id="bench-1",
        endpoint="http://localhost:5000/graphql",
        config={"label": "before batching refactor"},
    )
    db.create_benchmark(
        benchmark_id="bench-2",
        endpoint="http://localhost:5000/graphql",
        config={"label": "after path enum upgrade"},
    )

    filtered = db.list_benchmarks(label="before")

    assert len(filtered) == 1
    assert filtered[0]["id"] == "bench-1"
    assert db.count_benchmarks(label="after") == 1


def test_benchmark_list_supports_group_filter(tmp_path):
    db = Database(str(tmp_path / "guardian.db"))
    db.create_benchmark(
        benchmark_id="bench-1",
        endpoint="http://localhost:5000/graphql",
        config={"label": "before auth", "group": "pre-auth-fix"},
    )
    db.create_benchmark(
        benchmark_id="bench-2",
        endpoint="http://localhost:5000/graphql",
        config={"label": "after auth", "group": "post-auth-fix"},
    )

    filtered = db.list_benchmarks(group="post-auth")

    assert len(filtered) == 1
    assert filtered[0]["group"] == "post-auth-fix"
    assert db.count_benchmarks(group="pre-auth") == 1


def test_benchmark_group_summary_includes_role_breakdown(tmp_path):
    db = Database(str(tmp_path / "guardian.db"))
    db.create_benchmark(
        benchmark_id="bench-1",
        endpoint="http://localhost:5000/graphql",
        config={"label": "before auth", "group": "pre-auth-fix"},
    )
    db.save_benchmark_results(
        "bench-1",
        {
            "benchmark": {
                "metrics": {"precision": 0.5, "recall": 0.4, "f1_score": 0.44},
                "role_breakdown": {
                    "auth": {
                        "truth_count": 2,
                        "metrics": {"precision": 0.5, "recall": 0.5, "f1_score": 0.5},
                    },
                    "recon": {
                        "truth_count": 1,
                        "metrics": {"precision": 1.0, "recall": 1.0, "f1_score": 1.0},
                    },
                },
            }
        },
    )
    db.update_benchmark_status("bench-1", "completed")

    groups = db.summarize_benchmark_groups(group="pre-auth")

    assert len(groups) == 1
    assert groups[0]["name"] == "pre-auth-fix"
    assert groups[0]["role_breakdown"]["auth"]["avg_f1_score"] == 0.5
    assert groups[0]["role_breakdown"]["recon"]["avg_recall"] == 1.0


def test_list_manual_finding_provenance_collects_note_and_replay_history(tmp_path):
    db = Database(str(tmp_path / "guardian.db"))
    db.create_scan("scan-1", "http://localhost/graphql", {"profile": "default"})
    db.save_scan_results(
        "scan-1",
        {
            "summary": {"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "findings": [],
            "metadata": {"endpoint": "http://localhost/graphql"},
        },
    )
    db.save_manual_note(
        scan_id="scan-1",
        operation_name="Query.user",
        status="confirmed",
        observations="Confirmed BOLA on user query.",
        payload_tweaks="Changed id from 1 to 2",
        request_override={"query": 'query { user(id: "2") { id } }', "variables": {}},
    )
    db.save_manual_replay(
        scan_id="scan-1",
        operation_name="Query.user",
        request_override={"query": 'query { user(id: "2") { id } }', "variables": {}},
        replay_result={"status_code": 200, "ok": True, "body": {"data": {"user": {"id": "2"}}}},
    )
    promoted = db.promote_manual_note_to_finding(
        "scan-1",
        "Query.user",
        {
            "category": "AUTH",
            "severity": "HIGH",
            "title": "Manual validation: Query.user",
            "description": "Confirmed BOLA on user query.",
        },
    )

    bundles = db.list_manual_finding_provenance("scan-1", finding_id=promoted["finding"]["id"])

    assert len(bundles) == 1
    assert bundles[0]["note"]["status"] == "confirmed"
    assert bundles[0]["request_override"]["query"] == 'query { user(id: "2") { id } }'
    assert bundles[0]["replay_history_count"] == 1
    assert bundles[0]["promotion"]["manual_mode_path"] == "/manual/scan-1?op=Query.user"


def test_list_benchmarks_includes_role_breakdown_for_completed_runs(tmp_path):
    db = Database(str(tmp_path / "guardian.db"))
    db.create_benchmark(
        benchmark_id="bench-1",
        endpoint="http://localhost:5000/graphql",
        config={"label": "auth tuning", "group": "post-auth-fix"},
    )
    db.save_benchmark_results(
        "bench-1",
        {
            "benchmark": {
                "metrics": {"precision": 0.8, "recall": 0.6, "f1_score": 0.6857},
                "role_breakdown": {
                    "auth": {
                        "truth_count": 4,
                        "metrics": {"precision": 0.75, "recall": 0.5, "f1_score": 0.6},
                    }
                },
            }
        },
    )
    db.update_benchmark_status("bench-1", "completed")

    rows = db.list_benchmarks(limit=10, offset=0, group="post-auth")

    assert len(rows) == 1
    assert rows[0]["role_breakdown"]["auth"]["metrics"]["f1_score"] == 0.6
