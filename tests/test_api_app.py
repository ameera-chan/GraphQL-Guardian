import importlib
from fastapi.testclient import TestClient
from src.api.database import Database

app_module = importlib.import_module("src.api.app")

class _Elapsed:
    def __init__(self, seconds):
        self._seconds = seconds

    def total_seconds(self):
        return self._seconds


class _Response:
    def __init__(self):
        self.ok = True
        self.status_code = 200
        self.headers = {"content-type": "application/json"}
        self.elapsed = _Elapsed(0.123)

    def json(self):
        return {"data": {"user": {"id": "2"}}}


def test_manual_replay_endpoint_persists_response(tmp_path, monkeypatch):
    temp_db = Database(str(tmp_path / "guardian.db"))
    temp_db.create_scan("scan-1", "http://localhost/graphql", {"profile": "default"})

    monkeypatch.setattr(app_module, "db", temp_db)
    monkeypatch.setattr(app_module.requests, "post", lambda *args, **kwargs: _Response())

    client = TestClient(app_module.app)
    response = client.post(
        "/scan/scan-1/manual-replay",
        json={
            "operation_name": "Query.user",
            "status": "retested",
            "observations": "User 2 data is still exposed.",
            "payload_tweaks": "Changed id to 2",
            "request_override": {
                "query": 'query { user(id: "2") { id } }',
                "variables": {},
            },
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["last_replay"]["status_code"] == 200
    assert payload["last_replay"]["body"]["data"]["user"]["id"] == "2"

    saved_note = temp_db.get_manual_note("scan-1", "Query.user")
    assert saved_note["status"] == "retested"
    assert saved_note["last_replay"]["elapsed_ms"] == 123.0
    history = temp_db.list_manual_replays("scan-1", "Query.user", limit=5)
    assert history[0]["replay_result"]["status_code"] == 200


def test_scan_endpoint_accepts_localhost_target(tmp_path, monkeypatch):
    temp_db = Database(str(tmp_path / "guardian.db"))
    monkeypatch.setattr(app_module, "db", temp_db)
    monkeypatch.setattr(app_module, "active_tasks", {})

    async def noop_run_scan(task_id, task):
        return None

    monkeypatch.setattr(app_module, "run_scan", noop_run_scan)

    client = TestClient(app_module.app)
    response = client.post(
        "/scan",
        json={
            "endpoint": "http://localhost:5013/graphql",
            "enable_ml": False,
            "enable_llm": False,
            "risk_level": 1,
            "technique": "IDAC",
            "profile": "default",
        },
    )

    assert response.status_code == 200
    assert response.json()["scan_id"]


def test_benchmark_endpoint_accepts_localhost_target(tmp_path, monkeypatch):
    temp_db = Database(str(tmp_path / "guardian.db"))
    monkeypatch.setattr(app_module, "db", temp_db)
    monkeypatch.setattr(app_module, "active_benchmark_tasks", {})

    async def noop_run_benchmark(benchmark_id, task):
        return None

    monkeypatch.setattr(app_module, "run_benchmark", noop_run_benchmark)

    client = TestClient(app_module.app)
    response = client.post(
        "/benchmarks/dvga",
        json={
            "endpoint": "http://localhost:5013/graphql",
            "label": "local",
            "group": "dvga",
            "profile": "default",
            "enable_ml": False,
            "enable_llm": False,
        },
    )

    assert response.status_code == 200
    assert response.json()["benchmark_id"]


def test_promote_manual_note_endpoint_updates_report(tmp_path, monkeypatch):
    temp_db = Database(str(tmp_path / "guardian.db"))
    temp_db.create_scan("scan-1", "http://localhost/graphql", {"profile": "default"})
    temp_db.save_scan_results(
        "scan-1",
        {
            "summary": {"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "findings": [],
            "metadata": {"endpoint": "http://localhost/graphql"},
        },
    )
    temp_db.save_manual_note(
        scan_id="scan-1",
        operation_name="Query.user",
        status="confirmed",
        observations="Confirmed BOLA on user query.",
        payload_tweaks="Changed id to 2",
        request_override={
            "query": 'query { user(id: "2") { id } }',
            "variables": {},
        },
    )

    monkeypatch.setattr(app_module, "db", temp_db)

    client = TestClient(app_module.app)
    response = client.post(
        "/scan/scan-1/manual-note/promote",
        json={
            "operation_name": "Query.user",
            "severity": "HIGH",
            "category": "AUTH",
            "title": "Manual validation: Query.user",
            "description": "Confirmed BOLA on user query.",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["finding"]["source"] == "manual"
    assert payload["finding"]["provenance"]["replay_history_count"] == 0
    assert payload["summary"]["critical"] == 1
    assert payload["finding"]["severity"] == "CRITICAL"
    assert temp_db.get_scan_results("scan-1")["findings"][0]["title"] == "Manual validation: Query.user"


def test_manual_provenance_export_endpoint_returns_note_and_replay_history(tmp_path, monkeypatch):
    temp_db = Database(str(tmp_path / "guardian.db"))
    temp_db.create_scan("scan-1", "http://localhost/graphql", {"profile": "default"})
    temp_db.save_scan_results(
        "scan-1",
        {
            "summary": {"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "findings": [],
            "metadata": {"endpoint": "http://localhost/graphql"},
        },
    )
    temp_db.save_manual_note(
        scan_id="scan-1",
        operation_name="Query.user",
        status="confirmed",
        observations="Confirmed BOLA on user query.",
        payload_tweaks="Changed id to 2",
        request_override={
            "query": 'query { user(id: "2") { id } }',
            "variables": {},
        },
    )
    temp_db.save_manual_replay(
        scan_id="scan-1",
        operation_name="Query.user",
        request_override={
            "query": 'query { user(id: "2") { id } }',
            "variables": {},
        },
        replay_result={"status_code": 200, "ok": True, "body": {"data": {"user": {"id": "2"}}}},
    )
    promoted = temp_db.promote_manual_note_to_finding(
        "scan-1",
        "Query.user",
        {
            "severity": "HIGH",
            "category": "AUTH",
            "title": "Manual validation: Query.user",
            "description": "Confirmed BOLA on user query.",
        },
    )
    temp_db.update_scan_status("scan-1", "completed")

    monkeypatch.setattr(app_module, "db", temp_db)

    client = TestClient(app_module.app)
    response = client.get(
        f"/scan/scan-1/export/manual-provenance?format=json&finding_id={promoted['finding']['id']}"
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["finding_id"] == promoted["finding"]["id"]
    assert payload["items"][0]["note"]["status"] == "confirmed"
    assert payload["items"][0]["replay_history"][0]["replay_result"]["status_code"] == 200


def test_finding_dossier_and_relationship_exports_work_for_completed_scan(tmp_path, monkeypatch):
    temp_db = Database(str(tmp_path / "guardian.db"))
    temp_db.create_scan("scan-1", "http://localhost/graphql", {"profile": "default"})
    temp_db.save_scan_results(
        "scan-1",
        {
            "summary": {"total": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
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
                    "reproduction": "curl ...",
                    "evidence": {"reproduction": "curl ..."},
                }
            ],
            "metadata": {"endpoint": "http://localhost/graphql"},
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
                    {"path": "Query.user", "target_type": "User", "score": 80}
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
        },
    )
    temp_db.update_scan_status("scan-1", "completed")

    monkeypatch.setattr(app_module, "db", temp_db)
    client = TestClient(app_module.app)

    dossier_response = client.get("/scan/scan-1/export/finding-dossier?format=json")
    relationship_response = client.get("/scan/scan-1/export/relationship-map?format=txt")

    assert dossier_response.status_code == 200
    dossier_payload = dossier_response.json()
    assert dossier_payload["summary"]["total_items"] == 1
    assert dossier_payload["items"][0]["relationship_context"]["location"] == "User.email"

    assert relationship_response.status_code == 200
    assert "## User.email" in relationship_response.text
    assert "Query.user" in relationship_response.text
