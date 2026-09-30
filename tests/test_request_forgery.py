from src.config import PROFILE_DEFAULT
from src.scanner.request_forgery import RequestForgeryScanner


class _Elapsed:
    def __init__(self, seconds):
        self._seconds = seconds

    def total_seconds(self):
        return self._seconds


class _Response:
    def __init__(self, url, status_code, payload):
        self.url = url
        self.status_code = status_code
        self._payload = payload
        self.headers = {"content-type": "application/json"}
        self.elapsed = _Elapsed(0.02)
        self.text = str(payload)

    def json(self):
        return self._payload


def test_request_forgery_detects_form_encoded_mutation(monkeypatch):
    operation_pack = {
        "operations": [
            {
                "operation_type": "query",
                "operation_name": "Query.viewer",
                "operation": "query GuardianRequestForgery { __typename }",
            },
            {
                "operation_type": "mutation",
                "operation_name": "Mutation.updateUser",
                "operation": 'mutation { updateUser(id: "1") { id } }',
            },
        ]
    }

    def fake_get(url, params=None, **kwargs):
        return _Response(f"{url}?query=test", 405, {"errors": [{"message": "GET support disabled"}]})

    def fake_post(url, data=None, files=None, **kwargs):
        if data is not None:
            return _Response(url, 200, {"errors": [{"message": "Field 'updateUser' argument 'name' of type 'String!' is required"}]})
        return _Response(url, 415, {"errors": [{"message": "Unsupported Media Type"}]})

    monkeypatch.setattr("src.scanner.request_forgery.requests.get", fake_get)
    monkeypatch.setattr("src.scanner.request_forgery.requests.post", fake_post)

    scanner = RequestForgeryScanner(
        "http://localhost/graphql",
        operation_pack=operation_pack,
        profile=PROFILE_DEFAULT,
    )
    findings = scanner.run()

    assert scanner.report["summary"]["variants_tested"] == 6
    assert scanner.report["summary"]["variants_accepted"] == 2
    assert scanner.report["summary"]["mutation_variants_accepted"] == 1
    assert any(finding.title == "URL-encoded POST mutation Accepted" for finding in findings)

