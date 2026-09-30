import sys
from types import SimpleNamespace

import pytest

from src.reporters.models import Finding
from src.scanner.llm_validator import LLMValidator


def _finding():
    return Finding(
        title="Reviewed Sensitive Field: User.email",
        description="Potentially sensitive field.",
        severity="MEDIUM",
        category="AUDIT",
        field="User.email",
    )


def test_llm_validator_parses_string_boolean_without_treating_false_as_true():
    validator = LLMValidator(api_key="test")
    payload = validator._parse_json_response(
        '{"is_false_positive":"false","confidence":"1.4","reasoning":"ok","recommendation":"review"}'
    )

    assert validator._parse_bool(payload["is_false_positive"]) is False
    assert validator._parse_confidence(payload["confidence"]) == 1.0


def test_llm_filter_keeps_low_confidence_results():
    validator = LLMValidator(api_key=None)
    finding = _finding()

    validator.enabled = True
    validator.validate_finding = lambda _finding, _context: {
        "validated": True,
        "confidence": 0.4,
        "reasoning": "uncertain",
        "is_false_positive": True,
    }

    assert validator.filter_false_positives([finding], {}) == [finding]


def test_llm_filter_removes_only_high_confidence_false_positive():
    validator = LLMValidator(api_key=None)
    finding = _finding()

    validator.enabled = True
    validator.validate_finding = lambda _finding, _context: {
        "validated": True,
        "confidence": 0.9,
        "reasoning": "metadata only",
        "is_false_positive": True,
    }

    assert validator.filter_false_positives([finding], {}) == []


def test_openai_validation_supports_responses_client(monkeypatch):
    class Responses:
        def create(self, **_kwargs):
            return SimpleNamespace(
                output_text=(
                    '{"decision":"valid","confidence":0.8,"reason":"field is sensitive",'
                    '"evidence_used":["field name"],"manual_check":"verify role access"}'
                )
            )

    class FakeOpenAI:
        def __init__(self, api_key):
            self.api_key = api_key
            self.responses = Responses()

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=FakeOpenAI))

    result = LLMValidator(api_key="test", provider="openai")._validate_with_openai("prompt")

    assert result["is_false_positive"] is False
    assert result["decision"] == "valid"
    assert result["reason"] == "field is sensitive"
    assert result["confidence"] == 0.8


def test_openai_validation_requires_responses_client(monkeypatch):
    class ChatCompletions:
        def create(self, **_kwargs):
            message = SimpleNamespace(
                content='{"is_false_positive":"true","confidence":"0.9","reasoning":"metadata","recommendation":"drop"}'
            )
            return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    class FakeOpenAI:
        def __init__(self, api_key):
            self.api_key = api_key
            self.chat = SimpleNamespace(completions=ChatCompletions())

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=FakeOpenAI))

    with pytest.raises(RuntimeError, match="Responses API"):
        LLMValidator(api_key="test", provider="openai")._validate_with_openai("prompt")


def test_gemini_validation_uses_generate_content(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "responseId": "gemini-response-1",
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": (
                                        '{"decision":"likely_false_positive","confidence":0.9,'
                                        '"reason":"metadata","evidence_used":["field type"],'
                                        '"manual_check":"confirm with tester"}'
                                    )
                                }
                            ]
                        }
                    }
                ],
            }

    calls = {}

    def fake_post(url, **kwargs):
        calls["url"] = url
        calls["kwargs"] = kwargs
        return FakeResponse()

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(post=fake_post))

    result = LLMValidator(api_key="test", provider="gemini", model_name="gemini-test")._validate_with_gemini("prompt")

    assert "gemini-test:generateContent" in calls["url"]
    assert calls["kwargs"]["params"]["key"] == "test"
    assert result["provider"] == "gemini"
    assert result["decision"] == "likely_false_positive"
    assert result["is_false_positive"] is True
    assert result["confidence"] == 0.9


def test_ollama_validation_uses_local_chat_endpoint(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "model": "qwen3:8b",
                "message": {
                    "content": (
                        '{"decision":"valid","confidence":0.82,'
                        '"reason":"field and parent type indicate PII",'
                        '"evidence_used":["field name","parent type"],'
                        '"manual_check":"verify role access"}'
                    )
                },
            }

    calls = {}

    def fake_post(url, **kwargs):
        calls["url"] = url
        calls["kwargs"] = kwargs
        return FakeResponse()

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(post=fake_post))

    result = LLMValidator(provider="ollama", model_name="qwen3:8b")._validate_with_ollama("prompt")

    assert calls["url"] == "http://localhost:11434/api/chat"
    assert calls["kwargs"]["json"]["model"] == "qwen3:8b"
    response_schema = calls["kwargs"]["json"]["format"]
    assert response_schema["type"] == "object"
    assert response_schema["properties"]["decision"]["enum"] == [
        "valid",
        "needs_manual_review",
        "likely_false_positive",
    ]
    assert calls["kwargs"]["json"]["think"] is False
    assert calls["kwargs"]["json"]["keep_alive"] == "10m"
    assert calls["kwargs"]["json"]["options"]["num_predict"] == 512
    assert calls["kwargs"]["timeout"] == (10, 300)
    assert result["provider"] == "ollama"
    assert result["decision"] == "valid"
    assert result["confidence"] == 0.82


def test_llm_prompt_uses_structured_security_evidence_only():
    finding = Finding(
        title="Reviewed Sensitive Field: User.email",
        description="Sensitive field candidate.",
        severity="MEDIUM",
        category="AUDIT",
        field="User.email",
        rule_id="GG-AUDIT-SENSITIVE-FIELD-REVIEWED",
        evidence={
            "location": "User.email",
            "field_type": "String",
            "matched_keywords": ["email"],
            "body_sample": '{"email":"alice@example.com","id":"1"}',
            "review_reasons": ["Matched PII naming rule."],
        },
    )
    schema_context = {
        "field": "User.email",
        "parent_type": "User",
        "field_definition": {
            "name": "email",
            "type": {"kind": "SCALAR", "name": "String"},
            "args": [{"name": "id", "type": {"kind": "SCALAR", "name": "ID"}}],
        },
    }

    validator = LLMValidator(api_key="test", provider="gemini")
    structured = validator._build_structured_evidence(finding, schema_context)
    prompt = validator._build_validation_prompt(structured)

    assert structured["field_name"] == "email"
    assert structured["parent_type"] == "User"
    assert structured["graphql_return_type"] == "String"
    assert structured["arguments"] == [{"name": "id", "type": "ID"}]
    assert structured["returned_sample_shape"] == {"email": "str", "id": "str"}
    assert "whole project" not in prompt.lower()
    assert '"decision": "valid"' in prompt
    assert "alice@example.com" not in prompt


def test_finding_serialization_preserves_ai_validation():
    finding = _finding()
    finding.ai_validation = {
        "decision": "needs_manual_review",
        "confidence": 0.6,
        "reason": "schema exposure without response evidence",
        "evidence_used": ["field name", "field type"],
        "manual_check": "verify role-based access",
    }

    data = finding.to_dict()

    assert data["ai_validation"]["decision"] == "needs_manual_review"
    assert data["ai_validation"]["manual_check"] == "verify role-based access"
