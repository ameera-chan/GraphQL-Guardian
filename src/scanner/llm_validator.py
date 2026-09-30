"""LLM-based validation to reduce false positives."""

from __future__ import annotations

import json
import re
import sys
from typing import Any, Dict, List, Optional

from src.reporters.models import Finding
from src.utils.credentials import get_llm_api_key, get_llm_model, get_llm_provider, get_ollama_base_url


class LLMValidator:
    """Use an LLM provider to review security findings before they are reported."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        provider: Optional[str] = None,
    ):
        self.provider = (provider or get_llm_provider()).strip().lower()
        if self.provider not in {"ollama", "gemini", "openai"}:
            raise ValueError("Unsupported LLM provider. Use 'ollama', 'gemini', or 'openai'.")
        self.api_key = api_key or get_llm_api_key(self.provider)
        self.model_name = model_name or get_llm_model(self.provider)
        self.ollama_base_url = get_ollama_base_url()
        self.enabled = self.provider == "ollama" or bool(self.api_key)

        if not self.enabled:
            env_name = "GEMINI_API_KEY" if self.provider == "gemini" else "OPENAI_API_KEY"
            print(f"[!] LLM validation disabled: {env_name} is not set", file=sys.stderr)

    def validate_finding(self, finding: Finding, schema_context: Dict) -> Dict:
        """Ask the configured LLM whether a finding looks true positive or false positive."""
        if not self.enabled:
            return self._disabled_result()

        # Send only structured scanner evidence, not the full project or raw private data.
        structured_evidence = self._build_structured_evidence(finding, schema_context)
        prompt = self._build_validation_prompt(structured_evidence)

        try:
            if self.provider == "ollama":
                return self._validate_with_ollama(prompt)
            if self.provider == "gemini":
                return self._validate_with_gemini(prompt)
            return self._validate_with_openai(prompt)
        except Exception as exc:
            print(f"[!] {self.provider.title()} validation error: {exc}", file=sys.stderr)
            return {
                "validated": False,
                "decision": "needs_manual_review",
                "confidence": 0.0,
                "reason": f"{self.provider.title()} validation error: {exc}",
                "reasoning": f"{self.provider.title()} validation error: {exc}",
                "evidence_used": [],
                "manual_check": "Review the scanner evidence manually because AI validation failed.",
                "is_false_positive": False,
                "recommendation": "Manual review recommended",
                "remediation": "",
                "error": True,
            }

    def batch_validate_findings(self, findings: List[Finding], schema: Dict) -> List[Dict]:
        """Validate multiple findings."""
        results = []
        for finding in findings:
            context = self._extract_schema_context(finding, schema)
            results.append({"finding": finding, "validation": self.validate_finding(finding, context)})
        return results

    def filter_false_positives(
        self,
        findings: List[Finding],
        schema: Dict,
        confidence_threshold: float = 0.7,
    ) -> List[Finding]:
        """Return findings kept after LLM validation."""
        if not self.enabled:
            return findings

        kept = []
        for finding in findings:
            context = self._extract_schema_context(finding, schema)
            validation = self.validate_finding(finding, context)
            if not (validation["is_false_positive"] and validation["confidence"] >= confidence_threshold):
                kept.append(finding)
        return kept

    def _build_validation_prompt(self, structured_evidence: Dict[str, Any]) -> str:
        # Keep the scanner result as the main source and ask for a bounded JSON review.
        return f"""You are a GraphQL security reviewer. Review only the structured evidence below.

Task:
- Keep GraphQL Guardian's scanner result as the main evidence.
- Decide whether the finding is valid, needs manual review, or is likely a false positive.
- Do not invent schema fields, responses, users, or exploit results.
- If evidence is weak, choose "needs_manual_review".

Structured security evidence:
{json.dumps(structured_evidence, indent=2)}

Return only JSON:
{{
  "decision": "valid",
  "reason": "short reason based only on evidence_used",
  "confidence": 0.0,
  "evidence_used": ["field name", "parent type"],
  "manual_check": "specific verification step",
  "remediation": "short fix suggestion"
}}

Allowed decision values: "valid", "needs_manual_review", "likely_false_positive".
`confidence` must be a number from 0.0 to 1.0."""

    def _validate_with_openai(self, prompt: str) -> Dict:
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError("OpenAI package is not installed. Install python3-openai or pip install openai.") from exc

        client = OpenAI(api_key=self.api_key)
        if not hasattr(client, "responses"):
            raise RuntimeError("Installed OpenAI package does not support Responses API. Upgrade with: pip install -U openai")

        response = client.responses.create(
            model=self.model_name,
            input=[
                {"role": "system", "content": "You are a GraphQL security expert. Return valid JSON only."},
                {"role": "user", "content": prompt},
            ],
            max_output_tokens=500,
        )
        result_text = getattr(response, "output_text", "")
        response_id = getattr(response, "id", None)

        result = self._parse_json_response(result_text or "")
        return self._format_validation_result(result, "openai", response_id)

    def _validate_with_ollama(self, prompt: str) -> Dict:
        try:
            import requests
        except ImportError as exc:
            raise RuntimeError("Requests package is not installed.") from exc

        url = f"{self.ollama_base_url}/api/chat"
        # Ollama runs locally and is requested to return JSON for repeatable parsing.
        response_schema = {
            "type": "object",
            "properties": {
                "decision": {
                    "type": "string",
                    "enum": ["valid", "needs_manual_review", "likely_false_positive"],
                },
                "reason": {"type": "string"},
                "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "evidence_used": {
                    "type": "array",
                    "items": {"type": "string"},
                    "maxItems": 8,
                },
                "manual_check": {"type": "string"},
                "remediation": {"type": "string"},
            },
            "required": [
                "decision",
                "reason",
                "confidence",
                "evidence_used",
                "manual_check",
                "remediation",
            ],
            "additionalProperties": False,
        }
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": "You are a GraphQL security expert. Return valid JSON only."},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            # Security review only needs a short verdict. Disabling Qwen's
            # thinking mode avoids long CPU-only generations and timeouts.
            "think": False,
            "format": response_schema,
            "keep_alive": "10m",
            "options": {
                "temperature": 0.0,
                "top_p": 0.9,
                "num_predict": 512,
                "num_ctx": 4096,
            },
        }
        response = requests.post(url, json=payload, timeout=(10, 300))
        response.raise_for_status()
        data = response.json()
        result_text = data.get("message", {}).get("content") or data.get("response") or ""
        if data.get("done_reason") == "length":
            raise ValueError("Ollama JSON response reached the output-token limit")
        result = self._parse_json_response(result_text)
        return self._format_validation_result(result, "ollama", data.get("model") or self.model_name)

    def _validate_with_gemini(self, prompt: str) -> Dict:
        try:
            import requests
        except ImportError as exc:
            raise RuntimeError("Requests package is not installed.") from exc

        schema = {
            "type": "OBJECT",
            "properties": {
                "decision": {
                    "type": "STRING",
                    "enum": ["valid", "needs_manual_review", "likely_false_positive"],
                },
                "reason": {"type": "STRING"},
                "confidence": {"type": "NUMBER"},
                "evidence_used": {
                    "type": "ARRAY",
                    "items": {"type": "STRING"},
                },
                "manual_check": {"type": "STRING"},
                "remediation": {"type": "STRING"},
            },
            "required": ["decision", "reason", "confidence", "evidence_used", "manual_check"],
        }
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent"
        payload = {
            "systemInstruction": {
                "parts": [{"text": "You are a GraphQL security expert. Return valid JSON only."}]
            },
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 500,
                "responseMimeType": "application/json",
                "responseSchema": schema,
            },
        }
        response = requests.post(url, params={"key": self.api_key}, json=payload, timeout=45)
        response.raise_for_status()
        data = response.json()
        result_text = self._extract_gemini_text(data)
        result = self._parse_json_response(result_text)
        response_id = data.get("responseId")
        return self._format_validation_result(result, "gemini", response_id)

    def _extract_gemini_text(self, data: Dict) -> str:
        candidates = data.get("candidates") or []
        if not candidates:
            raise ValueError("Gemini response did not contain candidates")
        parts = candidates[0].get("content", {}).get("parts", [])
        text = "".join(str(part.get("text", "")) for part in parts)
        if not text:
            raise ValueError("Gemini response did not contain text")
        return text

    def _format_validation_result(self, result: Dict, provider: str, response_id: Optional[str] = None) -> Dict:
        # Normalize all provider responses into the same finding validation format.
        decision = self._normalize_decision(result)
        reason = result.get("reason") or result.get("reasoning") or ""
        manual_check = result.get("manual_check") or result.get("recommendation") or ""
        evidence_used = result.get("evidence_used") or []
        if isinstance(evidence_used, str):
            evidence_used = [evidence_used]
        return {
            "validated": True,
            "decision": decision,
            "confidence": self._parse_confidence(result.get("confidence", 0.5)),
            "reason": reason,
            "reasoning": reason,
            "evidence_used": [str(item) for item in evidence_used[:8]],
            "manual_check": manual_check,
            "is_false_positive": decision == "likely_false_positive",
            "recommendation": result.get("remediation") or manual_check,
            "remediation": result.get("remediation", ""),
            "provider": provider,
            "model": self.model_name,
            "api_response_id": response_id,
        }

    def _build_structured_evidence(self, finding: Finding, schema_context: Dict) -> Dict[str, Any]:
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        field_definition = schema_context.get("field_definition") or {}
        field_name = schema_context.get("field") or finding.field or evidence.get("location") or ""
        parent_type = schema_context.get("parent_type") or evidence.get("parent_type") or ""
        graph_path = evidence.get("graphql_path") or evidence.get("location") or finding.field
        response = evidence.get("response") if isinstance(evidence.get("response"), dict) else {}

        if "." in field_name:
            split_parent, split_field = field_name.split(".", 1)
            parent_type = parent_type or split_parent
            field_name = split_field
        elif "." in str(graph_path) and not parent_type:
            parent_type = str(graph_path).split(".", 1)[0]

        field_type = evidence.get("field_type") or self._format_type_ref(field_definition.get("type")) or "Unknown"
        related_operations = evidence.get("related_operations") or evidence.get("operations") or []
        if isinstance(related_operations, str):
            related_operations = [related_operations]

        # These fields are the feature set used by the LLM review stage.
        return {
            "field_name": field_name,
            "parent_type": parent_type,
            "graphql_path": graph_path or "N/A",
            "graphql_return_type": field_type,
            "operation": finding.operation_name or evidence.get("operation") or "unknown",
            "operation_context": evidence.get("operation_context") or evidence.get("candidate_source") or "scanner_finding",
            "arguments": self._compact_args(field_definition.get("args") or evidence.get("arguments") or []),
            "auth_role_used": evidence.get("auth_role") or evidence.get("role") or "unknown",
            "response_status": evidence.get("response_status") or response.get("status_code") or "unknown",
            "graphql_errors": self._compact_list(evidence.get("graphql_errors") or response.get("graphql_errors") or []),
            "returned_sample_shape": self._sample_shape(
                evidence.get("returned_sample_shape")
                or evidence.get("sample_shape")
                or evidence.get("body_sample")
                or response.get("body_sample")
            ),
            "scanner_rule": finding.rule_id or evidence.get("rule_id") or evidence.get("candidate_kind") or finding.category,
            "scanner_reason": evidence.get("reasoning") or evidence.get("review_reasons") or finding.description,
            "scanner_confidence": finding.confidence,
            "scanner_state": finding.state,
            "matched_keywords": self._compact_list(evidence.get("matched_keywords") or []),
            "ml_score": evidence.get("ml_score"),
            "ml_components": evidence.get("ml_components"),
            "related_operations": self._compact_list(related_operations),
        }

    def _format_type_ref(self, type_ref: Any) -> str:
        if not isinstance(type_ref, dict):
            return ""
        kind = type_ref.get("kind")
        name = type_ref.get("name")
        if kind == "NON_NULL":
            return f"{self._format_type_ref(type_ref.get('ofType'))}!"
        if kind == "LIST":
            return f"[{self._format_type_ref(type_ref.get('ofType'))}]"
        return name or kind or ""

    def _compact_args(self, args: Any) -> List[Dict[str, Any]]:
        if not isinstance(args, list):
            return []
        compacted = []
        for item in args[:8]:
            if isinstance(item, dict):
                compacted.append(
                    {
                        "name": item.get("name"),
                        "type": self._format_type_ref(item.get("type")) or item.get("type"),
                    }
                )
        return compacted

    def _compact_list(self, value: Any, limit: int = 8) -> List[Any]:
        if value in (None, ""):
            return []
        if not isinstance(value, list):
            value = [value]
        return value[:limit]

    def _sample_shape(self, value: Any) -> Any:
        if value in (None, ""):
            return "not captured"
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except Exception:
                stripped = value.strip()
                if not stripped:
                    return "not captured"
                if len(stripped) > 120:
                    return {"text_sample_length": len(stripped), "text_prefix": stripped[:80]}
                return {"text_sample_length": len(stripped), "text_prefix": stripped}
            return self._shape_of(parsed)
        return self._shape_of(value)

    def _shape_of(self, value: Any, depth: int = 0) -> Any:
        if depth >= 3:
            return type(value).__name__
        if isinstance(value, dict):
            return {str(key): self._shape_of(nested, depth + 1) for key, nested in list(value.items())[:8]}
        if isinstance(value, list):
            if not value:
                return []
            return [self._shape_of(value[0], depth + 1)]
        return type(value).__name__

    def _normalize_decision(self, result: Dict) -> str:
        decision = str(result.get("decision") or "").strip().lower().replace("-", "_")
        if decision in {"valid", "true_positive", "keep"}:
            return "valid"
        if decision in {"likely_false_positive", "false_positive", "reject"}:
            return "likely_false_positive"
        if "is_false_positive" in result:
            return "likely_false_positive" if self._parse_bool(result.get("is_false_positive")) else "valid"
        return "needs_manual_review"

    def _parse_json_response(self, text: str) -> Dict:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if not match:
                raise ValueError("LLM response did not contain JSON")
            return json.loads(match.group(0))

    def _parse_bool(self, value) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"true", "yes", "1"}:
                return True
            if lowered in {"false", "no", "0", ""}:
                return False
        if isinstance(value, (int, float)):
            return bool(value)
        return False

    def _parse_confidence(self, value) -> float:
        try:
            confidence = float(value)
        except (TypeError, ValueError):
            return 0.5
        return min(max(confidence, 0.0), 1.0)

    def _disabled_result(self) -> Dict:
        return {
            "validated": False,
            "decision": "needs_manual_review",
            "confidence": 0.0,
            "reason": f"{self.provider.title()} validation disabled",
            "reasoning": f"{self.provider.title()} validation disabled",
            "evidence_used": [],
            "manual_check": "Configure an AI provider key, then rerun validation if AI review is required.",
            "is_false_positive": False,
            "recommendation": "Set GEMINI_API_KEY or choose OpenAI and set OPENAI_API_KEY",
            "remediation": "",
            "error": True,
        }

    def _extract_schema_context(self, finding: Finding, schema: Dict) -> Dict:
        context = {
            "finding_type": finding.category,
            "field": finding.field,
        }

        if finding.field and "." in finding.field:
            type_name, field_name = finding.field.split(".", 1)
            schema_data = schema.get("data", schema) if "data" in schema else schema
            type_map = {t["name"]: t for t in schema_data.get("__schema", {}).get("types", [])}

            type_def = type_map.get(type_name)
            if type_def:
                field_def = next(
                    (field for field in type_def.get("fields", []) if field["name"] == field_name),
                    None,
                )
                if field_def:
                    context["field_definition"] = {
                        "name": field_def["name"],
                        "type": field_def["type"],
                        "description": field_def.get("description"),
                        "args": field_def.get("args", []),
                    }
                    context["parent_type"] = type_name

        return context


class ValidationReport:
    """Report generator for LLM validation results."""

    @staticmethod
    def generate_report(validation_results: List[Dict]) -> str:
        """Generate human-readable validation report."""
        total = len(validation_results)
        false_positives = sum(1 for item in validation_results if item["validation"]["is_false_positive"])

        report = [
            "=" * 60,
            "LLM VALIDATION REPORT",
            "=" * 60,
            f"Total Findings: {total}",
            f"False Positives Detected: {false_positives}",
            f"True Positives: {total - false_positives}",
            "",
            "Detailed Results:",
            "-" * 60,
        ]

        for result in validation_results:
            finding = result["finding"]
            validation = result["validation"]
            status = "FALSE POSITIVE" if validation["is_false_positive"] else "TRUE POSITIVE"
            report.append(f"\n[{status}] {finding.title}")
            report.append(f"  Confidence: {validation['confidence']:.2f}")
            report.append(f"  Reasoning: {validation['reasoning']}")
            if validation.get("recommendation"):
                report.append(f"  Recommendation: {validation['recommendation']}")

        return "\n".join(report)
