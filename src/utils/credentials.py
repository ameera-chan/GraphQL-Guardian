"""Per-user credential helpers for optional AI features."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict


CONFIG_DIR_ENV = "GUARDQL_CONFIG_DIR"
LLM_PROVIDER_ENV = "GUARDQL_LLM_PROVIDER"
DEFAULT_LLM_PROVIDER = "ollama"
OLLAMA_BASE_URL_ENV = "GUARDQL_OLLAMA_BASE_URL"
OLLAMA_MODEL_ENV = "GUARDQL_OLLAMA_MODEL"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "qwen3:8b"
FALLBACK_OLLAMA_MODEL = "llama3.1:8b"
GEMINI_KEY_ENV = "GEMINI_API_KEY"
GEMINI_MODEL_ENV = "GUARDQL_GEMINI_MODEL"
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash"
OPENAI_KEY_ENV = "OPENAI_API_KEY"
OPENAI_MODEL_ENV = "GUARDQL_OPENAI_MODEL"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"


SUPPORTED_LLM_PROVIDERS = {"ollama", "gemini", "openai"}


def guardql_config_dir() -> Path:
    configured = os.getenv(CONFIG_DIR_ENV)
    if configured:
        return Path(configured).expanduser()

    xdg_config_home = os.getenv("XDG_CONFIG_HOME")
    if xdg_config_home:
        return Path(xdg_config_home).expanduser() / "guardql"

    return Path.home() / ".config" / "guardql"


def credentials_file() -> Path:
    return guardql_config_dir() / "credentials.env"


def _parse_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def load_user_credentials() -> Dict[str, str]:
    return _parse_env_file(credentials_file())


def save_user_credentials(
    openai_api_key: str | None = None,
    openai_model: str | None = None,
    *,
    provider: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
) -> Path:
    path = credentials_file()
    path.parent.mkdir(parents=True, exist_ok=True)

    current = load_user_credentials()
    selected_provider = (provider or current.get(LLM_PROVIDER_ENV) or DEFAULT_LLM_PROVIDER).strip().lower()
    if selected_provider not in SUPPORTED_LLM_PROVIDERS:
        selected_provider = DEFAULT_LLM_PROVIDER
    current[LLM_PROVIDER_ENV] = selected_provider

    if api_key is not None:
        if selected_provider == "gemini":
            current[GEMINI_KEY_ENV] = api_key.strip()
        elif selected_provider == "openai":
            current[OPENAI_KEY_ENV] = api_key.strip()
    if model is not None:
        if selected_provider == "ollama":
            current[OLLAMA_MODEL_ENV] = model.strip() or DEFAULT_OLLAMA_MODEL
        elif selected_provider == "gemini":
            current[GEMINI_MODEL_ENV] = model.strip() or DEFAULT_GEMINI_MODEL
        else:
            current[OPENAI_MODEL_ENV] = model.strip() or DEFAULT_OPENAI_MODEL
    if base_url is not None and selected_provider == "ollama":
        current[OLLAMA_BASE_URL_ENV] = base_url.strip().rstrip("/") or DEFAULT_OLLAMA_BASE_URL

    if openai_api_key is not None:
        current[OPENAI_KEY_ENV] = openai_api_key.strip()
        current[LLM_PROVIDER_ENV] = "openai"
    if openai_model is not None:
        current[OPENAI_MODEL_ENV] = openai_model.strip() or DEFAULT_OPENAI_MODEL
        current[LLM_PROVIDER_ENV] = "openai"

    lines = [
        "# GraphQL Guardian user credentials",
        "# Keep this file private. Do not commit it.",
    ]
    if current.get(LLM_PROVIDER_ENV):
        lines.append(f"{LLM_PROVIDER_ENV}={current[LLM_PROVIDER_ENV]}")
    if current.get(OLLAMA_BASE_URL_ENV):
        lines.append(f"{OLLAMA_BASE_URL_ENV}={current[OLLAMA_BASE_URL_ENV]}")
    if current.get(OLLAMA_MODEL_ENV):
        lines.append(f"{OLLAMA_MODEL_ENV}={current[OLLAMA_MODEL_ENV]}")
    if current.get(GEMINI_KEY_ENV):
        lines.append(f"{GEMINI_KEY_ENV}={current[GEMINI_KEY_ENV]}")
    if current.get(GEMINI_MODEL_ENV):
        lines.append(f"{GEMINI_MODEL_ENV}={current[GEMINI_MODEL_ENV]}")
    if current.get(OPENAI_KEY_ENV):
        lines.append(f"{OPENAI_KEY_ENV}={current[OPENAI_KEY_ENV]}")
    if current.get(OPENAI_MODEL_ENV):
        lines.append(f"{OPENAI_MODEL_ENV}={current[OPENAI_MODEL_ENV]}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def clear_user_credentials() -> None:
    path = credentials_file()
    if path.exists():
        path.unlink()


def get_openai_api_key() -> str | None:
    return os.getenv(OPENAI_KEY_ENV) or load_user_credentials().get(OPENAI_KEY_ENV)


def get_openai_model(default: str = DEFAULT_OPENAI_MODEL) -> str:
    return os.getenv(OPENAI_MODEL_ENV) or load_user_credentials().get(OPENAI_MODEL_ENV) or default


def get_llm_provider(default: str = DEFAULT_LLM_PROVIDER) -> str:
    provider = os.getenv(LLM_PROVIDER_ENV) or load_user_credentials().get(LLM_PROVIDER_ENV) or default
    provider = provider.strip().lower()
    return provider if provider in SUPPORTED_LLM_PROVIDERS else default


def get_llm_api_key(provider: str | None = None) -> str | None:
    selected_provider = (provider or get_llm_provider()).strip().lower()
    if selected_provider == "ollama":
        return None
    if selected_provider == "openai":
        return get_openai_api_key()
    return os.getenv(GEMINI_KEY_ENV) or load_user_credentials().get(GEMINI_KEY_ENV)


def get_llm_model(provider: str | None = None) -> str:
    selected_provider = (provider or get_llm_provider()).strip().lower()
    if selected_provider == "ollama":
        return os.getenv(OLLAMA_MODEL_ENV) or load_user_credentials().get(OLLAMA_MODEL_ENV) or DEFAULT_OLLAMA_MODEL
    if selected_provider == "openai":
        return get_openai_model()
    return os.getenv(GEMINI_MODEL_ENV) or load_user_credentials().get(GEMINI_MODEL_ENV) or DEFAULT_GEMINI_MODEL


def get_ollama_base_url(default: str = DEFAULT_OLLAMA_BASE_URL) -> str:
    return (os.getenv(OLLAMA_BASE_URL_ENV) or load_user_credentials().get(OLLAMA_BASE_URL_ENV) or default).rstrip("/")


def mask_secret(value: str | None) -> str:
    if not value:
        return "<not set>"
    if len(value) <= 10:
        return value[:2] + "***"
    return value[:6] + "***" + value[-4:]
