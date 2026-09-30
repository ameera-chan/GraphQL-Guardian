from click.testing import CliRunner

from src.main import cli
from src.scanner.llm_validator import LLMValidator
from src.utils.credentials import credentials_file, get_llm_api_key, get_llm_model, get_llm_provider, get_ollama_base_url


def test_config_ai_stores_per_user_ollama_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDQL_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("GUARDQL_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("GUARDQL_OLLAMA_MODEL", raising=False)
    monkeypatch.delenv("GUARDQL_OLLAMA_BASE_URL", raising=False)

    result = CliRunner().invoke(
        cli,
        ["config", "ai"],
        input="qwen3:8b\nhttp://localhost:11434\n",
    )

    assert result.exit_code == 0
    assert credentials_file().exists()
    assert get_llm_provider() == "ollama"
    assert get_llm_api_key("ollama") is None
    assert get_llm_model("ollama") == "qwen3:8b"
    assert get_ollama_base_url() == "http://localhost:11434"


def test_config_ai_show_masks_key_and_env_overrides_saved_key(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDQL_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("GUARDQL_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("GUARDQL_OLLAMA_MODEL", raising=False)
    CliRunner().invoke(cli, ["config", "ai"], input="qwen3:8b\nhttp://localhost:11434\n")

    monkeypatch.setenv("GUARDQL_OLLAMA_MODEL", "llama3.1:8b")
    result = CliRunner().invoke(cli, ["config", "ai", "--show"])

    assert result.exit_code == 0
    assert "Ollama base URL" in result.output
    assert "llama3.1:8b" in result.output
    assert LLMValidator().provider == "ollama"
    assert LLMValidator().api_key is None
    assert LLMValidator().model_name == "llama3.1:8b"


def test_config_ai_clear_removes_saved_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDQL_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("GUARDQL_OLLAMA_MODEL", raising=False)
    CliRunner().invoke(cli, ["config", "ai"], input="qwen3:8b\nhttp://localhost:11434\n")

    result = CliRunner().invoke(cli, ["config", "ai", "--clear"])

    assert result.exit_code == 0
    assert not credentials_file().exists()
