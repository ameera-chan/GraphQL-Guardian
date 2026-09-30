"""Config-file scaffolding and validation commands for GraphQL Guardian."""

from __future__ import annotations

from pathlib import Path

import click
import yaml

from src.cli.commands.scan import _load_scan_config_file, _normalize_modules, resolve_scan_config
from src.cli.shared import DEFAULT_GRAPHQL_ENDPOINT, EXIT_RUNTIME_ERROR, kv, ok, warn
from src.utils.credentials import (
    DEFAULT_GEMINI_MODEL,
    DEFAULT_LLM_PROVIDER,
    DEFAULT_OLLAMA_BASE_URL,
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OPENAI_MODEL,
    FALLBACK_OLLAMA_MODEL,
    clear_user_credentials,
    credentials_file,
    get_llm_api_key,
    get_llm_model,
    get_llm_provider,
    get_ollama_base_url,
    mask_secret,
    save_user_credentials,
)


@click.group(name="config")
def config_group():
    """Inspect and validate scan configuration files."""


def _build_scan_template(
    endpoint,
    auth_config,
    profile,
    modules,
    fmt,
    report_output,
    discover,
    ml,
    llm_validate,
    fail_on_severity,
    authorization_header,
):
    payload = {
        "guardian": {
            "scan": {
                "endpoint": endpoint,
                "auth_config": auth_config or None,
                "schema": None,
                "format": fmt,
                "output": report_output,
                "profile": profile,
                "modules": list(modules),
                "level": 1,
                "risk": 1,
                "discover": discover,
                "verbose": False,
                "ml": ml,
                "llm_validate": llm_validate,
                "llm_provider": DEFAULT_LLM_PROVIDER,
                "llm_model": None,
                "proxy": None,
                "fail_on_severity": fail_on_severity,
                "json_stdout": False,
            }
        }
    }

    headers = {"X-Requested-With": "GraphQL-Guardian"}
    if authorization_header:
        headers["Authorization"] = authorization_header
    payload["guardian"]["scan"]["headers"] = headers
    return payload


@config_group.command("init")
@click.option("--output", default="scan.yaml", show_default=True, help="Where to write the generated config file.")
@click.option("--force", is_flag=True, help="Overwrite the output file without asking.")
def init_config(output, force):
    """Interactively scaffold a fresh scan config file.

    \b
    Examples:
      guardql config init
      guardql config init --output configs/passive-scan.yaml
    """
    output_path = Path(output)
    if output_path.exists() and not force:
        overwrite = click.confirm(f"{output_path} already exists. Overwrite it?", default=False)
        if not overwrite:
            raise click.Abort()

    default_modules = ("config", "auth", "injection", "dos")
    endpoint = click.prompt("GraphQL endpoint", default=DEFAULT_GRAPHQL_ENDPOINT, show_default=True)
    auth_config = click.prompt("Auth config path", default="users.yaml", show_default=True)
    profile = click.prompt(
        "Scan profile",
        type=click.Choice(["passive", "default", "aggressive"], case_sensitive=False),
        default="default",
        show_default=True,
    ).lower()
    modules_input = click.prompt(
        "Modules (comma-separated)",
        default="config,auth,injection,dos",
        show_default=True,
    )
    modules = _normalize_modules(modules_input)
    fmt = click.prompt(
        "Report format",
        type=click.Choice(["json", "csv", "html"], case_sensitive=False),
        default="json",
        show_default=True,
    ).lower()
    report_output = click.prompt(
        "Report output path",
        default=f"reports/report.{fmt}",
        show_default=True,
    )
    discover = click.confirm("Enable endpoint discovery?", default=False)
    ml = click.confirm("Enable ML semantic analysis?", default=False)
    llm_validate = click.confirm("Enable LLM false-positive validation?", default=False)
    fail_on_severity = click.prompt(
        "Fail on severity threshold",
        type=click.Choice(["none", "info", "low", "medium", "high", "critical"], case_sensitive=False),
        default="none",
        show_default=True,
    ).lower()
    authorization_header = click.prompt(
        "Authorization header value (leave blank to skip)",
        default="",
        show_default=False,
    ).strip()

    payload = _build_scan_template(
        endpoint=endpoint,
        auth_config=auth_config.strip(),
        profile=profile,
        modules=modules or default_modules,
        fmt=fmt,
        report_output=report_output,
        discover=discover,
        ml=ml,
        llm_validate=llm_validate,
        fail_on_severity=fail_on_severity,
        authorization_header=authorization_header,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    ok(f"Created scan config: {output_path.resolve()}")
    kv("Endpoint", endpoint)
    kv("Modules", ", ".join(payload["guardian"]["scan"]["modules"]))
    kv("Profile", profile)
    kv("Format", fmt)
    click.echo("")
    ok(f"Next step: guardql config validate --config-file {output_path}")


@config_group.command("ai")
@click.option("--show", is_flag=True, help="Show current AI configuration without printing the raw key.")
@click.option("--clear", "clear_config", is_flag=True, help="Remove saved GuardQL AI credentials.")
@click.option("--provider", default=DEFAULT_LLM_PROVIDER, type=click.Choice(["ollama", "gemini", "openai"], case_sensitive=False), help="AI provider for LLM validation.")
@click.option("--model", default=None, help=f"Model name. Ollama default: {DEFAULT_OLLAMA_MODEL}; fallback: {FALLBACK_OLLAMA_MODEL}.")
@click.option("--base-url", default=None, help=f"Ollama base URL. [default: {DEFAULT_OLLAMA_BASE_URL}]")
def configure_ai(show, clear_config, provider, model, base_url):
    """Configure per-user AI settings for LLM validation.

    \b
    Examples:
      guardql config ai
      guardql config ai --show
      guardql config ai --clear
      guardql config ai --provider ollama --model qwen3:8b
      guardql config ai --provider ollama --model llama3.1:8b
      guardql config ai --provider gemini --model gemini-3.5-flash
      guardql config ai --provider openai --model gpt-4o-mini
    """
    path = credentials_file()
    provider = provider.lower()

    if clear_config:
        clear_user_credentials()
        ok(f"Removed saved AI credentials from {path}.")
        return

    if show:
        kv("Credentials file", path)
        current_provider = get_llm_provider()
        kv("AI provider", current_provider)
        if current_provider == "ollama":
            kv("Ollama base URL", get_ollama_base_url())
        else:
            kv("AI API key", mask_secret(get_llm_api_key(current_provider)))
        kv("AI model", get_llm_model(current_provider))
        return

    if provider == "ollama":
        selected_model = model or click.prompt("Ollama model", default=get_llm_model(provider), show_default=True)
        selected_base_url = base_url or click.prompt("Ollama base URL", default=get_ollama_base_url(), show_default=True)
        saved_path = save_user_credentials(provider=provider, model=selected_model, base_url=selected_base_url)

        ok(f"Saved AI settings to {saved_path}.")
        kv("AI provider", provider)
        kv("Ollama base URL", selected_base_url.rstrip("/"))
        kv("AI model", selected_model)
        return

    env_name = "GEMINI_API_KEY" if provider == "gemini" else "OPENAI_API_KEY"
    default_model = DEFAULT_GEMINI_MODEL if provider == "gemini" else DEFAULT_OPENAI_MODEL
    api_key = click.prompt(f"{provider.title()} API key ({env_name})", hide_input=True, confirmation_prompt=False).strip()
    if not api_key:
        raise click.ClickException("AI API key cannot be empty.")
    selected_model = model or click.prompt("AI model", default=get_llm_model(provider) or default_model, show_default=True)
    saved_path = save_user_credentials(provider=provider, api_key=api_key, model=selected_model)

    ok(f"Saved AI settings to {saved_path}.")
    kv("AI provider", provider)
    kv("AI API key", mask_secret(api_key))
    kv("AI model", selected_model)
    warn(f"Environment variable {env_name} overrides this saved key when set.")


@config_group.command("validate")
@click.option("--config-file", required=True, help="YAML or JSON scan config file to validate.")
def validate_config(config_file):
    """Validate a scan config file before running a scan.

    Checks file structure, supported keys, normalized module/profile values,
    and referenced file paths such as auth configs or schema JSON files.

    \b
    Examples:
      guardql config validate --config-file scan.yaml
      guardql config validate --config-file configs/passive.json
    """
    config_data = _load_scan_config_file(config_file)
    resolved = resolve_scan_config(config_data)
    config_path = Path(config_file).resolve()
    base_dir = config_path.parent

    warnings = []

    def _check_reference(label, value):
        if not value:
            return
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = base_dir / candidate
        if not candidate.exists():
            warnings.append(f"{label} path does not exist: {candidate}")

    _check_reference("Auth config", resolved.get("config"))
    _check_reference("Schema file", resolved.get("schema"))

    if not resolved.get("url"):
        warnings.append("No endpoint is set in the config file. You will need -u/--endpoint when running `scan`.")

    ok(f"Configuration file is valid: {config_path}")
    kv("Endpoint", resolved.get("url") or "<unset>")
    kv("Modules", ", ".join(resolved.get("module") or ("config", "auth", "injection", "dos")))
    kv("Profile", resolved["scan_profile"])
    kv("Format", resolved["fmt"])
    kv("Output", "stdout" if resolved["out"] == "-" else resolved["out"])
    kv("ML", "enabled" if resolved["ml"] else "disabled")
    kv("LLM validation", resolved.get("llm_provider") or DEFAULT_LLM_PROVIDER if resolved["llm_validate"] else "disabled")

    if warnings:
        click.echo("")
        for message in warnings:
            warn(message)
        raise SystemExit(EXIT_RUNTIME_ERROR)

    click.echo("")
    ok("No validation problems found.")


__all__ = ["config_group", "validate_config", "init_config", "configure_ai"]
