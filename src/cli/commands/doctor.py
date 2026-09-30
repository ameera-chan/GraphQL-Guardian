"""Environment and readiness checks for GraphQL Guardian."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from importlib.util import find_spec
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import List

import click
import requests

from src.cli.shared import EXIT_RUNTIME_ERROR, err, header as section_header, kv, ok, warn
from src.utils.credentials import credentials_file, get_llm_api_key, get_llm_model, get_llm_provider, get_ollama_base_url


REPO_ROOT = Path(__file__).resolve().parents[3]
SYSTEM_SHARE = Path("/usr/share/guardql")


def _find_frontend_dir() -> Path | None:
    candidates = (
        Path.cwd() / "frontend",
        REPO_ROOT / "frontend",
        SYSTEM_SHARE / "frontend",
    )
    for candidate in candidates:
        if (candidate / "package.json").exists():
            return candidate
    return None

CORE_DEPENDENCIES = (
    ("graphql-core", "graphql"),
    ("requests", "requests"),
    ("click", "click"),
    ("networkx", "networkx"),
    ("PyYAML", "yaml"),
    ("jinja2", "jinja2"),
    ("fastapi", "fastapi"),
    ("uvicorn", "uvicorn"),
    ("python-multipart", "multipart"),
)

ML_DEPENDENCIES = (
    ("scikit-learn", "sklearn"),
)

LLM_DEPENDENCIES = ()


@dataclass
class DoctorItem:
    status: str
    name: str
    message: str


@dataclass
class DoctorSection:
    title: str
    items: List[DoctorItem]


def _import_status(display_name, import_name, required=True):
    if find_spec(import_name) is None:
        status = "fail" if required else "warn"
        return DoctorItem(status, display_name, f"Missing import `{import_name}`.")
    return DoctorItem("pass", display_name, f"`{import_name}` is importable.")


def _probe_url(url, timeout):
    try:
        response = requests.get(url, timeout=timeout)
        if response.ok:
            return DoctorItem("pass", url, f"Responding with HTTP {response.status_code}.")
        return DoctorItem("warn", url, f"Responded with HTTP {response.status_code}.")
    except Exception as exc:
        return DoctorItem("warn", url, f"Not responding: {exc}")


def _command_version(command_name):
    executable = shutil.which(command_name)
    if not executable:
        return DoctorItem("warn", command_name, "Command not found in PATH.")

    try:
        result = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        output = (result.stdout or result.stderr).strip().splitlines()
        if result.returncode == 0 and output:
            return DoctorItem("pass", command_name, output[0])
        if result.returncode == 0:
            return DoctorItem("pass", command_name, "Command is available.")
        return DoctorItem("warn", command_name, f"Command returned exit code {result.returncode}.")
    except Exception as exc:
        return DoctorItem("warn", command_name, f"Could not run `--version`: {exc}")


def _check_api(api_url, timeout):
    items = []
    try:
        import_module("src.api.app")
        items.append(DoctorItem("pass", "API module", "`src.api.app` imports successfully."))
    except Exception as exc:
        items.append(DoctorItem("fail", "API module", f"`src.api.app` failed to import: {exc}"))

    items.append(_probe_url(api_url, timeout))
    return DoctorSection("API readiness", items)


def _check_dashboard(dashboard_url, timeout):
    items = []
    frontend_dir = _find_frontend_dir()
    if frontend_dir is None:
        items.append(DoctorItem("fail", "Frontend package", "Dashboard frontend files were not found."))
        return DoctorSection("Dashboard readiness", items)

    package_json = frontend_dir / "package.json"
    items.append(DoctorItem("pass", "Frontend package", f"Found {package_json}."))
    try:
        payload = json.loads(package_json.read_text(encoding="utf-8"))
        scripts = payload.get("scripts", {})
        missing_scripts = [name for name in ("dev", "build") if name not in scripts]
        if missing_scripts:
            items.append(DoctorItem("warn", "Frontend scripts", f"Missing scripts: {', '.join(missing_scripts)}."))
        else:
            items.append(DoctorItem("pass", "Frontend scripts", "Found `dev` and `build` scripts."))
    except Exception as exc:
        items.append(DoctorItem("warn", "Frontend scripts", f"Could not read package.json: {exc}"))

    node_modules = frontend_dir / "node_modules"
    if node_modules.exists():
        items.append(DoctorItem("pass", "Frontend dependencies", f"Found {node_modules}."))
    else:
        items.append(DoctorItem("warn", "Frontend dependencies", "Run `npm install` in the frontend directory."))

    items.append(_command_version("node"))
    items.append(_command_version("npm"))
    items.append(_probe_url(dashboard_url, timeout))
    return DoctorSection("Dashboard readiness", items)


def _llm_key_status():
    provider = get_llm_provider()
    if provider == "ollama":
        return DoctorItem("pass", "Ollama provider", f"Using local Ollama at {get_ollama_base_url()}.")
    env_name = "GEMINI_API_KEY" if provider == "gemini" else "OPENAI_API_KEY"
    if get_llm_api_key(provider):
        return DoctorItem("pass", f"{provider.title()} API key", f"Configured via environment or {credentials_file()}.")
    return DoctorItem("warn", f"{provider.title()} API key", f"Not set. Run `guardql config ai` or set `{env_name}`.")


def _llm_live_status():
    provider = get_llm_provider()
    api_key = get_llm_api_key(provider)
    if provider != "ollama" and not api_key:
        return DoctorItem("warn", "LLM live check", "Skipped because no API key is configured.")

    model = get_llm_model(provider)
    try:
        if provider == "ollama":
            response = requests.post(
                f"{get_ollama_base_url()}/api/chat",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": "Return exactly: ok"}],
                    "stream": False,
                },
                timeout=30,
            )
            response.raise_for_status()
            response_id = response.json().get("created_at")
        elif provider == "openai":
            from openai import OpenAI

            client = OpenAI(api_key=api_key)
            if not hasattr(client, "responses"):
                return DoctorItem("fail", "LLM live check", "Installed OpenAI package does not support Responses API.")
            response = client.responses.create(
                model=model,
                input="Return exactly: ok",
                max_output_tokens=8,
            )
            response_id = getattr(response, "id", None)
        else:
            response = requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                params={"key": api_key},
                json={"contents": [{"role": "user", "parts": [{"text": "Return exactly: ok"}]}]},
                timeout=20,
            )
            response.raise_for_status()
            response_id = response.json().get("responseId")
        suffix = f" Response id: {response_id}." if response_id else ""
        return DoctorItem("pass", "LLM live check", f"{provider.title()} API call succeeded with model `{model}`.{suffix}")
    except ImportError:
        return DoctorItem("warn", "LLM live check", "Skipped because the `openai` package is not installed.")
    except Exception as exc:
        return DoctorItem("fail", "LLM live check", f"API call failed: {exc}")


def _collect_doctor_sections(api_url, dashboard_url, timeout, check_ml=False, check_llm=False, live_llm=False):
    python_items = [DoctorItem("pass", "Python", sys.version.split()[0])]
    python_items.extend(_import_status(display_name, import_name, required=True) for display_name, import_name in CORE_DEPENDENCIES)
    python_items.append(_import_status("numpy", "numpy", required=True))
    if check_ml:
        python_items.extend(_import_status(display_name, import_name, required=False) for display_name, import_name in ML_DEPENDENCIES)
    if check_llm:
        python_items.extend(_import_status(display_name, import_name, required=False) for display_name, import_name in LLM_DEPENDENCIES)
        python_items.append(_llm_key_status())
        if live_llm:
            python_items.append(_llm_live_status())

    return [
        DoctorSection("Python dependencies", python_items),
        _check_api(api_url, timeout),
        _check_dashboard(dashboard_url, timeout),
    ]


@click.command()
@click.option("--api-url", default="http://127.0.0.1:8000/", show_default=True, help="API URL to probe.")
@click.option("--dashboard-url", default="http://127.0.0.1:5173/", show_default=True, help="Dashboard URL to probe.")
@click.option("--timeout", default=2.0, show_default=True, type=float, help="HTTP probe timeout in seconds.")
@click.option("--ml", "check_ml", is_flag=True, help="Also check optional ML dependencies.")
@click.option("--llm", "check_llm", is_flag=True, help="Also check optional LLM readiness.")
@click.option("--llm-live", is_flag=True, help="Make one small LLM API call to verify the configured key.")
def doctor(api_url, dashboard_url, timeout, check_ml, check_llm, llm_live):
    """Check Python deps and dashboard/API readiness.

    \b
    Examples:
      guardql doctor
      guardql doctor --ml
      guardql doctor --llm
      guardql doctor --llm --llm-live
      guardql doctor --api-url http://127.0.0.1:8001/ --dashboard-url http://127.0.0.1:4173/
    """
    check_llm = check_llm or llm_live
    if check_ml or check_llm:
        sections = _collect_doctor_sections(api_url, dashboard_url, timeout, check_ml, check_llm, llm_live)
    else:
        sections = _collect_doctor_sections(api_url, dashboard_url, timeout)
    failures = 0
    warnings = 0

    for section in sections:
        section_header(section.title.upper())
        for item in section.items:
            if item.status == "pass":
                ok(f"{item.name}: {item.message}")
            elif item.status == "warn":
                warnings += 1
                warn(f"{item.name}: {item.message}")
            else:
                failures += 1
                err(f"{item.name}: {item.message}")
        click.echo("")

    kv("Failures", str(failures))
    kv("Warnings", str(warnings))
    kv("API probe", api_url)
    kv("Dashboard probe", dashboard_url)
    click.echo("")

    if failures:
        err("Doctor found critical issues.")
        raise SystemExit(EXIT_RUNTIME_ERROR)

    if warnings:
        warn("Doctor completed with warnings.")
        return

    ok("Doctor completed successfully.")


__all__ = ["doctor", "_collect_doctor_sections"]
