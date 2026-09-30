"""Shared CLI helpers, styling, and shell-friendly output behavior."""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager, redirect_stdout
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path

import click

from src.reporters.models import normalize_state


VERSION = "1.0.0"
EXIT_SUCCESS = 0
EXIT_RUNTIME_ERROR = 1
EXIT_FINDINGS = 2
EXIT_INTERRUPTED = 130
DEFAULT_REPORT_PATH = "reports/report.json"
DEFAULT_GRAPHQL_ENDPOINT = os.getenv("GUARDQL_DEFAULT_TARGET_ENDPOINT", "http://localhost:5013/graphql")
DEFAULT_DVGA_ENDPOINT = os.getenv("GUARDQL_DEFAULT_DVGA_ENDPOINT", DEFAULT_GRAPHQL_ENDPOINT)
TECHNIQUE_ORDER = "IDAC"
TECHNIQUE_BY_MODULE = {
    "injection": "I",
    "dos": "D",
    "auth": "A",
    "config": "C",
}


def resolve_users_config_path(path: str) -> Path:
    """Resolve an auth config from the current directory or project root."""
    candidate = Path(path).expanduser()
    if candidate.is_absolute() or candidate.exists():
        return candidate

    project_candidate = Path(__file__).resolve().parents[2] / candidate
    if project_candidate.exists():
        return project_candidate

    return candidate
SEVERITY_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

BANNER = r"""
   ___                 _       ____  __     ___                     _ _
  / _ \_ __ __ _ _ __ | |__   /___ \/ /    / _ \_   _  __ _ _ __ __| (_) __ _ _ __
 / /_\/ '__/ _` | '_ \| '_ \ //  / / /    / /_\/ | | |/ _` | '__/ _` | |/ _` | '_ \
/ /_\\| | | (_| | |_) | | | / \_/ / /___ / /_\\| |_| | (_| | | | (_| | | (_| | | | |
\____/|_|  \__,_| .__/|_| |_\___,_\____/ \____/ \__,_|\__,_|_|  \__,_|_|\__,_|_| |_|
                |_|
"""

DIM = dict(dim=True)

SEVERITY_COLORS = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "white",
}

SEVERITY_ICONS = {
    "CRITICAL": "!",
    "HIGH": "\u2718",
    "MEDIUM": "\u26A0",
    "LOW": "\u2139",
    "INFO": "\u00B7",
}

CLI_PROGRESS_TO_STDERR = False
_ORIGINAL_CLICK_ECHO = click.echo
_ORIGINAL_CLICK_SECHO = click.secho

ASCII_FALLBACKS = str.maketrans(
    {
        "\u2718": "x",
        "\u2714": "+",
        "\u26A0": "!",
        "\u2139": "i",
        "\u00B7": ".",
        "\u2022": "*",
        "\u2500": "-",
        "\u2514": "`",
        "\u2588": "#",
        "\u2192": "->",
        "\u2026": "...",
    }
)


def _output_encoding(kwargs) -> str:
    stream = kwargs.get("file")
    if stream is not None and getattr(stream, "encoding", None):
        return stream.encoding
    if kwargs.get("err"):
        return sys.stderr.encoding or "utf-8"
    return sys.stdout.encoding or "utf-8"


def _safe_args(args, kwargs):
    if not args or not isinstance(args[0], str):
        return args

    encoding = _output_encoding(kwargs)
    try:
        args[0].encode(encoding)
        return args
    except (LookupError, UnicodeEncodeError):
        translated = args[0].translate(ASCII_FALLBACKS)
        safe_message = translated.encode(encoding, errors="replace").decode(encoding, errors="replace")
        return (safe_message, *args[1:])


def _guardian_click_echo(*args, **kwargs):
    if CLI_PROGRESS_TO_STDERR:
        kwargs.setdefault("err", True)
    return _ORIGINAL_CLICK_ECHO(*_safe_args(args, kwargs), **kwargs)


def _guardian_click_secho(*args, **kwargs):
    if CLI_PROGRESS_TO_STDERR:
        kwargs.setdefault("err", True)
    return _ORIGINAL_CLICK_SECHO(*_safe_args(args, kwargs), **kwargs)


click.echo = _guardian_click_echo
click.secho = _guardian_click_secho


def set_cli_progress_to_stderr(enabled: bool) -> None:
    """Toggle shell-friendly progress output routing."""
    global CLI_PROGRESS_TO_STDERR
    CLI_PROGRESS_TO_STDERR = bool(enabled)


def banner() -> None:
    """Print the application banner."""
    click.secho(BANNER, fg="cyan", bold=True)
    click.secho(f"  Automated GraphQL Security Scanner  v{VERSION}", fg="white", bold=True)
    click.secho(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", **DIM)
    click.echo("")


def header(title: str) -> None:
    """Print a section header."""
    width = 60
    click.echo("")
    click.secho(f"  {'=' * width}", fg="blue")
    click.secho(f"  {title.center(width)}", fg="blue", bold=True)
    click.secho(f"  {'=' * width}", fg="blue")


def subheader(title: str) -> None:
    """Print a sub-section header."""
    click.echo("")
    click.secho(f"  --- {title} ---", fg="cyan", bold=True)


def step(message: str) -> None:
    """Print a step/progress message."""
    click.secho(f"  [*] {message}", fg="white", bold=True)


def ok(message: str) -> None:
    """Print a success message."""
    click.secho(f"  [+] {message}", fg="green")


def warn(message: str) -> None:
    """Print a warning message."""
    click.secho(f"  [!] {message}", fg="yellow")


def err(message: str) -> None:
    """Print an error message."""
    click.secho(f"  [-] {message}", fg="red")


def finding(finding_item) -> None:
    """Print a single finding with severity color and icon."""
    severity = finding_item.severity
    color = SEVERITY_COLORS.get(severity, "white")
    icon = SEVERITY_ICONS.get(severity, " ")
    status = normalize_state(getattr(finding_item, "state", None), severity).upper()
    click.secho(f"      {icon}  [{severity:>6}] [{status:<13}]  {finding_item.title}", fg=color)


def finding_detail(finding_item, report_file: str = DEFAULT_REPORT_PATH) -> None:
    """Print a detailed evidence block for a single finding."""
    severity = finding_item.severity
    color = SEVERITY_COLORS.get(severity, "white")
    icon = SEVERITY_ICONS.get(severity, " ")
    click.echo("")
    click.secho(f"      {icon}  {finding_item.title}", fg=color, bold=True)
    line = "\u2500" * 50
    click.secho(f"      {line}", **DIM)
    if finding_item.operation_name:
        click.echo(f"        Operation:     {click.style(finding_item.operation_name, bold=True)}")
    if finding_item.field:
        click.echo(f"        Field:         {finding_item.field}")
    if finding_item.evidence:
        evidence = asdict(finding_item.evidence) if is_dataclass(finding_item.evidence) else finding_item.evidence
        if isinstance(evidence, dict):
            for evidence_key, evidence_value in evidence.items():
                label = evidence_key.replace("_", " ").title()
                if isinstance(evidence_value, float):
                    evidence_value = f"{evidence_value:.4f}"
                click.echo(f"        {label + ':':<15} {evidence_value}")
        else:
            click.echo(f"        Evidence:      {evidence}")
    if finding_item.reproduction:
        click.echo(f"        Reproduce:     {finding_item.reproduction[:80]}")
    click.echo(f"        Severity:      {click.style(severity, fg=color, bold=True)}")
    click.echo(f"        Status:        {normalize_state(getattr(finding_item, 'state', None), severity)}")
    if getattr(finding_item, "confidence", None):
        click.echo(f"        Confidence:    {finding_item.confidence}")
    click.echo(f"        Category:      {finding_item.category}")
    if finding_item.remediation:
        remediation_line = finding_item.remediation.split("\n")[0]
        if len(remediation_line) > 50:
            remediation_line = remediation_line[:47] + "..."
        click.echo(f"        Remediation:   {remediation_line}")
    click.echo(f"        Report File:   {click.style(report_file, bold=True)}")
    click.echo(f"        Finding ID:    {click.style(finding_item.id[:8], bold=True)}  ({finding_item.timestamp})")
    click.echo("")


def kv(key: str, value, indent: int = 6) -> None:
    """Print a key-value pair."""
    pad = " " * indent
    click.echo(f"{pad}{click.style(key + ':', bold=True)}  {value}")


def parse_headers(header_tuple):
    """Parse a tuple of 'Key: Value' strings into a dict."""
    headers = {}
    for header_value in (header_tuple or ()):
        if ":" in header_value:
            key, value = header_value.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers


def should_fail_scan(findings, threshold: str) -> bool:
    """Return True when findings meet the configured failure threshold."""
    threshold_name = str(threshold).upper()
    if threshold_name == "NONE":
        return False

    threshold_rank = SEVERITY_RANK[threshold_name]
    return any(SEVERITY_RANK.get(getattr(item, "severity", "INFO"), 0) >= threshold_rank for item in findings)


@contextmanager
def machine_output_mode(enabled: bool):
    """Redirect human-readable output to stderr while leaving machine output on stdout."""
    if not enabled:
        yield
        return

    original_echo = click.echo
    original_secho = click.secho

    def stderr_echo(*args, **kwargs):
        kwargs.setdefault("err", True)
        return original_echo(*args, **kwargs)

    def stderr_secho(*args, **kwargs):
        kwargs.setdefault("err", True)
        return original_secho(*args, **kwargs)

    click.echo = stderr_echo
    click.secho = stderr_secho
    try:
        with redirect_stdout(sys.stderr):
            yield
    finally:
        click.echo = original_echo
        click.secho = original_secho


def summary_table(findings, expected_categories=None) -> None:
    """Print a formatted summary table of findings."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    statuses = {"confirmed": 0, "possible": 0, "informational": 0}
    categories = {}
    for item in findings:
        counts[item.severity] = counts.get(item.severity, 0) + 1
        status = normalize_state(getattr(item, "state", None), item.severity)
        statuses[status] = statuses.get(status, 0) + 1
        categories[item.category] = categories.get(item.category, 0) + 1

    if expected_categories:
        for category in expected_categories:
            categories.setdefault(category, 0)

    header("SCAN SUMMARY")
    click.echo("")

    click.secho("      Severity         Count", bold=True)
    click.secho("      " + "\u2500" * 32)
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        color = SEVERITY_COLORS[severity]
        icon = SEVERITY_ICONS[severity]
        count = counts[severity]
        bar = "\u2588" * count
        click.echo(
            f"      {icon}  {click.style(f'{severity:<8}', fg=color, bold=True)}  "
            f"{click.style(str(count).rjust(3), bold=True)}  "
            f"{click.style(bar, fg=color)}"
        )

    click.echo("")

    click.secho("      Verification     Count", bold=True)
    click.secho("      " + "\u2500" * 32)
    for status, count in statuses.items():
        click.echo(f"      {click.style(status.title(), bold=True):<24}  {click.style(str(count).rjust(3), bold=True)}")

    click.echo("")

    if categories:
        click.secho("      Category         Count", bold=True)
        click.secho("      " + "\u2500" * 32)
        for category, count in sorted(categories.items()):
            color = "green" if count == 0 else "white"
            click.echo(f"      {click.style(category, fg=color):<24}  {click.style(str(count).rjust(3), bold=True)}")

    click.echo("")
    total = len(findings)
    if total == 0:
        click.secho("      \u2714  No vulnerabilities found.", fg="green", bold=True)
    else:
        click.secho(f"      Total findings:  {total}", bold=True)
    click.echo("")
