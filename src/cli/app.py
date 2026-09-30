"""Application entrypoint and CLI assembly."""

from __future__ import annotations

import importlib
import sys

import click

from src.cli.shared import DEFAULT_REPORT_PATH, EXIT_SUCCESS, VERSION, banner


COMMAND_SPECS = {
    "scan": ("src.cli.commands.scan", "scan", "Run a configurable GraphQL security scan."),
    "discover": ("src.cli.commands.recon", "discover", "Discover GraphQL endpoints by probing common paths."),
    "fingerprint": ("src.cli.commands.recon", "fingerprint", "Identify the backend GraphQL engine via error probing."),
    "introspect": ("src.cli.commands.recon", "introspect", "Fetch and save the GraphQL schema via introspection."),
    "clairvoy": ("src.cli.commands.recon", "clairvoy", "Blind schema reconstruction when introspection is disabled."),
    "overview": ("src.cli.commands.recon", "overview", "Build a schema-aware CLI overview for recon and reporting."),
    "graph": ("src.cli.commands.recon", "graph", "Build a dependency graph from a saved schema."),
    "paths": ("src.cli.commands.recon", "paths", "Enumerate GraphQL paths from operation roots to target types."),
    "inject": ("src.cli.commands.recon", "inject", "Run injection fuzzing (XSS, SQLi, SSRF, Path Traversal)."),
    "authz": ("src.cli.commands.recon", "authz", "Test broken object and role authorization."),
    "web": ("src.cli.commands.web", "web", "Start the API and web dashboard."),
    "doctor": ("src.cli.commands.doctor", "doctor", "Check Python deps and dashboard/API readiness."),
    "config": ("src.cli.commands.config", "config_group", "Inspect and validate scan configuration files."),
    "completion": ("src.cli.commands.completion", "completion", "Print a shell-completion setup script for Bash or PowerShell."),
    "wizard": ("src.cli.wizard", "wizard", "Launch the guided command menu."),
}

COMMAND_ALIASES = {
    "s": "scan",
    "d": "discover",
    "fp": "fingerprint",
    "i": "introspect",
    "cv": "clairvoy",
    "ov": "overview",
    "g": "graph",
    "p": "paths",
    "inj": "inject",
    "a": "authz",
    "w": "web",
    "dr": "doctor",
    "co": "config",
    "com": "completion",
    "wiz": "wizard",
}

HIDDEN_COMMAND_SPECS = {
    "test-auth": ("src.cli.commands.recon", "test_auth"),
}


class GuardianGroup(click.Group):
    """Custom Click group that keeps a stable command order."""

    def format_help(self, ctx, formatter):
        if "-q" not in sys.argv and "--quiet" not in sys.argv:
            banner()
        super().format_help(ctx, formatter)

    def list_commands(self, ctx):
        return list(COMMAND_SPECS.keys())

    def get_command(self, ctx, cmd_name):
        cmd_name = COMMAND_ALIASES.get(cmd_name, cmd_name)
        spec = COMMAND_SPECS.get(cmd_name)
        hidden_spec = HIDDEN_COMMAND_SPECS.get(cmd_name)
        if not spec and not hidden_spec:
            return None
        module_name, attribute_name = hidden_spec if hidden_spec else spec[:2]
        module = importlib.import_module(module_name)
        return getattr(module, attribute_name)

    def format_commands(self, ctx, formatter):
        aliases_by_command = {}
        for alias, command_name in COMMAND_ALIASES.items():
            aliases_by_command.setdefault(command_name, []).append(alias)

        rows = []
        for name, spec in COMMAND_SPECS.items():
            help_text = spec[2]
            aliases = aliases_by_command.get(name)
            if aliases:
                help_text = f"{help_text} [aliases: {', '.join(aliases)}]"
            rows.append((name, help_text))

        with formatter.section("Commands"):
            formatter.write_dl(rows)

    def format_options(self, ctx, formatter):
        self.format_commands(ctx, formatter)

        groups = (
            ("Options", ("version", "help")),
            ("Scan options", ("scan_profile", "level", "risk", "technique", "module")),
            ("AI options", ("ml", "ml_embeddings", "llm_validate", "llm_provider", "llm_model")),
            ("Output options", ("out", "fmt", "json_stdout", "fail_on_severity")),
            ("Display options", ("color", "quiet", "verbose")),
        )
        params = {param.name: param for param in self.get_params(ctx)}
        seen = set()

        for title, names in groups:
            rows = []
            for name in names:
                param = params.get(name)
                if not param:
                    continue
                record = param.get_help_record(ctx)
                if record:
                    rows.append(record)
                    seen.add(name)
            if rows:
                with formatter.section(title):
                    formatter.write_dl(rows)

        extra_rows = []
        for param in self.get_params(ctx):
            if param.name in seen:
                continue
            record = param.get_help_record(ctx)
            if record:
                extra_rows.append(record)
        if extra_rows:
            with formatter.section("Other options"):
                formatter.write_dl(extra_rows)


@click.group(
    cls=GuardianGroup,
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    options_metavar="[OPTIONS]",
    subcommand_metavar="<COMMAND>",
)
@click.version_option(VERSION, "--version", "-V", help="Print version.")
@click.option("-p", "--profile", "scan_profile", type=click.Choice(["passive", "default", "aggressive"], case_sensitive=False), help="Default scan depth profile.")
@click.option("--level", type=click.IntRange(1, 5), help="Default schema and path depth level.")
@click.option("--risk", type=click.IntRange(1, 3), help="Default active-test risk level.")
@click.option("-T", "--technique", help="Default techniques: I=injection, D=DoS, A=auth, C=config.")
@click.option("--module", "module", multiple=True, type=click.Choice(["config", "auth", "injection", "dos"], case_sensitive=False), help="Default scan module. Repeatable.")
@click.option("--ml", is_flag=True, help="Enable Random Forest sensitive-field analysis.")
@click.option("--ml-embeddings", is_flag=True, help="Add optional sentence-transformer similarity.")
@click.option("--llm-validate", is_flag=True, help="Enable LLM false-positive review.")
@click.option("--llm-provider", default=None, type=click.Choice(["ollama", "gemini", "openai"], case_sensitive=False), help="Default AI review provider.")
@click.option("--llm-model", default=None, help="Default AI review model name.")
@click.option("-o", "--out", default=None, help=f"Default report path. [default: {DEFAULT_REPORT_PATH}]")
@click.option("-f", "--format", "fmt", type=click.Choice(["json", "csv", "html"]), default=None, help="Default report format.")
@click.option("--json-stdout", is_flag=True, help="Send JSON report to stdout during scan.")
@click.option("--fail-on-severity", type=click.Choice(["none", "info", "low", "medium", "high", "critical"], case_sensitive=False), default=None, help="Fail scan when severity is reached.")
@click.option("--color", type=click.Choice(["auto", "always", "never"], case_sensitive=False), default="auto", show_default=True, help="Control colored output.")
@click.option("-q", "--quiet", is_flag=True, help="Do not print the banner.")
@click.option("-v", "--verbose", count=True, help="Increase verbosity. Repeat for more detail.")
@click.pass_context
def cli(ctx, scan_profile, level, risk, technique, module, ml, ml_embeddings, llm_validate, llm_provider, llm_model, out, fmt, json_stdout, fail_on_severity, color, quiet, verbose):
    """Find, map, test and report GraphQL API security issues."""
    if color == "always":
        ctx.color = True
    elif color == "never":
        ctx.color = False

    scan_defaults = {}
    if scan_profile:
        scan_defaults["scan_profile"] = scan_profile
    if level is not None:
        scan_defaults["level"] = level
    if risk is not None:
        scan_defaults["risk"] = risk
    if technique:
        scan_defaults["technique"] = technique
    if module:
        scan_defaults["module"] = module
    if ml:
        scan_defaults["ml"] = True
    if ml_embeddings:
        scan_defaults["ml_embeddings"] = True
    if llm_validate:
        scan_defaults["llm_validate"] = True
    if llm_provider:
        scan_defaults["llm_provider"] = llm_provider
    if llm_model:
        scan_defaults["llm_model"] = llm_model
    if out:
        scan_defaults["out"] = out
    if fmt:
        scan_defaults["fmt"] = fmt
    if json_stdout:
        scan_defaults["json_stdout"] = True
    if fail_on_severity:
        scan_defaults["fail_on_severity"] = fail_on_severity
    if verbose:
        scan_defaults["verbose"] = True

    if scan_defaults:
        ctx.default_map = ctx.default_map or {}
        ctx.default_map.setdefault("scan", {}).update(scan_defaults)

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        ctx.exit(EXIT_SUCCESS)


def main():
    """Console-script entry point."""
    cli()


cli.aliases = COMMAND_ALIASES
