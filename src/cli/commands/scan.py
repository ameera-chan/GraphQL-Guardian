"""Unified full-scan CLI command and scan-config helpers."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import click
import yaml
from click.core import ParameterSource

from src.config import PROFILE_AGGRESSIVE, PROFILE_DEFAULT, PROFILE_PASSIVE
from src.reporters.converter import ResultConverter
from src.reporters.finding_enricher import enrich_findings
from src.reporters.json_reporter import JSONReporter
from src.reporters.relationship_map import build_relationship_map_from_parts
from src.reporters.csv_reporter import CSVReporter
from src.reporters.html_reporter import HTMLReporter
from src.reporters.models import Finding
from src.scanner.active_security import ActiveSecurityScanner
from src.scanner.asset_recon import AssetReconScanner
from src.scanner.authentication_tester import AuthenticationScanner
from src.scanner.auth_tester import AuthTester
from src.scanner.config_checker import ConfigChecker
from src.scanner.dependency_graph import DependencyGraphBuilder
from src.scanner.dos_scanner import DoSScanner
from src.scanner.introspection_bypass import IntrospectionBypassScanner
from src.scanner.injector import PayloadInjector
from src.scanner.operation_pack import OperationPackGenerator
from src.scanner.path_enumerator import GraphQLPathEnumerator
from src.scanner.points_of_interest import build_points_of_interest
from src.scanner.request_forgery import RequestForgeryScanner
from src.scanner.schema_auditor import SchemaAuditor
from src.scanner.schema_overview import build_schema_overview
from src.scanner.schema_parser import fetch_introspection, parse_schema_details
from src.scanner.sensitive_field_review import review_sensitive_candidates, split_sensitive_candidates
from src.scanner.subscription_tester import SubscriptionSecurityScanner
from src.utils.evidence import build_evidence

from src.cli.shared import (
    DEFAULT_REPORT_PATH,
    DIM,
    EXIT_FINDINGS,
    EXIT_INTERRUPTED,
    EXIT_RUNTIME_ERROR,
    SEVERITY_COLORS,
    TECHNIQUE_BY_MODULE,
    TECHNIQUE_ORDER,
    err,
    finding,
    finding_detail,
    header as section_header,
    kv,
    ok,
    parse_headers,
    resolve_users_config_path,
    set_cli_progress_to_stderr,
    should_fail_scan,
    subheader as section_subheader,
    summary_table,
    warn,
)


class _DefaultSourceContext:
    """Lightweight context that treats every option as using its default value."""

    def get_parameter_source(self, _name):
        return ParameterSource.DEFAULT


class ScanCommand(click.Command):
    """Click command that groups scan options for readable help output."""

    OPTION_GROUPS = (
        ("Target options", ("url", "config", "config_file", "schema", "do_discover", "header", "proxy")),
        ("Scan depth options", ("scan_profile", "level", "risk")),
        ("Module options", ("technique", "module")),
        ("AI options", ("ml", "ml_embeddings", "llm_validate", "llm_provider", "llm_model")),
        ("Output options", ("out", "fmt", "json_stdout", "fail_on_severity")),
        ("Display options", ("verbose", "help")),
        ("Compatibility options", ("suggest",)),
    )

    def format_options(self, ctx, formatter):
        params = {param.name: param for param in self.get_params(ctx)}
        seen = set()

        for title, names in self.OPTION_GROUPS:
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


def _default_scan_options():
    return {
        "url": None,
        "config": None,
        "schema": None,
        "out": DEFAULT_REPORT_PATH,
        "fmt": "json",
        "scan_profile": "default",
        "level": 1,
        "risk": 1,
        "technique": TECHNIQUE_ORDER,
        "module": (),
        "suggest": False,
        "ml": False,
        "ml_embeddings": False,
        "llm_validate": False,
        "llm_provider": None,
        "llm_model": None,
        "proxy": None,
        "header": (),
        "do_discover": False,
        "verbose": False,
        "fail_on_severity": "none",
        "json_stdout": False,
    }


def _is_default_source(ctx, name):
    try:
        source = ctx.get_parameter_source(name)
    except Exception:
        return True
    return source in (None, ParameterSource.DEFAULT)


def _lookup_config_value(config_data, *keys):
    for key in keys:
        if key in config_data and config_data[key] is not None:
            return config_data[key]
    return None


def _normalize_header_options(value):
    if value in (None, ""):
        return ()
    if isinstance(value, dict):
        return tuple(f"{key}: {item}" for key, item in value.items())
    if isinstance(value, str):
        return (value,)

    normalized = []
    for item in value:
        if isinstance(item, dict):
            normalized.extend(f"{key}: {entry}" for key, entry in item.items())
        elif item is not None:
            normalized.append(str(item))
    return tuple(normalized)


def _normalize_modules(value):
    if value in (None, "", ()):
        return ()
    if isinstance(value, str):
        raw_items = [part.strip() for part in value.replace(",", " ").split()]
    else:
        raw_items = [str(item).strip() for item in value if str(item).strip()]

    allowed = tuple(TECHNIQUE_BY_MODULE.keys())
    normalized = []
    for item in raw_items:
        lowered = item.lower()
        if lowered not in allowed:
            raise click.BadParameter(
                f"Unsupported module '{item}'. Choose from: {', '.join(allowed)}."
            )
        if lowered not in normalized:
            normalized.append(lowered)
    return tuple(normalized)


def _normalize_technique(value):
    if value is None:
        return TECHNIQUE_ORDER

    selected = []
    for char in str(value).upper():
        if char in TECHNIQUE_ORDER and char not in selected:
            selected.append(char)
    return "".join(char for char in TECHNIQUE_ORDER if char in selected)


def _modules_to_technique(modules):
    normalized = _normalize_modules(modules)
    return "".join(
        code
        for code in TECHNIQUE_ORDER
        if any(TECHNIQUE_BY_MODULE[module] == code for module in normalized)
    )


def _load_scan_config_file(path):
    config_path = Path(path)
    if not config_path.exists():
        raise click.BadParameter(f"Config file not found: {path}", param_hint="--config-file")

    try:
        raw_text = config_path.read_text(encoding="utf-8")
        if config_path.suffix.lower() == ".json":
            payload = json.loads(raw_text)
        else:
            payload = yaml.safe_load(raw_text)
    except Exception as exc:
        raise click.BadParameter(
            f"Could not parse config file {path}: {exc}",
            param_hint="--config-file",
        ) from exc

    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise click.BadParameter(
            f"Config file {path} must contain a mapping/object at the top level.",
            param_hint="--config-file",
        )

    guardian_block = payload.get("guardian")
    if isinstance(guardian_block, dict) and isinstance(guardian_block.get("scan"), dict):
        return guardian_block["scan"]
    if isinstance(payload.get("scan"), dict):
        return payload["scan"]
    return payload


def resolve_scan_config(config_data):
    return _merge_scan_config(_DefaultSourceContext(), _default_scan_options(), config_data)


def _merge_scan_config(ctx, options, config_data):
    merged = dict(options)
    option_aliases = {
        "url": ("url", "endpoint", "target"),
        "config": ("auth_config", "users_config", "user_config", "config"),
        "schema": ("schema", "schema_file"),
        "out": ("out", "output", "output_path", "report"),
        "fmt": ("format", "report_format"),
        "scan_profile": ("profile", "scan_profile"),
        "level": ("level",),
        "risk": ("risk",),
        "technique": ("technique",),
        "ml": ("ml", "enable_ml"),
        "ml_embeddings": ("ml_embeddings", "enable_ml_embeddings"),
        "llm_validate": ("llm_validate", "enable_llm", "llm"),
        "llm_provider": ("llm_provider", "ai_provider", "provider"),
        "llm_model": ("llm_model",),
        "proxy": ("proxy",),
        "do_discover": ("discover", "auto_discover"),
        "verbose": ("verbose",),
        "fail_on_severity": ("fail_on_severity",),
        "json_stdout": ("json_stdout",),
    }

    for option_name, aliases in option_aliases.items():
        if not _is_default_source(ctx, option_name):
            continue
        value = _lookup_config_value(config_data, *aliases)
        if value is not None:
            merged[option_name] = value

    if _is_default_source(ctx, "header"):
        header_value = _lookup_config_value(config_data, "headers", "header")
        if header_value is not None:
            merged["header"] = _normalize_header_options(header_value)

    if _is_default_source(ctx, "module"):
        module_value = _lookup_config_value(config_data, "modules", "module")
        if module_value is not None:
            merged["module"] = _normalize_modules(module_value)

    merged["scan_profile"] = str(merged["scan_profile"]).lower()
    merged["fmt"] = str(merged["fmt"]).lower()
    if merged.get("llm_provider"):
        merged["llm_provider"] = str(merged["llm_provider"]).lower()
    merged["fail_on_severity"] = str(merged["fail_on_severity"]).lower()
    merged["module"] = _normalize_modules(merged.get("module"))
    merged["header"] = tuple(merged.get("header") or ())
    merged["technique"] = _normalize_technique(merged.get("technique"))

    if merged["module"]:
        merged["technique"] = _modules_to_technique(merged["module"])

    if not merged["technique"]:
        raise click.BadParameter(
            "At least one scan module must be enabled.",
            param_hint="--module / --technique",
        )

    if merged["json_stdout"]:
        merged["fmt"] = "json"
        merged["out"] = "-"

    if (
        _is_default_source(ctx, "out")
        and merged["out"] == DEFAULT_REPORT_PATH
        and merged["fmt"] != "json"
        and not merged["json_stdout"]
    ):
        merged["out"] = f"reports/report.{merged['fmt']}"

    if merged["scan_profile"] not in {"passive", "default", "aggressive"}:
        raise click.BadParameter(
            f"Unsupported profile '{merged['scan_profile']}'.",
            param_hint="--profile",
        )

    if merged["fmt"] not in {"json", "csv", "html"}:
        raise click.BadParameter(
            f"Unsupported report format '{merged['fmt']}'.",
            param_hint="--format",
        )

    if merged["fail_on_severity"] not in {"none", "info", "low", "medium", "high", "critical"}:
        raise click.BadParameter(
            f"Unsupported fail-on severity '{merged['fail_on_severity']}'.",
            param_hint="--fail-on-severity",
        )

    return merged


@click.command(cls=ScanCommand)
@click.option("-u", "--url", "--endpoint", required=False, help="GraphQL endpoint URL or base URL when --discover is used.")
@click.option("-c", "--config", required=False, help="Users YAML file for auth and authorization testing.")
@click.option("--config-file", required=False, help="YAML or JSON file with saved scan options.")
@click.option("-s", "--schema", required=False, help="Schema JSON file. If omitted, introspection is attempted.")
@click.option("-o", "--out", default=DEFAULT_REPORT_PATH, show_default=True, help="Output report file.")
@click.option("-f", "--format", "fmt", type=click.Choice(["json", "csv", "html"]), default="json", show_default=True, help="Report format.")
@click.option(
    "-p",
    "--profile",
    "scan_profile",
    type=click.Choice(["passive", "default", "aggressive"], case_sensitive=False),
    default="default",
    show_default=True,
    help="Depth profile: passive = recon only, default = normal pentest probes, aggressive = full attack checks.",
)
@click.option("--level", type=click.IntRange(1, 5), default=1, show_default=True, help="How deep to expand schema and path checks.")
@click.option("--risk", type=click.IntRange(1, 3), default=1, show_default=True, help="How much active traffic to allow.")
@click.option("-T", "--technique", default="IDAC", show_default=True, help="Technique letters: I=injection, D=DoS, A=auth, C=config.")
@click.option("--module", "module", multiple=True, type=click.Choice(["config", "auth", "injection", "dos"], case_sensitive=False), help="Readable module selector. Repeat to replace --technique.")
@click.option("--suggest", is_flag=True, help="Compatibility alias for the interactive wizard flow.")
@click.option("--ml", is_flag=True, help="Enable Random Forest sensitive-field analysis.")
@click.option("--ml-embeddings", is_flag=True, help="Add optional sentence-transformer semantic similarity.")
@click.option("--llm-validate", is_flag=True, help="Enable LLM-based false-positive filtering.")
@click.option("--llm-provider", default=None, type=click.Choice(["ollama", "gemini", "openai"], case_sensitive=False), help="LLM provider for AI review.")
@click.option("--llm-model", default=None, help="LLM model name.")
@click.option("--proxy", default=None, help="HTTP proxy (e.g. http://127.0.0.1:8080).")
@click.option("-H", "--header", multiple=True, help="Custom header (Key: Value). Repeatable.")
@click.option("--discover", "do_discover", is_flag=True, help="Probe common paths before scanning.")
@click.option("--fail-on-severity", type=click.Choice(["none", "info", "low", "medium", "high", "critical"], case_sensitive=False), default="none", show_default=True, help="Exit with code 2 when findings meet or exceed this severity.")
@click.option("--json-stdout", is_flag=True, help="Write the JSON report to stdout and send human-readable progress to stderr.")
@click.option("-v", "--verbose", is_flag=True, help="Show detailed finding breakdown after summary.")
@click.pass_context
def scan(ctx, url, config, config_file, schema, out, fmt, scan_profile, level, risk, technique, module, suggest, ml, ml_embeddings, llm_validate, llm_provider, llm_model, proxy, header, do_discover, fail_on_severity, json_stdout, verbose):
    """Run a configurable GraphQL security scan.

    Use the CLI when you need control, repeatability, shell history, scripts,
    CI jobs, proxies, headers, saved configs, and exact scan depth. The wizard
    is only a guided wrapper around these options.

    \b
    Examples:
      guardql scan -u http://localhost:5013/graphql
      guardql scan -u http://target/graphql --profile passive -f html -o reports/passive.html
      guardql scan -u http://target/graphql --profile default --module config --module auth
      guardql scan -u http://target/graphql --profile aggressive --level 4 --risk 3
      guardql scan --config-file scan.yaml
      guardql scan -u http://target/graphql --json-stdout > report.json

    \b
    Profiles:
      passive     recon and schema review only
      default     normal pentest checks with moderate active probes
      aggressive  full attack checks, including destructive DoS tests
    """
    if suggest:
        warn("`scan --suggest` is deprecated. Launching `wizard` instead.")
        from src.cli.wizard import interactive_menu
        from src.cli.shared import banner

        banner()
        interactive_menu(ctx)
        return

    option_values = {
        "url": url,
        "config": config,
        "schema": schema,
        "out": out,
        "fmt": fmt,
        "scan_profile": scan_profile,
        "level": level,
        "risk": risk,
        "technique": technique,
        "module": module,
        "ml": ml,
        "ml_embeddings": ml_embeddings,
        "llm_validate": llm_validate,
        "llm_provider": llm_provider,
        "llm_model": llm_model,
        "proxy": proxy,
        "header": header,
        "do_discover": do_discover,
        "verbose": verbose,
        "fail_on_severity": fail_on_severity,
        "json_stdout": json_stdout,
    }
    scan_config_data = _load_scan_config_file(config_file) if config_file else {}
    option_values = _merge_scan_config(ctx, option_values, scan_config_data)

    url = option_values["url"]
    config = option_values["config"]
    schema = option_values["schema"]
    out = option_values["out"]
    fmt = option_values["fmt"]
    scan_profile = option_values["scan_profile"]
    level = option_values["level"]
    risk = option_values["risk"]
    technique = option_values["technique"]
    ml = option_values["ml"]
    ml_embeddings = option_values["ml_embeddings"]
    llm_validate = option_values["llm_validate"]
    llm_provider = option_values["llm_provider"]
    llm_model = option_values["llm_model"]
    proxy = option_values["proxy"]
    header_values = option_values["header"]
    do_discover = option_values["do_discover"]
    verbose = option_values["verbose"]
    fail_on_severity = option_values["fail_on_severity"]
    json_stdout = option_values["json_stdout"]

    set_cli_progress_to_stderr(bool(json_stdout))
    ctx.call_on_close(lambda: set_cli_progress_to_stderr(False))

    target_url = url
    if not target_url:
        err("Missing target URL. Use -u <URL>, --config-file, or launch the wizard.")
        raise SystemExit(EXIT_RUNTIME_ERROR)

    extra_headers = parse_headers(header_values)
    scan_start = time.time()

    section_header("SCAN CONFIGURATION")
    profile_colors = {"passive": "green", "default": "yellow", "aggressive": "red"}
    profile_labels = {
        "passive": "PASSIVE   -  Safe recon only (no attack traffic)",
        "default": "DEFAULT   -  Standard pentest (moderate probes)",
        "aggressive": "AGGRESSIVE - Full attack (destructive DoS, can crash target)",
    }
    kv("Profile", click.style(profile_labels[scan_profile], fg=profile_colors[scan_profile], bold=True))
    kv("Target", target_url)
    kv(
        "Techniques",
        "  ".join(
            f"[{click.style(code, bold=True)}] {label}"
            for code, label in [("I", "Injection"), ("D", "DoS"), ("A", "Auth"), ("C", "Config")]
            if code in technique
        ),
    )
    kv("Level / Risk", f"{level} / {risk}")
    kv("ML Analysis", "Random Forest" if ml else "Disabled")
    if ml and ml_embeddings:
        kv("ML Embeddings", "Enabled")
    kv("LLM Validation", (llm_provider or "Ollama").title() if llm_validate else "Disabled")
    if proxy:
        kv("Proxy", proxy)
    if extra_headers:
        kv("Custom Headers", ", ".join(f"{key}: {value}" for key, value in extra_headers.items()))
    kv("Output", f"{'stdout' if out == '-' else out}  ({fmt})")

    try:
        config_results = []
        dos_results = []
        auth_results = []
        authn_results = []
        injection_results = []
        active_security_results = []
        active_security_report = {"summary": {"checks_sent": 0}}
        audit_results = []
        ml_results = []
        reviewed_sensitive_results = []
        path_results = []
        asset_results = []
        introspection_results = []
        request_forgery_results = []
        subscription_results = []
        subscription_report = {"summary": {}}
        rule_sensitive_candidates = []
        sensitive_review_report = {"summary": {"reported_sensitive_fields": 0}}
        relationship_map = {"summary": {"sensitive_fields_mapped": 0}}
        path_report = {"summary": {"total_paths": 0}, "paths": []}
        asset_report = {"summary": {}}
        operation_pack = {"operations": []}
        authorization_matrix = {"summary": {}}
        authentication_review = {"summary": {}}
        points_of_interest = {"summary": {}}
        schema_overview = {}
        schema_details = {}
        schema_source = "none"
        discovered_endpoints = []
        target_verified_graphql = None
        phase = 0
        fingerprint_result = None
        expected_categories = []

        config_data = {}
        if config:
            try:
                config_path = resolve_users_config_path(config)
                with config_path.open("r", encoding="utf-8") as handle:
                    config_data = yaml.safe_load(handle) or {}
                ok(f"Loaded auth config: {config_path}")
            except Exception as exc:
                err(f"Failed to load config: {exc}")

        if proxy:
            config_data["proxy"] = proxy
        if extra_headers:
            config_data.setdefault("headers", {}).update(extra_headers)
        if ml_embeddings:
            config_data["ml_embeddings"] = True

        logging.disable(logging.CRITICAL)

        if do_discover:
            phase += 1
            logging.disable(logging.NOTSET)
            section_subheader(f"Phase {phase}  •  Endpoint Discovery")
            logging.disable(logging.CRITICAL)
            try:
                from src.scanner.endpoint_discovery import EndpointDiscovery

                discovery = EndpointDiscovery(target_url, headers=extra_headers or None, proxy=proxy)
                logging.disable(logging.NOTSET)
                ok(f"Probing {len(discovery.paths)} common paths ...")
                logging.disable(logging.CRITICAL)
                endpoints = discovery.run()
                discovered_endpoints = list(endpoints or [])
                logging.disable(logging.NOTSET)
                if endpoints:
                    ok(f"Found {len(endpoints)} endpoint(s):")
                    for endpoint in endpoints:
                        click.secho(f"      \u2714  {endpoint}", fg="green")
                    if target_url.rstrip("/") in [endpoint.rsplit("/", 1)[0] for endpoint in endpoints]:
                        target_url = endpoints[0]
                        ok(f"Using discovered endpoint: {target_url}")
                else:
                    warn("No endpoints discovered. Continuing with provided URL.")
                logging.disable(logging.CRITICAL)
            except Exception as exc:
                logging.disable(logging.NOTSET)
                err(f"Discovery failed: {exc}")
                logging.disable(logging.CRITICAL)

        phase += 1
        expected_categories.append("RECON")
        logging.disable(logging.NOTSET)
        section_subheader(f"Phase {phase}  •  Engine Fingerprinting")
        logging.disable(logging.CRITICAL)
        try:
            from src.scanner.fingerprinter import GraphQLFingerprinter

            fingerprinter = GraphQLFingerprinter(target_url, headers=extra_headers or None, proxy=proxy)
            logging.disable(logging.NOTSET)
            ok("Verifying GraphQL endpoint ...")
            logging.disable(logging.CRITICAL)
            if fingerprinter.verify_graphql():
                target_verified_graphql = True
                logging.disable(logging.NOTSET)
                ok("GraphQL endpoint confirmed.")
                ok("Running engine probes ...")
                logging.disable(logging.CRITICAL)
                fingerprint_result = fingerprinter.run()
                logging.disable(logging.NOTSET)
                if fingerprint_result.detected:
                    ok(f"Engine: {click.style(fingerprint_result.engine_name, fg='green', bold=True)}")
                    if fingerprint_result.technologies:
                        kv("Technologies", ", ".join(fingerprint_result.technologies), indent=8)
                    if fingerprint_result.threat_matrix_url:
                        kv("Threat Matrix", fingerprint_result.threat_matrix_url, indent=8)
                else:
                    warn("Engine could not be identified.")
                logging.disable(logging.CRITICAL)
            else:
                target_verified_graphql = False
                logging.disable(logging.NOTSET)
                warn("Target may not be a GraphQL endpoint. Continuing anyway.")
                logging.disable(logging.CRITICAL)
        except Exception as exc:
            logging.disable(logging.NOTSET)
            err(f"Fingerprinting failed: {exc}")
            logging.disable(logging.CRITICAL)

        phase += 1
        logging.disable(logging.NOTSET)
        section_subheader(f"Phase {phase}  •  Asset Recon")
        logging.disable(logging.CRITICAL)
        try:
            asset_scanner = AssetReconScanner(target_url, config=config_data)
            asset_results = asset_scanner.run()
            asset_report = asset_scanner.report
            logging.disable(logging.NOTSET)
            summary = asset_report.get("summary", {})
            ok(
                "Scanned "
                f"{summary.get('documents_scanned', 0)} document(s), found "
                f"{summary.get('graphql_endpoints', 0)} endpoint hint(s), "
                f"{summary.get('subscription_endpoints', 0)} WebSocket hint(s), and "
                f"{summary.get('operations', 0)} named operation(s)"
            )
            for item in asset_results[:3]:
                finding(item)
            logging.disable(logging.CRITICAL)
        except Exception as exc:
            logging.disable(logging.NOTSET)
            err(f"Asset recon failed: {exc}")
            logging.disable(logging.CRITICAL)

        phase += 1
        logging.disable(logging.NOTSET)
        section_subheader(f"Phase {phase}  •  Introspection Bypass")
        logging.disable(logging.CRITICAL)
        try:
            bypass_scanner = IntrospectionBypassScanner(target_url, config=config_data)
            introspection_results = bypass_scanner.run()
            logging.disable(logging.NOTSET)
            summary = bypass_scanner.report.get("summary", {})
            ok(
                f"__schema: {'yes' if summary.get('schema_accessible') else 'no'}  •  "
                f"__type: {'yes' if summary.get('type_accessible') else 'no'}  •  "
                f"suggestions: {'yes' if summary.get('suggestion_leak') else 'no'}"
            )
            for item in introspection_results:
                finding(item)
            logging.disable(logging.CRITICAL)
        except Exception as exc:
            logging.disable(logging.NOTSET)
            err(f"Introspection bypass checks failed: {exc}")
            logging.disable(logging.CRITICAL)

        if "C" in technique:
            phase += 1
            expected_categories.append("CONFIG")
            logging.disable(logging.NOTSET)
            section_subheader(f"Phase {phase}  •  Configuration Checks")
            logging.disable(logging.CRITICAL)
            checker = ConfigChecker(target_url, schema={}, config=config_data)
            config_results = checker.run()
            logging.disable(logging.NOTSET)
            for item in config_results:
                finding(item)
            ok(f"{len(config_results)} finding(s)")
            logging.disable(logging.CRITICAL)

        logging.disable(logging.NOTSET)
        schema_data = None
        if schema:
            try:
                ok(f"Loading schema from {schema} ...")
                with open(schema, "r", encoding="utf-8") as handle:
                    schema_data = json.load(handle)
                if "data" in schema_data:
                    schema_data = schema_data["data"]
                schema_source = "file"
                ok("Schema loaded.")
            except Exception as exc:
                err(f"Failed to load schema: {exc}")
        else:
            phase += 1
            section_subheader(f"Phase {phase}  •  Schema Introspection")
            ok("Fetching schema via introspection ...")
            try:
                schema_data = fetch_introspection(target_url)
                schema_source = "introspection"
                ok("Schema retrieved successfully.")

            except Exception as exc:
                err(f"Introspection failed: {exc}")
                warn("Attempting blind schema reconstruction (Clairvoyance-style) ...")
                try:
                    from src.scanner.blind_introspector import BlindIntrospector

                    introspector = BlindIntrospector(
                        endpoint=target_url,
                        headers=extra_headers or None,
                        proxy=proxy if proxy else None,
                        bucket_size=10,
                        max_depth=1,
                    )
                    blind_schema = introspector.run()
                    blind_summary = introspector.summary()
                    if blind_summary["fields_discovered"] > 0:
                        schema_data = blind_schema.get("data", blind_schema)
                        schema_source = "blind"
                        ok(
                            f"Blind introspection found {blind_summary['fields_discovered']} field(s) "
                            f"across {blind_summary['types_discovered']} type(s)"
                        )
                    else:
                        warn("Blind introspection found no fields. Skipping schema-dependent checks.")
                except Exception as blind_exc:
                    err(f"Blind introspection also failed: {blind_exc}")
                    warn("Skipping schema-dependent checks.")
        logging.disable(logging.CRITICAL)

        graph_data = None
        if schema_data:
            try:
                schema_details = parse_schema_details(schema_data)
            except Exception:
                schema_details = {}
            try:
                operation_pack = OperationPackGenerator(schema_data).generate()
            except Exception:
                operation_pack = {"operations": []}

            phase += 1
            expected_categories.append("AUDIT")
            logging.disable(logging.NOTSET)
            section_subheader(f"Phase {phase}  •  Schema Audit")
            logging.disable(logging.CRITICAL)
            try:
                auditor = SchemaAuditor(target_url, schema_data, config=config_data)
                raw_audit_results = auditor.run()
                audit_results, rule_sensitive_candidates = split_sensitive_candidates(raw_audit_results)
                logging.disable(logging.NOTSET)
                for item in audit_results:
                    finding(item)
                if rule_sensitive_candidates:
                    warn(
                        f"Held back {len(rule_sensitive_candidates)} sensitive-field candidate(s) for "
                        "false-positive reduction."
                    )
                ok(
                    f"{len(audit_results)} structural finding(s), "
                    f"{len(rule_sensitive_candidates)} sensitive candidate(s)"
                )
                logging.disable(logging.CRITICAL)
            except Exception as exc:
                logging.disable(logging.NOTSET)
                err(f"Schema audit failed: {exc}")
                logging.disable(logging.CRITICAL)

            phase += 1
            logging.disable(logging.NOTSET)
            section_subheader(f"Phase {phase}  •  Path Enumeration")
            logging.disable(logging.CRITICAL)
            try:
                enumerator = GraphQLPathEnumerator(
                    schema_data,
                    max_depth=min(max(level + 4, 5), 8),
                    include_mutations=True,
                )
                path_report = enumerator.enumerate()
                top_paths = path_report.get("paths", [])[:10]
                logging.disable(logging.NOTSET)
                if top_paths:
                    for item in top_paths[:5]:
                        click.echo(f"      [{item['score']:>3}] {item['path']}  ->  {item['target_type']}")
                    if len(top_paths) > 5:
                        click.secho(f"      ... and {len(top_paths) - 5} more high-value path(s)", **DIM)
                    evidence = build_evidence(
                        rule_id="GG-RECON-PATH-ENUMERATION",
                        confidence="medium",
                        state="informational",
                        details={
                            "summary": path_report.get("summary", {}),
                            "top_paths": top_paths,
                        },
                    )
                    path_results.append(
                        Finding(
                            title="GraphQL Path Enumeration Results",
                            description="Guardian enumerated query and mutation paths to sensitive GraphQL object types for follow-up authorization and data exposure testing.",
                            severity="INFO",
                            category="RECON",
                            endpoint=target_url,
                            evidence=evidence,
                            rule_id="GG-RECON-PATH-ENUMERATION",
                            confidence="medium",
                            state="informational",
                        )
                    )
                    ok(f"{path_report['summary']['total_paths']} sensitive path(s) enumerated")
                else:
                    ok("No sensitive object paths matched the default target keywords.")
                logging.disable(logging.CRITICAL)
            except Exception as exc:
                logging.disable(logging.NOTSET)
                err(f"Path enumeration failed: {exc}")
                logging.disable(logging.CRITICAL)

            try:
                builder = DependencyGraphBuilder(schema_data)
                builder.build()
                graph_data = builder.export_dict()
            except Exception as exc:
                logging.disable(logging.NOTSET)
                err(f"Graph building failed: {exc}")
                logging.disable(logging.CRITICAL)

            try:
                points_of_interest = build_points_of_interest(
                    schema_data,
                    operation_pack,
                    path_report,
                    graph_data,
                )
            except Exception:
                points_of_interest = {"summary": {}}

            try:
                schema_overview = build_schema_overview(
                    schema_data,
                    endpoint=target_url,
                    source=schema_source,
                    verified_graphql=target_verified_graphql,
                    discovered_endpoints=discovered_endpoints,
                    fingerprint={
                        "detected": bool(fingerprint_result and fingerprint_result.detected),
                        "engine_name": getattr(fingerprint_result, "engine_name", None),
                        "technologies": getattr(fingerprint_result, "technologies", []),
                        "threat_matrix_url": getattr(fingerprint_result, "threat_matrix_url", None),
                    },
                    path_report=path_report,
                    operation_pack=operation_pack,
                    dependency_graph=graph_data,
                )
                click.echo("")
                click.secho("      Schema Overview", bold=True)
                click.secho(f"      {'─' * 40}")
                counts = schema_overview.get("counts", {})
                click.echo(f"        Source:         {schema_source}")
                click.echo(f"        Queries:        {click.style(str(counts.get('queries', 0)), bold=True)}")
                click.echo(f"        Mutations:      {click.style(str(counts.get('mutations', 0)), bold=True)}")
                if counts.get("subscriptions"):
                    click.echo(f"        Subscriptions:  {click.style(str(counts.get('subscriptions', 0)), bold=True)}")
                click.echo(f"        Types:          {click.style(str(counts.get('types', 0)), bold=True)}")
                if schema_overview.get("samples", {}).get("queries"):
                    click.echo(f"        Sample queries: {', '.join(schema_overview['samples']['queries'][:4])}")
                if schema_overview.get("samples", {}).get("mutations"):
                    click.echo(f"        Sample mutns:   {', '.join(schema_overview['samples']['mutations'][:4])}")
            except Exception:
                schema_overview = {}

            if ml:
                phase += 1
                expected_categories.append("ML")
                logging.disable(logging.NOTSET)
                section_subheader(f"Phase {phase}  •  ML Semantic Analysis")
                logging.disable(logging.CRITICAL)
                try:
                    from src.scanner.ml_analyzer import MLSemanticAnalyzer

                    logging.disable(logging.NOTSET)
                    ok("Loading Random Forest sensitive-field classifier ...")
                    logging.disable(logging.CRITICAL)
                    analyzer = MLSemanticAnalyzer(target_url, schema_data, config=config_data)
                    ml_results = analyzer.run()
                    logging.disable(logging.NOTSET)

                    if ml_results:
                        click.echo("")
                        click.secho("      ML-Flagged Candidate Fields", bold=True)
                        separator = "\u2500" * 50
                        click.secho(f"      {separator}", **DIM)
                        click.secho(f"      {'Field':<30} {'Score':>6}  {'Severity':<8}", bold=True)
                        click.secho(f"      {separator}", **DIM)
                        for item in ml_results:
                            field_name = item.field or item.title
                            score = "?"
                            if isinstance(item.evidence, dict) and item.evidence.get("ml_score") is not None:
                                score = f"{item.evidence['ml_score']:.2f}"
                            severity_color = SEVERITY_COLORS.get(item.severity, "white")
                            click.echo(
                                f"      {field_name:<30} "
                                f"{click.style(score.rjust(6), bold=True)}  "
                                f"{click.style(item.severity, fg=severity_color)}"
                            )
                        click.echo("")

                    ok(f"{len(ml_results)} sensitive field(s) detected via ML classifier")
                    logging.disable(logging.CRITICAL)
                except Exception as exc:
                    logging.disable(logging.NOTSET)
                    err(f"ML analysis failed: {exc}")
                    logging.disable(logging.CRITICAL)

            phase += 1
            logging.disable(logging.NOTSET)
            section_subheader(f"Phase {phase}  •  Sensitive Field Review")
            logging.disable(logging.CRITICAL)
            reviewed_sensitive_results, sensitive_review_report = review_sensitive_candidates(
                rule_sensitive_candidates,
                ml_results if ml else [],
            )
            logging.disable(logging.NOTSET)
            review_summary = sensitive_review_report.get("summary", {})
            for item in reviewed_sensitive_results:
                finding(item)
            ok(
                f"Reported {review_summary.get('reported_sensitive_fields', 0)} field(s); "
                f"filtered {review_summary.get('filtered_candidates', 0)} weaker candidate(s)"
            )
            logging.disable(logging.CRITICAL)

            phase += 1
            expected_categories.append("AUTH")
            logging.disable(logging.NOTSET)
            section_subheader(f"Phase {phase}  •  Authentication Checks")
            logging.disable(logging.CRITICAL)
            try:
                authn_scanner = AuthenticationScanner(
                    target_url,
                    schema=schema_data,
                    config=config_data,
                    operation_pack=operation_pack,
                )
                authn_results = authn_scanner.run()
                authentication_review = authn_scanner.report
                logging.disable(logging.NOTSET)
                authn_summary = authentication_review.get("summary", {})
                for item in authn_results:
                    finding(item)
                ok(
                    f"{authn_summary.get('auth_queries', 0)} auth query surface(s), "
                    f"{authn_summary.get('auth_mutations', 0)} auth mutation surface(s), "
                    f"{authn_summary.get('anonymous_identity_accesses', 0)} anonymous identity access issue(s), "
                    f"{authn_summary.get('verbose_auth_errors', 0)} verbose auth error clue(s)"
                )
                logging.disable(logging.CRITICAL)
            except Exception as exc:
                logging.disable(logging.NOTSET)
                err(f"Authentication checks failed: {exc}")
                logging.disable(logging.CRITICAL)

            if "A" in technique and config_data and graph_data and scan_profile != PROFILE_PASSIVE:
                phase += 1
                logging.disable(logging.NOTSET)
                section_subheader(f"Phase {phase}  •  Authorization (IDOR) Checks")
                logging.disable(logging.CRITICAL)
                try:
                    tester = AuthTester(
                        target_url,
                        config_data,
                        schema_data,
                        graph_data,
                        path_report=path_report,
                        operation_pack=operation_pack,
                        asset_recon=asset_report,
                    )
                    auth_results = tester.run()
                    authorization_matrix = tester.matrix_report
                    logging.disable(logging.NOTSET)
                    vulnerability_count = 0
                    anonymous_count = 0
                    for result in auth_results:
                        if result["idor_detected"]:
                            vulnerability_count += 1
                            click.secho(f"      \u2718  VULNERABLE  {result['creator']} -> {result['accessor']}", fg="red", bold=True)
                        elif result.get("anonymous_detected"):
                            anonymous_count += 1
                            click.secho(f"      \u2718  PUBLIC      {result['creator']} -> {result['accessor']}", fg="red", bold=True)
                        else:
                            click.secho(f"      \u2714  Safe        {result['creator']} -> {result['accessor']}", fg="green")
                    summary = authorization_matrix.get("summary", {})
                    ok(
                        f"{vulnerability_count} IDOR vulnerability(ies), "
                        f"{anonymous_count} anonymous resource exposure(s), "
                        f"{summary.get('mutation_vulnerabilities', 0)} mutation issue(s), "
                        f"{summary.get('subscription_vulnerabilities', 0)} subscription issue(s)"
                    )
                    logging.disable(logging.CRITICAL)
                except Exception as exc:
                    logging.disable(logging.NOTSET)
                    err(f"Auth testing failed: {exc}")
                    logging.disable(logging.CRITICAL)

            if "I" in technique and scan_profile != PROFILE_PASSIVE:
                phase += 1
                expected_categories.append("INJECTION")
                logging.disable(logging.NOTSET)
                section_subheader(f"Phase {phase}  •  Injection Fuzzing")
                logging.disable(logging.CRITICAL)
                injector = PayloadInjector(target_url, schema_data, config_data, graph=graph_data)
                injection_results = injector.run()
                logging.disable(logging.NOTSET)
                for item in injection_results[:10]:
                    finding(item)
                if len(injection_results) > 10:
                    click.secho(f"      ... and {len(injection_results) - 10} more", **DIM)
                ok(f"{len(injection_results)} finding(s)")
                logging.disable(logging.CRITICAL)

            if (
                scan_profile != PROFILE_PASSIVE
                and any(letter in technique for letter in ("I", "A"))
            ):
                phase += 1
                logging.disable(logging.NOTSET)
                section_subheader(
                    f"Phase {phase}  •  Active Security Validation"
                )
                logging.disable(logging.CRITICAL)

                try:
                    active_scanner = ActiveSecurityScanner(
                        target_url,
                        schema=schema_data,
                        config=config_data,
                        profile=scan_profile,
                        technique=technique,
                    )
                    active_security_results = active_scanner.run()
                    active_security_report = active_scanner.report

                    logging.disable(logging.NOTSET)
                    active_summary = active_security_report.get(
                        "summary",
                        {},
                    )

                    for item in active_security_results:
                        finding(item)

                    ok(
                        f"{active_summary.get('checks_sent', 0)} probe(s); "
                        f"{active_summary.get('anonymous_sensitive_access', 0)} "
                        f"anonymous access issue(s); "
                        f"{active_summary.get('token_binding_failures', 0)} "
                        f"token-binding issue(s); "
                        f"{active_summary.get('command_injection', 0)} "
                        f"command injection issue(s); "
                        f"{active_summary.get('sql_injection', 0)} "
                        f"SQL injection issue(s); "
                        f"{active_summary.get('same_origin_ssrf', 0)} "
                        f"SSRF issue(s)"
                    )
                    logging.disable(logging.CRITICAL)
                except Exception as exc:
                    logging.disable(logging.NOTSET)
                    err(
                        "Active security validation failed: "
                        f"{exc}"
                    )
                    logging.disable(logging.CRITICAL)

        if "C" in technique:
            phase += 1
            logging.disable(logging.NOTSET)
            section_subheader(f"Phase {phase}  •  Request Forgery Matrix")
            logging.disable(logging.CRITICAL)
            try:
                forgery_scanner = RequestForgeryScanner(
                    target_url,
                    config=config_data,
                    operation_pack=operation_pack,
                    profile=scan_profile,
                )
                request_forgery_results = forgery_scanner.run()
                logging.disable(logging.NOTSET)
                summary = forgery_scanner.report.get("summary", {})
                ok(
                    f"Tested {summary.get('variants_tested', 0)} transport variant(s); "
                    f"{summary.get('variants_accepted', 0)} accepted"
                )
                for item in request_forgery_results:
                    if item.severity != "INFO":
                        finding(item)
                logging.disable(logging.CRITICAL)
            except Exception as exc:
                logging.disable(logging.NOTSET)
                err(f"Request forgery checks failed: {exc}")
                logging.disable(logging.CRITICAL)

        phase += 1
        logging.disable(logging.NOTSET)
        section_subheader(f"Phase {phase}  •  Subscription Security")
        logging.disable(logging.CRITICAL)
        try:
            subscription_scanner = SubscriptionSecurityScanner(
                target_url,
                schema=schema_data or {},
                config=config_data,
                asset_recon=asset_report,
            )
            subscription_results = subscription_scanner.run()
            subscription_report = subscription_scanner.report
            logging.disable(logging.NOTSET)
            summary = subscription_report.get("summary", {})
            ok(
                f"Candidates: {summary.get('candidate_endpoints', 0)}  •  "
                f"active: {summary.get('active_endpoints', 0)}  •  "
                f"unauth handshakes: {summary.get('unauthenticated_handshakes', 0)}  •  "
                f"protocol acks: {summary.get('unauthenticated_acks', 0)}"
            )
            for item in subscription_results:
                finding(item)
            logging.disable(logging.CRITICAL)
        except Exception as exc:
            logging.disable(logging.NOTSET)
            err(f"Subscription security checks failed: {exc}")
            logging.disable(logging.CRITICAL)

        if "D" in technique and scan_profile != PROFILE_PASSIVE:
            phase += 1
            expected_categories.append("DOS")
            logging.disable(logging.NOTSET)
            dos_label = "Denial-of-Service Checks"
            if scan_profile == PROFILE_DEFAULT:
                dos_label += "  (safe probes only)"
            elif scan_profile == PROFILE_AGGRESSIVE:
                dos_label += "  (destructive)"
            section_subheader(f"Phase {phase}  •  {dos_label}")
            logging.disable(logging.CRITICAL)
            dos_scanner = DoSScanner(target_url, schema=schema_data or {}, config=config_data)
            dos_results = dos_scanner.run(profile=scan_profile)
            logging.disable(logging.NOTSET)
            for item in dos_results:
                finding(item)
            ok(f"{len(dos_results)} finding(s)")
            logging.disable(logging.CRITICAL)

        logging.disable(logging.NOTSET)

        auth_findings = ResultConverter.convert_auth_results(auth_results, matrix_report=authorization_matrix)
        all_findings = (
            asset_results
            + introspection_results
            + config_results
            + audit_results
            + reviewed_sensitive_results
            + path_results
            + request_forgery_results
            + subscription_results
            + authn_results
            + auth_findings
            + injection_results
            + active_security_results
            + dos_results
        )

        llm_validation_summary = {
            "enabled": bool(llm_validate),
            "provider": llm_provider,
            "model": llm_model,
            "findings_reviewed": 0,
            "api_successes": 0,
            "api_errors": 0,
            "filtered_false_positives": 0,
            "filtered_findings": [],
            "kept_findings": len(all_findings),
            "status": "disabled" if not llm_validate else "not-run",
        }

        if llm_validate and all_findings:
            phase += 1
            section_subheader(f"Phase {phase}  •  LLM Validation")
            try:
                from src.scanner.llm_validator import LLMValidator

                validator = LLMValidator(model_name=llm_model, provider=llm_provider)
                llm_validation_summary["provider"] = validator.provider
                llm_validation_summary["model"] = validator.model_name
                if not validator.enabled:
                    warn(f"LLM validation skipped because no {validator.provider.title()} API key is configured.")
                    llm_validation_summary["status"] = "skipped-no-api-key"
                else:
                    kv("LLM provider", validator.provider)
                    kv("LLM model", validator.model_name)
                    kv("Findings to review", len(all_findings))
                    llm_validation_summary["findings_reviewed"] = len(all_findings)
                    validation_results = validator.batch_validate_findings(all_findings, schema_data if schema_data else {})

                    click.echo("")
                    click.secho("      LLM Validation Verdicts", bold=True)
                    separator = "\u2500" * 58
                    click.secho(f"      {separator}", **DIM)

                    kept = []
                    filtered_count = 0
                    error_count = 0
                    for result in validation_results:
                        finding_item = result["finding"]
                        validation = result["validation"]
                        finding_item.ai_validation = validation
                        validated = validation.get("validated", False)
                        is_false_positive = validation.get("is_false_positive", False)
                        confidence = validation.get("confidence", 0)
                        reasoning = validation.get("reason") or validation.get("reasoning", "No reasoning")

                        if not validated:
                            verdict_icon = "!"
                            verdict_label = "ERROR"
                            verdict_color = "red"
                            error_count += 1
                            llm_validation_summary["api_errors"] += 1
                            kept.append(finding_item)
                        elif is_false_positive and confidence >= 0.65:
                            verdict_icon = "\u2718"
                            verdict_label = "REJECT (FP)"
                            verdict_color = "yellow"
                            filtered_count += 1
                            llm_validation_summary["api_successes"] += 1
                            llm_validation_summary["filtered_findings"].append(
                                {
                                    "title": finding_item.title,
                                    "field": finding_item.field,
                                    "decision": validation.get("decision"),
                                    "confidence": confidence,
                                    "reason": reasoning,
                                    "manual_check": validation.get("manual_check"),
                                }
                            )
                        else:
                            verdict_icon = "\u2714"
                            verdict_label = "KEEP"
                            verdict_color = "green"
                            llm_validation_summary["api_successes"] += 1
                            kept.append(finding_item)

                        title = finding_item.title
                        if len(title) > 42:
                            title = title[:39] + "..."
                        click.echo(
                            f"      {click.style(verdict_icon, fg=verdict_color)}  "
                            f"{title:<42} "
                            f"{click.style(f'{confidence:.0%}', bold=True)} "
                            f"{click.style(verdict_label, fg=verdict_color)}"
                        )
                        if len(reasoning) > 55:
                            reasoning = reasoning[:52] + "..."
                        click.secho(f"         \u2514\u2500 {reasoning}", **DIM)

                    click.echo("")
                    if filtered_count > 0:
                        warn(f"Filtered {filtered_count} likely false positive(s)")
                    if error_count > 0:
                        warn(f"{error_count} finding(s) kept because LLM validation failed")
                    ok(f"LLM API responses: {llm_validation_summary['api_successes']}/{llm_validation_summary['findings_reviewed']} succeeded")
                    ok(f"{len(kept)} finding(s) remain after LLM validation")
                    llm_validation_summary["filtered_false_positives"] = filtered_count
                    llm_validation_summary["kept_findings"] = len(kept)
                    llm_validation_summary["status"] = "completed-with-errors" if error_count else "completed"
                    all_findings = kept

            except Exception as exc:
                err(f"LLM validation failed: {exc}")
                llm_validation_summary["status"] = "failed"
                llm_validation_summary["error"] = str(exc)

        enrich_findings(all_findings)
        elapsed = time.time() - scan_start
        relationship_map = build_relationship_map_from_parts(
            sensitive_field_review=sensitive_review_report,
            points_of_interest=points_of_interest,
            path_report=path_report,
            operation_pack=operation_pack,
            authorization_matrix=authorization_matrix,
        )
        report_context = {
            "metadata": {
                "endpoint": target_url,
                "profile": scan_profile,
                "level": level,
                "risk": risk,
                "technique": technique,
                "duration_seconds": round(elapsed, 2),
            },
            "target_profile": {
                "selected_endpoint": target_url,
                "verified_graphql": target_verified_graphql,
                "discovered_endpoints": discovered_endpoints,
                "fingerprint": {
                    "detected": bool(fingerprint_result and fingerprint_result.detected),
                    "engine_name": getattr(fingerprint_result, "engine_name", None),
                    "technologies": getattr(fingerprint_result, "technologies", []),
                    "threat_matrix_url": getattr(fingerprint_result, "threat_matrix_url", None),
                },
            },
            "schema": {
                "available": bool(schema_data),
                "source": schema_source,
                "summary": schema_details,
                "overview": schema_overview,
            },
            "paths": path_report,
            "operation_pack": operation_pack,
            "authentication_review": authentication_review,
            "active_security_validation": active_security_report,
            "subscription_security": subscription_report,
            "authorization_matrix": authorization_matrix,
            "sensitive_field_review": sensitive_review_report,
            "points_of_interest": points_of_interest,
            "relationship_map": relationship_map,
            "llm_validation": llm_validation_summary,
        }

        if fmt == "json":
            JSONReporter.generate(all_findings, out, report_context=report_context)
        elif fmt == "csv":
            CSVReporter.generate(all_findings, out)
        elif fmt == "html":
            HTMLReporter(out).generate(all_findings, report_context=report_context)

        summary_table(all_findings, expected_categories=expected_categories)

        if verbose:
            sample = None
            for item in all_findings:
                if item.severity == "HIGH" and item.field:
                    sample = item
                    break
            if not sample:
                for item in all_findings:
                    if item.severity == "HIGH":
                        sample = item
                        break
            if not sample and all_findings:
                sample = all_findings[0]
            if sample:
                click.secho("      \u2500\u2500 Detailed Finding (sample) \u2500\u2500", bold=True)
                finding_detail(sample, out)

        if fingerprint_result and fingerprint_result.detected:
            kv(
                "Engine",
                f"{fingerprint_result.engine_name} ({', '.join(fingerprint_result.technologies)})"
                if fingerprint_result.technologies
                else fingerprint_result.engine_name,
            )
        kv("Report", f"{'stdout' if out == '-' else out}  ({fmt})")
        kv("Duration", f"{elapsed:.1f}s")
        click.echo("")

        if should_fail_scan(all_findings, fail_on_severity):
            warn(f"Failing scan because findings met the {str(fail_on_severity).upper()} threshold.")
            raise SystemExit(EXIT_FINDINGS)

    except KeyboardInterrupt:
        logging.disable(logging.NOTSET)
        err("Scan interrupted by user.")
        raise SystemExit(EXIT_INTERRUPTED)


__all__ = ["scan", "_load_scan_config_file", "_modules_to_technique", "resolve_scan_config"]
