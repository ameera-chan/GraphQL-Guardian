"""Reconnaissance and focused CLI commands."""

from __future__ import annotations

import json

import click
import yaml

from src.scanner.auth_tester import AuthTester
from src.scanner.operation_pack import OperationPackGenerator
from src.scanner.dependency_graph import DependencyGraphBuilder
from src.scanner.injector import PayloadInjector
from src.scanner.path_enumerator import GraphQLPathEnumerator
from src.scanner.schema_overview import build_schema_overview
from src.scanner.schema_parser import fetch_introspection, parse_schema_details, save_schema
from src.utils.files import write_json

from src.cli.shared import (
    EXIT_RUNTIME_ERROR,
    err,
    finding,
    header as section_header,
    kv,
    machine_output_mode,
    ok,
    parse_headers,
    resolve_users_config_path,
    step,
    subheader,
    warn,
    DIM,
)


@click.command()
@click.option("-u", "--endpoint", required=True, help="The GraphQL endpoint URL.")
@click.option("-o", "--out", default="reports/schema.json", show_default=True, help="Output file.")
def introspect(endpoint, out):
    """Fetch and save the GraphQL schema via introspection."""
    with machine_output_mode(out == "-"):
        section_header("INTROSPECTION")
        step(f"Target:  {endpoint}")
        step("Sending introspection query ...")

        try:
            data = fetch_introspection(endpoint)
            ok("Introspection successful.")

            save_schema(data, out)
            ok(f"Schema saved to {'stdout' if out == '-' else out}")

            summary = parse_schema_details(data)
            subheader("Schema Overview")
            kv("Types", len(summary["types"]))
            kv("Queries", len(summary["queries"]))
            kv("Mutations", len(summary["mutations"]))
            kv("Subscriptions", len(summary["subscriptions"]))
            kv("Input Objects", len(summary.get("input_objects", [])))
            kv("Enums", len(summary.get("enums", [])))
            abstract_count = len(summary.get("interfaces", [])) + len(summary.get("unions", []))
            kv("Abstract Types", abstract_count)
            kv("Custom Scalars", len(summary.get("custom_scalars", [])))

            if summary["queries"]:
                click.echo(f"\n      Sample Queries:    {', '.join(summary['queries'][:5])}")
            if summary["mutations"]:
                click.echo(f"      Sample Mutations:  {', '.join(summary['mutations'][:5])}")
            click.echo("")

        except Exception as exc:
            err(f"Error: {exc}")
            raise SystemExit(EXIT_RUNTIME_ERROR)


@click.command()
@click.option("-u", "--endpoint", required=True, help="The GraphQL endpoint URL.")
@click.option("--proxy", default=None, help="HTTP proxy (e.g. http://127.0.0.1:8080).")
@click.option("-H", "--header", multiple=True, help="Custom header (Key: Value). Repeatable.")
def fingerprint(endpoint, proxy, header):
    """Identify the backend GraphQL engine via error probing."""
    from src.scanner.fingerprinter import GraphQLFingerprinter

    section_header("ENGINE FINGERPRINTING")
    step(f"Target:  {endpoint}")

    extra_headers = parse_headers(header)

    scanner = GraphQLFingerprinter(endpoint, headers=extra_headers or None, proxy=proxy)

    step("Verifying GraphQL endpoint ...")
    if not scanner.verify_graphql():
        err("Target does not appear to be a GraphQL endpoint.")
        raise SystemExit(EXIT_RUNTIME_ERROR)
    ok("GraphQL endpoint confirmed.")

    step("Running engine fingerprint probes ...")
    result = scanner.run()

    if result.detected:
        ok(f"Engine detected: {click.style(result.engine_name, fg='green', bold=True)}")
        if result.technologies:
            kv("Technologies", ", ".join(result.technologies))
        if result.engine_url:
            kv("Project URL", result.engine_url)
        if result.threat_matrix_url:
            kv("Threat Matrix", result.threat_matrix_url)
    else:
        warn("Could not identify the GraphQL engine.")
    click.echo("")


@click.command()
@click.option("-u", "--url", required=True, help="Base URL to probe (e.g. http://target.com).")
@click.option("--proxy", default=None, help="HTTP proxy (e.g. http://127.0.0.1:8080).")
@click.option("-H", "--header", multiple=True, help="Custom header (Key: Value). Repeatable.")
def discover(url, proxy, header):
    """Discover GraphQL endpoints by probing common paths."""
    from src.scanner.endpoint_discovery import EndpointDiscovery

    section_header("ENDPOINT DISCOVERY")
    step(f"Base URL:  {url}")

    extra_headers = parse_headers(header)
    scanner = EndpointDiscovery(url, headers=extra_headers or None, proxy=proxy)
    step(f"Probing {len(scanner.paths)} common paths ...")

    endpoints = scanner.run()

    if endpoints:
        ok(f"Found {len(endpoints)} GraphQL endpoint(s):")
        for endpoint in endpoints:
            click.secho(f"      \u2714  {endpoint}", fg="green")
    else:
        warn("No GraphQL endpoints discovered.")
    click.echo("")


@click.command()
@click.option("-u", "--endpoint", required=False, help="The GraphQL endpoint URL.")
@click.option("-s", "--schema-file", required=False, help="Existing schema JSON file.")
@click.option("--base-url", required=False, help="Base URL to probe when using --discover.")
@click.option("--discover", is_flag=True, help="Run endpoint discovery before schema acquisition.")
@click.option("--proxy", default=None, help="HTTP proxy (e.g. http://127.0.0.1:8080).")
@click.option("-H", "--header", multiple=True, help="Custom header (Key: Value). Repeatable.")
@click.option("-o", "--out", default="reports/schema_overview.json", show_default=True, help="Output file.")
def overview(endpoint, schema_file, base_url, discover, proxy, header, out):
    """Build a schema-aware CLI overview for recon and follow-up testing."""
    from src.scanner.blind_introspector import BlindIntrospector
    from src.scanner.endpoint_discovery import EndpointDiscovery
    from src.scanner.fingerprinter import GraphQLFingerprinter

    if not endpoint and not schema_file and not base_url:
        raise click.UsageError("Provide --endpoint, --schema-file, or --base-url.")

    with machine_output_mode(out == "-"):
        section_header("SCHEMA-AWARE OVERVIEW")

        extra_headers = parse_headers(header)
        selected_endpoint = endpoint
        discovered_endpoints = []
        verified_graphql = None
        fingerprint = {}
        schema_source = "file"

        if discover and (base_url or endpoint):
            probe_url = base_url or endpoint
            step(f"Discovering GraphQL endpoints from {probe_url} ...")
            discovery = EndpointDiscovery(probe_url, headers=extra_headers or None, proxy=proxy)
            discovered_endpoints = discovery.run()
            if discovered_endpoints:
                ok(f"Found {len(discovered_endpoints)} endpoint hint(s)")
                selected_endpoint = selected_endpoint or discovered_endpoints[0]
            else:
                warn("No GraphQL endpoints discovered from the supplied base URL.")

        schema_data = None
        if schema_file:
            step(f"Loading schema from {schema_file} ...")
            with open(schema_file, "r", encoding="utf-8") as handle:
                schema_data = json.load(handle)
            if "data" in schema_data:
                schema_data = schema_data["data"]
            ok("Schema loaded from file.")

        if selected_endpoint:
            step(f"Confirming GraphQL behavior at {selected_endpoint} ...")
            fingerprinter = GraphQLFingerprinter(selected_endpoint, headers=extra_headers or None, proxy=proxy)
            verified_graphql = fingerprinter.verify_graphql()
            if verified_graphql:
                ok("GraphQL endpoint confirmed.")
                result = fingerprinter.run()
                fingerprint = {
                    "detected": result.detected,
                    "engine_name": result.engine_name,
                    "technologies": result.technologies,
                    "threat_matrix_url": result.threat_matrix_url,
                }
            else:
                warn("Target did not clearly match GraphQL response patterns.")

        if not schema_data and selected_endpoint:
            schema_source = "introspection"
            step("Fetching schema via introspection ...")
            try:
                schema_data = fetch_introspection(selected_endpoint)
                ok("Schema retrieved successfully.")
            except Exception as exc:
                warn(f"Introspection failed: {exc}")
                warn("Attempting blind schema reconstruction ...")
                schema_source = "blind"
                blind = BlindIntrospector(
                    endpoint=selected_endpoint,
                    headers=extra_headers or None,
                    proxy=proxy,
                    bucket_size=10,
                    max_depth=1,
                )
                blind_schema = blind.run()
                schema_data = blind_schema.get("data", blind_schema)
                ok("Blind schema reconstruction completed.")

        if not schema_data:
            raise click.ClickException("No schema data was available to build an overview.")

        details = parse_schema_details(schema_data)
        builder = DependencyGraphBuilder(schema_data)
        graph = builder.build()
        graph_data = builder.export_dict()
        path_report = GraphQLPathEnumerator(
            schema_data,
            max_depth=6,
            include_mutations=True,
        ).enumerate()
        operation_pack = OperationPackGenerator(schema_data).generate()
        overview_report = build_schema_overview(
            schema_data,
            endpoint=selected_endpoint,
            source=schema_source,
            verified_graphql=verified_graphql,
            discovered_endpoints=discovered_endpoints,
            fingerprint=fingerprint,
            path_report=path_report,
            operation_pack=operation_pack,
            dependency_graph=graph_data,
        )

        write_json(
            out,
            {
                "schema": {"summary": details, "overview": overview_report},
                "dependency_graph": {
                    "nodes": graph.number_of_nodes(),
                    "edges": graph.number_of_edges(),
                    "creators": len(graph_data.get("analysis", {}).get("creators", [])),
                    "accessors": len(graph_data.get("analysis", {}).get("accessors", [])),
                },
                "paths": path_report,
                "operation_pack": operation_pack,
            },
        )

        target = overview_report["target"]
        counts = overview_report["counts"]
        auth_surface = overview_report["auth_surface"]

        kv("Endpoint", target.get("endpoint") or "Schema file only")
        kv("Schema Source", overview_report["schema_source"])
        kv("Verified GraphQL", "yes" if target.get("verified_graphql") else "no")
        kv("Types", counts["types"])
        kv("Queries", counts["queries"])
        kv("Mutations", counts["mutations"])
        kv("Subscriptions", counts["subscriptions"])
        kv("Auth Paths", len(auth_surface.get("auth_paths", [])))
        kv("Creators", len(auth_surface.get("creators", [])))
        kv("Accessors", len(auth_surface.get("accessors", [])))

        if overview_report["samples"]["queries"]:
            subheader("Query Overview")
            click.echo(f"      {', '.join(overview_report['samples']['queries'][:6])}")
        if overview_report["samples"]["mutations"]:
            subheader("Mutation Overview")
            click.echo(f"      {', '.join(overview_report['samples']['mutations'][:6])}")
        if auth_surface.get("auth_paths"):
            subheader("Connected Access Paths")
            for item in auth_surface["auth_paths"][:5]:
                click.echo(f"      [{item['score']:>3}] {item['path']}  ->  {item['target_type']}")

        ok(f"Overview saved to {'stdout' if out == '-' else out}")
        click.echo("")


@click.command()
@click.option("-u", "--endpoint", required=True, help="The GraphQL endpoint URL.")
@click.option("-w", "--wordlist", default=None, help="Path to custom wordlist file.")
@click.option("-o", "--out", default="reports/blind_schema.json", show_default=True, help="Output schema file.")
@click.option("-b", "--bucket-size", default=10, show_default=True, type=int, help="Words per request bucket.")
@click.option("-d", "--depth", default=2, show_default=True, type=int, help="Max recursion depth for object types.")
@click.option("--proxy", default=None, help="HTTP proxy (e.g. http://127.0.0.1:8080).")
@click.option("-H", "--header", multiple=True, help="Custom header (Key: Value). Repeatable.")
def clairvoy(endpoint, wordlist, out, bucket_size, depth, proxy, header):
    """Blind schema reconstruction when introspection is disabled."""
    from src.scanner.blind_introspector import BlindIntrospector

    with machine_output_mode(out == "-"):
        section_header("BLIND SCHEMA RECONSTRUCTION")
        step(f"Target:  {endpoint}")

        extra_headers = parse_headers(header)
        words = None
        if wordlist:
            try:
                with open(wordlist, "r", encoding="utf-8") as handle:
                    words = [line.strip() for line in handle if line.strip() and not line.strip().startswith("#")]
                kv("Wordlist", f"{wordlist}  ({len(words)} words)")
            except Exception as exc:
                err(f"Failed to load wordlist: {exc}")
                raise SystemExit(EXIT_RUNTIME_ERROR)
        else:
            kv("Wordlist", "Built-in GraphQL wordlist")

        kv("Bucket Size", str(bucket_size))
        kv("Max Depth", str(depth))

        introspector = BlindIntrospector(
            endpoint=endpoint,
            wordlist=words,
            headers=extra_headers or None,
            proxy=proxy,
            bucket_size=bucket_size,
            max_depth=depth,
        )

        step("Running blind introspection ...")
        schema = introspector.run()
        summary = introspector.summary()

        write_json(out, schema)
        ok(f"Schema saved to {'stdout' if out == '-' else out}")

        subheader("Discovery Summary")
        kv("Types Discovered", str(summary["types_discovered"]))
        kv("Fields Discovered", str(summary["fields_discovered"]))
        kv("Arguments Discovered", str(summary["arguments_discovered"]))
        kv("Root Query Type", summary["root_query_type"] or "Not detected")
        kv("Mutation Type", summary["mutation_type"] or "Not detected")
        kv("Requests Sent", str(summary["requests_sent"]))
        kv("Duration", f"{summary['elapsed_seconds']}s")

        if summary["types"]:
            click.echo("")
            click.secho("      Reconstructed Types & Fields", bold=True)
            separator = "\u2500" * 50
            click.secho(f"      {separator}", **DIM)
            for type_name, fields in summary["types"].items():
                click.secho(f"      {click.style(type_name, fg='cyan', bold=True)}", nl=False)
                click.echo(f"  ({len(fields)} fields)")
                for field_name in fields[:15]:
                    click.echo(f"        \u2022 {field_name}")
                if len(fields) > 15:
                    click.secho(f"        ... and {len(fields) - 15} more", **DIM)

        click.echo("")


@click.command()
@click.option("-s", "--schema", required=True, help="Path to the schema JSON file.")
@click.option("-o", "--out", default="reports/graph.json", show_default=True, help="Output file.")
def graph(schema, out):
    """Build a dependency graph from a saved schema."""
    with machine_output_mode(out == "-"):
        section_header("DEPENDENCY GRAPH")
        step(f"Loading schema from {schema} ...")

        try:
            with open(schema, "r", encoding="utf-8") as handle:
                schema_data = json.load(handle)
            if "data" in schema_data:
                schema_data = schema_data["data"]

            builder = DependencyGraphBuilder(schema_data)
            builder.build()
            builder.export_json(out)
            stats = builder.get_stats()

            ok(f"Graph saved to {'stdout' if out == '-' else out}")
            subheader("Graph Statistics")
            kv("Nodes", stats["nodes"])
            kv("Edges", stats["edges"])
            kv("Creators", stats["creators"])
            kv("Accessors", stats["accessors"])

            if stats["creators"] > 0:
                subheader("Detected Creators")
                for creator in builder.resource_creators:
                    click.echo(f"        {creator['operation']}  ->  {creator['resource']}")
            click.echo("")

        except Exception as exc:
            err(f"Error: {exc}")
            raise SystemExit(EXIT_RUNTIME_ERROR)


@click.command(name="paths")
@click.option("-s", "--schema", required=True, help="Path to the schema JSON file.")
@click.option("-t", "--target-type", multiple=True, help="Target object/interface/union type. Repeatable.")
@click.option("--all-types", is_flag=True, help="Enumerate paths to all object/interface/union types.")
@click.option("--max-depth", default=6, show_default=True, type=int, help="Maximum field depth to traverse.")
@click.option("--include-mutations/--no-mutations", default=True, show_default=True, help="Include mutation roots.")
@click.option("--include-subscriptions", is_flag=True, help="Include subscription roots.")
@click.option("-o", "--out", default="reports/paths.json", show_default=True, help="Output file.")
def paths(schema, target_type, all_types, max_depth, include_mutations, include_subscriptions, out):
    """Enumerate GraphQL paths from operation roots to sensitive or target types."""
    with machine_output_mode(out == "-"):
        section_header("PATH ENUMERATION")
        step(f"Loading schema from {schema} ...")

        try:
            with open(schema, "r", encoding="utf-8") as handle:
                schema_data = json.load(handle)

            enumerator = GraphQLPathEnumerator(
                schema_data,
                target_types=target_type or None,
                max_depth=max_depth,
                include_mutations=include_mutations,
                include_subscriptions=include_subscriptions,
                all_types=all_types,
            )
            report = enumerator.enumerate()
            write_json(out, report)

            summary = report["summary"]
            ok(f"Path report saved to {'stdout' if out == '-' else out}")
            subheader("Enumeration Summary")
            kv("Total Paths", summary["total_paths"])
            kv("Max Depth", summary["max_depth"])
            kv("Targets", ", ".join(summary["target_types"][:12]) or "Sensitive types only")

            top_paths = report["paths"][:10]
            if top_paths:
                subheader("Top Paths")
                for item in top_paths:
                    click.echo(f"        [{item['score']:>3}] {item['path']}  ->  {item['target_type']}")
            else:
                warn("No matching paths found.")
            click.echo("")

        except Exception as exc:
            err(f"Error: {exc}")
            raise SystemExit(EXIT_RUNTIME_ERROR)


@click.command(name="authz")
@click.option("-u", "--endpoint", required=True, help="The GraphQL endpoint URL.")
@click.option("-c", "--config", required=True, help="Path to users YAML config.")
@click.option("-s", "--schema", required=True, help="Path to the schema JSON file.")
@click.option("-g", "--graph", default="reports/graph.json", show_default=True, help="Dependency graph file.")
@click.option("--paths-report", default=None, help="Optional path report JSON file.")
@click.option("-o", "--out", default="reports/auth_report.json", show_default=True, help="Detailed output file.")
def authz(endpoint, config, schema, graph, paths_report, out):
    """Test broken object and role authorization."""
    _run_authz(endpoint, config, schema, graph, paths_report, out)


@click.command(name="test-auth", hidden=True)
@click.option("-u", "--endpoint", required=True, help="The GraphQL endpoint URL.")
@click.option("-c", "--config", required=True, help="Path to users YAML config.")
@click.option("-s", "--schema", required=True, help="Path to the schema JSON file.")
@click.option("-g", "--graph", default="reports/graph.json", show_default=True, help="Dependency graph file.")
@click.option("--paths-report", default=None, help="Optional path report JSON file.")
@click.option("-o", "--out", default="reports/auth_report.json", show_default=True, help="Detailed output file.")
def test_auth(endpoint, config, schema, graph, paths_report, out):
    """Compatibility alias for authz."""
    _run_authz(endpoint, config, schema, graph, paths_report, out)


def _run_authz(endpoint, config, schema, graph, paths_report, out):
    """Run structured authorization tests with stateful creator-to-accessor evidence."""
    with machine_output_mode(out == "-"):
        section_header("AUTHORIZATION TESTING")
        step(f"Target:  {endpoint}")

        try:
            config_path = resolve_users_config_path(config)
            with config_path.open("r", encoding="utf-8") as handle:
                config_data = yaml.safe_load(handle)
            with open(schema, "r", encoding="utf-8") as handle:
                schema_data = json.load(handle)
            with open(graph, "r", encoding="utf-8") as handle:
                graph_data = json.load(handle)

            if "data" in schema_data:
                schema_data = schema_data["data"]

            if paths_report:
                with open(paths_report, "r", encoding="utf-8") as handle:
                    path_report = json.load(handle)
            else:
                path_report = GraphQLPathEnumerator(
                    schema_data,
                    max_depth=6,
                    include_mutations=True,
                ).enumerate()

            operation_pack = OperationPackGenerator(schema_data).generate()
            tester = AuthTester(
                endpoint,
                config_data,
                schema_data,
                graph_data,
                path_report=path_report,
                operation_pack=operation_pack,
            )
            results = tester.run()
            matrix = tester.matrix_report

            overview_report = build_schema_overview(
                schema_data,
                endpoint=endpoint,
                source="file",
                path_report=path_report,
                operation_pack=operation_pack,
                dependency_graph=graph_data,
            )

            summary = matrix.get("summary", {})
            subheader("Authorization Summary")
            kv("Configured Roles", summary.get("roles_available", 0))
            kv("Resource Checks", summary.get("resource_checks", 0))
            kv("Stateful Flows", summary.get("stateful_flows", 0))
            kv("Connected Paths", summary.get("connected_path_flows", 0))
            kv("Mutation Issues", summary.get("mutation_vulnerabilities", 0))
            kv("Subscription Issues", summary.get("subscription_vulnerabilities", 0))

            subheader("Stateful Flow Preview")
            flows = matrix.get("stateful_flows", [])
            if not flows:
                warn("No stateful creator-to-accessor flows were exercised.")
            else:
                for flow in flows[:5]:
                    state = "VULNERABLE" if flow.get("vulnerable_roles") else "SAFE"
                    color = "red" if flow.get("vulnerable_roles") else "green"
                    click.secho(
                        f"      {state:<10} {flow['creator']} -> {flow['accessor']}  "
                        f"({flow.get('id_argument') or 'id'}={flow['resource_id']})",
                        fg=color,
                        bold=True,
                    )
                    if flow.get("vulnerable_roles"):
                        click.echo(f"         Exposed to roles: {', '.join(flow['vulnerable_roles'])}")
                    if flow.get("decision_summary"):
                        click.echo(f"         {flow['decision_summary']}")

            write_json(
                out,
                {
                    "metadata": {
                        "endpoint": endpoint,
                    },
                    "schema": {
                        "summary": parse_schema_details(schema_data),
                        "overview": overview_report,
                    },
                    "authorization_matrix": matrix,
                    "legacy_results": results,
                    "paths": path_report,
                    "operation_pack": {
                        "summary": operation_pack.get("summary", {}),
                    },
                },
            )
            ok(f"Detailed auth report saved to {'stdout' if out == '-' else out}")
            click.echo("")

        except Exception as exc:
            err(f"Error: {exc}")
            raise SystemExit(EXIT_RUNTIME_ERROR)


@click.command()
@click.option("-u", "--endpoint", required=True, help="The GraphQL endpoint URL.")
@click.option("-s", "--schema", required=True, help="Path to the schema JSON file.")
@click.option("-c", "--config", required=False, help="Path to users YAML config.")
@click.option("-o", "--out", default="reports/injection_report.json", show_default=True, help="Output file.")
def inject(endpoint, schema, config, out):
    """Run injection fuzzing (XSS, SQLi, SSRF, Path Traversal)."""
    with machine_output_mode(out == "-"):
        section_header("INJECTION FUZZING")
        step(f"Target:  {endpoint}")

        try:
            with open(schema, "r", encoding="utf-8") as handle:
                schema_data = json.load(handle)
            if "data" in schema_data:
                schema_data = schema_data["data"]

            config_data = {}
            if config:
                with open(config, "r", encoding="utf-8") as handle:
                    config_data = yaml.safe_load(handle)

            injector = PayloadInjector(endpoint, schema_data, config_data)
            results = injector.run()

            subheader("Results")
            if not results:
                ok("No vulnerabilities detected.")
            else:
                for item in results:
                    finding(item)

            write_json(out, [item.to_dict() for item in results])
            ok(f"Report saved to {'stdout' if out == '-' else out}")
            click.echo("")

        except Exception as exc:
            err(f"Error: {exc}")
            raise SystemExit(EXIT_RUNTIME_ERROR)
