"""Interactive wizard flow for the CLI."""

from __future__ import annotations

import click

from src.cli.commands.recon import authz, clairvoy, discover, fingerprint, graph, inject, introspect
from src.cli.commands.scan import scan
from src.cli.shared import DEFAULT_GRAPHQL_ENDPOINT, banner, header as section_header


def interactive_menu(ctx):
    """Interactive menu for guided scanning."""
    width = 50
    click.echo("")
    click.secho(f"  {'=' * width}", fg="blue")
    click.secho(f"  {'MAIN MENU'.center(width)}", fg="blue", bold=True)
    click.secho(f"  {'=' * width}", fg="blue")
    click.echo("")
    click.echo("    Select an operation:\n")
    click.secho("      [1]  ", fg="cyan", nl=False)
    click.echo("Full Scan           - Run all security checks")
    click.secho("      [2]  ", fg="cyan", nl=False)
    click.echo("Fingerprint Engine  - Identify the GraphQL engine")
    click.secho("      [3]  ", fg="cyan", nl=False)
    click.echo("Discover Endpoints  - Probe common GraphQL paths")
    click.secho("      [4]  ", fg="cyan", nl=False)
    click.echo("Introspect Schema   - Fetch & save GraphQL schema")
    click.secho("      [5]  ", fg="cyan", nl=False)
    click.echo("Dependency Graph    - Build type/operation graph")
    click.secho("      [6]  ", fg="cyan", nl=False)
    click.echo("Authorization       - Test object and role access")
    click.secho("      [7]  ", fg="cyan", nl=False)
    click.echo("Injection Fuzzing   - Fuzz with XSS/SQLi/SSRF")
    click.secho("      [8]  ", fg="cyan", nl=False)
    click.echo("Blind Introspection - Reconstruct schema (no introspection)")
    click.secho("      [0]  ", fg="red", nl=False)
    click.echo("Exit")
    click.echo("")

    choice = click.prompt(
        "    Enter choice",
        type=click.Choice(["0", "1", "2", "3", "4", "5", "6", "7", "8"]),
        default="1",
        show_choices=False,
    )

    if choice == "1":
        section_header("FULL SCAN SETUP")
        endpoint = click.prompt("    Target Endpoint", default=DEFAULT_GRAPHQL_ENDPOINT)
        click.echo("")
        click.echo("    Scan Profiles:")
        click.secho("      passive    ", fg="green", nl=False)
        click.echo("->  Safe recon only (no attack traffic)")
        click.secho("      default    ", fg="yellow", nl=False)
        click.echo("->  Standard pentest (moderate probes)")
        click.secho("      aggressive ", fg="red", nl=False)
        click.echo("->  Full attack (destructive DoS, can crash target)")
        click.echo("")
        profile = click.prompt("    Profile", type=click.Choice(["passive", "default", "aggressive"]), default="default")
        config_file = click.prompt("    Config File (YAML)", default="users.yaml")
        ml_flag = click.confirm("    Enable ML analysis?", default=False)
        llm_flag = click.confirm("    Enable LLM validation?", default=False)
        fmt = click.prompt("    Report format", type=click.Choice(["json", "csv", "html"]), default="json")
        out = click.prompt("    Output file", default=f"reports/report.{fmt}")
        ctx.invoke(
            scan,
            url=endpoint,
            config=config_file,
            config_file=None,
            schema=None,
            out=out,
            fmt=fmt,
            scan_profile=profile,
            level=1,
            risk=1,
            technique="IDAC",
            module=(),
            suggest=False,
            ml=ml_flag,
            ml_embeddings=False,
            llm_validate=llm_flag,
            llm_model=None,
            proxy=None,
            header=(),
            do_discover=False,
            fail_on_severity="none",
            json_stdout=False,
            verbose=False,
        )

    elif choice == "2":
        section_header("ENGINE FINGERPRINTING")
        endpoint = click.prompt("    Target Endpoint", default=DEFAULT_GRAPHQL_ENDPOINT)
        ctx.invoke(fingerprint, endpoint=endpoint)

    elif choice == "3":
        section_header("ENDPOINT DISCOVERY")
        base_url = click.prompt("    Base URL", default=DEFAULT_GRAPHQL_ENDPOINT.rsplit("/graphql", 1)[0])
        ctx.invoke(discover, url=base_url)

    elif choice == "4":
        section_header("INTROSPECTION")
        endpoint = click.prompt("    Target Endpoint", default=DEFAULT_GRAPHQL_ENDPOINT)
        out = click.prompt("    Output file", default="reports/schema.json")
        ctx.invoke(introspect, endpoint=endpoint, out=out)

    elif choice == "5":
        section_header("DEPENDENCY GRAPH")
        schema_file = click.prompt("    Schema file", default="reports/schema.json")
        out = click.prompt("    Output file", default="reports/graph.json")
        ctx.invoke(graph, schema=schema_file, out=out)

    elif choice == "6":
        section_header("AUTHORIZATION TESTING")
        endpoint = click.prompt("    Target Endpoint", default=DEFAULT_GRAPHQL_ENDPOINT)
        config_file = click.prompt("    Config file (YAML)", default="users.yaml")
        schema_file = click.prompt("    Schema file", default="reports/schema.json")
        graph_file = click.prompt("    Graph file", default="reports/graph.json")
        ctx.invoke(authz, endpoint=endpoint, config=config_file, schema=schema_file, graph=graph_file)

    elif choice == "7":
        section_header("INJECTION FUZZING")
        endpoint = click.prompt("    Target Endpoint", default=DEFAULT_GRAPHQL_ENDPOINT)
        schema_file = click.prompt("    Schema file", default="reports/schema.json")
        out = click.prompt("    Output file", default="reports/injection_report.json")
        ctx.invoke(inject, endpoint=endpoint, schema=schema_file, config=None, out=out)

    elif choice == "8":
        section_header("BLIND SCHEMA RECONSTRUCTION")
        endpoint = click.prompt("    Target Endpoint", default=DEFAULT_GRAPHQL_ENDPOINT)
        out = click.prompt("    Output file", default="reports/blind_schema.json")
        ctx.invoke(clairvoy, endpoint=endpoint, wordlist=None, out=out, bucket_size=10, depth=2, proxy=None, header=())

    elif choice == "0":
        click.echo("")
        click.secho("  Goodbye!", fg="cyan")
        click.echo("")


@click.command()
@click.pass_context
def wizard(ctx):
    """Launch the interactive command menu."""
    banner()
    interactive_menu(ctx)
