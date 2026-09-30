import json
import yaml
from click.testing import CliRunner
from graphql import build_schema, get_introspection_query, graphql_sync

import src.cli.commands.doctor as doctor_module
import src.cli.commands.web as web_module
from src.main import cli, _load_scan_config_file, _modules_to_technique


def test_cli_no_args_shows_help_instead_of_menu():
    runner = CliRunner()

    result = runner.invoke(cli, [])

    assert result.exit_code == 0
    assert "Usage:" in result.output
    assert "wizard" in result.output
    assert "MAIN MENU" not in result.output


def test_wizard_command_is_listed_in_help():
    runner = CliRunner()

    result = runner.invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "wizard" in result.output
    assert "scan" in result.output
    assert "config" in result.output
    assert "completion" in result.output
    assert "doctor" in result.output
    assert "overview" in result.output
    assert "authz" in result.output
    assert "scan" in result.output
    assert "[aliases: s]" in result.output
    assert "completion" in result.output
    assert "[aliases: com]" in result.output
    assert "test-auth" not in result.output
    assert "benchmark-dvga" not in result.output


def test_root_command_aliases_work():
    runner = CliRunner()

    scan_result = runner.invoke(cli, ["s", "--help"])
    completion_result = runner.invoke(cli, ["com", "--help"])

    assert scan_result.exit_code == 0
    assert "Run a configurable GraphQL security scan." in scan_result.output
    assert completion_result.exit_code == 0
    assert "Print a shell-completion setup script" in completion_result.output


def test_authz_replaces_test_auth_but_keeps_hidden_alias():
    runner = CliRunner()

    authz_result = runner.invoke(cli, ["authz", "--help"])
    alias_result = runner.invoke(cli, ["test-auth", "--help"])

    assert authz_result.exit_code == 0
    assert "Test broken object and role authorization." in authz_result.output
    assert alias_result.exit_code == 0
    assert "Compatibility alias for authz." in alias_result.output


def test_web_default_port_moves_when_busy(monkeypatch):
    monkeypatch.setattr(web_module, "_is_port_available", lambda host, port: port == 8001)

    assert web_module._resolve_port("127.0.0.1", 8000, False, "API") == 8001


def test_web_explicit_busy_port_fails(monkeypatch):
    monkeypatch.setattr(web_module, "_is_port_available", lambda host, port: False)

    try:
        web_module._resolve_port("127.0.0.1", 8000, True, "API")
    except Exception as exc:
        assert "already in use" in str(exc)
    else:
        raise AssertionError("busy explicit port should fail")


def test_web_frontend_cache_refreshes_when_css_changes(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source_src = source / "src"
    source_src.mkdir(parents=True)
    (source / "package.json").write_text('{"scripts":{"dev":"vite"}}', encoding="utf-8")
    (source_src / "index.css").write_text(".guardql-header{height:84px}", encoding="utf-8")

    monkeypatch.setattr(web_module, "USER_SHARE", tmp_path / "user-share")

    first_copy = web_module._copy_frontend_to_user_dir(source)
    assert (first_copy / "src" / "index.css").read_text(encoding="utf-8") == ".guardql-header{height:84px}"

    (source_src / "index.css").write_text(".guardql-header{height:72px}", encoding="utf-8")
    second_copy = web_module._copy_frontend_to_user_dir(source)

    assert second_copy == first_copy
    assert (second_copy / "src" / "index.css").read_text(encoding="utf-8") == ".guardql-header{height:72px}"


def test_web_prefers_current_project_frontend(tmp_path, monkeypatch):
    cwd = tmp_path / "project"
    cwd_frontend = cwd / "frontend"
    repo_frontend = tmp_path / "repo" / "frontend"
    system_frontend = tmp_path / "system" / "frontend"
    for frontend in (cwd_frontend, repo_frontend, system_frontend):
        frontend.mkdir(parents=True)
        (frontend / "package.json").write_text("{}", encoding="utf-8")

    monkeypatch.chdir(cwd)
    monkeypatch.setattr(web_module, "REPO_ROOT", repo_frontend.parent)
    monkeypatch.setattr(web_module, "SYSTEM_SHARE", system_frontend.parent)

    assert web_module._find_frontend_dir() == cwd_frontend


def test_scan_help_includes_new_shell_friendly_options():
    runner = CliRunner()

    result = runner.invoke(cli, ["scan", "--help"])

    assert result.exit_code == 0
    assert "--config-file" in result.output
    assert "--module" in result.output
    assert "--json-stdout" in result.output
    assert "--fail-on-severity" in result.output
    assert "Examples:" in result.output
    assert "guardql scan --config-file scan.yaml" in result.output


def test_overview_command_supports_schema_file(tmp_path):
    runner = CliRunner()
    schema_path = tmp_path / "schema.json"
    output_path = tmp_path / "overview.json"
    schema = build_schema(
        """
        type User {
          id: ID!
          email: String
        }

        type Query {
          user(id: ID!): User
        }

        type Mutation {
          createUser(name: String!): User
        }
        """
    )
    payload = graphql_sync(schema, get_introspection_query())
    schema_path.write_text(
        json.dumps(payload.data),
        encoding="utf-8",
    )

    result = runner.invoke(
        cli,
        ["overview", "--schema-file", str(schema_path), "--out", str(output_path)],
    )

    assert result.exit_code == 0
    assert "SCHEMA-AWARE OVERVIEW" in result.output
    assert "Schema Source:" in result.output
    assert output_path.exists()


def test_load_scan_config_file_supports_nested_scan_block(tmp_path):
    config_path = tmp_path / "scan.yaml"
    config_path.write_text(
        "guardian:\n"
        "  scan:\n"
        "    endpoint: https://example.com/graphql\n"
        "    modules:\n"
        "      - config\n"
        "      - auth\n",
        encoding="utf-8",
    )

    payload = _load_scan_config_file(str(config_path))

    assert payload["endpoint"] == "https://example.com/graphql"
    assert payload["modules"] == ["config", "auth"]


def test_modules_to_technique_uses_stable_order():
    assert _modules_to_technique(("config", "auth")) == "AC"
    assert _modules_to_technique(("dos", "injection", "auth")) == "IDA"


def test_config_validate_accepts_scan_template(tmp_path):
    runner = CliRunner()
    users_path = tmp_path / "users.yaml"
    users_path.write_text("user_a: {}\nuser_b: {}\n", encoding="utf-8")
    config_path = tmp_path / "scan.yaml"
    config_path.write_text(
        "guardian:\n"
        "  scan:\n"
        "    endpoint: https://example.com/graphql\n"
        "    auth_config: users.yaml\n"
        "    modules:\n"
        "      - config\n"
        "      - auth\n",
        encoding="utf-8",
    )

    result = runner.invoke(cli, ["config", "validate", "--config-file", str(config_path)])

    assert result.exit_code == 0
    assert "Configuration file is valid" in result.output
    assert "No validation problems found." in result.output


def test_config_init_writes_scan_yaml(tmp_path):
    runner = CliRunner()
    config_path = tmp_path / "generated-scan.yaml"
    user_input = (
        "https://example.com/graphql\n"
        "users.yaml\n"
        "default\n"
        "config,auth\n"
        "json\n"
        "reports/generated.json\n"
        "n\n"
        "n\n"
        "n\n"
        "n\n"
        "none\n"
        "\n"
    )

    result = runner.invoke(cli, ["config", "init", "--output", str(config_path)], input=user_input)

    assert result.exit_code == 0
    assert config_path.exists()
    payload = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    scan_payload = payload["guardian"]["scan"]
    assert scan_payload["endpoint"] == "https://example.com/graphql"
    assert scan_payload["modules"] == ["config", "auth"]
    assert scan_payload["headers"]["X-Requested-With"] == "GraphQL-Guardian"


def test_completion_bash_outputs_script():
    runner = CliRunner()

    result = runner.invoke(cli, ["completion", "--shell", "bash"])

    assert result.exit_code == 0
    assert "_GUARDQL_COMPLETE=bash_complete" in result.output
    assert "_guardql_completion" in result.output
    assert "guardql" in result.output


def test_completion_powershell_outputs_script():
    runner = CliRunner()

    result = runner.invoke(cli, ["completion", "--shell", "powershell"])

    assert result.exit_code == 0
    assert "Register-ArgumentCompleter" in result.output
    assert "Invoke-GuardianPathCompletion" in result.output
    assert "--config-file" in result.output
    assert "guardql" in result.output


def test_doctor_command_uses_collected_sections(monkeypatch):
    runner = CliRunner()

    monkeypatch.setattr(
        doctor_module,
        "_collect_doctor_sections",
        lambda api_url, dashboard_url, timeout: [
            doctor_module.DoctorSection(
                "Python dependencies",
                [doctor_module.DoctorItem("pass", "Python", "3.11.9")],
            ),
            doctor_module.DoctorSection(
                "API readiness",
                [doctor_module.DoctorItem("pass", "API module", "ok")],
            ),
        ],
    )

    result = runner.invoke(cli, ["doctor"])

    assert result.exit_code == 0
    assert "PYTHON DEPENDENCIES" in result.output
    assert "Doctor completed successfully." in result.output

def test_scan_cli_integrates_active_security_validation():
    import importlib
    import inspect

    scan_module = importlib.import_module(
        "src.cli.commands.scan"
    )
    source = inspect.getsource(scan_module)

    assert "ActiveSecurityScanner(" in source
    assert "+ active_security_results" in source
    assert (
        '"active_security_validation": active_security_report'
        in source
    )
    assert '"subscription_security": subscription_report' in source

