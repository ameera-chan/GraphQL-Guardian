"""Shell-completion helpers for GraphQL Guardian."""

from __future__ import annotations

from typing import Dict, List

import click
from click.shell_completion import get_completion_class


ROOT_KEY = "__root__"


def _dedupe(values: List[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _build_completion_metadata(root_command, prog_name: str) -> Dict[str, Dict[str, List[str]]]:
    subcommands: Dict[str, List[str]] = {}
    options: Dict[str, List[str]] = {}
    choices: Dict[str, List[str]] = {}
    path_options: Dict[str, List[str]] = {}
    root_aliases = getattr(root_command, "aliases", {})

    def visit(command, path):
        key = " ".join(path) if path else ROOT_KEY
        ctx = click.Context(command, info_name=path[-1] if path else prog_name)

        command_options: List[str] = []
        command_path_options: List[str] = []
        for param in command.get_params(ctx):
            if isinstance(param, click.Option):
                names = _dedupe(list(param.opts) + list(param.secondary_opts))
                command_options.extend(names)
                if getattr(param, "name", None) in {"config_file", "schema", "config"}:
                    command_path_options.extend(names)
                if isinstance(param.type, click.Choice):
                    choice_values = [str(choice) for choice in param.type.choices]
                    for name in names:
                        choices[f"{key}|{name}"] = choice_values

        options[key] = _dedupe(command_options)
        path_options[key] = _dedupe(command_path_options)

        if isinstance(command, click.MultiCommand):
            names = list(command.list_commands(ctx))
            if not path and root_aliases:
                names = names + list(root_aliases.keys())
            subcommands[key] = names
            for name in names:
                child = command.get_command(ctx, name)
                if child is not None:
                    visit(child, path + (name,))

    visit(root_command, ())
    return {"subcommands": subcommands, "options": options, "choices": choices, "path_options": path_options}


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _ps_array(values: List[str]) -> str:
    if not values:
        return "@()"
    return "@(" + ", ".join(_ps_quote(value) for value in values) + ")"


def _ps_hashtable(mapping: Dict[str, List[str]]) -> str:
    lines = ["@{"]
    for key, values in mapping.items():
        lines.append(f"    {_ps_quote(key)} = {_ps_array(values)}")
    lines.append("}")
    return "\n".join(lines)


def _render_bash_completion(root_command, prog_name: str) -> str:
    complete_var = f"_{prog_name.replace('-', '_').upper()}_COMPLETE"
    completion_cls = get_completion_class("bash")
    if completion_cls is None:
        raise click.ClickException("Bash completion is not available in the installed Click version.")
    completion = completion_cls(root_command, {}, prog_name, complete_var)
    return completion.source_template % completion.source_vars()


def _render_powershell_completion(root_command, prog_name: str) -> str:
    metadata = _build_completion_metadata(root_command, prog_name)
    subcommands = _ps_hashtable(metadata["subcommands"])
    options = _ps_hashtable(metadata["options"])
    choices = _ps_hashtable(metadata["choices"])
    path_options = _ps_hashtable(metadata["path_options"])

    return f"""$GuardianRootKey = '{ROOT_KEY}'
$GuardianSubcommands = {subcommands}
$GuardianOptions = {options}
$GuardianChoices = {choices}
$GuardianPathOptions = {path_options}

function Invoke-GuardianCompletion {{
    param(
        [string[]]$Items,
        [string]$WordToComplete
    )

    foreach ($Item in $Items | Sort-Object -Unique) {{
        if ([string]::IsNullOrWhiteSpace($WordToComplete) -or $Item -like "$WordToComplete*") {{
            [System.Management.Automation.CompletionResult]::new($Item, $Item, 'ParameterValue', $Item)
        }}
    }}
}}

function Invoke-GuardianPathCompletion {{
    param(
        [string]$WordToComplete
    )

    $InputPath = if ([string]::IsNullOrWhiteSpace($WordToComplete)) {{ '.' }} else {{ $WordToComplete }}
    $ParentPath = Split-Path -Path $InputPath -Parent
    $Leaf = Split-Path -Path $InputPath -Leaf

    if ([string]::IsNullOrWhiteSpace($ParentPath)) {{
        $ParentPath = '.'
    }}

    if (-not (Test-Path -LiteralPath $ParentPath)) {{
        return
    }}

    foreach ($Entry in Get-ChildItem -Force -LiteralPath $ParentPath) {{
        if (-not [string]::IsNullOrWhiteSpace($Leaf) -and $Entry.Name -notlike "$Leaf*") {{
            continue
        }}

        $CompletionValue = if ($ParentPath -eq '.') {{ $Entry.Name }} else {{ Join-Path $ParentPath $Entry.Name }}
        if ($Entry.PSIsContainer) {{
            $CompletionValue = $CompletionValue + [IO.Path]::DirectorySeparatorChar
        }}

        [System.Management.Automation.CompletionResult]::new(
            $CompletionValue,
            $CompletionValue,
            'ParameterValue',
            $CompletionValue
        )
    }}
}}

Register-ArgumentCompleter -Native -CommandName '{prog_name}' -ScriptBlock {{
    param($WordToComplete, $CommandAst, $CursorPosition)

    $Tokens = @($CommandAst.CommandElements | ForEach-Object {{ $_.Extent.Text }})
    if ($Tokens.Count -eq 0) {{
        return
    }}

    $ArgsOnly = if ($Tokens.Count -gt 1) {{ @($Tokens[1..($Tokens.Count - 1)]) }} else {{ @() }}
    $Path = @()
    $CurrentKey = $GuardianRootKey
    $Index = 0

    while ($Index -lt $ArgsOnly.Count) {{
        $Token = $ArgsOnly[$Index]
        if ($Token.StartsWith('-')) {{
            break
        }}

        if (-not $GuardianSubcommands.ContainsKey($CurrentKey)) {{
            break
        }}

        if ($GuardianSubcommands[$CurrentKey] -contains $Token) {{
            $Path += $Token
            $CurrentKey = ($Path -join ' ')
            $Index += 1
            continue
        }}

        break
    }}

    $PathKey = if ($Path.Count -gt 0) {{ $Path -join ' ' }} else {{ $GuardianRootKey }}

    $PreviousToken = ''
    if ($ArgsOnly.Count -gt 0) {{
        if (-not [string]::IsNullOrEmpty($WordToComplete) -and $ArgsOnly[-1] -eq $WordToComplete) {{
            if ($ArgsOnly.Count -gt 1) {{
                $PreviousToken = $ArgsOnly[-2]
            }}
        }} else {{
            $PreviousToken = $ArgsOnly[-1]
        }}
    }}

    $ChoiceKey = "$PathKey|$PreviousToken"
    if ($PreviousToken -and $GuardianPathOptions.ContainsKey($PathKey) -and $GuardianPathOptions[$PathKey] -contains $PreviousToken) {{
        Invoke-GuardianPathCompletion -WordToComplete $WordToComplete
        return
    }}

    if ($PreviousToken -and $GuardianChoices.ContainsKey($ChoiceKey)) {{
        Invoke-GuardianCompletion -Items $GuardianChoices[$ChoiceKey] -WordToComplete $WordToComplete
        return
    }}

    $Candidates = @()
    if ($GuardianSubcommands.ContainsKey($PathKey)) {{
        $Candidates += $GuardianSubcommands[$PathKey]
    }}
    if ($GuardianOptions.ContainsKey($PathKey)) {{
        $Candidates += $GuardianOptions[$PathKey]
    }}

    Invoke-GuardianCompletion -Items $Candidates -WordToComplete $WordToComplete
}}
"""


@click.command()
@click.option("--shell", type=click.Choice(["bash", "powershell"], case_sensitive=False), required=True, help="Shell to generate completion for.")
@click.option("--program-name", default="guardql", show_default=True, help="Program name to register in the completion script.")
@click.pass_context
def completion(ctx, shell, program_name):
    """Print a shell-completion setup script for Bash or PowerShell.

    \b
    Examples:
      guardql completion --shell bash > ~/.guardql-complete.sh
      guardql completion --shell powershell > $HOME\\Documents\\PowerShell\\guardql.ps1
    """
    root_command = ctx.find_root().command
    shell = shell.lower()

    if shell == "bash":
        click.echo(_render_bash_completion(root_command, program_name))
        return

    if shell == "powershell":
        click.echo(_render_powershell_completion(root_command, program_name))
        return

    raise click.ClickException(f"Unsupported shell: {shell}")


__all__ = ["completion"]
