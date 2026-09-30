"""Compatibility wrapper for the GraphQL Guardian CLI."""

from src.cli.app import cli, main
from src.cli.commands.scan import _load_scan_config_file, _modules_to_technique
from src.cli.shared import VERSION

__all__ = [
    "VERSION",
    "cli",
    "main",
    "_load_scan_config_file",
    "_modules_to_technique",
]


if __name__ == "__main__":
    main()
