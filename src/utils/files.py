"""Small file-system helpers used by CLI commands and reporters."""

import json
import sys
from pathlib import Path
from typing import Any, Union


PathLike = Union[str, Path]


def is_stdout_path(path: PathLike) -> bool:
    """Return True when the caller wants to write content to stdout."""
    return str(path).strip() == "-"


def ensure_parent_dir(path: PathLike) -> Path:
    """Return path as a Path and create its parent directory when needed."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    return output_path


def write_json(path: PathLike, data: Any) -> None:
    """Write JSON with UTF-8 encoding, creating parent directories first."""
    if is_stdout_path(path):
        json.dump(data, sys.stdout, indent=2)
        sys.stdout.write("\n")
        sys.stdout.flush()
        return

    output_path = ensure_parent_dir(path)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def write_text(path: PathLike, text: str) -> None:
    """Write UTF-8 text either to a file or directly to stdout."""
    if is_stdout_path(path):
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")
        sys.stdout.flush()
        return

    output_path = ensure_parent_dir(path)
    with output_path.open("w", encoding="utf-8") as handle:
        handle.write(text)
