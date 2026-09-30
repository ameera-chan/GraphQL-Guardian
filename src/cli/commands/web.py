"""Start the Guardian API and web dashboard from one CLI command."""

from __future__ import annotations

import os
from pathlib import Path
import hashlib
import shutil
import socket
import subprocess
import sys
import time

import click

from src.cli.shared import EXIT_RUNTIME_ERROR, ok, step, warn


REPO_ROOT = Path(__file__).resolve().parents[3]
SYSTEM_SHARE = Path("/usr/share/guardql")
USER_SHARE = Path.home() / ".local" / "share" / "guardql"


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


def _is_writable(path: Path) -> bool:
    try:
        probe = path / ".guardql-write-test"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def _copy_frontend_to_user_dir(frontend_dir: Path) -> Path:
    target = USER_SHARE / "frontend"
    source_fingerprint = _frontend_fingerprint(frontend_dir)
    stamp = target / ".guardql-source-fingerprint"

    if target.exists() and stamp.exists():
        if stamp.read_text(encoding="utf-8") == source_fingerprint:
            return target

    if target.exists():
        shutil.rmtree(target)

    def ignore(_dir: str, names: list[str]) -> set[str]:
        return {"node_modules", "dist", ".vite"} & set(names)

    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(frontend_dir, target, ignore=ignore)
    stamp.write_text(source_fingerprint, encoding="utf-8")
    return target


def _frontend_fingerprint(frontend_dir: Path) -> str:
    digest = hashlib.sha256()
    include_roots = ["src"]
    include_files = [
        "index.html",
        "package.json",
        "package-lock.json",
        "postcss.config.js",
        "tailwind.config.js",
        "vite.config.js",
    ]

    for relative in include_files:
        path = frontend_dir / relative
        if path.exists():
            digest.update(relative.encode("utf-8"))
            digest.update(path.read_bytes())

    for root in include_roots:
        source_root = frontend_dir / root
        if not source_root.exists():
            continue
        for path in sorted(source_root.rglob("*")):
            if path.is_file():
                relative = path.relative_to(frontend_dir).as_posix()
                digest.update(relative.encode("utf-8"))
                digest.update(path.read_bytes())

    return digest.hexdigest()


def _prepare_frontend_dir(frontend_dir: Path) -> Path:
    if frontend_dir.is_relative_to(SYSTEM_SHARE) or not _is_writable(frontend_dir):
        return _copy_frontend_to_user_dir(frontend_dir)
    return frontend_dir


def _is_port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def _resolve_port(host: str, port: int, explicit: bool, label: str) -> int:
    if _is_port_available(host, port):
        return port

    if explicit:
        raise click.ClickException(
            f"{label} port {port} is already in use. Stop that process or choose another port."
        )

    for candidate in range(port + 1, port + 100):
        if _is_port_available(host, candidate):
            warn(f"{label} port {port} is in use; using {candidate} instead.")
            return candidate

    raise click.ClickException(f"No free {label.lower()} port found near {port}.")


def _start_process(args: list[str], cwd: Path, env: dict[str, str] | None = None) -> subprocess.Popen:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.Popen(args, cwd=str(cwd), env=merged_env)


def _frontend_dependencies_ready(frontend_dir: Path) -> bool:
    node = shutil.which("node")
    if not node:
        return False

    result = subprocess.run(
        [
            node,
            "-e",
            "import('vite').then(() => process.exit(0)).catch(() => process.exit(1))",
        ],
        cwd=str(frontend_dir),
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def _install_frontend_dependencies(frontend_dir: Path, npm: str, reinstall: bool = False) -> None:
    node_modules = frontend_dir / "node_modules"
    if reinstall and node_modules.exists():
        shutil.rmtree(node_modules)

    step("Installing dashboard dependencies")
    result = subprocess.run([npm, "install"], cwd=str(frontend_dir), check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def _stop_process(process: subprocess.Popen | None) -> None:
    if not process or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


@click.command()
@click.option("--api-host", default="127.0.0.1", show_default=True, help="API bind host.")
@click.option("--api-port", default=8000, show_default=True, type=int, help="API bind port.")
@click.option("--ui-host", default="127.0.0.1", show_default=True, help="Dashboard bind host.")
@click.option("--ui-port", default=5173, show_default=True, type=int, help="Dashboard bind port.")
@click.option("--no-install", is_flag=True, help="Do not install missing dashboard npm dependencies.")
@click.pass_context
def web(ctx: click.Context, api_host: str, api_port: int, ui_host: str, ui_port: int, no_install: bool) -> None:
    """Start the Guardian API and dashboard.

    \b
    Examples:
      guardql web
      guardql web --api-port 8001 --ui-port 5174
    """
    frontend_dir = _find_frontend_dir()
    if not frontend_dir:
        raise click.ClickException("Dashboard frontend files were not found.")
    frontend_dir = _prepare_frontend_dir(frontend_dir)

    npm = shutil.which("npm")
    if not npm:
        raise click.ClickException("npm is required for `guardql web`. Install npm, then run again.")

    api_port = _resolve_port(
        api_host,
        api_port,
        ctx.get_parameter_source("api_port") == click.core.ParameterSource.COMMANDLINE,
        "API",
    )
    ui_port = _resolve_port(
        ui_host,
        ui_port,
        ctx.get_parameter_source("ui_port") == click.core.ParameterSource.COMMANDLINE,
        "Dashboard",
    )

    node_modules = frontend_dir / "node_modules"
    if not node_modules.exists():
        if no_install:
            raise click.ClickException(f"Missing dashboard dependencies: {node_modules}")
        _install_frontend_dependencies(frontend_dir, npm)
    elif not _frontend_dependencies_ready(frontend_dir):
        if no_install:
            raise click.ClickException(
                "Dashboard dependencies are installed but unusable on this system. "
                "Remove frontend/node_modules or run without --no-install."
            )
        warn("Dashboard dependencies are incomplete for this system; reinstalling.")
        _install_frontend_dependencies(frontend_dir, npm, reinstall=True)

    api_url = f"http://{api_host}:{api_port}"
    ui_url = f"http://{ui_host}:{ui_port}"
    api_process: subprocess.Popen | None = None
    ui_process: subprocess.Popen | None = None

    try:
        step(f"Starting API at {api_url}")
        api_process = _start_process(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "src.api.app:app",
                "--host",
                api_host,
                "--port",
                str(api_port),
            ],
            cwd=REPO_ROOT if (REPO_ROOT / "src").exists() else Path.cwd(),
        )

        step(f"Starting dashboard at {ui_url}")
        ui_process = _start_process(
            [npm, "run", "dev", "--", "--host", ui_host, "--port", str(ui_port)],
            cwd=frontend_dir,
            env={"VITE_API_BASE_URL": "/api", "VITE_API_PROXY_TARGET": api_url},
        )

        ok(f"Open {ui_url}")
        warn("Press Ctrl+C to stop Guardian Web.")

        while True:
            if api_process.poll() is not None:
                raise click.ClickException(f"API stopped with exit code {api_process.returncode}.")
            if ui_process.poll() is not None:
                raise click.ClickException(f"Dashboard stopped with exit code {ui_process.returncode}.")
            time.sleep(1)
    except KeyboardInterrupt:
        click.echo("")
        ok("Stopped Guardian Web.")
    finally:
        _stop_process(ui_process)
        _stop_process(api_process)


__all__ = ["web"]
