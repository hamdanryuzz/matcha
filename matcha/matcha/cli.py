from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click
import yaml

from matcha import __version__
from matcha.detector import normalize_language
from matcha.engine import EngineConfig, MatchaError, RuleEngine
from matcha.formatter import format_console, format_json, format_sarif
from matcha.walker import WalkerConfig, walk_source_files


@dataclass(slots=True)
class ScanSettings:
    severity: str
    output_format: str
    output_file: Path | None
    language: str | None
    rules_dir: Path | None
    exclude: list[str]


@click.group()
@click.version_option(__version__, prog_name="matcha")
def main() -> None:
    """matcha SAST CLI."""


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--severity",
    "severity",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
    help="Minimum severity to report.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["console", "json", "sarif"], case_sensitive=False),
    default=None,
    help="Output format.",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(path_type=Path),
    default=None,
    help="Write output to file.",
)
@click.option(
    "--language",
    "language",
    type=click.Choice(["javascript", "typescript"], case_sensitive=False),
    default=None,
    help="Force language instead of auto-detection.",
)
@click.option(
    "--rules-dir",
    "rules_dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Load additional rules from a custom directory.",
)
def scan(
    path: Path,
    severity: str | None,
    output_format: str | None,
    output_file: Path | None,
    language: str | None,
    rules_dir: Path | None,
) -> None:
    """Scan a codebase for common JavaScript and TypeScript security issues."""

    try:
        settings = resolve_settings(
            target_path=path,
            severity=severity,
            output_format=output_format,
            output_file=output_file,
            language=language,
            rules_dir=rules_dir,
        )
        root = path.resolve() if path.is_dir() else path.resolve().parent
        started_at = time.perf_counter()
        files = walk_source_files(
            WalkerConfig(
                root=path.resolve(),
                forced_language=settings.language,
                extra_ignores=settings.exclude,
            )
        )
        engine = RuleEngine(
            EngineConfig(
                rules_directories=_rule_directories(settings.rules_dir),
                minimum_severity=settings.severity,
            )
        )
        findings = engine.scan_files(files, forced_language=settings.language)
        elapsed = time.perf_counter() - started_at
        rendered = render_output(settings.output_format, findings, root, elapsed)
        if settings.output_file is not None:
            settings.output_file.parent.mkdir(parents=True, exist_ok=True)
            settings.output_file.write_text(rendered, encoding="utf-8")
        if settings.output_file is None or settings.output_format == "console":
            click.echo(rendered)
        raise click.exceptions.Exit(1 if findings else 0)
    except click.exceptions.Exit:
        raise
    except MatchaError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise click.exceptions.Exit(2) from exc
    except Exception as exc:
        click.echo(f"Unhandled error: {exc}", err=True)
        raise click.exceptions.Exit(2) from exc


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Host to bind to.")
@click.option("--port", default=8000, show_default=True, type=int, help="Port to listen on.")
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload (development only).")
def serve(host: str, port: int, reload: bool) -> None:
    """Start the matcha HTTP API server."""
    try:
        import uvicorn
    except ImportError:
        click.echo("uvicorn is required to run the API server. Install it with: pip install 'matcha-sast[api]'", err=True)
        raise click.exceptions.Exit(2)
    click.echo(f"Starting matcha API on http://{host}:{port}")
    uvicorn.run("matcha.api:app", host=host, port=port, reload=reload)


def resolve_settings(
    target_path: Path,
    severity: str | None,
    output_format: str | None,
    output_file: Path | None,
    language: str | None,
    rules_dir: Path | None,
) -> ScanSettings:
    config = load_config(target_path)
    resolved_language = normalize_language(language or config.get("language"))
    configured_output = config.get("output")
    configured_severity = str(config.get("severity", "low")).lower()
    if configured_severity not in {"low", "medium", "high", "critical"}:
        configured_severity = "low"
    configured_format = str(config.get("format", "console")).lower()
    if configured_format not in {"console", "json", "sarif"}:
        configured_format = "console"
    return ScanSettings(
        severity=(severity or configured_severity).lower(),
        output_format=(output_format or configured_format).lower(),
        output_file=output_file or _optional_path(configured_output, target_path),
        language=resolved_language,
        rules_dir=rules_dir or _optional_path(config.get("rules_dir"), target_path),
        exclude=[str(item) for item in config.get("exclude", [])],
    )


def load_config(target_path: Path) -> dict[str, Any]:
    root = target_path.resolve() if target_path.is_dir() else target_path.resolve().parent
    config_path = root / ".matcha.yaml"
    if not config_path.exists():
        return {}
    payload = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def render_output(output_format: str, findings: list[Any], root: Path, elapsed_seconds: float) -> str:
    if output_format == "json":
        return format_json(findings, root, elapsed_seconds)
    if output_format == "sarif":
        return format_sarif(findings, root, elapsed_seconds)
    return format_console(findings, root, elapsed_seconds)


def _rule_directories(custom_rules_dir: Path | None) -> list[Path]:
    directories = [builtin_rules_dir()]
    if custom_rules_dir is not None:
        directories.append(custom_rules_dir.resolve())
    return directories


def builtin_rules_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "rules"


def _optional_path(value: Any, target_path: Path) -> Path | None:
    if value in (None, ""):
        return None
    path = Path(str(value))
    if path.is_absolute():
        return path
    root = target_path.resolve() if target_path.is_dir() else target_path.resolve().parent
    return (root / path).resolve()


if __name__ == "__main__":
    main()
