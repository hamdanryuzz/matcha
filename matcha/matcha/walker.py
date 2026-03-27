from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pathspec import PathSpec

from matcha.detector import is_supported_source

DEFAULT_IGNORES = [
    ".git/",
    "node_modules/",
    "dist/",
    "build/",
    ".next/",
    "coverage/",
]


@dataclass(slots=True)
class WalkerConfig:
    root: Path
    forced_language: str | None = None
    extra_ignores: list[str] | None = None


def build_ignore_spec(root: Path, extra_ignores: list[str] | None = None) -> PathSpec:
    patterns = list(DEFAULT_IGNORES)
    gitignore_path = root / ".gitignore"
    if gitignore_path.exists():
        patterns.extend(_sanitize_ignore_patterns(gitignore_path.read_text(encoding="utf-8").splitlines()))
    if extra_ignores:
        patterns.extend(_sanitize_ignore_patterns(extra_ignores))
    return PathSpec.from_lines("gitignore", patterns)


def walk_source_files(config: WalkerConfig) -> list[Path]:
    root = config.root.resolve()
    spec = build_ignore_spec(root, config.extra_ignores)
    discovered: list[Path] = []

    if root.is_file():
        if is_supported_source(root, config.forced_language):
            return [root]
        return []

    for candidate in root.rglob("*"):
        if not candidate.is_file():
            continue
        relative = candidate.relative_to(root).as_posix()
        if spec.match_file(relative):
            continue
        if is_supported_source(candidate, config.forced_language):
            discovered.append(candidate)

    discovered.sort()
    return discovered


def _sanitize_ignore_patterns(patterns: list[str]) -> list[str]:
    sanitized: list[str] = []
    for raw_pattern in patterns:
        pattern = raw_pattern.strip()
        if not pattern or pattern.startswith("#"):
            continue
        if pattern == "/":
            continue
        sanitized.append(pattern)
    return sanitized
