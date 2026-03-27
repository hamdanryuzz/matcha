from __future__ import annotations

from pathlib import Path

SUPPORTED_EXTENSIONS: dict[str, set[str]] = {
    "javascript": {".js", ".jsx"},
    "typescript": {".ts", ".tsx"},
}


def normalize_language(language: str | None) -> str | None:
    if language is None:
        return None
    lowered = language.strip().lower()
    if lowered not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported language: {language}")
    return lowered


def detect_language(path: Path, forced_language: str | None = None) -> str | None:
    normalized = normalize_language(forced_language)
    if normalized is not None:
        return normalized

    suffix = path.suffix.lower()
    for language, extensions in SUPPORTED_EXTENSIONS.items():
        if suffix in extensions:
            return language
    return None


def is_supported_source(path: Path, forced_language: str | None = None) -> bool:
    return detect_language(path, forced_language) is not None
