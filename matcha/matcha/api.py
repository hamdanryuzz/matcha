from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from matcha import __version__
from matcha.cli import builtin_rules_dir
from matcha.detector import normalize_language
from matcha.engine import EngineConfig, Finding, RuleEngine
from matcha.formatter import summary_counts
from matcha.walker import WalkerConfig, walk_source_files

app = FastAPI(title="matcha SAST API", version=__version__)


class FileInput(BaseModel):
    filename: str
    content: str


class ScanRequest(BaseModel):
    files: list[FileInput]
    severity: str = "low"
    language: str | None = None


class GitHubScanRequest(BaseModel):
    repo: str
    token: str | None = None
    branch: str | None = None
    severity: str = "low"
    language: str | None = None


def _finding_to_dict(finding: Finding, root: Path) -> dict[str, Any]:
    try:
        file_str = finding.file_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        file_str = finding.file_path.name
    return {
        "rule_id": finding.rule_id,
        "rule_name": finding.rule_name,
        "description": finding.description,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "cwe": finding.cwe,
        "owasp": finding.owasp,
        "file": file_str,
        "line": finding.line,
        "column": finding.column,
        "end_line": finding.end_line,
        "end_column": finding.end_column,
        "code": finding.code,
        "snippet": finding.snippet,
        "language": finding.language,
        "reasoning": finding.reasoning,
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/rules")
def list_rules() -> list[dict[str, Any]]:
    engine = RuleEngine(EngineConfig(rules_directories=[builtin_rules_dir()], minimum_severity="low"))
    return [
        {
            "id": rule.id,
            "name": rule.name,
            "description": rule.description,
            "severity": rule.severity,
            "confidence": rule.confidence,
            "cwe": rule.cwe,
            "owasp": rule.owasp,
            "languages": rule.languages,
        }
        for rule in engine.rules
    ]


@app.post("/scan")
def scan(request: ScanRequest) -> dict[str, Any]:
    if not request.files:
        raise HTTPException(status_code=400, detail="No files provided.")

    severity = request.severity.lower()
    if severity not in {"low", "medium", "high", "critical"}:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {request.severity}")

    language = normalize_language(request.language) if request.language else None

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        for file_input in request.files:
            dest = root / file_input.filename
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(file_input.content, encoding="utf-8")

        started_at = time.perf_counter()
        files = walk_source_files(WalkerConfig(root=root, forced_language=language, extra_ignores=[]))
        engine = RuleEngine(EngineConfig(rules_directories=[builtin_rules_dir()], minimum_severity=severity))
        findings = engine.scan_files(files, forced_language=language)
        elapsed = time.perf_counter() - started_at
        serialized = [_finding_to_dict(f, root) for f in findings]

    return {
        "elapsed_seconds": round(elapsed, 4),
        "summary": summary_counts(findings),
        "findings": serialized,
    }


def _build_clone_url(repo: str, token: str | None) -> str:
    parsed = urlparse(repo)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid repository URL. Must be an http/https GitHub URL.")
    if token:
        return f"https://oauth2:{token}@{parsed.netloc}{parsed.path}"
    return repo


@app.post("/scan/github")
def scan_github(request: GitHubScanRequest) -> dict[str, Any]:
    severity = request.severity.lower()
    if severity not in {"low", "medium", "high", "critical"}:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {request.severity}")

    language = normalize_language(request.language) if request.language else None
    clone_url = _build_clone_url(request.repo, request.token)

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        cmd = ["git", "clone", "--depth", "1", "--single-branch"]
        if request.branch:
            cmd += ["--branch", request.branch]
        cmd += [clone_url, str(root)]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            # Sanitize error: strip token from message before returning
            err = result.stderr.replace(request.token, "***") if request.token else result.stderr
            raise HTTPException(status_code=422, detail=f"git clone failed: {err.strip()}")

        started_at = time.perf_counter()
        files = walk_source_files(WalkerConfig(root=root, forced_language=language, extra_ignores=[]))
        engine = RuleEngine(EngineConfig(rules_directories=[builtin_rules_dir()], minimum_severity=severity))
        findings = engine.scan_files(files, forced_language=language)
        elapsed = time.perf_counter() - started_at
        serialized = [_finding_to_dict(f, root) for f in findings]

    return {
        "repo": request.repo,
        "branch": request.branch,
        "elapsed_seconds": round(elapsed, 4),
        "summary": summary_counts(findings),
        "findings": serialized,
    }
