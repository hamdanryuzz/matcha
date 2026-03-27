from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from matcha.engine import Finding, SEVERITY_ORDER


def format_console(findings: list[Finding], root: Path, elapsed_seconds: float) -> str:
    lines: list[str] = []
    ordered = sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_ORDER.get(finding.severity, 0),
            finding.file_path.as_posix(),
            finding.line,
            finding.column,
        ),
    )
    for finding in ordered:
        relative_path = _display_path(finding.file_path, root)
        lines.append(
            f"[{finding.severity.upper()}] [{finding.cwe}] {finding.rule_name} - {relative_path}:{finding.line}"
        )
        lines.append(f"Rule: {finding.rule_id} | Confidence: {finding.confidence}")
        lines.append(f"Code: {_single_line(finding.code)}")
        if finding.reasoning:
            lines.append(f"LLM: {finding.reasoning}")
        lines.append("")

    summary = summarize_findings(findings)
    lines.append(f"Summary: {summary} in {elapsed_seconds:.2f}s")
    return "\n".join(lines).strip()


def format_json(findings: list[Finding], root: Path, elapsed_seconds: float) -> str:
    payload = {
        "tool": "matcha",
        "elapsed_seconds": round(elapsed_seconds, 4),
        "summary": summary_counts(findings),
        "findings": [
            {
                "rule_id": finding.rule_id,
                "rule_name": finding.rule_name,
                "description": finding.description,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "cwe": finding.cwe,
                "owasp": finding.owasp,
                "file": _display_path(finding.file_path, root),
                "line": finding.line,
                "column": finding.column,
                "end_line": finding.end_line,
                "end_column": finding.end_column,
                "code": finding.code,
                "snippet": finding.snippet,
                "language": finding.language,
                "reasoning": finding.reasoning,
            }
            for finding in findings
        ],
    }
    return json.dumps(payload, indent=2)


def format_sarif(findings: list[Finding], root: Path, elapsed_seconds: float) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.rule_name,
                "shortDescription": {"text": finding.rule_name},
                "fullDescription": {"text": finding.description},
                "help": {"text": finding.description},
                "properties": {
                    "security-severity": finding.severity,
                    "precision": finding.confidence,
                    "cwe": finding.cwe,
                    "owasp": finding.owasp,
                },
            },
        )
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _display_path(finding.file_path, root)},
                            "region": {
                                "startLine": finding.line,
                                "startColumn": finding.column,
                                "endLine": finding.end_line,
                                "endColumn": finding.end_column,
                                "snippet": {"text": finding.code},
                            },
                        }
                    }
                ],
                "properties": {
                    "confidence": finding.confidence,
                    "cwe": finding.cwe,
                    "owasp": finding.owasp,
                    "reasoning": finding.reasoning,
                },
            }
        )

    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "matcha",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/example/matcha",
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "properties": {"elapsed_seconds": round(elapsed_seconds, 4)},
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2)


def summary_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(finding.severity for finding in findings)
    summary = {"total": len(findings)}
    for severity in ("critical", "high", "medium", "low"):
        summary[severity] = counts.get(severity, 0)
    return summary


def summarize_findings(findings: list[Finding]) -> str:
    counts = summary_counts(findings)
    pieces = [f"{counts['total']} findings"]
    severity_pieces = [
        f"{counts[severity]} {severity}"
        for severity in ("critical", "high", "medium", "low")
        if counts[severity]
    ]
    if severity_pieces:
        pieces.append(f"({', '.join(severity_pieces)})")
    return " ".join(pieces)


def _display_path(file_path: Path, root: Path) -> str:
    try:
        return file_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return file_path.resolve().as_posix()


def _single_line(text: str, limit: int = 140) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return f"{compact[: limit - 3]}..."


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
