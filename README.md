<p align="center">
  <img src="./matcha-logo.svg" alt="matcha logo" width="220" />
</p>

<h1 align="center">matcha</h1>

<p align="center">
  A Python SAST CLI for JavaScript, TypeScript, NestJS, and Next.js codebases.
</p>

<p align="center">
  <strong>Tree-sitter parsing</strong> | <strong>YAML rules</strong> | <strong>NestJS-aware detectors</strong> | <strong>Console / JSON / SARIF</strong>
</p>

## What It Does

`matcha` scans JS/TS repositories for common security issues with a mix of:

- regex rules
- AST-aware rules via tree-sitter
- semantic detectors for framework-specific patterns
- optional LLM-based false-positive filtering via Groq

It is designed for real-world NestJS and Next.js codebases, while staying easy to extend for open source use.

## Features

- Recursive file discovery with `.gitignore` support
- Auto-detection for `.js`, `.jsx`, `.ts`, `.tsx`
- YAML rule packs under [`rules/`](./rules)
- Semantic detectors for:
  - raw SQL sinks in Prisma / TypeORM style code
  - NestJS CSRF heuristics based on auth mode
  - weak fallback secrets such as `process.env.JWT_SECRET_KEY || 'secret'`
  - insecure wildcard CORS in NestJS
  - SSRF-style dynamic outbound requests
  - unsafe file upload handling
- Output formats:
  - `console`
  - `json`
  - `sarif`
- Config file support with `.matcha.yaml`

## Current Coverage

`matcha` does not aim to cover every CWE. It currently focuses on high-signal issues for JavaScript, TypeScript, NestJS, and Next.js codebases.

Current mapped coverage includes:

- `CWE-79` Cross-Site Scripting
- `CWE-78` Command Injection
- `CWE-89` SQL Injection
- `CWE-95` Code Injection via `eval`
- `CWE-200` Information Exposure
- `CWE-327` Weak Cryptographic Algorithm
- `CWE-330` Insufficiently Random Values
- `CWE-352` Cross-Site Request Forgery
- `CWE-693` Protection Mechanism Failure
- `CWE-770` Allocation of Resources Without Limits or Throttling
- `CWE-434` Unsafe File Upload Handling
- `CWE-601` Open Redirect
- `CWE-613` Insufficient Session Expiration
- `CWE-614` Insecure Cookie Configuration
- `CWE-532` Sensitive Information in Logs
- `CWE-798` Hardcoded or Weak Fallback Secrets
- `CWE-915` Mass Assignment
- `CWE-918` Server-Side Request Forgery
- `CWE-943` NoSQL Injection
- `CWE-942` Permissive CORS Configuration
- `CWE-1333` Inefficient Regular Expression Complexity

Coverage will expand over time as new rules are added and validated.
- Exit codes suitable for CI

## Install

```bash
pip install -e .
```

## Quick Start

Scan a project:

```bash
matcha scan ./src
```

Scan a full repo with JSON output:

```bash
matcha scan ./project --format json --output findings.json
```

Only report high severity and above:

```bash
matcha scan ./project --severity high
```

Use a custom rules directory:

```bash
matcha scan ./project --rules-dir ./custom-rules
```

## CLI

```text
matcha scan <path> [options]

Options:
  --severity [low|medium|high|critical]
  --format [console|json|sarif]
  --output <file>
  --enable-llm
  --language [javascript|typescript]
  --rules-dir <path>
```

## Example Output

```text
[HIGH] [CWE-798] Weak Fallback Secret in Configuration - src/auth/auth.module.ts:15
Rule: TS-AUTH-003 | Confidence: high
Code: secret: process.env.JWT_SECRET_KEY || 'secret',

[HIGH] [CWE-942] Insecure CORS Wildcard Origin - src/main.ts:13
Rule: TS-WEB-003 | Confidence: high
Code: app.enableCors({

Summary: 2 findings (2 high) in 0.73s
```

## Config

`matcha` reads `.matcha.yaml` from the scan root and merges it with CLI flags. CLI flags take precedence.

```yaml
severity: medium
format: console
enable_llm: false
language: typescript
rules_dir: ./custom-rules
exclude:
  - generated/**
  - vendor/**
```

## Rules

Rules live in [`rules/`](./rules) and are self-contained YAML files.

Example:

```yaml
id: TS-AUTH-003
name: Weak Fallback Secret in Configuration
description: Falling back to weak inline secrets can expose production authentication flows.
severity: high
confidence: high
cwe: CWE-798
owasp:
  - A02:2021-Cryptographic Failures
languages:
  - javascript
  - typescript
logic: any
patterns:
  - type: semantic
    value: env_fallback_secret
```

Supported pattern types:

- `regex`
- `ast_node_type`
- `semantic`

Current rule families:

- `rules/auth`
- `rules/injection`
- `rules/web`
- `rules/crypto`
- `rules/logging`

## LLM Filtering

When `--enable-llm` is enabled, `matcha` sends each finding's rule description plus a short code snippet to Groq model `llama-3.3-70b-versatile` and removes findings classified as false positives.

Set the API key before use:

```bash
export GROQ_API_KEY=your_key_here
```

## Exit Codes

- `0` no findings
- `1` findings found
- `2` error

## Development

Run tests:

```bash
python -m unittest discover -s tests -v
```

Project layout:

```text
matcha/
|-- matcha/
|   |-- cli.py
|   |-- detector.py
|   |-- engine.py
|   |-- formatter.py
|   |-- llm.py
|   |-- parser.py
|   `-- walker.py
|-- rules/
|-- tests/
|-- matcha-logo.svg
`-- pyproject.toml
```

## Roadmap

- Better finding grouping and suppression support
- More framework-aware detectors
- Expanded CWE coverage for auth, path traversal, redirects, and access control
- Release automation and CI
- More rule packs and community contributions
