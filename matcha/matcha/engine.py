from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from matcha.detector import detect_language
from matcha.parser import ASTParser

SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SQL_ASSIGNMENT_RE = re.compile(
    r"""(?is)
    \b(?:const|let|var)\s+
    (?P<name>[A-Za-z_][A-Za-z0-9_]*)
    \s*=\s*
    (?P<expr>[^;]+;)
    """,
    re.VERBOSE,
)
SQL_LITERAL_START_RE = re.compile(
    r"""(?is)
    [`'"]\s*
    (
        select\b
        |insert\s+into\b
        |update\b[\s\S]{0,120}?\bset\b
        |delete\s+from\b
    )
    """,
    re.VERBOSE,
)
STATE_CHANGING_DECORATOR_RE = re.compile(r"@(Post|Put|Patch|Delete)\s*\(")
CONTROLLER_RE = re.compile(r"@Controller\s*\(")
CSRF_MITIGATION_RE = re.compile(
    r"(?i)\bcsrf\b|csurf|@UseGuards\([^)]*Csrf|@UseInterceptors\([^)]*Csrf"
)
ENV_FALLBACK_SECRET_RE = re.compile(
    r"""(?ix)
    (?:
        \bsecret\b
        |\bjwt[_-]?secret(?:[_-]?key)?\b
        |\bprivate[_-]?key\b
        |\bapi[_-]?key\b
    )
    [\s\S]{0,120}?
    process\.env\.[A-Z0-9_]+
    \s*(?:\|\||\?\?)\s*
    (?P<quote>['"])(?P<fallback>[^'"]+)(?P=quote)
    """
)
SSR_SINK_RE = re.compile(
    r"""(?ix)
    (?:
        this\.httpService\.(?:get|post|put|patch|delete|request)
        |httpService\.(?:get|post|put|patch|delete|request)
        |axios\.(?:get|post|put|patch|delete|request)
        |fetch
        |got
    )\s*\(
    """
)
USER_URL_HINT_RE = re.compile(
    r"""(?ix)
    @(?:Query|Body|Param)\s*\(\s*['"]?(?:url|uri|endpoint|callback|redirect|webhook|host|domain)['"]?
    |(?:req|request)\.(?:query|body|params)\.[A-Za-z0-9_]+
    |\b(?:url|uri|endpoint|callbackUrl|redirectUrl|webhookUrl|targetUrl|remoteUrl)\b
    """
)
UPLOAD_INTERCEPTOR_RE = re.compile(r"@UseInterceptors\([^)]*(?:FileInterceptor|FilesInterceptor|AnyFilesInterceptor)", re.I)
UNSAFE_UPLOAD_RE = re.compile(
    r"""(?ix)
    (
        filename\s*:\s*\([^)]*\)\s*=>[\s\S]{0,160}?file\.originalname
        |filename\s*:\s*function\s*\([^)]*\)\s*\{[\s\S]{0,160}?file\.originalname
        |destination\s*:\s*\([^)]*\)\s*=>[\s\S]{0,160}?(?:req|request)\.(?:body|query|params)
        |destination\s*:\s*function\s*\([^)]*\)\s*\{[\s\S]{0,160}?(?:req|request)\.(?:body|query|params)
        |path\.join\s*\([^)]*file\.originalname
    )
    """
)
DIRECT_UPLOAD_WRITE_RE = re.compile(
    r"""(?ix)
    (?:fs\.(?:writeFile|writeFileSync|createWriteStream)|createWriteStream)\s*\([\s\S]{0,160}?file\.originalname
    """
)
WILDCARD_CORS_RE = re.compile(
    r"""(?ix)
    (
        enableCors\s*\(\s*\{[\s\S]{0,220}?origin\s*:\s*['"]\*['"]
        |@Cors\s*\(\s*\{[\s\S]{0,220}?origin\s*:\s*['"]\*['"]
        |Access-Control-Allow-Origin['"]?\s*,\s*['"]\*['"]
    )
    """
)
DEV_CORS_HINT_RE = re.compile(
    r"""(?ix)
    NODE_ENV
    |development
    |localhost
    |127\.0\.0\.1
    |\bisDev\b
    |!==\s*['"]production['"]
    |===\s*['"]development['"]
    """
)
WEAK_FALLBACK_SECRET_VALUES = {
    "secret",
    "default",
    "changeme",
    "change-me",
    "password",
    "test",
    "dev",
    "jwtsecret",
    "your-secret-key",
    "your_jwt_secret",
}


class MatchaError(Exception):
    """Base application error."""


@dataclass(slots=True)
class RulePattern:
    type: str
    value: str
    condition: str = "present"
    flags: str = ""
    text_regex: str | None = None
    message: str | None = None

    def regex_flags(self) -> int:
        mapping = {
            "i": re.IGNORECASE,
            "m": re.MULTILINE,
            "s": re.DOTALL,
        }
        compiled = 0
        for flag in self.flags:
            compiled |= mapping.get(flag, 0)
        return compiled


@dataclass(slots=True)
class Rule:
    id: str
    name: str
    description: str
    severity: str
    confidence: str
    cwe: str
    owasp: list[str]
    languages: list[str]
    patterns: list[RulePattern]
    logic: str = "any"
    source_path: Path | None = None


@dataclass(slots=True)
class Finding:
    rule_id: str
    rule_name: str
    description: str
    severity: str
    confidence: str
    cwe: str
    owasp: list[str]
    file_path: Path
    line: int
    column: int
    end_line: int
    end_column: int
    code: str
    snippet: str
    language: str
    reasoning: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def dedupe_key(self) -> tuple[str, str, int, int, str]:
        return (
            self.rule_id,
            self.file_path.as_posix(),
            self.line,
            self.column,
            self.code.strip(),
        )


@dataclass(slots=True)
class EngineConfig:
    rules_directories: list[Path]
    minimum_severity: str = "low"


@dataclass(slots=True)
class ProjectContext:
    uses_nestjs: bool = False
    uses_bearer_auth: bool = False
    uses_cookie_sessions: bool = False
    uses_csrf_protection: bool = False
    uses_prisma: bool = False
    uses_typeorm: bool = False
    env_name: str | None = None


@dataclass(slots=True)
class SQLAssignment:
    variable_name: str
    line: int
    end_line: int
    column: int
    code: str
    snippet: str


@dataclass(slots=True)
class SinkMatch:
    line: int
    end_line: int
    column: int
    code: str
    snippet: str
    detector: str


class RuleEngine:
    def __init__(self, config: EngineConfig) -> None:
        self.config = config
        self.rules = self._load_rules(config.rules_directories)
        self.parser = ASTParser()

    def scan_files(self, file_paths: list[Path], forced_language: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        file_entries: list[tuple[Path, str, str]] = []
        for file_path in file_paths:
            language = detect_language(file_path, forced_language)
            if language is None:
                continue
            source = file_path.read_text(encoding="utf-8", errors="ignore")
            file_entries.append((file_path, source, language))

        project_context = self._build_project_context(file_entries)
        for file_path, source, language in file_entries:
            findings.extend(
                self.scan_source(
                    file_path=file_path,
                    source=source,
                    language=language,
                    project_context=project_context,
                )
            )
        return self._filter_by_severity(self._dedupe(findings))

    def scan_source(
        self,
        file_path: Path,
        source: str,
        language: str,
        project_context: ProjectContext | None = None,
    ) -> list[Finding]:
        prefer_tsx = file_path.suffix.lower() == ".tsx"
        parse_result = self.parser.parse(source=source, language=language, prefer_tsx=prefer_tsx)
        findings: list[Finding] = []
        context = project_context or self._build_project_context([(file_path, source, language)])

        for rule in self.rules:
            if language not in rule.languages:
                continue
            if rule.logic == "all":
                findings.extend(
                    self._scan_all_patterns(
                        rule,
                        file_path,
                        source,
                        language,
                        parse_result,
                        context,
                    )
                )
            else:
                findings.extend(
                    self._scan_any_patterns(
                        rule,
                        file_path,
                        source,
                        language,
                        parse_result,
                        context,
                    )
                )

        return findings

    def _scan_any_patterns(
        self,
        rule: Rule,
        file_path: Path,
        source: str,
        language: str,
        parse_result: Any,
        project_context: ProjectContext,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in rule.patterns:
            if pattern.condition != "present":
                continue
            if pattern.type == "regex":
                findings.extend(
                    self._build_findings_from_regex(rule, pattern, file_path, source, language)
                )
            elif pattern.type == "ast_node_type":
                findings.extend(
                    self._build_findings_from_ast(rule, pattern, file_path, source, language, parse_result)
                )
            elif pattern.type == "semantic":
                findings.extend(
                    self._build_findings_from_semantic(
                        rule,
                        pattern,
                        file_path,
                        source,
                        language,
                        project_context,
                    )
                )
        return findings

    def _scan_all_patterns(
        self,
        rule: Rule,
        file_path: Path,
        source: str,
        language: str,
        parse_result: Any,
        project_context: ProjectContext,
    ) -> list[Finding]:
        positive_matches: list[list[Finding]] = []
        for pattern in rule.patterns:
            current_matches: list[Finding]
            if pattern.type == "regex":
                current_matches = self._build_findings_from_regex(rule, pattern, file_path, source, language)
            elif pattern.type == "ast_node_type":
                current_matches = self._build_findings_from_ast(
                    rule,
                    pattern,
                    file_path,
                    source,
                    language,
                    parse_result,
                )
            elif pattern.type == "semantic":
                current_matches = self._build_findings_from_semantic(
                    rule,
                    pattern,
                    file_path,
                    source,
                    language,
                    project_context,
                )
            else:
                current_matches = []

            if pattern.condition == "absent":
                if current_matches:
                    return []
                continue

            if not current_matches:
                return []
            positive_matches.append(current_matches)

        if not positive_matches:
            return []

        return positive_matches[0]

    def _build_findings_from_regex(
        self,
        rule: Rule,
        pattern: RulePattern,
        file_path: Path,
        source: str,
        language: str,
    ) -> list[Finding]:
        compiled = re.compile(pattern.value, pattern.regex_flags())
        findings: list[Finding] = []
        lines = source.splitlines()
        for match in compiled.finditer(source):
            start = match.start()
            end = match.end()
            line, column = _offset_to_line_col(source, start)
            end_line, end_column = _offset_to_line_col(source, max(end - 1, start))
            matched_line = lines[line - 1] if lines else ""
            findings.append(
                Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                    file_path=file_path,
                    line=line,
                    column=column,
                    end_line=end_line,
                    end_column=end_column,
                    code=matched_line.strip() or match.group(0).strip(),
                    snippet=_build_snippet(source, line, end_line),
                    language=language,
                )
            )
        return findings

    def _build_findings_from_ast(
        self,
        rule: Rule,
        pattern: RulePattern,
        file_path: Path,
        source: str,
        language: str,
        parse_result: Any,
    ) -> list[Finding]:
        nodes = self.parser.find_nodes(
            parse_result=parse_result,
            node_type=pattern.value,
            text_regex=pattern.text_regex,
            regex_flags=pattern.regex_flags(),
        )
        findings: list[Finding] = []
        lines = source.splitlines()
        for node in nodes:
            code_line = lines[node.start_line - 1] if lines else node.text
            findings.append(
                Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                    file_path=file_path,
                    line=node.start_line,
                    column=node.start_column,
                    end_line=node.end_line,
                    end_column=node.end_column,
                    code=code_line.strip() or node.text.strip(),
                    snippet=_build_snippet(source, node.start_line, node.end_line),
                    language=language,
                    metadata={"parser_error": parse_result.parser_error},
                )
            )
        return findings

    def _build_findings_from_semantic(
        self,
        rule: Rule,
        pattern: RulePattern,
        file_path: Path,
        source: str,
        language: str,
        project_context: ProjectContext,
    ) -> list[Finding]:
        if pattern.value == "sql_injection":
            return self._detect_sql_injection(rule, file_path, source, language)
        if pattern.value == "nestjs_csrf":
            return self._detect_nestjs_csrf(rule, file_path, source, language, project_context)
        if pattern.value == "env_fallback_secret":
            return self._detect_env_fallback_secret(rule, file_path, source, language)
        if pattern.value == "nestjs_ssrf":
            return self._detect_nestjs_ssrf(rule, file_path, source, language, project_context)
        if pattern.value == "nestjs_unsafe_upload":
            return self._detect_nestjs_unsafe_upload(rule, file_path, source, language, project_context)
        if pattern.value == "nestjs_cors_wildcard":
            return self._detect_nestjs_cors(rule, file_path, source, language, project_context)
        return []

    def _detect_sql_injection(
        self,
        rule: Rule,
        file_path: Path,
        source: str,
        language: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        dynamic_assignments = self._find_dynamic_sql_assignments(source)

        for sink in self._find_direct_dynamic_sql_sinks(source):
            findings.append(
                self._make_finding(
                    rule=rule,
                    file_path=file_path,
                    language=language,
                    line=sink.line,
                    end_line=sink.end_line,
                    column=sink.column,
                    code=sink.code,
                    snippet=sink.snippet,
                    metadata={"detector": sink.detector},
                )
            )

        for assignment in dynamic_assignments:
            detector = self._find_variable_sql_sink(assignment.variable_name, source)
            if detector is None:
                continue
            findings.append(
                self._make_finding(
                    rule=rule,
                    file_path=file_path,
                    language=language,
                    line=assignment.line,
                    end_line=assignment.end_line,
                    column=assignment.column,
                    code=assignment.code,
                    snippet=assignment.snippet,
                    metadata={"detector": detector},
                )
            )
        return findings

    def _detect_nestjs_csrf(
        self,
        rule: Rule,
        file_path: Path,
        source: str,
        language: str,
        project_context: ProjectContext,
    ) -> list[Finding]:
        if not project_context.uses_nestjs:
            return []
        if not project_context.uses_cookie_sessions:
            return []
        if project_context.uses_csrf_protection:
            return []
        if not CONTROLLER_RE.search(source):
            return []
        if not STATE_CHANGING_DECORATOR_RE.search(source):
            return []
        if CSRF_MITIGATION_RE.search(source):
            return []

        findings: list[Finding] = []
        for match in CONTROLLER_RE.finditer(source):
            line, column = _offset_to_line_col(source, match.start())
            findings.append(
                self._make_finding(
                    rule=rule,
                    file_path=file_path,
                    language=language,
                    line=line,
                    end_line=line,
                    column=column,
                    code=_line_at(source, line),
                    snippet=_build_snippet(source, line, line),
                    metadata={
                        "detector": "nestjs_csrf",
                        "auth_profile": {
                            "uses_bearer_auth": project_context.uses_bearer_auth,
                            "uses_cookie_sessions": project_context.uses_cookie_sessions,
                        },
                    },
                )
            )
        return findings

    def _detect_env_fallback_secret(
        self,
        rule: Rule,
        file_path: Path,
        source: str,
        language: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for match in ENV_FALLBACK_SECRET_RE.finditer(source):
            fallback = match.group("fallback").strip()
            if not _is_weak_fallback_secret(fallback):
                continue
            line, column = _offset_to_line_col(source, match.start())
            end_line, _ = _offset_to_line_col(source, match.end() - 1)
            findings.append(
                self._make_finding(
                    rule=rule,
                    file_path=file_path,
                    language=language,
                    line=line,
                    end_line=end_line,
                    column=column,
                    code=_line_at(source, line),
                    snippet=_build_snippet(source, line, end_line),
                    metadata={"fallback_secret": fallback},
                )
            )
        return findings

    def _detect_nestjs_ssrf(
        self,
        rule: Rule,
        file_path: Path,
        source: str,
        language: str,
        project_context: ProjectContext,
    ) -> list[Finding]:
        if not project_context.uses_nestjs:
            return []
        if not USER_URL_HINT_RE.search(source):
            return []

        findings: list[Finding] = []
        lines = source.splitlines()
        for index, line in enumerate(lines):
            if not SSR_SINK_RE.search(line):
                continue
            window = "\n".join(lines[max(index - 3, 0) : min(index + 4, len(lines))])
            if not USER_URL_HINT_RE.search(window):
                continue
            if re.search(r"\(\s*['\"]https?://", line, re.IGNORECASE):
                continue
            findings.append(
                self._make_finding(
                    rule=rule,
                    file_path=file_path,
                    language=language,
                    line=index + 1,
                    end_line=index + 1,
                    column=max(SSR_SINK_RE.search(line).start(), 0) + 1,
                    code=line.strip(),
                    snippet=_build_snippet(source, index + 1, index + 1),
                    metadata={"detector": "nestjs_ssrf"},
                )
            )
        return findings

    def _detect_nestjs_unsafe_upload(
        self,
        rule: Rule,
        file_path: Path,
        source: str,
        language: str,
        project_context: ProjectContext,
    ) -> list[Finding]:
        if not project_context.uses_nestjs:
            return []
        if not (UPLOAD_INTERCEPTOR_RE.search(source) or "diskStorage" in source or "UploadedFile" in source):
            return []

        findings: list[Finding] = []
        for pattern, detector in (
            (UNSAFE_UPLOAD_RE, "upload_config"),
            (DIRECT_UPLOAD_WRITE_RE, "upload_write"),
        ):
            for match in pattern.finditer(source):
                line, column = _offset_to_line_col(source, match.start())
                end_line, _ = _offset_to_line_col(source, match.end() - 1)
                findings.append(
                    self._make_finding(
                        rule=rule,
                        file_path=file_path,
                        language=language,
                        line=line,
                        end_line=end_line,
                        column=column,
                        code=_line_at(source, line),
                        snippet=_build_snippet(source, line, end_line),
                        metadata={"detector": detector},
                    )
                )
        return findings

    def _detect_nestjs_cors(
        self,
        rule: Rule,
        file_path: Path,
        source: str,
        language: str,
        project_context: ProjectContext,
    ) -> list[Finding]:
        if not project_context.uses_nestjs:
            return []

        findings: list[Finding] = []
        for match in WILDCARD_CORS_RE.finditer(source):
            line, column = _offset_to_line_col(source, match.start())
            end_line, _ = _offset_to_line_col(source, match.end() - 1)
            snippet = _build_snippet(source, line, end_line)
            dev_only = bool(DEV_CORS_HINT_RE.search(snippet) or DEV_CORS_HINT_RE.search(source))
            findings.append(
                self._make_finding(
                    rule=rule,
                    file_path=file_path,
                    language=language,
                    line=line,
                    end_line=end_line,
                    column=column,
                    code=_line_at(source, line),
                    snippet=snippet,
                    severity_override="low" if dev_only else None,
                    confidence_override="medium" if dev_only else None,
                    metadata={
                        "detector": "nestjs_cors_wildcard",
                        "environment": "development-like" if dev_only else "production-or-unconditional",
                    },
                )
            )
        return findings

    def _find_dynamic_sql_assignments(self, source: str) -> list[SQLAssignment]:
        assignments: list[SQLAssignment] = []
        for match in SQL_ASSIGNMENT_RE.finditer(source):
            expression = match.group("expr")
            if not _is_dynamic_sql_expression(expression):
                continue
            line, column = _offset_to_line_col(source, match.start())
            end_line, _ = _offset_to_line_col(source, match.end() - 1)
            assignments.append(
                SQLAssignment(
                    variable_name=match.group("name"),
                    line=line,
                    end_line=end_line,
                    column=column,
                    code=_line_at(source, line),
                    snippet=_build_snippet(source, line, end_line),
                )
            )
        return assignments

    def _find_direct_dynamic_sql_sinks(self, source: str) -> list[SinkMatch]:
        lines = source.splitlines()
        findings: list[SinkMatch] = []
        sink_windows = {
            "prisma_raw_query": ("$queryRawUnsafe(", "$executeRawUnsafe("),
            "typeorm_raw_query": (
                ".query(",
                "queryRunner.query(",
                "manager.query(",
                "repository.query(",
                "dataSource.query(",
                "entityManager.query(",
            ),
            "generic_raw_query": ("pool.query(", "client.query(", "sequelize.query(", "connection.query("),
        }

        for index, line in enumerate(lines):
            for detector, tokens in sink_windows.items():
                lowered = line.lower()
                if not any(token.lower() in lowered for token in tokens):
                    continue
                window = "\n".join(lines[index : index + 5])
                if not _is_dynamic_sql_expression(window):
                    continue
                findings.append(
                    SinkMatch(
                        line=index + 1,
                        end_line=min(index + 5, len(lines)),
                        column=max(line.find(next(token for token in tokens if token.lower() in lowered)), 0) + 1,
                        code=line.strip(),
                        snippet=_build_snippet(source, index + 1, min(index + 5, len(lines))),
                        detector=detector,
                    )
                )
                break
        return findings

    def _find_variable_sql_sink(self, variable_name: str, source: str) -> str | None:
        sink_patterns = {
            "prisma_raw_query": re.compile(
                rf"(?is)\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(\s*{re.escape(variable_name)}\b"
            ),
            "typeorm_raw_query": re.compile(
                rf"(?is)(?:queryRunner|manager|repository|dataSource|entityManager|connection)\.query\s*\(\s*{re.escape(variable_name)}\b"
            ),
            "generic_raw_query": re.compile(
                rf"(?is)(?:pool|client|sequelize|db|database)\.query\s*\(\s*{re.escape(variable_name)}\b"
            ),
        }
        for detector, pattern in sink_patterns.items():
            if pattern.search(source):
                return detector
        return None

    def _build_project_context(
        self,
        file_entries: list[tuple[Path, str, str]],
    ) -> ProjectContext:
        combined_source = "\n".join(source for _, source, _ in file_entries)
        return ProjectContext(
            uses_nestjs=bool(re.search(r"@nestjs/|@Controller\s*\(", combined_source)),
            uses_bearer_auth=bool(
                re.search(
                    r"@nestjs/jwt|JwtModule|JwtService|verifyAsync\(|Bearer\b|Authorization\b|AuthGuard\('jwt'\)|JwtAuthGuard",
                    combined_source,
                    re.IGNORECASE,
                )
            ),
            uses_cookie_sessions=bool(
                re.search(
                    r"cookieParser\s*\(|express-session|session\s*\(|@Session\b|res\.cookie\s*\(|response\.cookie\s*\(",
                    combined_source,
                    re.IGNORECASE,
                )
            ),
            uses_csrf_protection=bool(
                re.search(
                    r"\bcsrf\b|csurf|sameSite\s*:\s*['\"](?:strict|lax)['\"]",
                    combined_source,
                    re.IGNORECASE,
                )
            ),
            uses_prisma=bool(re.search(r"@prisma/client|PrismaService|\$queryRaw", combined_source)),
            uses_typeorm=bool(
                re.search(
                    r"@nestjs/typeorm|\btypeorm\b|DataSource\b|Repository<|EntityManager\b|QueryRunner\b",
                    combined_source,
                )
            ),
            env_name=_infer_environment_name(combined_source),
        )

    def _make_finding(
        self,
        rule: Rule,
        file_path: Path,
        language: str,
        line: int,
        end_line: int,
        column: int,
        code: str,
        snippet: str,
        metadata: dict[str, Any] | None = None,
        severity_override: str | None = None,
        confidence_override: str | None = None,
    ) -> Finding:
        return Finding(
            rule_id=rule.id,
            rule_name=rule.name,
            description=rule.description,
            severity=severity_override or rule.severity,
            confidence=confidence_override or rule.confidence,
            cwe=rule.cwe,
            owasp=rule.owasp,
            file_path=file_path,
            line=line,
            column=column,
            end_line=end_line,
            end_column=max(len(code), 1),
            code=code.strip(),
            snippet=snippet,
            language=language,
            metadata=metadata or {},
        )

    def _load_rules(self, directories: list[Path]) -> list[Rule]:
        rules: list[Rule] = []
        for directory in directories:
            if not directory.exists():
                raise MatchaError(f"Rules directory does not exist: {directory}")
            for rule_path in sorted(directory.rglob("*.yaml")):
                payload = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
                if not payload:
                    continue
                patterns = [
                    RulePattern(
                        type=str(pattern["type"]),
                        value=str(pattern["value"]),
                        condition=str(pattern.get("condition", "present")),
                        flags=str(pattern.get("flags", "")),
                        text_regex=pattern.get("text_regex"),
                        message=pattern.get("message"),
                    )
                    for pattern in payload.get("patterns", [])
                ]
                rules.append(
                    Rule(
                        id=str(payload["id"]),
                        name=str(payload["name"]),
                        description=str(payload["description"]),
                        severity=str(payload["severity"]).lower(),
                        confidence=str(payload["confidence"]).lower(),
                        cwe=_normalize_cwe(payload["cwe"]),
                        owasp=[str(item) for item in payload.get("owasp", [])],
                        languages=[str(item).lower() for item in payload.get("languages", [])],
                        patterns=patterns,
                        logic=str(payload.get("logic", "any")).lower(),
                        source_path=rule_path,
                    )
                )
        return rules

    def _filter_by_severity(self, findings: list[Finding]) -> list[Finding]:
        minimum = SEVERITY_ORDER[self.config.minimum_severity]
        return [
            finding
            for finding in findings
            if SEVERITY_ORDER.get(finding.severity, 0) >= minimum
        ]

    def _dedupe(self, findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str, int, int, str]] = set()
        deduped: list[Finding] = []
        for finding in findings:
            key = finding.dedupe_key()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped


def _normalize_cwe(value: Any) -> str:
    if isinstance(value, int):
        return f"CWE-{value}"
    text = str(value)
    if text.upper().startswith("CWE-"):
        return text.upper()
    return f"CWE-{text}"


def _offset_to_line_col(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    line_start = source.rfind("\n", 0, offset)
    column = offset - line_start
    return line, column


def _build_snippet(source: str, start_line: int, end_line: int, context: int = 2) -> str:
    lines = source.splitlines()
    if not lines:
        return ""
    start_index = max(start_line - context - 1, 0)
    end_index = min(end_line + context, len(lines))
    return "\n".join(lines[start_index:end_index])


def _line_at(source: str, line: int) -> str:
    lines = source.splitlines()
    if not lines or line < 1 or line > len(lines):
        return ""
    return lines[line - 1]


def _is_dynamic_sql_expression(text: str) -> bool:
    if not SQL_LITERAL_START_RE.search(text):
        return False
    if "${" in text:
        return True
    return bool(re.search(r"['\"`]\s*\+\s*[A-Za-z_(]", text) or re.search(r"\+\s*[A-Za-z_(]", text))


def _is_weak_fallback_secret(value: str) -> bool:
    normalized = value.strip().lower()
    return normalized in WEAK_FALLBACK_SECRET_VALUES or len(normalized) < 12


def _infer_environment_name(source: str) -> str | None:
    lowered = source.lower()
    if "production" in lowered:
        return "production"
    if "development" in lowered or "localhost" in lowered:
        return "development"
    return None
