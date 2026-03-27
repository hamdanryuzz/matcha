from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

from click.testing import CliRunner

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = PROJECT_ROOT / "matcha"
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from matcha.cli import main  # noqa: E402
from matcha.engine import EngineConfig, RuleEngine  # noqa: E402
from matcha.walker import WalkerConfig, walk_source_files  # noqa: E402


class MatchaScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures_dir = PROJECT_ROOT / "tests" / "fixtures"
        self.rules_dir = PROJECT_ROOT / "rules"
        self.config_fixture_dir = self.fixtures_dir / "configured_project"
        self.gitignore_fixture_dir = self.fixtures_dir / "gitignore_root_slash"
        self.nest_jwt_fixture_dir = self.fixtures_dir / "nest_jwt_project"
        self.nest_cookie_fixture_dir = self.fixtures_dir / "nest_cookie_project"
        self.nest_dev_cors_fixture_dir = self.fixtures_dir / "nest_dev_cors_project"

    def test_rule_engine_finds_expected_rules(self) -> None:
        engine = RuleEngine(
            EngineConfig(
                rules_directories=[self.rules_dir],
                minimum_severity="low",
            )
        )
        files = walk_source_files(WalkerConfig(root=self.fixtures_dir))
        findings = engine.scan_files(files)
        rule_ids = {finding.rule_id for finding in findings}
        expected = {
            "TS-AUTH-001",
            "TS-AUTH-002",
            "TS-AUTH-003",
            "TS-AUTH-004",
            "TS-INJ-001",
            "TS-INJ-002",
            "TS-INJ-003",
            "TS-INJ-004",
            "TS-WEB-001",
            "TS-WEB-002",
            "TS-WEB-003",
            "TS-WEB-004",
            "TS-WEB-005",
            "TS-WEB-006",
            "TS-WEB-007",
            "TS-WEB-008",
            "TS-WEB-009",
            "TS-API-001",
            "TS-API-002",
            "TS-API-003",
            "TS-LOG-001",
            "TS-CRYPTO-001",
            "TS-CRYPTO-002",
        }
        self.assertTrue(expected.issubset(rule_ids))

    def test_cli_json_output_contains_findings(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(self.fixtures_dir), "--format", "json"])
        self.assertEqual(result.exit_code, 1, msg=result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["tool"], "matcha")
        self.assertGreaterEqual(payload["summary"]["total"], 10)

    def test_config_file_is_applied(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(self.config_fixture_dir)])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["summary"]["total"], 0)

    def test_root_scan_ignores_bare_slash_gitignore_pattern(self) -> None:
        engine = RuleEngine(
            EngineConfig(
                rules_directories=[self.rules_dir],
                minimum_severity="low",
            )
        )
        files = walk_source_files(WalkerConfig(root=self.gitignore_fixture_dir))
        self.assertEqual(len(files), 1)
        findings = engine.scan_files(files)
        self.assertTrue(any(finding.rule_id == "TS-AUTH-001" for finding in findings))

    def test_sql_rule_ignores_non_sql_template_strings(self) -> None:
        engine = RuleEngine(
            EngineConfig(
                rules_directories=[self.rules_dir],
                minimum_severity="low",
            )
        )
        findings = engine.scan_source(
            file_path=Path("obs.service.ts"),
            source='this.logger.warn(`Delete failed: ${result.CommonMsg.Code}`);',
            language="typescript",
        )
        self.assertFalse(any(finding.rule_id == "TS-INJ-001" for finding in findings))

    def test_sql_rule_detects_prisma_and_typeorm_raw_queries(self) -> None:
        engine = RuleEngine(
            EngineConfig(
                rules_directories=[self.rules_dir],
                minimum_severity="low",
            )
        )
        prisma_findings = engine.scan_source(
            file_path=Path("repo.ts"),
            source='await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${userId}`);',
            language="typescript",
        )
        typeorm_findings = engine.scan_source(
            file_path=Path("repo.ts"),
            source='await dataSource.query("SELECT * FROM users WHERE id = " + userId);',
            language="typescript",
        )
        self.assertTrue(any(finding.metadata.get("detector") == "prisma_raw_query" for finding in prisma_findings))
        self.assertTrue(any(finding.metadata.get("detector") == "typeorm_raw_query" for finding in typeorm_findings))

    def test_csrf_rule_skips_bearer_token_nest_projects(self) -> None:
        engine = RuleEngine(
            EngineConfig(
                rules_directories=[self.rules_dir],
                minimum_severity="low",
            )
        )
        files = walk_source_files(WalkerConfig(root=self.nest_jwt_fixture_dir))
        findings = engine.scan_files(files)
        self.assertFalse(any(finding.rule_id == "TS-WEB-002" for finding in findings))

    def test_csrf_rule_flags_cookie_session_nest_projects(self) -> None:
        engine = RuleEngine(
            EngineConfig(
                rules_directories=[self.rules_dir],
                minimum_severity="low",
            )
        )
        files = walk_source_files(WalkerConfig(root=self.nest_cookie_fixture_dir))
        findings = engine.scan_files(files)
        self.assertTrue(any(finding.rule_id == "TS-WEB-002" for finding in findings))

    def test_fallback_secret_rule_detects_weak_env_default(self) -> None:
        engine = RuleEngine(
            EngineConfig(
                rules_directories=[self.rules_dir],
                minimum_severity="low",
            )
        )
        findings = engine.scan_source(
            file_path=Path("auth.module.ts"),
            source='JwtModule.register({ secret: process.env.JWT_SECRET_KEY || "secret" });',
            language="typescript",
        )
        self.assertTrue(any(finding.rule_id == "TS-AUTH-003" for finding in findings))

    def test_ssrf_rule_detects_dynamic_http_target(self) -> None:
        engine = RuleEngine(
            EngineConfig(
                rules_directories=[self.rules_dir],
                minimum_severity="low",
            )
        )
        findings = engine.scan_source(
            file_path=Path("proxy.controller.ts"),
            source=(
                'import { Controller, Get, Query } from "@nestjs/common";\n'
                "import { HttpService } from \"@nestjs/axios\";\n"
                '@Controller("proxy")\n'
                "export class ProxyController {\n"
                "  constructor(private readonly httpService: HttpService) {}\n"
                "  @Get()\n"
                "  proxy(@Query('url') url: string) {\n"
                "    return this.httpService.get(url);\n"
                "  }\n"
                "}\n"
            ),
            language="typescript",
        )
        self.assertTrue(any(finding.rule_id == "TS-WEB-004" for finding in findings))

    def test_upload_rule_detects_originalname_usage(self) -> None:
        engine = RuleEngine(
            EngineConfig(
                rules_directories=[self.rules_dir],
                minimum_severity="low",
            )
        )
        findings = engine.scan_source(
            file_path=Path("upload.controller.ts"),
            source=(
                'import { Controller, Post, UseInterceptors } from "@nestjs/common";\n'
                'import { FileInterceptor } from "@nestjs/platform-express";\n'
                'import { diskStorage } from "multer";\n'
                '@Controller("upload")\n'
                "export class UploadController {\n"
                "  @Post()\n"
                "  @UseInterceptors(FileInterceptor('file', {\n"
                "    storage: diskStorage({\n"
                "      filename: (req, file, cb) => cb(null, file.originalname),\n"
                "    }),\n"
                "  }))\n"
                "  upload() {}\n"
                "}\n"
            ),
            language="typescript",
        )
        self.assertTrue(any(finding.rule_id == "TS-WEB-005" for finding in findings))

    def test_cors_rule_lowers_severity_for_dev_only_wildcard(self) -> None:
        engine = RuleEngine(
            EngineConfig(
                rules_directories=[self.rules_dir],
                minimum_severity="low",
            )
        )
        files = walk_source_files(WalkerConfig(root=self.nest_dev_cors_fixture_dir))
        findings = engine.scan_files(files)
        cors_finding = next(finding for finding in findings if finding.rule_id == "TS-WEB-003")
        self.assertEqual(cors_finding.severity, "low")

    def test_open_redirect_rule_detects_user_controlled_redirect(self) -> None:
        engine = RuleEngine(EngineConfig(rules_directories=[self.rules_dir], minimum_severity="low"))
        findings = engine.scan_source(
            file_path=Path("redirect.controller.ts"),
            source=(
                'import { Controller, Get, Query, Res } from "@nestjs/common";\n'
                '@Controller("auth")\n'
                "export class AuthController {\n"
                "  @Get('redirect')\n"
                "  go(@Query('next') next: string, @Res() res: any) {\n"
                "    return res.redirect(next);\n"
                "  }\n"
                "}\n"
            ),
            language="typescript",
        )
        self.assertTrue(any(finding.rule_id == "TS-WEB-006" for finding in findings))

    def test_mass_assignment_rule_detects_raw_body_to_save(self) -> None:
        engine = RuleEngine(EngineConfig(rules_directories=[self.rules_dir], minimum_severity="low"))
        findings = engine.scan_source(
            file_path=Path("user.controller.ts"),
            source=(
                'import { Body, Controller, Post } from "@nestjs/common";\n'
                '@Controller("users")\n'
                "export class UserController {\n"
                "  constructor(private readonly repo: any) {}\n"
                "  @Post()\n"
                "  create(@Body() body: any) {\n"
                "    return this.repo.save(body);\n"
                "  }\n"
                "}\n"
            ),
            language="typescript",
        )
        self.assertTrue(any(finding.rule_id == "TS-API-001" for finding in findings))

    def test_swagger_rule_detects_unconditional_setup(self) -> None:
        engine = RuleEngine(EngineConfig(rules_directories=[self.rules_dir], minimum_severity="low"))
        findings = engine.scan_source(
            file_path=Path("main.ts"),
            source=(
                'import { SwaggerModule, DocumentBuilder } from "@nestjs/swagger";\n'
                "const document = SwaggerModule.createDocument(app, new DocumentBuilder().build());\n"
                "SwaggerModule.setup('docs', app, document);\n"
            ),
            language="typescript",
        )
        self.assertTrue(any(finding.rule_id == "TS-API-002" for finding in findings))

    def test_swagger_rule_skips_dev_only_setup(self) -> None:
        engine = RuleEngine(EngineConfig(rules_directories=[self.rules_dir], minimum_severity="low"))
        findings = engine.scan_source(
            file_path=Path("main.ts"),
            source=(
                'import { SwaggerModule } from "@nestjs/swagger";\n'
                'if (process.env.NODE_ENV !== "production") {\n'
                "  SwaggerModule.setup('docs', app, document);\n"
                "}\n"
            ),
            language="typescript",
        )
        self.assertFalse(any(finding.rule_id == "TS-API-002" for finding in findings))

    def test_jwt_expiry_missing_rule_detects_jwt_module_without_expiry(self) -> None:
        engine = RuleEngine(EngineConfig(rules_directories=[self.rules_dir], minimum_severity="low"))
        findings = engine.scan_source(
            file_path=Path("auth.module.ts"),
            source='JwtModule.register({ secret: process.env.JWT_SECRET_KEY });',
            language="typescript",
        )
        self.assertTrue(any(finding.rule_id == "TS-AUTH-004" for finding in findings))

    def test_insecure_cookie_rule_detects_secure_false(self) -> None:
        engine = RuleEngine(EngineConfig(rules_directories=[self.rules_dir], minimum_severity="low"))
        findings = engine.scan_source(
            file_path=Path("auth.controller.ts"),
            source='res.cookie("token", token, { httpOnly: true, secure: false });',
            language="typescript",
        )
        self.assertTrue(any(finding.rule_id == "TS-WEB-007" for finding in findings))

    def test_nosql_injection_rule_detects_raw_query_object(self) -> None:
        engine = RuleEngine(EngineConfig(rules_directories=[self.rules_dir], minimum_severity="low"))
        findings = engine.scan_source(
            file_path=Path("user.controller.ts"),
            source=(
                'import { Controller, Get, Query } from "@nestjs/common";\n'
                '@Controller("users")\n'
                "export class UserController {\n"
                "  constructor(private readonly model: any) {}\n"
                "  @Get()\n"
                "  search(@Query() filter: any) {\n"
                "    return this.model.find(filter);\n"
                "  }\n"
                "}\n"
            ),
            language="typescript",
        )
        self.assertTrue(any(finding.rule_id == "TS-INJ-003" for finding in findings))

    def test_command_injection_rule_detects_exec_with_user_command(self) -> None:
        engine = RuleEngine(EngineConfig(rules_directories=[self.rules_dir], minimum_severity="low"))
        findings = engine.scan_source(
            file_path=Path("job.controller.ts"),
            source=(
                'import { Body, Controller, Post } from "@nestjs/common";\n'
                'import { exec } from "child_process";\n'
                '@Controller("jobs")\n'
                "export class JobController {\n"
                "  @Post()\n"
                "  run(@Body('cmd') cmd: string) {\n"
                "    return exec(cmd);\n"
                "  }\n"
                "}\n"
            ),
            language="typescript",
        )
        self.assertTrue(any(finding.rule_id == "TS-INJ-004" for finding in findings))

    def test_security_headers_rule_detects_missing_helmet(self) -> None:
        engine = RuleEngine(EngineConfig(rules_directories=[self.rules_dir], minimum_severity="low"))
        findings = engine.scan_source(
            file_path=Path("main.ts"),
            source=(
                'import { NestFactory } from "@nestjs/core";\n'
                "async function bootstrap() {\n"
                "  const app = await NestFactory.create(AppModule);\n"
                "  await app.listen(3000);\n"
                "}\n"
            ),
            language="typescript",
        )
        self.assertTrue(any(finding.rule_id == "TS-WEB-008" for finding in findings))

    def test_regex_dos_rule_detects_nested_quantifier_pattern(self) -> None:
        engine = RuleEngine(EngineConfig(rules_directories=[self.rules_dir], minimum_severity="low"))
        findings = engine.scan_source(
            file_path=Path("validator.ts"),
            source='const dangerous = /(a+)+$/;\n',
            language="typescript",
        )
        self.assertTrue(any(finding.rule_id == "TS-WEB-009" for finding in findings))

    def test_rate_limiting_rule_detects_auth_route_without_throttle(self) -> None:
        engine = RuleEngine(EngineConfig(rules_directories=[self.rules_dir], minimum_severity="low"))
        findings = engine.scan_source(
            file_path=Path("auth.controller.ts"),
            source=(
                'import { Controller, Post, Body } from "@nestjs/common";\n'
                '@Controller("auth")\n'
                "export class AuthController {\n"
                "  @Post('login')\n"
                "  login(@Body() body: any) {\n"
                "    return body;\n"
                "  }\n"
                "}\n"
            ),
            language="typescript",
        )
        self.assertTrue(any(finding.rule_id == "TS-API-003" for finding in findings))


if __name__ == "__main__":
    unittest.main()
