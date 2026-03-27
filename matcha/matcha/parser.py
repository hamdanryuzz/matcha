from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from tree_sitter import Language, Parser

try:
    import tree_sitter_javascript as tree_sitter_javascript
except ImportError:  # pragma: no cover
    tree_sitter_javascript = None

try:
    import tree_sitter_typescript as tree_sitter_typescript
except ImportError:  # pragma: no cover
    tree_sitter_typescript = None


@dataclass(slots=True)
class ParseResult:
    language: str
    tree: Any | None
    source_bytes: bytes
    parser_error: str | None = None

    @property
    def available(self) -> bool:
        return self.tree is not None and self.parser_error is None


@dataclass(slots=True)
class ASTNodeMatch:
    node_type: str
    text: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int


def _coerce_language(raw_language: Any) -> Language | Any:
    if isinstance(raw_language, Language):
        return raw_language
    try:
        return Language(raw_language)
    except Exception:
        return raw_language


@lru_cache(maxsize=4)
def _load_language(language: str, use_tsx: bool = False) -> Language | Any:
    if language == "javascript":
        if tree_sitter_javascript is None:
            raise RuntimeError("tree-sitter-javascript is not installed")
        return _coerce_language(tree_sitter_javascript.language())
    if language == "typescript":
        if tree_sitter_typescript is None:
            raise RuntimeError("tree-sitter-typescript is not installed")
        loader = (
            tree_sitter_typescript.language_tsx
            if use_tsx and hasattr(tree_sitter_typescript, "language_tsx")
            else tree_sitter_typescript.language_typescript
        )
        return _coerce_language(loader())
    raise RuntimeError(f"Unsupported parser language: {language}")


class ASTParser:
    def __init__(self) -> None:
        self._parser = Parser()

    def parse(self, source: str, language: str, prefer_tsx: bool = False) -> ParseResult:
        source_bytes = source.encode("utf-8", errors="ignore")
        try:
            grammar = _load_language(language, use_tsx=prefer_tsx)
            self._set_language(grammar)
            tree = self._parser.parse(source_bytes)
            return ParseResult(language=language, tree=tree, source_bytes=source_bytes)
        except Exception as exc:
            return ParseResult(
                language=language,
                tree=None,
                source_bytes=source_bytes,
                parser_error=str(exc),
            )

    def _set_language(self, language: Language | Any) -> None:
        try:
            self._parser.language = language
        except AttributeError:
            self._parser.set_language(language)

    def find_nodes(
        self,
        parse_result: ParseResult,
        node_type: str,
        text_regex: str | None = None,
        regex_flags: int = 0,
    ) -> list[ASTNodeMatch]:
        if not parse_result.available:
            return []

        import re

        compiled = re.compile(text_regex, regex_flags) if text_regex else None
        matches: list[ASTNodeMatch] = []
        stack = [parse_result.tree.root_node]
        while stack:
            node = stack.pop()
            if node.type == node_type:
                text = parse_result.source_bytes[node.start_byte : node.end_byte].decode(
                    "utf-8",
                    errors="ignore",
                )
                if compiled is None or compiled.search(text):
                    matches.append(
                        ASTNodeMatch(
                            node_type=node.type,
                            text=text,
                            start_line=node.start_point[0] + 1,
                            start_column=node.start_point[1] + 1,
                            end_line=node.end_point[0] + 1,
                            end_column=node.end_point[1] + 1,
                        )
                    )
            stack.extend(reversed(node.children))
        return matches
