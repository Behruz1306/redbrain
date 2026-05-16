from __future__ import annotations

import re

from .base import BaseParser, ParsedFunction


class JavaScriptParser(BaseParser):
    """Regex-based JS/TS parser. Fast, good enough for hackathon MVP."""

    _FUNC_PATTERNS = [
        # function name(params) {
        re.compile(
            r"(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)",
            re.MULTILINE,
        ),
        # const name = (params) => {
        re.compile(
            r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>",
            re.MULTILINE,
        ),
        # const name = function(params) {
        re.compile(
            r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function\s*\(([^)]*)\)",
            re.MULTILINE,
        ),
        # name(params) { — method in class/object
        re.compile(
            r"^\s+(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{",
            re.MULTILINE,
        ),
        # router.get/post/put/delete('/path', (req, res) => {
        re.compile(
            r"\.(?:get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]",
            re.MULTILINE,
        ),
    ]

    def supported_extensions(self) -> list[str]:
        return [".js", ".ts", ".mjs", ".cjs"]

    def parse_file(self, file_path: str, source: str) -> list[ParsedFunction]:
        functions: list[ParsedFunction] = []
        lines = source.split("\n")

        for pattern in self._FUNC_PATTERNS[:-1]:
            for match in pattern.finditer(source):
                name = match.group(1)
                params_str = match.group(2) if match.lastindex and match.lastindex >= 2 else ""
                params = [p.strip().split(":")[0].strip() for p in params_str.split(",") if p.strip()]

                start_pos = match.start()
                line_num = source[:start_pos].count("\n") + 1

                body = self._extract_body(source, match.end())
                func_source = source[match.start():match.end() + len(body)]

                functions.append(ParsedFunction(
                    name=name,
                    file_path=file_path,
                    line=line_num,
                    end_line=line_num + func_source.count("\n"),
                    source_code=func_source[:2000],
                    parameters=params,
                ))

        # Route handlers
        route_pattern = self._FUNC_PATTERNS[-1]
        for match in route_pattern.finditer(source):
            path = match.group(1)
            start_pos = match.start()
            line_num = source[:start_pos].count("\n") + 1

            line_start = source.rfind("\n", 0, start_pos) + 1
            line_end = source.find("\n", match.end())
            if line_end == -1:
                line_end = len(source)

            method_match = re.search(r"\.(get|post|put|delete|patch)", source[line_start:match.end()])
            method = method_match.group(1).upper() if method_match else "GET"

            body = self._extract_body(source, match.end())
            func_source = source[line_start:match.end() + len(body)]

            functions.append(ParsedFunction(
                name=f"{method}:{path}",
                file_path=file_path,
                line=line_num,
                end_line=line_num + func_source.count("\n"),
                source_code=func_source[:2000],
                parameters=[],
            ))

        return functions

    def _extract_body(self, source: str, start: int) -> str:
        brace_pos = source.find("{", start)
        if brace_pos == -1:
            end = source.find("\n", start)
            return source[start:end] if end != -1 else source[start:]

        depth = 0
        i = brace_pos
        while i < len(source):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    return source[start:i + 1]
            i += 1
        return source[start:min(start + 500, len(source))]
