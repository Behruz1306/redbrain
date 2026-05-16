from __future__ import annotations

import ast
from typing import Any

from .base import BaseParser, ParsedFunction


class PythonParser(BaseParser):
    def supported_extensions(self) -> list[str]:
        return [".py"]

    def parse_file(self, file_path: str, source: str) -> list[ParsedFunction]:
        functions: list[ParsedFunction] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return functions

        lines = source.split("\n")

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params = [
                    arg.arg for arg in node.args.args
                    if arg.arg != "self" and arg.arg != "cls"
                ]
                start_line = node.lineno
                end_line = node.end_lineno or start_line
                func_source = "\n".join(lines[start_line - 1:end_line])

                functions.append(ParsedFunction(
                    name=node.name,
                    file_path=file_path,
                    line=start_line,
                    end_line=end_line,
                    source_code=func_source[:2000],
                    parameters=params,
                ))

        return functions
