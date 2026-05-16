from __future__ import annotations

import os
import tempfile
from pathlib import Path

import git

from ..core.models import FunctionInfo
from ..event_bus import event_bus
from ..parsers.javascript import JavaScriptParser
from ..parsers.python import PythonParser
from ..patterns.sast import (
    command_injection,
    eval_user_input,
    hardcoded_secrets,
    missing_auth,
    raw_sql,
    unsafe_deserialization,
)

DETECTORS = [
    ("raw_sql", raw_sql.detect),
    ("eval_user_input", eval_user_input.detect),
    ("hardcoded_secrets", hardcoded_secrets.detect),
    ("missing_auth", missing_auth.detect),
    ("unsafe_deserialization", unsafe_deserialization.detect),
    ("command_injection", command_injection.detect),
]

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "coverage",
    "__pycache__", ".venv", "vendor", ".next",
}

MAX_FILE_SIZE = 100_000


class SASTAgent:
    def __init__(self, scan_id: str, repo_url: str) -> None:
        self.scan_id = scan_id
        self.repo_url = repo_url
        self.js_parser = JavaScriptParser()
        self.py_parser = PythonParser()
        self.functions: list[FunctionInfo] = []

    async def run(self) -> list[FunctionInfo]:
        clone_dir = tempfile.mkdtemp(prefix=f"redbrain-{self.scan_id}-")
        try:
            git.Repo.clone_from(self.repo_url, clone_dir, depth=1)
        except Exception as e:
            await event_bus.emit(self.scan_id, "sast:error", {"error": str(e)})
            return []

        try:
            all_files = self._collect_files(clone_dir)

            for file_path in all_files:
                rel_path = os.path.relpath(file_path, clone_dir)
                await event_bus.emit(self.scan_id, "sast:file_started", {"path": rel_path})

                try:
                    source = Path(file_path).read_text(errors="ignore")
                except Exception:
                    continue

                if len(source) > MAX_FILE_SIZE:
                    continue

                ext = Path(file_path).suffix
                parser = self._get_parser(ext)
                if not parser:
                    continue

                parsed = parser.parse_file(rel_path, source)
                for func in parsed:
                    signals = self._detect_patterns(func.source_code)
                    func_info = FunctionInfo(
                        file_path=rel_path,
                        name=func.name,
                        line=func.line,
                        source_code=func.source_code,
                        parameters=func.parameters,
                        risk_signals=signals,
                    )
                    self.functions.append(func_info)

                    if signals:
                        await event_bus.emit(self.scan_id, "sast:function_analyzed", {
                            "function_id": func_info.id,
                            "name": func_info.name,
                            "file": rel_path,
                            "line": func.line,
                            "risk_signals": signals,
                        })
        finally:
            import shutil
            shutil.rmtree(clone_dir, ignore_errors=True)

        await event_bus.emit(self.scan_id, "sast:complete", {
            "total_functions": len(self.functions),
            "high_risk_count": sum(1 for f in self.functions if f.risk_signals),
        })

        return self.functions

    def _collect_files(self, root: str) -> list[str]:
        files: list[str] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                ext = Path(fname).suffix
                if ext in (".js", ".ts", ".mjs", ".cjs", ".py"):
                    files.append(os.path.join(dirpath, fname))
        return files

    def _get_parser(self, ext: str):
        if ext in self.js_parser.supported_extensions():
            return self.js_parser
        if ext in self.py_parser.supported_extensions():
            return self.py_parser
        return None

    def _detect_patterns(self, source: str) -> list[str]:
        signals = []
        for name, detect_fn in DETECTORS:
            if detect_fn(source):
                signals.append(name)
        return signals
