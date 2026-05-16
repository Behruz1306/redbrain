from __future__ import annotations

from ..core.llm_client import llm
from ..core.models import FunctionInfo, Remediation, Vulnerability
from ..event_bus import event_bus


class RemediateAgent:
    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id

    async def run(
        self, vulnerabilities: list[Vulnerability], func_map: dict[str, FunctionInfo]
    ) -> None:
        await event_bus.emit(self.scan_id, "agent:reasoning", {
            "agent": "remediate",
            "thought": f"Generating AI code fixes for {len(vulnerabilities)} vulnerabilities...",
        })

        for vuln in vulnerabilities:
            if not vuln.function_id or vuln.function_id not in func_map:
                continue

            func = func_map[vuln.function_id]

            try:
                fix = await self._generate_fix(vuln, func)
                vuln.remediation = fix

                await event_bus.emit(self.scan_id, "remediate:fix_generated", {
                    "vuln_id": vuln.id,
                    "title": vuln.title,
                    "file_path": fix.file_path,
                    "has_fix": bool(fix.fixed_code),
                })
            except Exception:
                continue

        fixed_count = sum(1 for v in vulnerabilities if v.remediation and v.remediation.fixed_code)
        await event_bus.emit(self.scan_id, "agent:reasoning", {
            "agent": "remediate",
            "thought": f"Generated {fixed_count}/{len(vulnerabilities)} code fixes.",
        })

    async def _generate_fix(self, vuln: Vulnerability, func: FunctionInfo) -> Remediation:
        prompt = f"""Analyze this vulnerable code and provide a secure fix.

VULNERABILITY:
- Type: {vuln.vuln_class}
- Severity: {vuln.severity}
- Title: {vuln.title}
- Description: {vuln.description}

VULNERABLE CODE (file: {func.file_path}, line {func.line}):
```
{func.source_code}
```

Provide a JSON response with:
- "fixed_code": the corrected source code (complete function, ready to paste)
- "explanation": 1-2 sentences explaining what was fixed and why
"""

        result = await llm.ask_json("remediate", prompt)

        if result.get("parse_error"):
            raw = result.get("raw", "")
            return Remediation(
                fixed_code="",
                explanation=raw[:200] if raw else "AI fix generation failed",
                file_path=func.file_path,
                line=func.line,
            )

        return Remediation(
            fixed_code=result.get("fixed_code", ""),
            explanation=result.get("explanation", ""),
            file_path=func.file_path,
            line=func.line,
        )
