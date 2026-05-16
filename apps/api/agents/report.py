from __future__ import annotations

from ..core.models import (
    Correlation,
    EndpointInfo,
    ExploitResult,
    FunctionInfo,
    Severity,
    Vulnerability,
)
from ..event_bus import event_bus


class ReportAgent:
    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id

    async def run(
        self,
        functions: list[FunctionInfo],
        endpoints: list[EndpointInfo],
        correlations: list[Correlation],
        exploit_data: tuple[list[Vulnerability], list[ExploitResult]],
    ) -> str:
        vulnerabilities, exploits = exploit_data
        func_map = {f.id: f for f in functions}
        endpoint_map = {e.id: e for e in endpoints}
        exploit_map: dict[str, list[ExploitResult]] = {}
        for exp in exploits:
            exploit_map.setdefault(exp.vulnerability_id, []).append(exp)

        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }
        sorted_vulns = sorted(vulnerabilities, key=lambda v: severity_order.get(v.severity, 99))

        report_lines: list[str] = []
        report_lines.append("# RedBrain Security Report")
        report_lines.append("")
        report_lines.append("## Executive Summary")
        report_lines.append("")

        crit = sum(1 for v in vulnerabilities if v.severity == Severity.CRITICAL)
        high = sum(1 for v in vulnerabilities if v.severity == Severity.HIGH)
        med = sum(1 for v in vulnerabilities if v.severity == Severity.MEDIUM)
        low = sum(1 for v in vulnerabilities if v.severity == Severity.LOW)

        report_lines.append(f"- **Total vulnerabilities found:** {len(vulnerabilities)}")
        report_lines.append(f"- **Critical:** {crit} | **High:** {high} | **Medium:** {med} | **Low:** {low}")
        report_lines.append(f"- **Functions analyzed:** {len(functions)}")
        report_lines.append(f"- **Endpoints discovered:** {len(endpoints)}")
        report_lines.append(f"- **Correlations established:** {len(correlations)}")
        report_lines.append(f"- **Successful exploits:** {sum(1 for e in exploits if e.success)}")
        report_lines.append("")

        bounty = crit * 3000 + high * 1500 + med * 500 + low * 100
        report_lines.append(f"**Estimated bug bounty value:** ~${bounty:,}")
        report_lines.append("")
        report_lines.append("---")
        report_lines.append("")

        for vuln in sorted_vulns:
            badge = self._severity_badge(vuln.severity)
            report_lines.append(f"## {badge} {vuln.title}")
            report_lines.append("")
            report_lines.append(f"**Class:** {vuln.vuln_class.value} | **Confidence:** {vuln.confidence:.0%} | **Status:** {vuln.status.value}")
            report_lines.append("")
            report_lines.append(f"> {vuln.description}")
            report_lines.append("")

            # Static evidence
            func = func_map.get(vuln.function_id or "")
            if func:
                report_lines.append("### Static Evidence")
                report_lines.append("")
                report_lines.append(f"**File:** `{func.file_path}` (line {func.line})")
                report_lines.append(f"**Function:** `{func.name}`")
                report_lines.append(f"**Risk signals:** {', '.join(func.risk_signals)}")
                report_lines.append("")
                report_lines.append("```javascript")
                report_lines.append(func.source_code[:500])
                report_lines.append("```")
                report_lines.append("")

            # Dynamic exploit
            vuln_exploits = exploit_map.get(vuln.id, [])
            for exp in vuln_exploits:
                if exp.success:
                    report_lines.append("### Dynamic Exploit")
                    report_lines.append("")
                    report_lines.append(f"**Technique:** {exp.technique}")
                    report_lines.append(f"**Payload:** `{exp.payload}`")
                    report_lines.append(f"**Proof:** {exp.proof}")
                    report_lines.append("")
                    report_lines.append("**Reproduce:**")
                    report_lines.append("```bash")
                    report_lines.append(exp.repro_curl)
                    report_lines.append("```")
                    report_lines.append("")

            report_lines.append("---")
            report_lines.append("")

        report_md = "\n".join(report_lines)

        await event_bus.emit(self.scan_id, "report:complete", {
            "vulnerability_count": len(vulnerabilities),
            "report_length": len(report_md),
        })

        return report_md

    def _severity_badge(self, severity: Severity) -> str:
        badges = {
            Severity.CRITICAL: "🔴 CRITICAL",
            Severity.HIGH: "🟠 HIGH",
            Severity.MEDIUM: "🟡 MEDIUM",
            Severity.LOW: "🟢 LOW",
        }
        return badges.get(severity, "⚪ UNKNOWN")
