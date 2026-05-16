from __future__ import annotations

from typing import Any

from ..core.llm_client import llm
from ..core.thehog_client import thehog
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
        attack_chains: list[dict[str, Any]] | None = None,
        risk_score: dict[str, Any] | None = None,
    ) -> str:
        vulnerabilities, exploits = exploit_data
        func_map = {f.id: f for f in functions}
        endpoint_map = {e.id: e for e in endpoints}
        exploit_map: dict[str, list[ExploitResult]] = {}
        for exp in exploits:
            exploit_map.setdefault(exp.vulnerability_id, []).append(exp)

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

        # Risk Score Section
        if risk_score:
            report_lines.append("## Risk Assessment")
            report_lines.append("")
            grade = risk_score.get("grade", "?")
            score = risk_score.get("score", 0)
            report_lines.append(f"**Security Grade: {grade}** (Score: {score}/100)")
            report_lines.append("")
            if risk_score.get("recommendation"):
                report_lines.append(f"> {risk_score['recommendation']}")
                report_lines.append("")
            report_lines.append("---")
            report_lines.append("")

        report_lines.append("## Executive Summary")
        report_lines.append("")

        crit = sum(1 for v in vulnerabilities if v.severity == Severity.CRITICAL)
        high = sum(1 for v in vulnerabilities if v.severity == Severity.HIGH)
        med = sum(1 for v in vulnerabilities if v.severity == Severity.MEDIUM)
        low = sum(1 for v in vulnerabilities if v.severity == Severity.LOW)

        # AI-generated executive summary
        ai_summary = await self._generate_ai_summary(vulnerabilities, endpoints, correlations, exploits)
        if ai_summary:
            report_lines.append(ai_summary)
            report_lines.append("")

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

        # Attack Chains Section
        if attack_chains:
            report_lines.append("---")
            report_lines.append("")
            report_lines.append("## Attack Chains")
            report_lines.append("")
            report_lines.append(f"RedBrain identified **{len(attack_chains)} potential attack chains** where vulnerabilities can be combined for greater impact:")
            report_lines.append("")
            for i, chain in enumerate(attack_chains[:5], 1):
                desc = chain.get("description", "Unknown chain")
                length = chain.get("chain_length", 0)
                report_lines.append(f"{i}. **{desc}** (chain length: {length})")
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

            if func and func.cve_matches:
                report_lines.append("### Similar CVEs")
                report_lines.append("")
                for match in func.cve_matches[:3]:
                    report_lines.append(
                        f"- **{match.cve_id}** (similarity: {match.similarity:.0%})"
                    )
                report_lines.append("")

            report_lines.append("---")
            report_lines.append("")

        # Threat Intelligence Section (The Hog)
        threat_intel = await self._gather_threat_intel(vulnerabilities)
        if threat_intel:
            report_lines.append("## Threat Intelligence (powered by The Hog)")
            report_lines.append("")
            report_lines.append("Real-world threat signals from social listening across Reddit, Twitter, forums:")
            report_lines.append("")
            for intel in threat_intel[:8]:
                source = intel.get("source", "Web")
                signal = intel.get("signal", "")
                severity = intel.get("severity", "medium")
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
                report_lines.append(f"- {icon} **[{source}]** {signal}")
            report_lines.append("")
            report_lines.append("---")
            report_lines.append("")

        # AI Analysis Footer
        report_lines.append("## AI Analysis Metadata")
        report_lines.append("")
        report_lines.append("- **Engine:** RedBrain AI (ZeroEntropy zembed-1 + zerank-2)")
        report_lines.append(f"- **LLM Provider:** {llm.provider}")
        report_lines.append(f"- **Threat Intel:** The Hog (YC F25) — social listening")
        report_lines.append(f"- **Semantic correlations:** {sum(1 for c in correlations if c.reasoning.startswith('[AI]'))}")
        report_lines.append(f"- **Attack chains detected:** {len(attack_chains) if attack_chains else 0}")
        report_lines.append(f"- **Knowledge base:** CVEs + techniques + prior scan patterns")
        report_lines.append("")

        report_md = "\n".join(report_lines)

        await event_bus.emit(self.scan_id, "report:complete", {
            "vulnerability_count": len(vulnerabilities),
            "report_length": len(report_md),
            "risk_grade": risk_score.get("grade", "?") if risk_score else "?",
        })

        return report_md

    async def _gather_threat_intel(
        self, vulnerabilities: list[Vulnerability]
    ) -> list[dict[str, Any]]:
        """Gather threat intelligence from The Hog for found vulnerability classes."""
        vuln_classes = list({v.vuln_class.value for v in vulnerabilities})
        all_intel: list[dict[str, Any]] = []

        for vc in vuln_classes[:4]:
            try:
                intel = await thehog.get_vuln_class_intel(vc)
                all_intel.extend(intel.get("signals", []))
            except Exception:
                continue

        await event_bus.emit(self.scan_id, "agent:reasoning", {
            "agent": "report",
            "thought": f"Gathered {len(all_intel)} threat intelligence signals from The Hog for {len(vuln_classes)} vulnerability classes",
        })

        return all_intel

    async def _generate_ai_summary(
        self,
        vulnerabilities: list[Vulnerability],
        endpoints: list[EndpointInfo],
        correlations: list[Correlation],
        exploits: list[ExploitResult],
    ) -> str:
        if not llm.available or not vulnerabilities:
            return ""

        try:
            vuln_summary = ", ".join(
                f"{v.vuln_class.value}({v.severity.value})" for v in vulnerabilities[:10]
            )
            successful = sum(1 for e in exploits if e.success)
            prompt = (
                f"Write a 2-3 sentence executive summary for a security assessment report.\n"
                f"Findings: {len(vulnerabilities)} vulnerabilities [{vuln_summary}]\n"
                f"Endpoints tested: {len(endpoints)}\n"
                f"Successful exploits: {successful}/{len(exploits)}\n"
                f"Correlations: {len(correlations)} code-to-endpoint links confirmed\n\n"
                f"Be concise, professional, and highlight the most critical risk."
            )
            summary = await llm.ask("report", prompt, max_tokens=200)
            if summary and "offline" not in summary:
                return summary.strip()
        except Exception:
            pass
        return ""

    def _severity_badge(self, severity: Severity) -> str:
        badges = {
            Severity.CRITICAL: "🔴 CRITICAL",
            Severity.HIGH: "🟠 HIGH",
            Severity.MEDIUM: "🟡 MEDIUM",
            Severity.LOW: "🟢 LOW",
        }
        return badges.get(severity, "⚪ UNKNOWN")
