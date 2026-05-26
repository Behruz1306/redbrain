"""Nuclei integration — optional external vulnerability scanner.

Nuclei (by ProjectDiscovery) is a fast, template-based vulnerability
scanner. When the `nuclei` binary is on PATH, RedBrain uses it for
high-confidence CVE/misconfiguration detection before manual exploit
attempts.

Templates are organized by category: cves, exposures, misconfiguration,
default-logins, etc. Results are parsed from JSON-lines output.

Install: https://github.com/projectdiscovery/nuclei
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from typing import Any

logger = logging.getLogger(__name__)

# Default template categories to run when none are specified
DEFAULT_CATEGORIES = ["cves", "exposures", "misconfiguration", "default-logins"]

# Map nuclei severity strings to our internal severity names
SEVERITY_MAP = {
    "info": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "medium",
}


class NucleiClient:
    """Wrapper around the nuclei CLI binary."""

    def __init__(self) -> None:
        self.binary_path = shutil.which("nuclei")
        self.available = self.binary_path is not None

    async def scan(
        self,
        target_url: str,
        templates: list[str] | None = None,
        severity: str = "medium,high,critical",
        timeout: int = 120,
        rate_limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Run nuclei against target and return findings.

        Args:
            target_url: The URL to scan.
            templates: Template categories to use (e.g. ["cves", "exposures"]).
                       Defaults to DEFAULT_CATEGORIES.
            severity: Comma-separated severity filter.
            timeout: Maximum scan duration in seconds.
            rate_limit: Max requests per second.

        Returns:
            List of finding dicts with keys: template_id, name, severity,
            matched_url, extracted_results, curl_command, description, tags.
        """
        if not self.available:
            logger.debug("Nuclei binary not found on PATH, skipping scan")
            return []

        categories = templates or DEFAULT_CATEGORIES

        cmd = [
            self.binary_path,
            "-target", target_url,
            "-severity", severity,
            "-json",              # JSON lines output
            "-silent",            # suppress banner/info
            "-no-color",
            "-rate-limit", str(rate_limit),
            "-timeout", "10",     # per-request timeout
            "-retries", "1",
            "-no-interactsh",     # don't use external interaction server
        ]

        # Add template tags for requested categories
        for cat in categories:
            cmd.extend(["-tags", cat])

        logger.info(f"Running nuclei scan: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                logger.warning(f"Nuclei scan timed out after {timeout}s")
                return []

            if stderr:
                stderr_text = stderr.decode(errors="ignore").strip()
                if stderr_text:
                    logger.debug(f"Nuclei stderr: {stderr_text[:500]}")

            return self._parse_output(stdout.decode(errors="ignore"))

        except FileNotFoundError:
            self.available = False
            logger.warning("Nuclei binary disappeared from PATH")
            return []
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            return []

    def _parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse nuclei JSON-lines output into standardized findings."""
        findings: list[dict[str, Any]] = []

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = entry.get("info", {})
            finding = {
                "template_id": entry.get("template-id", entry.get("templateID", "")),
                "name": info.get("name", entry.get("template-id", "unknown")),
                "severity": SEVERITY_MAP.get(
                    info.get("severity", "unknown").lower(), "medium"
                ),
                "matched_url": entry.get("matched-at", entry.get("host", "")),
                "description": info.get("description", ""),
                "tags": info.get("tags", []),
                "reference": info.get("reference", []),
                "extracted_results": entry.get("extracted-results", []),
                "matcher_name": entry.get("matcher-name", ""),
                "curl_command": entry.get("curl-command", self._build_curl(entry)),
                "type": entry.get("type", "http"),
            }

            findings.append(finding)

        logger.info(f"Nuclei found {len(findings)} results")
        return findings

    def _build_curl(self, entry: dict[str, Any]) -> str:
        """Build a reproduction curl command from a nuclei result."""
        matched = entry.get("matched-at", entry.get("host", ""))
        req = entry.get("request", "")

        if not matched:
            return ""

        # If nuclei provided the raw request, extract method and headers
        if req:
            lines = req.strip().split("\n")
            if lines:
                first_line = lines[0]
                parts = first_line.split()
                method = parts[0] if parts else "GET"
                curl = f"curl -X {method} '{matched}'"
                for hdr_line in lines[1:]:
                    if ": " in hdr_line and not hdr_line.startswith("Host:"):
                        curl += f" -H '{hdr_line.strip()}'"
                return curl

        return f"curl -v '{matched}'"

    async def update_templates(self) -> bool:
        """Update nuclei templates to latest version."""
        if not self.available:
            return False

        try:
            process = await asyncio.create_subprocess_exec(
                self.binary_path, "-update-templates",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(process.communicate(), timeout=120)
            return process.returncode == 0
        except Exception as e:
            logger.warning(f"Template update failed: {e}")
            return False


nuclei = NucleiClient()
