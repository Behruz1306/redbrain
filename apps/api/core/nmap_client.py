"""Nmap integration -- optional network port scanner.

When the `nmap` binary is on PATH, RedBrain uses it to discover open
ports, running services, and version information on the target host.
Results are parsed from nmap's XML output format.

Install: apt-get install nmap
"""
from __future__ import annotations

import asyncio
import logging
import re
import shutil
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class NmapClient:
    """Wrapper around the nmap CLI binary."""

    def __init__(self) -> None:
        self.binary_path = shutil.which("nmap")
        self.available = self.binary_path is not None

    async def scan(
        self,
        target_url: str,
        ports: str = "21-25,53,80,110,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017",
        timeout: int = 120,
        service_detection: bool = True,
    ) -> dict[str, Any]:
        """Run nmap port scan + optional service detection.

        Args:
            target_url: URL or hostname to scan.
            ports: Port specification string.
            timeout: Maximum scan duration in seconds.
            service_detection: Whether to run -sV for service/version detection.

        Returns:
            Dict with keys: host, ports (list of open port dicts),
            os_guess, scan_time.
        """
        if not self.available:
            logger.debug("Nmap binary not found on PATH, skipping scan")
            return {"host": "", "ports": [], "os_guess": "", "scan_time": 0}

        host = self._extract_host(target_url)
        if not host:
            logger.warning(f"Could not extract host from: {target_url}")
            return {"host": "", "ports": [], "os_guess": "", "scan_time": 0}

        cmd = [
            self.binary_path,
            "-p", ports,
            "-oX", "-",       # XML output to stdout
            "--open",         # only show open ports
            "-T4",            # aggressive timing
            "--max-retries", "1",
            "--host-timeout", f"{timeout}s",
        ]

        if service_detection:
            cmd.append("-sV")
            cmd.extend(["--version-intensity", "5"])

        cmd.append(host)

        logger.info(f"Running nmap scan: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout + 10
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                logger.warning(f"Nmap scan timed out after {timeout}s")
                return {"host": host, "ports": [], "os_guess": "", "scan_time": 0}

            if stderr:
                stderr_text = stderr.decode(errors="ignore").strip()
                if stderr_text:
                    logger.debug(f"Nmap stderr: {stderr_text[:500]}")

            return self._parse_xml(host, stdout.decode(errors="ignore"))

        except FileNotFoundError:
            self.available = False
            logger.warning("Nmap binary disappeared from PATH")
            return {"host": host, "ports": [], "os_guess": "", "scan_time": 0}
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return {"host": host, "ports": [], "os_guess": "", "scan_time": 0}

    def _extract_host(self, target_url: str) -> str:
        """Extract hostname from a URL or return as-is if already a host."""
        if "://" in target_url:
            parsed = urlparse(target_url)
            return parsed.hostname or ""
        # Strip any path/port if someone passed host:port/path
        host = target_url.split("/")[0].split(":")[0]
        return host

    def _parse_xml(self, host: str, xml_output: str) -> dict[str, Any]:
        """Parse nmap XML output into structured results."""
        result: dict[str, Any] = {
            "host": host,
            "ports": [],
            "os_guess": "",
            "scan_time": 0,
        }

        if not xml_output.strip():
            return result

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as e:
            logger.warning(f"Failed to parse nmap XML: {e}")
            return result

        # Extract scan time
        runstats = root.find(".//runstats/finished")
        if runstats is not None:
            elapsed = runstats.get("elapsed", "0")
            try:
                result["scan_time"] = float(elapsed)
            except ValueError:
                pass

        # Extract host information
        for host_elem in root.findall(".//host"):
            # OS detection results
            for osmatch in host_elem.findall(".//osmatch"):
                os_name = osmatch.get("name", "")
                os_accuracy = osmatch.get("accuracy", "")
                if os_name:
                    result["os_guess"] = f"{os_name} ({os_accuracy}% confidence)"
                    break

            # Port results
            for port_elem in host_elem.findall(".//port"):
                state_elem = port_elem.find("state")
                if state_elem is None:
                    continue

                state = state_elem.get("state", "")
                if state != "open":
                    continue

                port_num = port_elem.get("portid", "")
                protocol = port_elem.get("protocol", "tcp")

                service_elem = port_elem.find("service")
                service_name = ""
                service_product = ""
                service_version = ""
                service_extra = ""

                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    service_product = service_elem.get("product", "")
                    service_version = service_elem.get("version", "")
                    service_extra = service_elem.get("extrainfo", "")

                port_info: dict[str, Any] = {
                    "port": int(port_num) if port_num.isdigit() else port_num,
                    "protocol": protocol,
                    "state": state,
                    "service": service_name,
                    "product": service_product,
                    "version": service_version,
                    "extra_info": service_extra,
                }

                # Build version string
                version_parts = [service_product, service_version, service_extra]
                port_info["version_string"] = " ".join(
                    p for p in version_parts if p
                ).strip()

                # Check for known vulnerable service versions
                port_info["risk_notes"] = self._assess_service_risk(port_info)

                result["ports"].append(port_info)

        logger.info(f"Nmap found {len(result['ports'])} open ports on {host}")
        return result

    def _assess_service_risk(self, port_info: dict[str, Any]) -> list[str]:
        """Flag known risky services or configurations."""
        risks: list[str] = []
        service = port_info.get("service", "").lower()
        product = port_info.get("product", "").lower()
        version = port_info.get("version", "")
        port = port_info.get("port", 0)

        # Databases exposed to the network
        db_services = {"mysql", "postgresql", "mongodb", "redis", "memcached", "ms-sql-s", "oracle"}
        if service in db_services or port in (3306, 5432, 27017, 6379, 11211, 1433, 1521):
            risks.append(f"Database service ({service}) exposed -- check authentication requirements")

        # Unencrypted protocols
        if service in ("ftp", "telnet", "http") and port not in (80,):
            risks.append(f"Unencrypted protocol ({service}) in use")

        if service == "http" and port in (8080, 8443, 9090, 9200):
            risks.append(f"Management/internal HTTP port {port} exposed")

        # Known vulnerable versions (simplified checks)
        if "apache" in product and version:
            if version.startswith("2.4.") and self._version_lt(version, "2.4.54"):
                risks.append("Apache HTTP Server may be outdated -- check for CVEs")

        if "nginx" in product and version:
            if self._version_lt(version, "1.25.0"):
                risks.append("Nginx may be outdated -- check for CVEs")

        if "openssh" in product and version:
            if self._version_lt(version, "9.0"):
                risks.append("OpenSSH may be outdated -- check for CVEs")

        return risks

    def _version_lt(self, version_str: str, target: str) -> bool:
        """Simple version comparison (best-effort)."""
        try:
            v_parts = [int(x) for x in re.findall(r"\d+", version_str)[:3]]
            t_parts = [int(x) for x in re.findall(r"\d+", target)[:3]]
            # Pad to same length
            while len(v_parts) < 3:
                v_parts.append(0)
            while len(t_parts) < 3:
                t_parts.append(0)
            return v_parts < t_parts
        except (ValueError, IndexError):
            return False


nmap = NmapClient()
