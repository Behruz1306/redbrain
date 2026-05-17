"""Seed GBrain with comprehensive security knowledge.

Creates a densely interconnected knowledge graph:
- CVEs linked to CWEs, techniques, and OWASP categories
- Techniques linked to vuln classes and detection methods
- OWASP Top 10 linked to everything
- Bug bounty patterns as attack playbooks
- All nodes embedded in ZeroEntropy for semantic search

Auto-runs on app startup. Also runnable standalone:
    python -m apps.api.seed.seed_brain
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from ..core.gbrain_client import gbrain
from ..core.zeroentropy_client import zeroentropy

SEED_DIR = Path(__file__).parent
logger = logging.getLogger(__name__)

_seeded = False


async def seed_cves() -> int:
    cves = json.loads((SEED_DIR / "cves.json").read_text())

    advanced_path = SEED_DIR / "advanced_cves.json"
    if advanced_path.exists():
        cves.extend(json.loads(advanced_path.read_text()))

    logger.info(f"Seeding {len(cves)} CVEs...")

    for cve in cves:
        content = f"{cve['description']}\n\nCVSS: {cve['cvss_score']}\nCWE: {cve['cwe']}\nPoC: {cve['poc_code']}"

        page_id = await gbrain.create_page(
            title=cve["id"],
            content=content,
            page_type="CVE",
            metadata={
                "cvss_score": cve["cvss_score"],
                "cwe": cve["cwe"],
                "class": cve["class"],
                "affected_products": cve["affected_products"],
            },
        )

        # Link CVE → CWE
        cwe_id = f"CWE/{cve['cwe']}"
        await gbrain.create_link(page_id, cwe_id, "has_weakness")

        # Link CVE → VulnClass
        class_page = f"VulnClass/{cve['class']}"
        await gbrain.create_link(page_id, class_page, "belongs_to_class")

        # Embed for semantic search
        embedding = await zeroentropy.embed(content, input_type="document")
        zeroentropy.store_embedding(f"cve:{cve['id']}", embedding)

    return len(cves)


async def seed_techniques() -> int:
    techniques = json.loads((SEED_DIR / "techniques.json").read_text())
    logger.info(f"Seeding {len(techniques)} techniques...")

    for tech in techniques:
        content = (
            f"Technique: {tech['name']}\n"
            f"Class: {tech['class']}\n"
            f"Payloads ({len(tech['payloads'])}):\n" + "\n".join(f"  - {p}" for p in tech["payloads"]) + "\n"
            f"Detection: {', '.join(tech['detection_signatures'])}"
        )

        page_id = await gbrain.create_page(
            title=tech["name"],
            content=content,
            page_type="Technique",
            metadata={
                "class": tech["class"],
                "payload_count": len(tech["payloads"]),
            },
        )

        # Link Technique → VulnClass
        class_page = f"VulnClass/{tech['class']}"
        await gbrain.create_link(page_id, class_page, "targets_class")

        # Embed for reranking
        embedding = await zeroentropy.embed(content, input_type="document")
        zeroentropy.store_embedding(f"tech:{tech['name']}", embedding)

    return len(techniques)


async def seed_owasp() -> int:
    owasp_path = SEED_DIR / "owasp.json"
    if not owasp_path.exists():
        return 0

    owasp = json.loads(owasp_path.read_text())
    logger.info(f"Seeding {len(owasp)} OWASP Top 10 entries...")

    for entry in owasp:
        content = (
            f"{entry['name']}\n\n"
            f"{entry['description']}\n\n"
            f"Prevalence: {entry['prevalence']}\n"
            f"Impact: {entry['impact']}\n\n"
            f"Prevention:\n" + "\n".join(f"  - {p}" for p in entry["prevention"])
        )

        page_id = await gbrain.create_page(
            title=f"OWASP {entry['id']}: {entry['name']}",
            content=content,
            page_type="OWASP",
            metadata={
                "owasp_id": entry["id"],
                "cwes": entry["cwes"],
                "vuln_classes": entry["vuln_classes"],
            },
        )

        # Link OWASP → CWEs
        for cwe in entry["cwes"]:
            cwe_page = f"CWE/{cwe}"
            await gbrain.create_link(page_id, cwe_page, "maps_to_cwe")

        # Link OWASP → VulnClasses
        for vc in entry["vuln_classes"]:
            vc_page = f"VulnClass/{vc}"
            await gbrain.create_link(page_id, vc_page, "covers_class")

        # Embed
        embedding = await zeroentropy.embed(content, input_type="document")
        zeroentropy.store_embedding(f"owasp:{entry['id']}", embedding)

    return len(owasp)


async def seed_bugbounty() -> int:
    bb_path = SEED_DIR / "bugbounty_patterns.json"
    if not bb_path.exists():
        return 0

    patterns = json.loads(bb_path.read_text())
    logger.info(f"Seeding {len(patterns)} bug bounty patterns...")

    for pattern in patterns:
        content = (
            f"Bug Bounty Pattern: {pattern['name']}\n"
            f"Severity: {pattern['severity']} | Bounty: {pattern['bounty_range']}\n\n"
            f"{pattern['description']}\n\n"
            f"Attack Steps:\n" + "\n".join(f"  {i+1}. {s}" for i, s in enumerate(pattern["steps"])) + "\n\n"
            f"Detection:\n" + "\n".join(f"  - {d}" for d in pattern["detection"]) + "\n\n"
            f"Found on: {', '.join(pattern['platforms_found'])}"
        )

        page_id = await gbrain.create_page(
            title=pattern["name"],
            content=content,
            page_type="BugBounty",
            metadata={
                "category": pattern["category"],
                "severity": pattern["severity"],
                "bounty_range": pattern["bounty_range"],
                "platforms": pattern["platforms_found"],
            },
        )

        # Link BugBounty → VulnClass
        class_page = f"VulnClass/{pattern['category']}"
        await gbrain.create_link(page_id, class_page, "exploits_class")

        # Embed for semantic matching during scans
        embedding = await zeroentropy.embed(content, input_type="document")
        zeroentropy.store_embedding(f"bb:{pattern['id']}", embedding)

    return len(patterns)


async def seed_vuln_classes() -> int:
    """Create VulnClass hub nodes that everything links to."""
    classes = [
        ("sqli", "SQL Injection", "Injection of SQL commands via user input into database queries"),
        ("xss", "Cross-Site Scripting", "Injection of client-side scripts into web pages viewed by other users"),
        ("idor", "Insecure Direct Object Reference", "Accessing objects directly by manipulating identifiers without authorization checks"),
        ("broken_auth", "Broken Authentication", "Flaws in authentication mechanisms allowing attackers to assume other users' identities"),
        ("info_disclosure", "Information Disclosure", "Unintended exposure of sensitive information to unauthorized actors"),
        ("ssrf", "Server-Side Request Forgery", "Inducing server to make HTTP requests to attacker-specified destinations"),
        ("prototype_pollution", "Prototype Pollution", "Modifying JavaScript Object.prototype to affect all objects in the application"),
        ("jwt_vuln", "JWT Vulnerabilities", "Weaknesses in JSON Web Token implementation allowing token forgery or manipulation"),
        ("path_traversal", "Path Traversal", "Accessing files outside intended directory via path manipulation"),
        ("nosql_injection", "NoSQL Injection", "Injecting query operators into NoSQL database queries"),
        ("ssti", "Server-Side Template Injection", "Injecting template directives that execute on the server"),
        ("race_condition", "Race Condition", "Exploiting timing gaps in concurrent operations (TOCTOU)"),
        ("mass_assignment", "Mass Assignment", "Binding request parameters to internal object properties without filtering"),
        ("insecure_crypto", "Insecure Cryptography", "Use of weak algorithms, short keys, or improper cryptographic implementations"),
        ("open_redirect", "Open Redirect", "Redirecting users to arbitrary URLs via unvalidated redirect parameters"),
        ("deserialization", "Insecure Deserialization", "Deserializing untrusted data leading to code execution"),
        ("command_injection", "Command Injection", "Executing arbitrary OS commands via user-controlled input"),
    ]

    for class_id, name, desc in classes:
        await gbrain.create_page(
            title=name,
            content=f"{name}: {desc}",
            page_type="VulnClass",
            metadata={"class_id": class_id},
        )

    return len(classes)


async def seed_cwes() -> int:
    """Create CWE nodes for the most important weaknesses."""
    cwes = [
        ("CWE-79", "Improper Neutralization of Input During Web Page Generation (XSS)"),
        ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command"),
        ("CWE-94", "Improper Control of Generation of Code (Code Injection)"),
        ("CWE-77", "Improper Neutralization of Special Elements used in a Command"),
        ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command"),
        ("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory"),
        ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        ("CWE-287", "Improper Authentication"),
        ("CWE-284", "Improper Access Control"),
        ("CWE-502", "Deserialization of Untrusted Data"),
        ("CWE-918", "Server-Side Request Forgery"),
        ("CWE-362", "Concurrent Execution using Shared Resource with Improper Synchronization"),
        ("CWE-1321", "Improperly Controlled Modification of Object Prototype Attributes"),
        ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"),
        ("CWE-601", "URL Redirection to Untrusted Site"),
        ("CWE-306", "Missing Authentication for Critical Function"),
        ("CWE-862", "Missing Authorization"),
        ("CWE-863", "Incorrect Authorization"),
        ("CWE-400", "Uncontrolled Resource Consumption"),
        ("CWE-119", "Improper Restriction of Operations within the Bounds of a Memory Buffer"),
        ("CWE-190", "Integer Overflow or Wraparound"),
        ("CWE-798", "Use of Hard-coded Credentials"),
        ("CWE-913", "Improper Control of Dynamically-Managed Code Resources"),
        ("CWE-917", "Improper Neutralization of Special Elements used in an Expression Language Statement"),
        ("CWE-1104", "Use of Unmaintained Third Party Components"),
    ]

    for cwe_id, name in cwes:
        await gbrain.create_page(
            title=cwe_id,
            content=f"{cwe_id}: {name}",
            page_type="CWE",
            metadata={"cwe_id": cwe_id},
        )

    return len(cwes)


async def create_cross_links() -> int:
    """Create links between related knowledge after all nodes exist."""
    link_count = 0

    # Link OWASP categories to each other (attack chain awareness)
    owasp_chains = [
        ("OWASP/OWASP A03:2021: Injection", "OWASP/OWASP A01:2021: Broken Access Control", "escalates_to"),
        ("OWASP/OWASP A07:2021: Identification and Authentication Failures", "OWASP/OWASP A01:2021: Broken Access Control", "enables"),
        ("OWASP/OWASP A05:2021: Security Misconfiguration", "OWASP/OWASP A09:2021: Security Logging and Monitoring Failures", "exacerbated_by"),
        ("OWASP/OWASP A10:2021: Server-Side Request Forgery (SSRF)", "OWASP/OWASP A05:2021: Security Misconfiguration", "exploits"),
        ("OWASP/OWASP A08:2021: Software and Data Integrity Failures", "OWASP/OWASP A06:2021: Vulnerable and Outdated Components", "related_to"),
    ]
    for src, tgt, link_type in owasp_chains:
        await gbrain.create_link(src, tgt, link_type)
        link_count += 1

    # Link bug bounty patterns to OWASP
    bb_owasp_map = [
        ("BugBounty/Account Takeover via Password Reset Poisoning", "OWASP/OWASP A07:2021: Identification and Authentication Failures"),
        ("BugBounty/OAuth Token Theft via Open Redirect", "OWASP/OWASP A07:2021: Identification and Authentication Failures"),
        ("BugBounty/Race Condition in Payment/Transfer", "OWASP/OWASP A04:2021: Insecure Design"),
        ("BugBounty/SSRF to Cloud Metadata to RCE", "OWASP/OWASP A10:2021: Server-Side Request Forgery (SSRF)"),
        ("BugBounty/Prototype Pollution to XSS/RCE", "OWASP/OWASP A08:2021: Software and Data Integrity Failures"),
        ("BugBounty/JWT Algorithm Confusion Attack", "OWASP/OWASP A02:2021: Cryptographic Failures"),
        ("BugBounty/SSTI to RCE via Template Engine", "OWASP/OWASP A03:2021: Injection"),
        ("BugBounty/NoSQL Injection Authentication Bypass", "OWASP/OWASP A03:2021: Injection"),
        ("BugBounty/Mass Assignment Privilege Escalation", "OWASP/OWASP A01:2021: Broken Access Control"),
        ("BugBounty/HTTP Request Smuggling (CL.TE)", "OWASP/OWASP A05:2021: Security Misconfiguration"),
    ]
    for src, tgt in bb_owasp_map:
        await gbrain.create_link(src, tgt, "demonstrates")
        link_count += 1

    # Link techniques to related techniques (attack chains)
    technique_chains = [
        ("Technique/sqli_error_based", "Technique/sqli_union_based", "escalates_to"),
        ("Technique/sqli_union_based", "Technique/sqli_time_based_blind", "alternative"),
        ("Technique/xss_reflected", "Technique/xss_stored", "escalates_to"),
        ("Technique/ssrf_basic", "Technique/ssrf_cloud_metadata", "chains_to"),
        ("Technique/ssrf_filter_bypass", "Technique/ssrf_cloud_metadata", "enables"),
        ("Technique/ssti_jinja2", "Technique/command_injection_basic", "leads_to_rce"),
        ("Technique/prototype_pollution_server", "Technique/command_injection_basic", "gadget_chain"),
        ("Technique/broken_auth_jwt_none", "Technique/jwt_algorithm_confusion", "related"),
        ("Technique/nosql_injection_auth_bypass", "Technique/nosql_injection_data_extraction", "escalates_to"),
        ("Technique/path_traversal_basic", "Technique/path_traversal_filter_bypass", "evolved_from"),
    ]
    for src, tgt, link_type in technique_chains:
        await gbrain.create_link(src, tgt, link_type)
        link_count += 1

    return link_count


async def ensure_seeded() -> None:
    """Seed knowledge base if not already done. Safe to call multiple times."""
    global _seeded
    if _seeded:
        return

    logger.info("=== RedBrain Brain Seeder v2 — Building Knowledge Graph ===")

    # Create hub nodes first
    class_count = await seed_vuln_classes()
    cwe_count = await seed_cwes()
    logger.info(f"  Hub nodes: {class_count} vuln classes, {cwe_count} CWEs")

    # Seed main knowledge
    cve_count = await seed_cves()
    tech_count = await seed_techniques()
    owasp_count = await seed_owasp()
    bb_count = await seed_bugbounty()

    # Wire cross-links
    link_count = await create_cross_links()

    _seeded = True
    logger.info(
        f"Brain seeded: {cve_count} CVEs, {tech_count} techniques, "
        f"{owasp_count} OWASP, {bb_count} bug bounty patterns | "
        f"{gbrain.page_count} pages, {gbrain.link_count} links, "
        f"{zeroentropy.corpus_size} embeddings"
    )


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    await ensure_seeded()
    print(f"Total: {gbrain.page_count} pages, {gbrain.link_count} links, {zeroentropy.corpus_size} embeddings")


if __name__ == "__main__":
    asyncio.run(main())
