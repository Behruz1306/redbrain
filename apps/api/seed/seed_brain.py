"""Seed GBrain with CVE and Technique data.

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
    logger.info(f"Seeding {len(cves)} CVEs...")

    for cve in cves:
        content = f"{cve['description']}\n\nCVSS: {cve['cvss_score']}\nCWE: {cve['cwe']}\nPoC: {cve['poc_code']}"

        await gbrain.create_page(
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

        embedding = await zeroentropy.embed(content, input_type="document")
        zeroentropy.store_embedding(f"cve:{cve['id']}", embedding)

    return len(cves)


async def seed_techniques() -> int:
    techniques = json.loads((SEED_DIR / "techniques.json").read_text())
    logger.info(f"Seeding {len(techniques)} techniques...")

    for tech in techniques:
        content = (
            f"Class: {tech['class']}\n"
            f"Payloads:\n" + "\n".join(f"  - {p}" for p in tech["payloads"]) + "\n"
            f"Detection: {', '.join(tech['detection_signatures'])}"
        )

        await gbrain.create_page(
            title=tech["name"],
            content=content,
            page_type="Technique",
            metadata={
                "class": tech["class"],
                "payload_count": len(tech["payloads"]),
            },
        )

    return len(techniques)


async def ensure_seeded() -> None:
    """Seed knowledge base if not already done. Safe to call multiple times."""
    global _seeded
    if _seeded:
        return

    logger.info("=== RedBrain Brain Seeder ===")
    cve_count = await seed_cves()
    tech_count = await seed_techniques()
    _seeded = True
    logger.info(
        f"Brain seeded: {cve_count} CVEs, {tech_count} techniques, "
        f"{zeroentropy.corpus_size} embeddings cached"
    )


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    await ensure_seeded()
    print(f"Total: {gbrain.page_count} pages, {gbrain.link_count} links")


if __name__ == "__main__":
    asyncio.run(main())
