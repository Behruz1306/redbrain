"""Seed GBrain with CVE and Technique data.

Run once before first scan:
    python -m apps.api.seed.seed_brain
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from ..core.gbrain_client import gbrain
from ..core.zeroentropy_client import zeroentropy

SEED_DIR = Path(__file__).parent


async def seed_cves() -> None:
    cves = json.loads((SEED_DIR / "cves.json").read_text())
    print(f"Seeding {len(cves)} CVEs...")

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

    print(f"  Done. {gbrain.page_count} pages in brain.")


async def seed_techniques() -> None:
    techniques = json.loads((SEED_DIR / "techniques.json").read_text())
    print(f"Seeding {len(techniques)} techniques...")

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

    print(f"  Done. {gbrain.page_count} pages in brain.")


async def main() -> None:
    print("=== RedBrain Brain Seeder ===")
    await seed_cves()
    await seed_techniques()
    print(f"\nTotal: {gbrain.page_count} pages, {gbrain.link_count} links")
    print("Brain seeded successfully.")


if __name__ == "__main__":
    asyncio.run(main())
