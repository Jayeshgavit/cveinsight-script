import logging
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

import ai_processor
import db
import fetcher
from utils import (
    parse_affected_software,
    parse_cvss_metrics,
    parse_description,
    parse_references,
    setup_logging,
)


def run_pipeline() -> None:
    logger = setup_logging()
    logger.info("=== CVEInsight pipeline started ===")

    # Determine fetch window: 30 days on first run, 7 days for incremental updates
    first_run = db.is_first_run()
    days = 30 if first_run else 7
    logger.info(f"{'First run' if first_run else 'Incremental run'} — fetching last {days} days")

    # Step 1: Fetch CVEs from NVD
    raw_cves = fetcher.fetch_cves(days=days)
    total_fetched = len(raw_cves)
    logger.info(f"NVD returned {total_fetched} CVEs")

    inserted = 0
    skipped = 0
    failed = 0

    for cve in raw_cves:
        cve_id = cve.get("id")
        if not cve_id:
            logger.warning("CVE entry missing id field — skipping")
            failed += 1
            continue

        # Step 2: Skip if CVE already exists in DB
        if db.cve_exists(cve_id):
            logger.debug(f"Already exists, skipping: {cve_id}")
            skipped += 1
            continue

        # Parse all fields from raw NVD data
        description = parse_description(cve)
        metrics = parse_cvss_metrics(cve)
        references = parse_references(cve)
        affected_software = parse_affected_software(cve)

        published = cve.get("published", "")[:10] or None
        last_modified = cve.get("lastModified", "")[:10] or None

        # Step 3: Insert into cves table
        cve_record = {
            "cve_id": cve_id,
            "title": cve_id,  # NVD has no separate title; use cve_id as title
            "description": description,
            "severity": metrics["severity"],
            "cvss_score": metrics["cvss_score"],
            "cvss_vector": metrics["cvss_vector"],
            "attack_vector": metrics["attack_vector"],
            "attack_complexity": metrics["attack_complexity"],
            "privileges_required": metrics["privileges_required"],
            "user_interaction": metrics["user_interaction"],
            "published_at": published,
            "last_modified_at": last_modified,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }

        cve_uuid = db.insert_cve(cve_record)
        if cve_uuid is None:
            logger.error(f"Insert failed for {cve_id} — skipping remaining steps for this CVE")
            failed += 1
            continue

        # Steps 4 & 5: Upsert software rows, then link to CVE
        for sw in affected_software:
            software_id = db.upsert_software(sw["vendor"], sw["product"], sw["ecosystem"])
            if software_id:
                db.insert_affected_software(
                    cve_uuid,
                    software_id,
                    sw.get("version_start"),
                    sw.get("version_end"),
                    sw.get("fixed_version"),
                )

        # Step 6: Insert references
        db.insert_references(cve_uuid, references)

        # Steps 7 & 8: Generate AI insights (skip if already present)
        if not db.ai_insights_exist(cve_uuid):
            insights = ai_processor.generate_insights(
                cve_id=cve_id,
                description=description,
                cvss_score=metrics["cvss_score"],
                severity=metrics["severity"],
                attack_vector=metrics["attack_vector"],
            )
            if insights:
                db.insert_ai_insights(cve_uuid, insights)
            else:
                logger.warning(f"AI insights unavailable for {cve_id} — CVE still inserted")

        # Step 9: Compute and store CVE relations by shared software
        related_uuids = db.get_cves_sharing_software(cve_uuid)
        if related_uuids:
            db.insert_cve_relations(cve_uuid, related_uuids, "same_software")
            logger.debug(f"{cve_id} linked to {len(related_uuids)} related CVE(s)")

        inserted += 1
        logger.info(f"[{inserted}] Inserted {cve_id}")

    # Step 10: Final summary
    logger.info("=== Pipeline complete ===")
    logger.info(f"  Fetched  : {total_fetched}")
    logger.info(f"  Inserted : {inserted}")
    logger.info(f"  Skipped  : {skipped}")
    logger.info(f"  Failed   : {failed}")


if __name__ == "__main__":
    run_pipeline()
