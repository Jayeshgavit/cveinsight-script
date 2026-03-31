import json
import logging
import os
import time
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

import db
import fetcher
from utils import (
    parse_affected_software,
    parse_cvss_metrics,
    parse_description,
    parse_references,
    setup_logging,
)

STATE_FILE = "backfill_state.json"

def load_state() -> int:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                data = json.load(f)
                return data.get("current_index", 0)
        except Exception:
            return 0
    return 0

def save_state(index: int, total: int):
    with open(STATE_FILE, "w") as f:
        json.dump({"current_index": index, "total_results": total, "last_updated": datetime.now(timezone.utc).isoformat()}, f)

def run_backfill() -> None:
    logger = setup_logging()
    logger.info("=== Historical CVE Backfill Started ===")
    
    start_index = load_state()
    logger.info(f"Resuming backfill from startIndex={start_index}")
    
    while True:
        logger.info(f"\n--- Fetching chunk starting at {start_index} ---")
        raw_cves, total_results = fetcher.fetch_cves_historical(start_index)
        
        if not raw_cves:
            logger.error("Failed to fetch chunk or reached end. Stopping backfill.")
            break
            
        total_fetched = len(raw_cves)
        logger.info(f"Fetched {total_fetched} CVEs. (Total NVD DB size: {total_results})")

        # Check existing to save time (though historical assumes mostly new if resuming)
        all_cve_ids = [c.get("id") for c in raw_cves if c.get("id")]
        existing_ids = db.get_existing_cve_ids(all_cve_ids)
        
        fetched_at = datetime.now(timezone.utc).isoformat()
        cve_records = []
        all_software = []
        all_ref_rows = []
        cve_software_map = {}

        skipped = 0
        failed = 0

        for cve in raw_cves:
            cve_id = cve.get("id")
            if not cve_id:
                failed += 1
                continue

            if cve_id in existing_ids:
                skipped += 1
                continue

            description = parse_description(cve)
            metrics = parse_cvss_metrics(cve)
            affected_software = parse_affected_software(cve)

            published = cve.get("published", "")[:10] or None
            last_modified = cve.get("lastModified", "")[:10] or None

            cve_records.append({
                "cve_id": cve_id,
                "title": cve_id,
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
                "fetched_at": fetched_at,
            })

            cve_software_map[cve_id] = affected_software
            all_software.extend(affected_software)
            cve_software_map[cve_id + "__refs"] = parse_references(cve)

        new_count = len(cve_records)
        logger.info(f"Parsed {new_count} new CVEs (skipped {skipped} existing).")

        if new_count > 0:
            uuid_map = db.insert_cves_batch(cve_records)
            inserted = len(uuid_map)
            logger.info(f"Inserted {inserted} CVE records into DB.")

            sw_id_map = db.upsert_software_bulk(all_software)

            affected_rows = []
            for cve_id, uuid in uuid_map.items():
                for sw in cve_software_map.get(cve_id, []):
                    key = f"{sw['vendor']}|{sw['product']}"
                    if key in sw_id_map:
                        affected_rows.append({
                            "cve_id": uuid,
                            "software_id": sw_id_map[key],
                            "version_start": sw.get("version_start"),
                            "version_end": sw.get("version_end"),
                            "fixed_version": sw.get("fixed_version"),
                            "status": "affected",
                        })

                for ref in cve_software_map.get(cve_id + "__refs", []):
                    all_ref_rows.append({"cve_id": uuid, **ref})

            if affected_rows:
                db.insert_affected_software_bulk(affected_rows)
            if all_ref_rows:
                db.insert_references_bulk(all_ref_rows)

        # Update and save state
        start_index += total_fetched
        save_state(start_index, total_results)
        logger.info(f"State saved. Next startIndex: {start_index}")

        if start_index >= total_results:
            logger.info("=== Backfill Complete! ===")
            break
            
        logger.info("Sleeping 2 seconds before next page to respect NVD limits...")
        time.sleep(2)

if __name__ == "__main__":
    run_backfill()
