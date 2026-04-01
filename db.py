import logging
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

logger = logging.getLogger("cveinsight")

CHUNK_SIZE = 500  # rows per batch insert

_client: Client = None


def get_client() -> Client:
    global _client
    if _client is None:
        url = os.environ["SUPABASE_URL"]
        key = os.environ["SUPABASE_SERVICE_KEY"]
        _client = create_client(url, key)
    return _client


def is_first_run() -> bool:
    result = get_client().table("cves").select("id").limit(1).execute()
    return len(result.data) == 0


def get_existing_cve_ids(cve_ids: list) -> set:
    """
    1 DB query per 500 IDs — returns set of cve_id strings already in DB.
    Handles any number of IDs by chunking.
    """
    if not cve_ids:
        return set()
    existing = set()
    for i in range(0, len(cve_ids), CHUNK_SIZE):
        chunk = cve_ids[i: i + CHUNK_SIZE]
        try:
            result = get_client().table("cves").select("cve_id").in_("cve_id", chunk).execute()
            existing.update(row["cve_id"] for row in result.data)
        except Exception as e:
            logger.error(f"Failed to batch check existing CVE IDs (chunk {i}): {e}")
    return existing


def insert_cves_batch(records: list) -> dict:
    """
    Bulk insert CVE records in chunks of CHUNK_SIZE.
    Returns {cve_id: uuid} map for all successfully inserted rows.
    Skips duplicates silently (already filtered before calling this).
    """
    uuid_map = {}
    for i in range(0, len(records), CHUNK_SIZE):
        chunk = records[i: i + CHUNK_SIZE]
        try:
            result = get_client().table("cves").insert(chunk).execute()
            for row in result.data:
                uuid_map[row["cve_id"]] = row["id"]
            logger.info(f"CVEs inserted: {len(uuid_map)}/{len(records)}")
        except Exception as e:
            logger.error(f"Failed to bulk insert CVE chunk {i}–{i + len(chunk)}: {e}")
    return uuid_map


def upsert_software_bulk(software_list: list) -> dict:
    """
    Bulk upsert all unique software rows in chunks.
    Returns {vendor|product: id} map.
    """
    if not software_list:
        return {}
    # Deduplicate before sending
    seen = set()
    unique_rows = []
    for s in software_list:
        key = f"{s['vendor']}|{s['product']}"
        if key not in seen:
            seen.add(key)
            unique_rows.append({"vendor": s["vendor"], "product": s["product"], "ecosystem": s["ecosystem"]})

    id_map = {}
    for i in range(0, len(unique_rows), CHUNK_SIZE):
        chunk = unique_rows[i: i + CHUNK_SIZE]
        try:
            result = (
                get_client()
                .table("software")
                .upsert(chunk, on_conflict="vendor,product")
                .execute()
            )
            for r in result.data:
                id_map[f"{r['vendor']}|{r['product']}"] = r["id"]
        except Exception as e:
            logger.error(f"Failed to bulk upsert software chunk {i}: {e}")
    return id_map


def insert_affected_software_bulk(rows: list) -> None:
    """Bulk insert cve_affected_software rows in chunks."""
    for i in range(0, len(rows), CHUNK_SIZE):
        chunk = rows[i: i + CHUNK_SIZE]
        try:
            get_client().table("cve_affected_software").insert(chunk).execute()
        except Exception as e:
            logger.error(f"Failed to bulk insert affected software chunk {i}: {e}")


def insert_references_bulk(rows: list) -> None:
    """Bulk insert cve_references rows in chunks."""
    for i in range(0, len(rows), CHUNK_SIZE):
        chunk = rows[i: i + CHUNK_SIZE]
        try:
            get_client().table("cve_references").insert(chunk).execute()
        except Exception as e:
            logger.error(f"Failed to bulk insert references chunk {i}: {e}")


# ── AI insights helpers ──────────────────────────────────────────────────────

def get_all_insight_cve_ids() -> set:
    """Return set of all cve UUIDs that already have AI insights. Paginated for large tables."""
    done = set()
    offset = 0
    while True:
        result = (
            get_client()
            .table("cve_ai_insights")
            .select("cve_id")
            .limit(1000)
            .offset(offset)
            .execute()
        )
        for row in result.data:
            done.add(row["cve_id"])
        if len(result.data) < 1000:
            break
        offset += 1000
    return done


def get_cves_for_year(year: int, batch_size: int = 50, offset: int = 0) -> list:
    """Fetch a page of CVEs for a year, ordered newest first. Filtering is done client-side in ai_step."""
    result = (
        get_client()
        .table("cves")
        .select("id, cve_id, description, cvss_score, severity, attack_vector")
        .gte("published_at", f"{year}-01-01")
        .lte("published_at", f"{year}-12-31")
        .order("published_at", desc=True)
        .limit(batch_size)
        .offset(offset)
        .execute()
    )
    return result.data


# ── kept for single-CVE operations ───────────────────────────────────────────

def cve_exists(cve_id: str) -> bool:
    result = get_client().table("cves").select("id").eq("cve_id", cve_id).execute()
    return len(result.data) > 0


def insert_cve(cve_data: dict) -> str | None:
    try:
        result = get_client().table("cves").insert(cve_data).execute()
        return result.data[0]["id"]
    except Exception as e:
        logger.error(f"Failed to insert CVE {cve_data.get('cve_id')}: {e}")
        return None


def ai_insights_exist(cve_uuid: str) -> bool:
    result = (
        get_client().table("cve_ai_insights").select("id").eq("cve_id", cve_uuid).execute()
    )
    return len(result.data) > 0


def insert_ai_insights(cve_uuid: str, insights: dict, model_used: str = "llama-3.3-70b-versatile") -> None:
    try:
        get_client().table("cve_ai_insights").insert({
            "cve_id": cve_uuid,
            "plain_english": insights.get("plain_english"),
            "fix_steps": insights.get("fix_steps"),
            "risk_summary": insights.get("risk_summary"),
            "model_used": model_used,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as e:
        logger.error(f"Failed to insert AI insights for CVE {cve_uuid}: {e}")


def get_cves_sharing_software(cve_uuid: str) -> list:
    try:
        sw_result = (
            get_client()
            .table("cve_affected_software")
            .select("software_id")
            .eq("cve_id", cve_uuid)
            .execute()
        )
        software_ids = [row["software_id"] for row in sw_result.data]
        if not software_ids:
            return []
        rel_result = (
            get_client()
            .table("cve_affected_software")
            .select("cve_id")
            .in_("software_id", software_ids)
            .neq("cve_id", cve_uuid)
            .execute()
        )
        return list({row["cve_id"] for row in rel_result.data})
    except Exception as e:
        logger.error(f"Failed to get related CVEs for {cve_uuid}: {e}")
        return []


def insert_cve_relations(cve_uuid: str, related_uuids: list, relation_type: str) -> None:
    rows = [
        {"cve_id": cve_uuid, "related_cve_id": rel_id, "relation_type": relation_type}
        for rel_id in related_uuids
        if rel_id != cve_uuid
    ]
    if not rows:
        return
    try:
        get_client().table("cve_relations").upsert(
            rows, on_conflict="cve_id,related_cve_id"
        ).execute()
    except Exception as e:
        logger.error(f"Failed to insert CVE relations for {cve_uuid}: {e}")
