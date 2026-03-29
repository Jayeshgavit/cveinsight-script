import logging
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

logger = logging.getLogger("cveinsight")

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


def cve_exists(cve_id: str) -> bool:
    result = get_client().table("cves").select("id").eq("cve_id", cve_id).execute()
    return len(result.data) > 0


def insert_cve(cve_data: dict) -> str | None:
    """Insert a CVE row and return its uuid, or None on failure."""
    try:
        result = get_client().table("cves").insert(cve_data).execute()
        return result.data[0]["id"]
    except Exception as e:
        logger.error(f"Failed to insert CVE {cve_data.get('cve_id')}: {e}")
        return None


def upsert_software(vendor: str, product: str, ecosystem: str) -> str | None:
    """Upsert a software row and return its uuid."""
    try:
        result = (
            get_client()
            .table("software")
            .upsert(
                {"vendor": vendor, "product": product, "ecosystem": ecosystem},
                on_conflict="vendor,product",
            )
            .execute()
        )
        return result.data[0]["id"]
    except Exception as e:
        logger.error(f"Failed to upsert software {vendor}/{product}: {e}")
        return None


def insert_affected_software(
    cve_uuid: str,
    software_id: str,
    version_start: str | None,
    version_end: str | None,
    fixed_version: str | None,
) -> None:
    try:
        get_client().table("cve_affected_software").insert({
            "cve_id": cve_uuid,
            "software_id": software_id,
            "version_start": version_start,
            "version_end": version_end,
            "fixed_version": fixed_version,
            "status": "affected",
        }).execute()
    except Exception as e:
        logger.error(f"Failed to insert affected software for CVE {cve_uuid}: {e}")


def insert_references(cve_uuid: str, references: list) -> None:
    if not references:
        return
    rows = [{"cve_id": cve_uuid, **ref} for ref in references]
    try:
        get_client().table("cve_references").insert(rows).execute()
    except Exception as e:
        logger.error(f"Failed to insert references for CVE {cve_uuid}: {e}")


def ai_insights_exist(cve_uuid: str) -> bool:
    result = (
        get_client().table("cve_ai_insights").select("id").eq("cve_id", cve_uuid).execute()
    )
    return len(result.data) > 0


def insert_ai_insights(cve_uuid: str, insights: dict) -> None:
    try:
        get_client().table("cve_ai_insights").insert({
            "cve_id": cve_uuid,
            "plain_english": insights.get("plain_english"),
            "fix_steps": insights.get("fix_steps"),
            "risk_summary": insights.get("risk_summary"),
            "model_used": "gemini-1.5-flash",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as e:
        logger.error(f"Failed to insert AI insights for CVE {cve_uuid}: {e}")


def get_cves_sharing_software(cve_uuid: str) -> list:
    """Return uuids of other CVEs that share affected software with this CVE."""
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
