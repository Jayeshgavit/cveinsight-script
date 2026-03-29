import logging
import os
import time
from datetime import datetime, timedelta, timezone

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("cveinsight")

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000


def _headers() -> dict:
    api_key = os.environ.get("NVD_API_KEY")
    return {"apiKey": api_key} if api_key else {}


def fetch_cves(days: int = 7) -> list:
    """Fetch CVEs published in the last `days` days from NVD. Returns list of raw cve dicts."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    pub_start = start.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = end.strftime("%Y-%m-%dT%H:%M:%S.000")

    logger.info(f"Fetching CVEs published between {pub_start} and {pub_end}")

    all_cves = []
    start_index = 0
    headers = _headers()

    with httpx.Client(timeout=60.0) as client:
        while True:
            params = {
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "resultsPerPage": RESULTS_PER_PAGE,
                "startIndex": start_index,
            }
            logger.info(f"NVD request: startIndex={start_index}")

            response = _get_with_retry(client, params, headers)
            if response is None:
                break

            data = response.json()
            total = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            for item in vulnerabilities:
                all_cves.append(item["cve"])

            logger.info(f"Progress: {len(all_cves)}/{total} CVEs")

            if start_index + RESULTS_PER_PAGE >= total:
                break

            start_index += RESULTS_PER_PAGE
            time.sleep(1)  # respect NVD rate limits between pages

    logger.info(f"Fetch complete — {len(all_cves)} total CVEs retrieved")
    return all_cves


def _get_with_retry(client: httpx.Client, params: dict, headers: dict):
    try:
        response = client.get(NVD_BASE_URL, params=params, headers=headers)
    except httpx.RequestError as e:
        logger.error(f"NVD request error: {e}")
        return None

    if response.status_code == 200:
        return response

    if response.status_code == 403:
        logger.error("NVD returned 403 — invalid or missing API key. Stopping pipeline.")
        raise SystemExit(1)

    if response.status_code == 503:
        logger.warning("NVD returned 503 — waiting 60s and retrying once")
        time.sleep(60)
        try:
            retry = client.get(NVD_BASE_URL, params=params, headers=headers)
            if retry.status_code == 200:
                return retry
            logger.error(f"NVD retry failed with status {retry.status_code}. Skipping page.")
        except httpx.RequestError as e:
            logger.error(f"NVD retry request error: {e}")
        return None

    logger.error(f"NVD unexpected status {response.status_code}. Skipping page.")
    return None
