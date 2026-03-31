import json
import logging
import os
import time

from dotenv import load_dotenv
from openai import OpenAI, RateLimitError

load_dotenv()

logger = logging.getLogger("cveinsight")

_client = None
MODEL = "llama-3.3-70b-versatile"
MAX_RETRIES = 5
BASE_BACKOFF = 30  # seconds for first retry


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(
            api_key=os.environ["GROQ_API_KEY"],
            base_url="https://api.groq.com/openai/v1",
        )
    return _client


def _parse_retry_after(exc: RateLimitError) -> int:
    """Extract retry-after seconds from Groq 429 response headers."""
    try:
        after = exc.response.headers.get("retry-after")
        if after:
            return int(float(after)) + 2
    except Exception:
        pass
    # Fallback: scan error message for a number like "try again in 12.5s"
    for word in str(exc).split():
        try:
            val = float(word.rstrip("s.,"))
            if 1 < val < 300:
                return int(val) + 2
        except ValueError:
            continue
    return BASE_BACKOFF


def generate_insights_batch(cves: list) -> dict:
    """
    Send up to BATCH_SIZE CVEs in ONE API call. Returns {cve_id: insights_dict}.
    Any CVE that fails gets None in the result — never raises.
    """
    if not cves:
        return {}

    # Build a single prompt listing all CVEs
    cve_blocks = []
    for c in cves:
        cve_blocks.append(
            f'  {{"cve_id": "{c["cve_id"]}", "description": {json.dumps(c.get("description") or "")}, '
            f'"cvss_score": {json.dumps(c.get("cvss_score"))}, '
            f'"severity": {json.dumps(c.get("severity"))}, '
            f'"attack_vector": {json.dumps(c.get("attack_vector"))}}}'
        )

    prompt = f"""You are a cybersecurity expert. I will give you {len(cves)} CVEs.
Respond ONLY with a JSON array — one object per CVE, in the same order.

CVEs:
[
{chr(10).join(cve_blocks)}
]

Return a JSON array where each element has exactly these fields:
{{
  "cve_id": "the CVE ID from input",
  "plain_english": "2-3 sentence explanation a developer can understand",
  "fix_steps": "numbered steps to fix or mitigate this vulnerability",
  "risk_summary": "one sentence: who is at risk and how serious"
}}

Return ONLY the JSON array. No markdown, no explanation."""

    backoff = BASE_BACKOFF
    for attempt in range(MAX_RETRIES):
        try:
            response = _get_client().chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=2048,  # cap response to reduce token pressure
            )
            text = response.choices[0].message.content.strip()

            # Strip markdown fences
            if text.startswith("```"):
                parts = text.split("```")
                text = parts[1] if len(parts) > 1 else text
                if text.startswith("json"):
                    text = text[4:]
                text = text.strip()

            results = json.loads(text)
            if not isinstance(results, list):
                raise ValueError("Expected a JSON array")

            return {item["cve_id"]: item for item in results if "cve_id" in item}

        except json.JSONDecodeError as e:
            logger.error(f"Groq returned invalid JSON for batch: {e}")
            return {}

        except RateLimitError as e:
            wait = _parse_retry_after(e)
            logger.warning(f"Groq 429 — waiting {wait}s (attempt {attempt + 1}/{MAX_RETRIES})")
            time.sleep(wait)
            backoff = min(backoff * 2, 300)  # exponential backoff, cap at 5 min
            continue

        except Exception as e:
            logger.error(f"Groq batch failed: {e}")
            return {}

    logger.error(f"Groq batch abandoned after {MAX_RETRIES} retries")
    return {}


def generate_insights(
    cve_id: str,
    description: str,
    cvss_score,
    severity: str | None,
    attack_vector: str | None,
) -> dict | None:
    """Single CVE wrapper — used by main.py for small new-CVE batches."""
    results = generate_insights_batch([{
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "severity": severity,
        "attack_vector": attack_vector,
    }])
    return results.get(cve_id)
