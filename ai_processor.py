import json
import logging
import os

import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("cveinsight")

_model = None


def _get_model():
    global _model
    if _model is None:
        genai.configure(api_key=os.environ["GEMINI_API_KEY"])
        _model = genai.GenerativeModel("gemini-1.5-flash")
    return _model


def generate_insights(
    cve_id: str,
    description: str,
    cvss_score,
    severity: str | None,
    attack_vector: str | None,
) -> dict | None:
    """
    Send CVE data to Gemini and return parsed insights dict, or None on failure.
    Never raises — caller inserts CVE regardless of AI outcome.
    """
    prompt = f"""You are a cybersecurity expert. Given this CVE data, respond ONLY in JSON.

CVE ID: {cve_id}
Description: {description}
CVSS Score: {cvss_score}
Severity: {severity}
Attack Vector: {attack_vector}

Return exactly this JSON structure:
{{
  "plain_english": "2-3 sentence explanation a developer can understand",
  "fix_steps": "numbered steps to fix or mitigate this vulnerability",
  "risk_summary": "one sentence: who is at risk and how serious"
}}"""

    try:
        response = _get_model().generate_content(prompt)
        text = response.text.strip()

        # Strip markdown code fences if Gemini wraps output in ```json ... ```
        if text.startswith("```"):
            parts = text.split("```")
            text = parts[1] if len(parts) > 1 else text
            if text.startswith("json"):
                text = text[4:]
            text = text.strip()

        return json.loads(text)

    except json.JSONDecodeError as e:
        logger.error(f"Gemini returned invalid JSON for {cve_id}: {e}")
        return None
    except Exception as e:
        logger.error(f"Gemini failed for {cve_id}: {e}")
        return None
