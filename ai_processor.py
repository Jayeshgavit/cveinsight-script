import json
import logging
import os
import time

from dotenv import load_dotenv
from openai import OpenAI, RateLimitError, AuthenticationError

load_dotenv()

logger = logging.getLogger("cveinsight")

# ── Provider configuration ───────────────────────────────────────────────────
# Chain: Groq (primary) → Gemini (fallback 1) → OpenAI (fallback 2)

GROQ_MODEL   = "llama-3.3-70b-versatile"
GEMINI_MODEL = "gemini-2.5-flash"
OPENAI_MODEL = "gpt-4o-mini"

GEMINI_RETRIES = 3
GEMINI_BACKOFF = 10   # seconds per retry
OPENAI_RETRIES = 3
OPENAI_BACKOFF = 10   # seconds per retry

_PROVIDER_ORDER  = ["groq", "gemini", "openai"]
_PROVIDER_MODELS = {
    "groq":   GROQ_MODEL,
    "gemini": GEMINI_MODEL,
    "openai": OPENAI_MODEL,
}

_groq_client      = None
_gemini_client    = None
_openai_client    = None
_active_provider  = "groq"
_disabled_providers: set = set()   # providers permanently skipped due to auth errors


# ── Client getters ───────────────────────────────────────────────────────────

def _get_groq_client() -> OpenAI | None:
    global _groq_client
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        logger.warning("GROQ_API_KEY not set — Groq provider unavailable")
        return None
    if _groq_client is None:
        _groq_client = OpenAI(
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1",
        )
    return _groq_client


def _get_gemini_client():
    global _gemini_client
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        logger.warning("GEMINI_API_KEY not set — Gemini provider unavailable")
        return None
    if _gemini_client is None:
        from google import genai
        _gemini_client = genai.Client(api_key=api_key)
    return _gemini_client


def _get_openai_client() -> OpenAI | None:
    global _openai_client
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        logger.warning("OPENAI_API_KEY not set — OpenAI provider unavailable")
        return None
    if _openai_client is None:
        _openai_client = OpenAI(api_key=api_key)
    return _openai_client


# ── Shared helpers ───────────────────────────────────────────────────────────

def _build_prompt(cves: list) -> str:
    """Build the shared prompt for all providers."""
    cve_blocks = []
    for c in cves:
        cve_blocks.append(
            f'  {{"cve_id": "{c["cve_id"]}", "description": {json.dumps(c.get("description") or "")}, '
            f'"cvss_score": {json.dumps(c.get("cvss_score"))}, '
            f'"severity": {json.dumps(c.get("severity"))}, '
            f'"attack_vector": {json.dumps(c.get("attack_vector"))}}}'
        )

    return f"""You are a cybersecurity expert. I will give you {len(cves)} CVEs.
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


def _parse_response(text: str) -> dict:
    """Parse the LLM response text into {cve_id: insights_dict}."""
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


# ── Provider call functions ──────────────────────────────────────────────────

def _call_groq(prompt: str) -> dict | None:
    """Try Groq. Returns None immediately on rate-limit to trigger next fallback."""
    client = _get_groq_client()
    if not client:
        return None

    try:
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=2048,
        )
        text = response.choices[0].message.content.strip()
        return _parse_response(text)

    except json.JSONDecodeError as e:
        logger.error(f"[Groq] Invalid JSON response: {e}")
        return None

    except AuthenticationError:
        logger.error("[Groq] Invalid API key (401) — disabling Groq for this run")
        _disabled_providers.add("groq")
        return None

    except RateLimitError:
        logger.warning("[Groq] 429 Rate Limited — switching to next provider")
        return None

    except Exception as e:
        logger.error(f"[Groq] Failed: {e}")
        return None


def _call_gemini(prompt: str) -> dict | None:
    """Try Gemini. Retries on rate-limits with backoff."""
    client = _get_gemini_client()
    if not client:
        return None

    for attempt in range(GEMINI_RETRIES):
        try:
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
            )
            text = response.text.strip()
            return _parse_response(text)

        except json.JSONDecodeError as e:
            logger.error(f"[Gemini] Invalid JSON response: {e}")
            return None

        except Exception as e:
            err_str = str(e).lower()
            if "401" in err_str or "invalid_api_key" in err_str or "api_key_invalid" in err_str:
                logger.error("[Gemini] Invalid API key (401) — disabling Gemini for this run")
                _disabled_providers.add("gemini")
                return None
            if "429" in err_str or "resource_exhausted" in err_str or "rate" in err_str:
                wait = GEMINI_BACKOFF * (attempt + 1)
                logger.warning(f"[Gemini] Rate limited — waiting {wait}s (attempt {attempt + 1}/{GEMINI_RETRIES})")
                time.sleep(wait)
                continue
            logger.error(f"[Gemini] Failed: {e}")
            return None

    logger.warning("[Gemini] Rate limit retries exhausted — switching to next provider")
    return None


def _call_openai(prompt: str) -> dict | None:
    """Try OpenAI. Retries on rate-limits with backoff."""
    client = _get_openai_client()
    if not client:
        return None

    for attempt in range(OPENAI_RETRIES):
        try:
            response = client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=2048,
            )
            text = response.choices[0].message.content.strip()
            return _parse_response(text)

        except json.JSONDecodeError as e:
            logger.error(f"[OpenAI] Invalid JSON response: {e}")
            return None

        except AuthenticationError:
            logger.error("[OpenAI] Invalid API key (401) — disabling OpenAI for this run")
            _disabled_providers.add("openai")
            return None

        except RateLimitError:
            wait = OPENAI_BACKOFF * (attempt + 1)
            logger.warning(f"[OpenAI] Rate limited — waiting {wait}s (attempt {attempt + 1}/{OPENAI_RETRIES})")
            time.sleep(wait)
            continue

        except Exception as e:
            logger.error(f"[OpenAI] Failed: {e}")
            return None

    logger.warning("[OpenAI] Rate limit retries exhausted — all providers failed")
    return None


def _call_provider(provider: str, prompt: str) -> dict | None:
    if provider == "groq":
        return _call_groq(prompt)
    elif provider == "gemini":
        return _call_gemini(prompt)
    elif provider == "openai":
        return _call_openai(prompt)
    return None


# ── Public API ───────────────────────────────────────────────────────────────

def generate_insights_batch(cves: list) -> tuple[dict, str]:
    """
    Send up to AI_BATCH CVEs in ONE API call.
    Tries providers in order starting from _active_provider:
      Groq → Gemini → OpenAI → (back to Groq next call)

    Returns (results_dict, model_used).
    """
    global _active_provider

    if not cves:
        return {}, GROQ_MODEL

    prompt = _build_prompt(cves)

    # Rotate provider list so active provider is tried first, skip disabled ones
    start = _PROVIDER_ORDER.index(_active_provider)
    rotation = [p for p in (_PROVIDER_ORDER[start:] + _PROVIDER_ORDER[:start])
                if p not in _disabled_providers]

    if not rotation:
        logger.error("All providers are disabled (invalid API keys) — cannot process batch")
        return {}, GROQ_MODEL

    for i, provider in enumerate(rotation):
        result = _call_provider(provider, prompt)
        if result is not None:
            _active_provider = provider
            return result, _PROVIDER_MODELS[provider]

        # Log the switch before trying next
        if i < len(rotation) - 1:
            next_p = rotation[i + 1]
            logger.info(f"[Fallback] {provider} failed — trying {next_p}")
            _active_provider = next_p

    logger.error("All providers (Groq, Gemini, OpenAI) failed for this batch")
    return {}, _PROVIDER_MODELS[_active_provider]


def reset_to_groq():
    """Reset the active provider back to Groq (call between pipeline runs)."""
    global _active_provider
    _active_provider = "groq"


def generate_insights(
    cve_id: str,
    description: str,
    cvss_score,
    severity: str | None,
    attack_vector: str | None,
) -> dict | None:
    """Single CVE wrapper — used by main.py for small new-CVE batches."""
    results, _ = generate_insights_batch([{
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "severity": severity,
        "attack_vector": attack_vector,
    }])
    return results.get(cve_id)
