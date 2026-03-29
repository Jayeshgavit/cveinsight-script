import logging
import sys


def setup_logging() -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    return logging.getLogger("cveinsight")


def parse_description(cve: dict) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def parse_cvss_metrics(cve: dict) -> dict:
    metrics = cve.get("metrics", {})

    # Prefer CVSSv3.1, then v3.0, then v2
    for key in ["cvssMetricV31", "cvssMetricV30"]:
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            return {
                "cvss_score": data.get("baseScore"),
                "severity": data.get("baseSeverity"),
                "cvss_vector": data.get("vectorString"),
                "attack_vector": data.get("attackVector"),
                "attack_complexity": data.get("attackComplexity"),
                "privileges_required": data.get("privilegesRequired"),
                "user_interaction": data.get("userInteraction"),
            }

    if metrics.get("cvssMetricV2"):
        entry = metrics["cvssMetricV2"][0]
        data = entry.get("cvssData", {})
        return {
            "cvss_score": data.get("baseScore"),
            "severity": entry.get("baseSeverity"),
            "cvss_vector": data.get("vectorString"),
            "attack_vector": data.get("accessVector"),
            "attack_complexity": data.get("accessComplexity"),
            "privileges_required": None,
            "user_interaction": None,
        }

    return {
        "cvss_score": None,
        "severity": "NONE",
        "cvss_vector": None,
        "attack_vector": None,
        "attack_complexity": None,
        "privileges_required": None,
        "user_interaction": None,
    }


def parse_references(cve: dict) -> list:
    refs = []
    for ref in cve.get("references", []):
        tags = ref.get("tags", [])
        refs.append({
            "url": ref.get("url", ""),
            "source": ref.get("source", ""),
            "tag": tags[0] if tags else None,
        })
    return refs


def parse_affected_software(cve: dict) -> list:
    software_list = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) < 5:
                    continue
                vendor = parts[3] if parts[3] != "*" else None
                product = parts[4] if parts[4] != "*" else None
                if not vendor or not product:
                    continue
                software_list.append({
                    "vendor": vendor,
                    "product": product,
                    "ecosystem": "NVD",
                    "version_start": (
                        match.get("versionStartIncluding")
                        or match.get("versionStartExcluding")
                    ),
                    "version_end": (
                        match.get("versionEndIncluding")
                        or match.get("versionEndExcluding")
                    ),
                    "fixed_version": None,
                })
    return software_list
