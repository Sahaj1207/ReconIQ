"""
Helpers shared by report renderers.
"""

from typing import Any, Dict, List, Tuple

CATEGORY_LABELS = {
    "urls": "URL", "domains": "Domain", "ipv4": "IPv4", "ipv6": "IPv6",
    "emails": "Email", "phone_numbers": "Phone", "hashes": "Hash",
}
CATEGORY_ORDER = ["urls", "domains", "ipv4", "ipv6", "emails", "hashes", "phone_numbers"]


def defang(value: str) -> str:
    """Defangs an indicator for safe inclusion in human-readable reports."""
    out = value.replace("http", "hxxp", 1) if value.lower().startswith("http") else value
    return out.replace(".", "[.]").replace("@", "[at]")


def indicator_rows(result: Dict[str, Any]) -> List[Tuple[str, str, str, str]]:
    """(category label, value, validation note, intel summary) rows for every indicator."""
    evidence = result.get("normalized_evidence") or result.get("evidence") or {}
    validations = result.get("validation_results") or {}
    intel = result.get("threat_intelligence") or {}
    rows = []
    for cat in CATEGORY_ORDER:
        for value in evidence.get(cat, []):
            v = next((x for x in validations.get(cat, []) if x.get("artifact") == value), None)
            valid = "valid" if v is None or v.get("valid") else "invalid"
            hits = [r for r in intel.get(cat, []) if r.get("artifact") == value]
            flagged = [f"{r['provider']}: {len(r.get('threat_indicators', []))} flag(s)" for r in hits if r.get("threat_indicators")]
            summary = "; ".join(flagged) or ("no detections" if any(r.get("status") == "SUCCESS" for r in hits) else
                                             "not looked up" if not hits else "lookup unavailable")
            rows.append((CATEGORY_LABELS.get(cat, cat), value, valid, summary))
    return rows


def matched_rules(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [r for r in (result.get("risk_assessment") or {}).get("applied_rules", []) if r.get("matched")]
