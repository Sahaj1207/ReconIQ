"""
ReconIQ CWE Mappings

Purpose:
Maps threat types to Common Weakness Enumeration (CWE) entries that the evidence exploits.
"""

from typing import Dict, List, Optional, Iterable

CWE_MAPPINGS: Dict[str, str] = {
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-290": "Authentication Bypass by Spoofing",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-451": "User Interface (UI) Misrepresentation of Critical Information",
    "CWE-601": "URL Redirection to Untrusted Site ('Open Redirect')",
    "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
    "CWE-494": "Download of Code Without Integrity Check",
    "CWE-506": "Embedded Malicious Code",
    "CWE-250": "Execution with Unnecessary Privileges",
}


def cwe_url(cwe_id: str) -> str:
    return f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[-1]}.html"


def get_cwe(cwe_id: str) -> Optional[Dict[str, str]]:
    """Returns a structured CWE reference, or None when unknown."""
    name = CWE_MAPPINGS.get(cwe_id)
    return {"id": cwe_id, "name": name, "url": cwe_url(cwe_id)} if name else None


def resolve_cwes(cwe_ids: Iterable[str]) -> List[Dict[str, str]]:
    seen = set()
    out = []
    for cid in cwe_ids:
        if cid not in seen and (ref := get_cwe(cid)):
            seen.add(cid)
            out.append(ref)
    return out
