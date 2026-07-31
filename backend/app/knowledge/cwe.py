"""
ReconIQ CWE Mappings

Purpose:
Maps threat types to Common Weakness Enumeration (CWE) entries.

Responsibilities:
- Provide CWE lookup reference (e.g. CWE-200 Exposure of Sensitive Information, CWE-290 Authentication Bypass)

Future Implementation Notes:
- Dynamic XML/JSON parsing of MITRE CWE dictionary.

TODO:
- [ ] Implement CWE dictionary lookups.
"""

from typing import Dict

CWE_MAPPINGS: Dict[str, str] = {
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-290": "Authentication Bypass by Spoofing",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
}
