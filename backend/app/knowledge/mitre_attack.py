"""
ReconIQ MITRE ATT&CK Matrix Mappings

Purpose:
Maps evidence patterns and threat rules to official MITRE ATT&CK enterprise tactics & techniques.

Responsibilities:
- Provide lookup dictionary for technique IDs (e.g. T1566 Phishing, T1071 Application Layer Protocol, T1583 Acquire Infrastructure)

Future Implementation Notes:
- Dynamic ingestion of MITRE ATT&CK v14+ JSON data definitions.

TODO:
- [ ] Implement MITRE technique lookup helper functions.
"""

from typing import Dict, Any

# MITRE ATT&CK Sample Mappings (Placeholder)
MITRE_ATTACK_MAPPINGS: Dict[str, Dict[str, str]] = {
    "T1566.002": {
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/002/"
    },
    "T1583.001": {
        "name": "Acquire Infrastructure: Domains",
        "tactic": "Resource Development",
        "url": "https://attack.mitre.org/techniques/T1583/001/"
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/001/"
    }
}
