"""
ReconIQ MITRE ATT&CK Matrix Mappings

Purpose:
Maps evidence patterns and threat rules to official MITRE ATT&CK enterprise tactics & techniques.

Responsibilities:
- Provide a curated lookup of the techniques ReconIQ rules can evidence
- Resolve technique IDs into structured references for findings and reports
"""

from typing import Dict, List, Optional, Iterable

MITRE_ATTACK_MAPPINGS: Dict[str, Dict[str, str]] = {
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access"},
    "T1566.002": {"name": "Phishing: Spearphishing Link", "tactic": "Initial Access"},
    "T1566.004": {"name": "Phishing: Spearphishing Voice", "tactic": "Initial Access"},
    "T1598": {"name": "Phishing for Information", "tactic": "Reconnaissance"},
    "T1598.003": {"name": "Phishing for Information: Spearphishing Link", "tactic": "Reconnaissance"},
    "T1583.001": {"name": "Acquire Infrastructure: Domains", "tactic": "Resource Development"},
    "T1583.003": {"name": "Acquire Infrastructure: Virtual Private Server", "tactic": "Resource Development"},
    "T1584": {"name": "Compromise Infrastructure", "tactic": "Resource Development"},
    "T1608.005": {"name": "Stage Capabilities: Link Target", "tactic": "Resource Development"},
    "T1656": {"name": "Impersonation", "tactic": "Defense Evasion"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1027.015": {"name": "Obfuscated Files or Information: Compression", "tactic": "Defense Evasion"},
    "T1059.005": {"name": "Command and Scripting Interpreter: Visual Basic", "tactic": "Execution"},
    "T1137": {"name": "Office Application Startup", "tactic": "Persistence"},
    "T1204.001": {"name": "User Execution: Malicious Link", "tactic": "Execution"},
    "T1204.002": {"name": "User Execution: Malicious File", "tactic": "Execution"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
    "T1571": {"name": "Non-Standard Port", "tactic": "Command and Control"},
    "T1090": {"name": "Proxy", "tactic": "Command and Control"},
    "T1056.003": {"name": "Input Capture: Web Portal Capture", "tactic": "Credential Access"},
    "T1476": {"name": "Deliver Malicious App via Other Means (Mobile)", "tactic": "Initial Access"},
}


def technique_url(technique_id: str) -> str:
    """Returns the attack.mitre.org URL for a technique or sub-technique."""
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def get_technique(technique_id: str) -> Optional[Dict[str, str]]:
    """Returns a structured technique reference, or None when unknown."""
    entry = MITRE_ATTACK_MAPPINGS.get(technique_id)
    if not entry:
        return None
    return {"id": technique_id, "name": entry["name"], "tactic": entry["tactic"], "url": technique_url(technique_id)}


def resolve_techniques(technique_ids: Iterable[str]) -> List[Dict[str, str]]:
    """Resolves technique IDs into references, de-duplicated and in input order."""
    seen = set()
    resolved = []
    for tid in technique_ids:
        if tid in seen:
            continue
        seen.add(tid)
        ref = get_technique(tid)
        if ref:
            resolved.append(ref)
    return resolved
