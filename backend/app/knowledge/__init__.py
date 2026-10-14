"""
ReconIQ Knowledge Package

Repository for security taxonomies, severity scales, MITRE ATT&CK technique references,
and CWE weakness mappings. Risk rules reference these by ID so every finding carries
framework context in reports and STIX exports.
"""

from app.knowledge.severity import SeverityLevel
from app.knowledge.taxonomy import ThreatCategory, describe as describe_category
from app.knowledge.mitre_attack import get_technique, resolve_techniques
from app.knowledge.cwe import get_cwe, resolve_cwes

__all__ = [
    "SeverityLevel", "ThreatCategory", "describe_category",
    "get_technique", "resolve_techniques", "get_cwe", "resolve_cwes",
]
