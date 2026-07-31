"""
ReconIQ Threat Taxonomy Framework

Purpose:
Standardized taxonomy definitions for categorizing cybersecurity threats and scam attacks.

Responsibilities:
- Provide enterprise threat classification categories (e.g. Credential Harvesting, Brand Impersonation, Ransomware Distribution, Tech Support Fraud)

Future Implementation Notes:
- Standardized taxonomy alignment with NIST IR 8401 and ENISA threat taxonomies.

TODO:
- [ ] Implement full threat category enum and descriptions.
"""

from enum import Enum


class ThreatCategory(str, Enum):
    """Standardized threat categories."""
    PHISHING_EMAIL = "phishing_email"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    BRAND_IMPERSONATION = "brand_impersonation"
    MALWARE_DISTRIBUTION = "malware_distribution"
    FINANCIAL_SCAM = "financial_scam"
    SUSPICIOUS_INFRASTRUCTURE = "suspicious_infrastructure"
    UNKNOWN = "unknown"
