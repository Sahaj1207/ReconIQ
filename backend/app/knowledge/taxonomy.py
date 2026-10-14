"""
ReconIQ Threat Taxonomy Framework

Purpose:
Standardized taxonomy definitions for categorizing cybersecurity threats and scam attacks.
"""

from enum import Enum
from typing import Dict, Iterable, List


class ThreatCategory(str, Enum):
    """Standardized threat categories."""
    PHISHING_EMAIL = "phishing_email"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    BRAND_IMPERSONATION = "brand_impersonation"
    MALWARE_DISTRIBUTION = "malware_distribution"
    FINANCIAL_SCAM = "financial_scam"
    TECH_SUPPORT_FRAUD = "tech_support_fraud"
    QR_PHISHING = "qr_phishing"
    MOBILE_MALWARE = "mobile_malware"
    EMAIL_SPOOFING = "email_spoofing"
    SUSPICIOUS_INFRASTRUCTURE = "suspicious_infrastructure"
    COMMAND_AND_CONTROL = "command_and_control"
    UNKNOWN = "unknown"


CATEGORY_DESCRIPTIONS: Dict[ThreatCategory, str] = {
    ThreatCategory.PHISHING_EMAIL: "Deceptive message designed to lure the recipient into an unsafe action.",
    ThreatCategory.CREDENTIAL_HARVESTING: "Attempt to collect usernames, passwords or one-time codes.",
    ThreatCategory.BRAND_IMPERSONATION: "Infrastructure or content imitating a trusted brand.",
    ThreatCategory.MALWARE_DISTRIBUTION: "Delivery of executable or otherwise malicious payloads.",
    ThreatCategory.FINANCIAL_SCAM: "Fraud seeking payments, gift cards, crypto or banking details.",
    ThreatCategory.TECH_SUPPORT_FRAUD: "Fake support lure pushing a call-back number or remote access.",
    ThreatCategory.QR_PHISHING: "QR code used to move the victim to an unmanaged device or hidden URL.",
    ThreatCategory.MOBILE_MALWARE: "Android package or mobile payload with dangerous capabilities.",
    ThreatCategory.EMAIL_SPOOFING: "Sender identity forged or failing authentication checks.",
    ThreatCategory.SUSPICIOUS_INFRASTRUCTURE: "Hosts, domains or addresses with risky characteristics.",
    ThreatCategory.COMMAND_AND_CONTROL: "Infrastructure used to control compromised systems.",
    ThreatCategory.UNKNOWN: "No specific threat category could be established.",
}


def describe(category: str) -> str:
    try:
        return CATEGORY_DESCRIPTIONS[ThreatCategory(category)]
    except ValueError:
        return CATEGORY_DESCRIPTIONS[ThreatCategory.UNKNOWN]


# Catch-all categories only lead the classification when nothing more specific is evidenced.
GENERIC_CATEGORIES = {ThreatCategory.SUSPICIOUS_INFRASTRUCTURE.value, ThreatCategory.UNKNOWN.value}


def rank_categories(weighted: Dict[str, float]) -> List[str]:
    """Orders categories: specific before generic, then by accumulated weight (desc), then name."""
    return [c for c, _ in sorted(weighted.items(), key=lambda kv: (kv[0] in GENERIC_CATEGORIES, -kv[1], kv[0]))]


def labels(categories: Iterable[str]) -> List[str]:
    return [c.replace("_", " ").title() for c in categories]
