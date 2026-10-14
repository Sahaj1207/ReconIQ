"""
ReconIQ Extended Deterministic Rule Library

Purpose:
Content, infrastructure, email-authentication, file and intel-context rules that complement the
core validation / intel / evidence rules in rules.py.

IMPORTANT:
Every rule is a fixed, explainable predicate over the assessment context. No ML or AI is used.

Context keys available to rules:
- evidence: normalized artifacts by category
- validation_results: ValidationResult objects (or dicts) by category
- intel_results: ThreatIntelResponse objects (or dicts) by category
- raw_text: analysed text content
- ingestion: analysis produced by file/email ingestion (see app/ingestion/parsers)
"""

import re
import urllib.parse
from typing import Any, Dict, List, Tuple

from app.risk_engine.models import RiskFinding
from app.risk_engine.rules import BaseRule
from app.risk_engine.weights import RiskWeights

RuleResult = Tuple[bool, List[RiskFinding], Dict[str, Any]]


def _get(item: Any, key: str, default: Any = None) -> Any:
    """Reads a field from either a Pydantic object or a plain dict."""
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def registrable_domain(host: str) -> str:
    """Approximates the registrable domain (eTLD+1), handling common two-level suffixes."""
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and labels[-2] in {"co", "com", "net", "org", "gov", "ac", "edu"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _hostnames(context: Dict[str, Any]) -> List[str]:
    """All hostnames seen in domains and URLs."""
    evidence = context.get("evidence", {})
    hosts = list(evidence.get("domains", []))
    for url in evidence.get("urls", []):
        host = urllib.parse.urlsplit(url).hostname
        if host:
            hosts.append(host.lower())
    return sorted(set(hosts))


class _Rule(BaseRule):
    """Small helper base that builds findings with consistent IDs."""

    def finding(self, title: str, description: str, artifact: Any = None) -> RiskFinding:
        return RiskFinding(
            finding_id=f"{self.id}_FINDING",
            title=title,
            description=description,
            severity=self.severity,
            score_impact=self.weight,
            artifact=artifact,
        )


# --- Content Rules ---

URGENCY_TERMS = [
    "urgent", "immediately", "within 24 hours", "within 48 hours", "suspended", "locked", "final notice",
    "act now", "expire", "unusual sign-in", "unusual activity", "permanently", "last warning", "deactivated",
]
CREDENTIAL_TERMS = [
    "verify your", "confirm your", "password", "log in", "login", "sign in", "credentials", "update your payment",
    "billing information", "social security", "one-time code", "verification code", "reset your", "validate your",
]
SCAM_TERMS = {
    "financial_scam": ["gift card", "wire transfer", "bitcoin", "crypto wallet", "payment overdue", "refund",
                       "invoice attached", "bank transfer", "western union", "you have won", "lottery", "inheritance"],
    "tech_support_fraud": ["virus detected", "your computer is infected", "call our support", "technical support",
                           "remote access", "anydesk", "teamviewer", "call immediately", "toll free"],
}


class CredentialPhishingLanguageRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_CNT_001", "Credential Phishing Language",
            "Text combines urgency pressure with requests to verify credentials or account details",
            RiskWeights.MEDIUM, "MEDIUM",
            categories=["phishing_email", "credential_harvesting"], mitre=["T1566.002", "T1598.003"], cwe=["CWE-451"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        text = context.get("raw_text", "").lower()
        urgency = [t for t in URGENCY_TERMS if t in text]
        credential = [t for t in CREDENTIAL_TERMS if t in text]
        if urgency and credential:
            return True, [self.finding(
                "Urgent Credential Request",
                f"Urgency cues ({', '.join(urgency[:3])}) paired with credential requests ({', '.join(credential[:3])})",
            )], {"urgency_terms": urgency, "credential_terms": credential}
        return False, [], {}


class ScamLanguageRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_CNT_002", "Financial or Tech-Support Scam Language",
            "Text contains two or more phrases typical of payment fraud or fake technical support",
            RiskWeights.MEDIUM, "MEDIUM",
            categories=["financial_scam", "tech_support_fraud"], mitre=["T1566", "T1566.004"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        text = context.get("raw_text", "").lower()
        hits = {cat: [t for t in terms if t in text] for cat, terms in SCAM_TERMS.items()}
        hits = {cat: terms for cat, terms in hits.items() if terms}
        total = sum(len(t) for t in hits.values())
        if total >= 2:
            phrases = [t for terms in hits.values() for t in terms]
            finding = self.finding("Scam Lure Phrasing", f"Scam phrasing detected: {', '.join(phrases[:4])}")
            finding.categories = sorted(hits)  # only the scam types actually evidenced
            return True, [finding], hits
        return False, [], {}


# --- Infrastructure Rules ---

BRANDS: Dict[str, List[str]] = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "office365.com"],
    "office365": ["office.com", "office365.com"],
    "outlook": ["outlook.com", "live.com"],
    "apple": ["apple.com", "icloud.com"],
    "icloud": ["icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazonaws.com"],
    "google": ["google.com", "gmail.com", "googleusercontent.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "linkedin": ["linkedin.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "adobe": ["adobe.com"],
}


def brand_in(text: str) -> List[str]:
    t = text.lower()
    return [b for b in BRANDS if b in t]


class BrandImpersonationDomainRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_EVI_004", "Brand Impersonation Domain",
            "A hostname embeds a well-known brand name but is not one of that brand's official domains",
            RiskWeights.HIGH, "HIGH",
            categories=["brand_impersonation", "credential_harvesting"], mitre=["T1583.001", "T1656"], cwe=["CWE-451"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        matches = []
        for host in _hostnames(context):
            reg = registrable_domain(host)
            for brand in brand_in(host):
                if reg not in BRANDS[brand]:
                    matches.append({"host": host, "brand": brand})
        if matches:
            first = matches[0]
            return True, [self.finding(
                "Brand Lookalike Host",
                f"'{first['host']}' references '{first['brand']}' but is not an official {first['brand']} domain",
                first["host"],
            )], {"matches": matches}
        return False, [], {}


DECEPTIVE_TOKENS = ["login", "signin", "verify", "secure", "account", "update", "support", "wallet", "auth",
                    "confirm", "billing", "recovery", "unlock", "bank", "helpdesk", "webscr"]


class DeceptiveKeywordDomainRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_EVI_005", "Deceptive Keyword Domain",
            "A registrable domain stacks two or more trust keywords (e.g. secure-bank-verify)",
            RiskWeights.MEDIUM, "MEDIUM",
            categories=["credential_harvesting", "suspicious_infrastructure"], mitre=["T1583.001"], cwe=["CWE-451"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        flagged = []
        for host in _hostnames(context):
            label = registrable_domain(host).split(".")[0]
            tokens = [t for t in DECEPTIVE_TOKENS if t in label]
            if len(tokens) >= 2:
                flagged.append({"host": host, "tokens": tokens})
        if flagged:
            f = flagged[0]
            return True, [self.finding(
                "Trust-Keyword Stacked Domain",
                f"'{f['host']}' combines trust keywords: {', '.join(f['tokens'])}", f["host"],
            )], {"domains": flagged}
        return False, [], {}


class PunycodeDomainRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_EVI_006", "Punycode / Homograph Domain",
            "A hostname uses IDN punycode (xn--), commonly used for homograph lookalikes",
            RiskWeights.MEDIUM, "MEDIUM",
            categories=["brand_impersonation"], mitre=["T1583.001", "T1036"], cwe=["CWE-451"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        hosts = [h for h in _hostnames(context) if "xn--" in h]
        for item in context.get("validation_results", {}).get("domains", []):
            if (_get(item, "properties") or {}).get("is_punycode"):
                hosts.append(_get(item, "artifact"))
        hosts = sorted(set(h for h in hosts if h))
        if hosts:
            return True, [self.finding("Homograph-Capable Domain", f"Punycode hostnames: {', '.join(hosts[:3])}", hosts[0])], {"hosts": hosts}
        return False, [], {}


SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "country", "kim",
                   "work", "rest", "cam", "icu", "buzz", "sbs", "cfd", "lol", "monster", "quest", "bond"}


class SuspiciousTLDRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_EVI_007", "High-Abuse Top-Level Domain",
            "A hostname uses a TLD with a disproportionate share of abuse reports",
            RiskWeights.LOW, "LOW", categories=["suspicious_infrastructure"], mitre=["T1583.001"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        hosts = [h for h in _hostnames(context) if h.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS]
        if hosts:
            return True, [self.finding("High-Abuse TLD", f"Hosts on high-abuse TLDs: {', '.join(hosts[:3])}", hosts[0])], {"hosts": hosts}
        return False, [], {}


URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
                  "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id", "v.gd"}


class URLShortenerRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_EVI_008", "URL Shortener Concealment",
            "A URL uses a link shortener that hides the final destination",
            RiskWeights.LOW, "LOW", categories=["phishing_email"], mitre=["T1608.005", "T1204.001"], cwe=["CWE-601"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        hosts = [h for h in _hostnames(context) if h in URL_SHORTENERS]
        if hosts:
            return True, [self.finding("Shortened Link", f"Destination hidden behind {', '.join(hosts)}", hosts[0])], {"shorteners": hosts}
        return False, [], {}


class IPLiteralURLRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_EVI_009", "IP-Literal URL",
            "A URL points directly at an IP address instead of a domain name",
            RiskWeights.MEDIUM, "MEDIUM",
            categories=["suspicious_infrastructure", "command_and_control"], mitre=["T1071.001"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        urls = []
        for url in context.get("evidence", {}).get("urls", []):
            host = urllib.parse.urlsplit(url).hostname or ""
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) or ":" in host:
                urls.append(url)
        if urls:
            return True, [self.finding("Direct-to-IP Link", f"URL addresses a raw IP: {urls[0]}", urls[0])], {"urls": urls}
        return False, [], {}


class NonStandardPortRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_EVI_010", "Non-Standard Port",
            "A web URL specifies a port other than 80 or 443",
            RiskWeights.LOW, "LOW", categories=["command_and_control"], mitre=["T1571"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        urls = []
        for url in context.get("evidence", {}).get("urls", []):
            try:
                port = urllib.parse.urlsplit(url).port
            except ValueError:
                continue
            if port and port not in (80, 443):
                urls.append(url)
        if urls:
            return True, [self.finding("Unusual Port", f"URL uses a non-standard port: {urls[0]}", urls[0])], {"urls": urls}
        return False, [], {}


PAYLOAD_EXTENSIONS = (".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".hta", ".jar",
                      ".apk", ".dll", ".iso", ".img", ".lnk", ".bin", ".docm", ".xlsm", ".pptm", ".one", ".wsf")


class PayloadDownloadURLRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_EVI_011", "Executable Payload Download",
            "A URL path ends in an executable, script, disk-image or macro-enabled document extension",
            RiskWeights.HIGH, "HIGH",
            categories=["malware_distribution"], mitre=["T1105", "T1204.002"], cwe=["CWE-494"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        urls = [u for u in context.get("evidence", {}).get("urls", [])
                if urllib.parse.urlsplit(u).path.lower().endswith(PAYLOAD_EXTENSIONS)]
        if urls:
            return True, [self.finding("Payload Delivery Link", f"URL serves an executable payload: {urls[0]}", urls[0])], {"urls": urls}
        return False, [], {}


# --- Email Header Rules ---

class EmailAuthenticationFailureRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_EML_001", "Email Authentication Failure",
            "SPF, DKIM or DMARC reported fail / softfail / permerror for the message",
            RiskWeights.HIGH, "HIGH",
            categories=["email_spoofing", "phishing_email"], mitre=["T1566", "T1656"], cwe=["CWE-290", "CWE-345"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        auth = ((context.get("ingestion") or {}).get("email") or {}).get("authentication") or {}
        failed = {k: v for k, v in auth.items() if v in ("fail", "softfail", "permerror", "hardfail")}
        if failed:
            summary = ", ".join(f"{k.upper()}={v}" for k, v in failed.items())
            return True, [self.finding("Sender Authentication Failed", f"Message failed authentication checks: {summary}")], {"failed": failed}
        return False, [], {}


class ReplyToMismatchRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_EML_002", "Reply-To / Return-Path Mismatch",
            "Replies or bounces are routed to a different domain than the visible sender",
            RiskWeights.MEDIUM, "MEDIUM",
            categories=["email_spoofing", "phishing_email"], mitre=["T1656"], cwe=["CWE-290"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        email = (context.get("ingestion") or {}).get("email") or {}
        sender = email.get("from_domain")
        mismatches = {}
        for field in ("reply_to_domain", "return_path_domain"):
            other = email.get(field)
            if sender and other and registrable_domain(other) != registrable_domain(sender):
                mismatches[field.replace("_domain", "")] = other
        if mismatches:
            desc = ", ".join(f"{k}={v}" for k, v in mismatches.items())
            return True, [self.finding("Routing Domain Mismatch", f"Sender {sender} but {desc}", sender)], {"from": sender, **mismatches}
        return False, [], {}


class DisplayNameSpoofRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_EML_003", "Display Name Spoofing",
            "The From display name claims a brand or address that does not match the sending domain",
            RiskWeights.MEDIUM, "MEDIUM",
            categories=["email_spoofing", "brand_impersonation"], mitre=["T1656", "T1566"], cwe=["CWE-451"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        email = (context.get("ingestion") or {}).get("email") or {}
        name = (email.get("display_name") or "").lower()
        sender = (email.get("from_domain") or "").lower()
        if not name or not sender:
            return False, [], {}
        reasons = []
        embedded = re.findall(r"[\w.+-]+@([\w-]+\.[\w.-]+)", name)
        if any(registrable_domain(d) != registrable_domain(sender) for d in embedded):
            reasons.append("display name embeds a different email address")
        for brand in brand_in(name.replace(" ", "")):
            if registrable_domain(sender) not in BRANDS[brand]:
                reasons.append(f"claims '{brand}' but sends from {sender}")
        if reasons:
            return True, [self.finding("Spoofed Sender Name", "; ".join(reasons), email.get("from"))], {"reasons": reasons}
        return False, [], {}


# --- File Rules ---

class DangerousFileTypeRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_FIL_001", "Dangerous File or Attachment",
            "The submitted file or an email attachment is an executable, script, archive or macro document",
            RiskWeights.HIGH, "HIGH",
            categories=["malware_distribution"], mitre=["T1566.001", "T1204.002"], cwe=["CWE-506"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        ingestion = context.get("ingestion") or {}
        names = []
        file_info = ingestion.get("file") or {}
        if file_info.get("dangerous"):
            names.append(file_info.get("filename") or "submitted file")
        for att in (ingestion.get("email") or {}).get("attachments", []):
            if att.get("dangerous"):
                names.append(att.get("filename") or "attachment")
        if names:
            return True, [self.finding("Risky File Type", f"High-risk file type(s): {', '.join(names[:3])}", names[0])], {"files": names}
        return False, [], {}


class QRCodeURLRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_FIL_002", "QR Code Leading to URL",
            "An image contains a QR code that encodes a web link (quishing)",
            RiskWeights.MEDIUM, "MEDIUM",
            categories=["qr_phishing"], mitre=["T1566.002", "T1204.001"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        payloads = ((context.get("ingestion") or {}).get("file") or {}).get("qr_payloads") or []
        links = [p for p in payloads if re.match(r"(?i)^(https?://|www\.)", p.strip())]
        if links:
            return True, [self.finding("QR-Encoded Link", f"QR code resolves to {links[0]}", links[0])], {"qr_links": links}
        return False, [], {}


class APKDangerousPermissionsRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_FIL_003", "Android App With Dangerous Permissions",
            "An APK requests permissions associated with SMS theft, overlays, accessibility abuse or device admin",
            RiskWeights.HIGH, "HIGH",
            categories=["mobile_malware", "malware_distribution"], mitre=["T1476"], cwe=["CWE-250"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        apk = ((context.get("ingestion") or {}).get("file") or {}).get("apk") or {}
        dangerous = apk.get("dangerous_permissions") or []
        if len(dangerous) >= 2:
            return True, [self.finding(
                "High-Risk Android Permissions",
                f"APK requests {len(dangerous)} dangerous permissions: {', '.join(p.split('.')[-1] for p in dangerous[:4])}",
                apk.get("package"),
            )], {"dangerous_permissions": dangerous}
        return False, [], {}


class PDFActiveContentRule(_Rule):
    def __init__(self) -> None:
        super().__init__(
            "RULE_FIL_004", "PDF Active Content",
            "A PDF contains JavaScript, auto-open or launch actions",
            RiskWeights.HIGH, "HIGH",
            categories=["malware_distribution"], mitre=["T1204.002", "T1566.001"], cwe=["CWE-506"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        markers = (((context.get("ingestion") or {}).get("file") or {}).get("pdf") or {}).get("active_content") or []
        if markers:
            return True, [self.finding("Scriptable PDF", f"PDF contains active content markers: {', '.join(markers)}")], {"markers": markers}
        return False, [], {}


# --- Intel Context Rules ---

class NewlyRegisteredDomainRule(_Rule):
    NEW_DOMAIN_DAYS = 30

    def __init__(self) -> None:
        super().__init__(
            "RULE_INT_004", "Newly Registered Domain",
            f"Registration data shows a domain is younger than {self.NEW_DOMAIN_DAYS} days",
            RiskWeights.HIGH, "HIGH",
            categories=["suspicious_infrastructure", "phishing_email"], mitre=["T1583.001"],
        )

    def evaluate(self, context: Dict[str, Any]) -> RuleResult:
        young = []
        for res in context.get("intel_results", {}).get("domains", []):
            age = (_get(res, "raw_data") or {}).get("domain_age_days")
            if isinstance(age, (int, float)) and age < self.NEW_DOMAIN_DAYS:
                young.append((_get(res, "artifact"), int(age)))
        if young:
            dom, age = young[0]
            return True, [self.finding("Freshly Registered Domain", f"'{dom}' was registered {age} day(s) ago", dom)], {"domains": young}
        return False, [], {}


EXTENDED_RULES = [
    CredentialPhishingLanguageRule,
    ScamLanguageRule,
    BrandImpersonationDomainRule,
    DeceptiveKeywordDomainRule,
    PunycodeDomainRule,
    SuspiciousTLDRule,
    URLShortenerRule,
    IPLiteralURLRule,
    NonStandardPortRule,
    PayloadDownloadURLRule,
    EmailAuthenticationFailureRule,
    ReplyToMismatchRule,
    DisplayNameSpoofRule,
    DangerousFileTypeRule,
    QRCodeURLRule,
    APKDangerousPermissionsRule,
    PDFActiveContentRule,
    NewlyRegisteredDomainRule,
]
