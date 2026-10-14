"""
Deterministic narrative generator.

Always available; used directly when no LLM is configured and as the fallback whenever the
model call fails or declines.
"""

from typing import Any, Dict, List

from app.analyst.models import AnalystReport
from app.knowledge.taxonomy import describe

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}

ACTIONS_BY_CATEGORY = {
    "credential_harvesting": "Reset credentials for any user who interacted with the link and review sign-in logs for the affected accounts.",
    "phishing_email": "Quarantine the message across mailboxes and notify recipients not to engage.",
    "brand_impersonation": "Report the lookalike domain to the impersonated brand and request a registrar takedown.",
    "malware_distribution": "Block the payload URLs and hashes at the proxy and EDR, then sweep endpoints for the file hashes.",
    "email_spoofing": "Tighten DMARC enforcement (p=quarantine or reject) for the spoofed domain and block the sending infrastructure.",
    "financial_scam": "Alert finance teams; never action payment or gift-card requests without out-of-band verification.",
    "tech_support_fraud": "Block the call-back numbers and remote-access domains; brief the help desk on the lure.",
    "qr_phishing": "Treat the QR destination as a phishing link: block it and warn users about scanning codes on personal devices.",
    "mobile_malware": "Block the APK hash in MDM and check enrolled devices for the package name.",
    "command_and_control": "Block the IPs/domains at the perimeter and hunt for beaconing from internal hosts.",
    "suspicious_infrastructure": "Add the infrastructure to watchlists and monitor for further activity.",
}


def build_template_report(result: Dict[str, Any], note: str = None) -> AnalystReport:
    risk = result.get("risk_assessment") or {}
    score = risk.get("total_score", 0)
    severity = risk.get("severity", "INFORMATIONAL")
    classification = risk.get("classification", "no_threat_identified")
    findings: List[Dict[str, Any]] = sorted(
        risk.get("findings", []),
        key=lambda f: (-SEVERITY_RANK.get(str(f.get("severity", "")).upper(), 0), -f.get("score_impact", 0)),
    )
    scored = [f for f in findings if f.get("score_impact", 0) > 0]
    total_iocs = sum((result.get("evidence_summary") or {}).values())
    source = result.get("source_name") or result.get("source_type", "text").replace("_", " ")

    if classification == "no_threat_identified":
        summary = (f"ReconIQ analysed the submitted {source} and extracted {total_iocs} indicator(s). "
                   f"The deterministic engine scored it {score:.0f}/100 ({severity}); no rule produced evidence of a "
                   f"specific threat.")
    else:
        label = classification.replace("_", " ")
        summary = (f"ReconIQ assessed the submitted {source} as {severity} risk ({score:.0f}/100), most consistent with "
                   f"{label}: {describe(classification).rstrip('.').lower()}. {len(scored)} rule(s) contributed to the "
                   f"score across {total_iocs} extracted indicator(s).")
        techniques = risk.get("mitre_techniques") or []
        if techniques:
            summary += " Mapped ATT&CK techniques: " + ", ".join(f"{t['id']} {t['name']}" for t in techniques[:3]) + "."

    key_findings = [f"{f.get('title')}: {f.get('description')}" for f in scored[:6]]
    actions = [ACTIONS_BY_CATEGORY[c] for c in risk.get("threat_categories", []) if c in ACTIONS_BY_CATEGORY][:4]
    if any(r.get("status") in ("FAILED", "UNAVAILABLE", "RATE_LIMITED")
           for items in (result.get("threat_intelligence") or {}).values() for r in items):
        actions.append("Some threat-intelligence lookups were unavailable; re-run once providers are reachable to raise confidence.")
    if not actions:
        actions.append("No action required beyond normal monitoring; re-submit if new context emerges.")

    return AnalystReport(summary=summary, key_findings=key_findings, recommended_actions=actions,
                         generated_by="template", note=note)
