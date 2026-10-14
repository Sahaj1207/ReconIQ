"""
Extended rule library, knowledge base and classification tests.
"""

import pytest
from app.risk_engine.scorer import RiskScorer
from app.risk_engine.content_rules import registrable_domain
from app.knowledge import resolve_techniques, get_cwe, SeverityLevel
from app.knowledge.taxonomy import rank_categories


def matched_ids(assessment):
    return {f.rule_id for f in assessment.findings}


def assess(**kwargs):
    kwargs.setdefault("evidence", {})
    return RiskScorer().assess(**kwargs)


def test_registrable_domain():
    assert registrable_domain("a.b.example.com") == "example.com"
    assert registrable_domain("login.example.co.uk") == "example.co.uk"


def test_brand_impersonation_and_official_domains():
    a = assess(evidence={"domains": ["paypal-account-security.xyz"]})
    assert {"RULE_EVI_004", "RULE_EVI_007"} <= matched_ids(a)
    assert "RULE_EVI_004" not in matched_ids(assess(evidence={"domains": ["www.paypal.com"]}))


def test_deceptive_keyword_domain():
    assert "RULE_EVI_005" in matched_ids(assess(evidence={"domains": ["secure-login-verify.com"]}))
    assert "RULE_EVI_005" not in matched_ids(assess(evidence={"domains": ["example.com"]}))


def test_url_rules():
    urls = ["http://45.33.32.156:8080/p.ps1", "https://bit.ly/abc"]
    ids = matched_ids(assess(evidence={"urls": urls}))
    assert {"RULE_EVI_008", "RULE_EVI_009", "RULE_EVI_010", "RULE_EVI_011"} <= ids


def test_punycode_rule():
    assert "RULE_EVI_006" in matched_ids(assess(evidence={"domains": ["xn--pypal-4ve.com"]}))


def test_credential_phishing_language_requires_both_signals():
    phish = "URGENT: your account is suspended. Verify your password now."
    assert "RULE_CNT_001" in matched_ids(assess(raw_text=phish))
    assert "RULE_CNT_001" not in matched_ids(assess(raw_text="Please log in to the wiki tomorrow."))


def test_scam_language_narrows_categories():
    a = assess(raw_text="Buy a gift card and send a wire transfer today")
    finding = next(f for f in a.findings if f.rule_id == "RULE_CNT_002")
    assert finding.categories == ["financial_scam"]


def test_email_header_rules():
    ingestion = {"email": {
        "from": "billing@contoso.com", "from_domain": "contoso.com", "display_name": "PayPal Billing",
        "reply_to_domain": "evil-mail.ru", "return_path_domain": "contoso.com",
        "authentication": {"spf": "fail", "dkim": "pass", "dmarc": "fail"},
    }}
    ids = matched_ids(assess(ingestion=ingestion))
    assert {"RULE_EML_001", "RULE_EML_002", "RULE_EML_003"} <= ids


def test_file_rules():
    ingestion = {"file": {
        "filename": "invoice.exe", "dangerous": True,
        "qr_payloads": ["https://evil.example/login"],
        "apk": {"package": "com.x", "dangerous_permissions": ["android.permission.READ_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE"]},
        "pdf": {"active_content": ["/JavaScript"]},
    }}
    ids = matched_ids(assess(ingestion=ingestion))
    assert {"RULE_FIL_001", "RULE_FIL_002", "RULE_FIL_003", "RULE_FIL_004"} <= ids


def test_newly_registered_domain_rule():
    intel = {"domains": [{"provider": "RDAP", "artifact": "new.com", "status": "SUCCESS", "confidence": 0.0,
                          "threat_indicators": [], "raw_data": {"domain_age_days": 3}}]}
    assert "RULE_INT_004" in matched_ids(assess(evidence={"domains": ["new.com"]}, intel_results=intel))


def test_findings_carry_framework_context_and_classification():
    a = assess(evidence={"urls": ["http://update-cdn.net/a/stage2.exe"]})
    finding = next(f for f in a.findings if f.rule_id == "RULE_EVI_011")
    assert {t["id"] for t in finding.mitre_techniques} == {"T1105", "T1204.002"}
    assert finding.cwes[0]["id"] == "CWE-494"
    assert a.classification == "malware_distribution"
    assert any(t["id"] == "T1105" for t in a.mitre_techniques)


def test_low_score_is_not_classified_as_threat():
    a = assess(evidence={"ipv4": ["10.0.0.1"]})
    assert a.classification == "no_threat_identified"


def test_knowledge_helpers():
    assert resolve_techniques(["T1566.002", "T1566.002", "T0000"])[0]["url"].endswith("/T1566/002/")
    assert get_cwe("CWE-290")["name"].startswith("Authentication Bypass")
    assert SeverityLevel.from_score(85) == SeverityLevel.CRITICAL
    assert rank_categories({"suspicious_infrastructure": 90, "phishing_email": 10})[0] == "phishing_email"


def test_hash_and_ip_url_extraction():
    from app.ingestion.collector import EvidenceCollector
    r = EvidenceCollector().collect("see http://45.33.32.156/x and 44D88612FEA8A8F36DE82E1278ABB02F").results
    assert r.hashes == ["44d88612fea8a8f36de82e1278abb02f"]
    assert "http://45.33.32.156/x" in r.urls
