"""
Corroboration thresholds: isolated provider detections are weak signals, not malicious verdicts,
and provider failures say what failed and why.
"""

import pytest

from app.integrations.models import LookupStatus, ThreatIntelResponse
from app.integrations.providers.virustotal import MIN_ENGINES_FOR_VERDICT, VirusTotalProvider
from app.risk_engine.rules import is_flagged_malicious
from app.risk_engine.scorer import RiskScorer


def vt_result(artifact="192.com", malicious=0, suspicious=0, categories=None, tags=None):
    indicators, confidence = VirusTotalProvider(api_key="k")._parse_attributes({
        "last_analysis_stats": {"malicious": malicious, "suspicious": suspicious, "harmless": 70, "undetected": 20},
        "categories": categories or {}, "tags": tags or [],
    })
    return ThreatIntelResponse(provider="VirusTotal", artifact=artifact, artifact_type="domain",
                               status=LookupStatus.SUCCESS, confidence=confidence, threat_indicators=indicators)


def assess(intel):
    return RiskScorer().assess(evidence={"domains": ["192.com"]}, intel_results={"domains": intel})


def rule_ids(assessment):
    return {f.rule_id for f in assessment.findings}


@pytest.mark.parametrize("engines", [1, 2])
def test_one_or_two_engines_are_a_weak_signal(engines):
    res = vt_result(malicious=engines)
    assert not is_flagged_malicious(res)
    a = assess([res])
    assert "RULE_INT_001" not in rule_ids(a) and "RULE_INT_005" in rule_ids(a)
    assert a.total_score == 10 and a.severity == "INFORMATIONAL"  # 192.com-style false positive no longer MEDIUM


def test_three_engines_are_a_verdict():
    res = vt_result(malicious=MIN_ENGINES_FOR_VERDICT)
    assert is_flagged_malicious(res)
    ids = rule_ids(assess([res]))
    assert "RULE_INT_001" in ids and "RULE_INT_005" not in ids


def test_single_suspicious_engine_or_vendor_category_is_weak():
    assert not is_flagged_malicious(vt_result(suspicious=1))
    assert not is_flagged_malicious(vt_result(categories={"Forcepoint": "phishing and other frauds"}))
    assert is_flagged_malicious(vt_result(categories={"Forcepoint": "phishing", "Sophos": "phishing"}))
    assert is_flagged_malicious(vt_result(tags=["phishing"]))


def test_c2_label_needs_a_whole_word():
    labels = {i.category for i in vt_result(categories={"A": "ec2 hosting", "B": "ec2 hosting"}).threat_indicators}
    assert "C2 / Botnet" not in labels


def test_context_indicators_do_not_count_as_weak_detections():
    from app.integrations.models import ThreatIndicator
    tor = ThreatIntelResponse(provider="AbuseIPDB", artifact="185.220.101.47", artifact_type="ipv4",
                              status=LookupStatus.SUCCESS, confidence=0.7,
                              threat_indicators=[ThreatIndicator(category="Tor Exit Node", severity="LOW",
                                                                 description="Tor exit node")])
    assert "RULE_INT_005" not in rule_ids(RiskScorer().assess(evidence={}, intel_results={"ipv4": [tor]}))


def test_degradation_notice_names_the_artifact_and_reason():
    failed = ThreatIntelResponse(provider="VirusTotal", artifact="garage-pirenne.be", artifact_type="domain",
                                 status=LookupStatus.FAILED, confidence=0.0,
                                 error_message="VirusTotal returned error status HTTP 400")
    limited = ThreatIntelResponse(provider="VirusTotal", artifact="www.garage-pirenne.be", artifact_type="domain",
                                  status=LookupStatus.RATE_LIMITED, confidence=0.0)
    a = RiskScorer().assess(evidence={}, intel_results={"domains": [failed, limited]})
    notice = next(f for f in a.findings if f.rule_id == "RULE_INT_003")
    assert notice.description == ("VirusTotal lookup failed for 'garage-pirenne.be': "
                                  "VirusTotal returned error status HTTP 400 (+1 more)")
    assert notice.score_impact == 0
