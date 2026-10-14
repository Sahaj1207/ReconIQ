"""
ReconIQ Phase 5 Risk Engine Unit Tests
"""

import pytest
from typing import Dict, Any, Tuple, List
from app.risk_engine.models import RiskFinding
from app.risk_engine.weights import RiskWeights, map_score_to_severity
from app.risk_engine.confidence import ConfidenceEngine
from app.risk_engine.rules import BaseRule, RuleRegistry, InvalidURLRule, PublicIPPresentRule
from app.risk_engine.scorer import RiskScorer
from app.validators.validator import ValidationResult
from app.integrations.models import ThreatIntelResponse, ThreatIndicator, LookupStatus


# --- Synthetic Crashing Rule for Test ---
class CrashingTestRule(BaseRule):
    """Rule that raises an unhandled exception for failure boundary testing."""
    def __init__(self) -> None:
        super().__init__(
            rule_id="RULE_CRASH_001",
            name="Crashing Rule",
            description="Simulates rule crash",
            weight=50.0,
            severity="HIGH"
        )

    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, List[RiskFinding], Dict[str, Any]]:
        raise RuntimeError("Simulated rule crash exception")


# --- Unit Test Cases ---

def test_severity_mapping_ranges():
    """Test map_score_to_severity thresholds."""
    assert map_score_to_severity(0.0) == "INFORMATIONAL"
    assert map_score_to_severity(19.9) == "INFORMATIONAL"
    assert map_score_to_severity(20.0) == "LOW"
    assert map_score_to_severity(39.9) == "LOW"
    assert map_score_to_severity(40.0) == "MEDIUM"
    assert map_score_to_severity(59.9) == "MEDIUM"
    assert map_score_to_severity(60.0) == "HIGH"
    assert map_score_to_severity(79.9) == "HIGH"
    assert map_score_to_severity(80.0) == "CRITICAL"
    assert map_score_to_severity(100.0) == "CRITICAL"


def test_confidence_engine_calculation():
    """Test ConfidenceEngine with empty and populating evidence."""
    # Empty
    assert ConfidenceEngine.calculate_confidence({}) == 0.0

    # Populated evidence
    evidence = {"ipv4": ["8.8.8.8"], "domains": ["example.com"]}
    val_results = {
        "ipv4": [ValidationResult(valid=True, artifact="8.8.8.8", artifact_type="ipv4")],
        "domains": [ValidationResult(valid=True, artifact="example.com", artifact_type="domain")]
    }
    conf = ConfidenceEngine.calculate_confidence(evidence, validation_results=val_results)
    assert 0.0 <= conf <= 1.0
    assert conf > 0.4


def test_rule_enable_disable():
    """Test rule registry enable/disable flags."""
    registry = RuleRegistry()
    total = len(registry.get_all_rules())

    assert len(registry.get_enabled_rules()) == total

    registry.disable_rule("RULE_VAL_001")
    assert len(registry.get_enabled_rules()) == total - 1

    registry.enable_rule("RULE_VAL_001")
    assert len(registry.get_enabled_rules()) == total


def test_empty_evidence_assessment():
    """Test RiskScorer with empty evidence."""
    scorer = RiskScorer()
    assessment = scorer.assess(evidence={})

    assert assessment.total_score == 0.0
    assert assessment.severity == "INFORMATIONAL"
    assert assessment.confidence == 0.0
    assert len(assessment.findings) == 0


def test_score_aggregation_and_max_cap():
    """Test score aggregation and 100.0 score cap."""
    # Create rules with total weight > 100
    class HighWeightRule(BaseRule):
        def evaluate(self, context: Dict[str, Any]):
            finding = RiskFinding(
                finding_id="HIGH_FINDING",
                title="Critical Threat",
                description="Critical vulnerability",
                severity="CRITICAL",
                score_impact=90.0
            )
            return True, [finding], {}

    r1 = HighWeightRule("HIGH_1", "Rule 1", "Desc", weight=90.0, severity="CRITICAL")
    r2 = HighWeightRule("HIGH_2", "Rule 2", "Desc", weight=90.0, severity="CRITICAL")

    registry = RuleRegistry()
    registry.register_rule(r1)
    registry.register_rule(r2)

    scorer = RiskScorer(registry=registry)
    evidence = {"ipv4": ["1.1.1.1"]}
    assessment = scorer.assess(evidence=evidence)

    # 90 + 90 = 180 raw score, capped at 100.0
    assert assessment.total_score == 100.0
    assert assessment.severity == "CRITICAL"


def test_mixed_evidence_scenarios():
    """Test mixed threat evidence evaluation (defanged text, malicious intel, public IP)."""
    scorer = RiskScorer()

    evidence = {
        "ipv4": ["198.51.100.45", "10.0.0.1"],
        "domains": ["phishing-portal.com"],
        "urls": ["https://phishing-portal.com/login"],
        "emails": ["attacker@malicious-bank.com"],
        "phone_numbers": ["+18005550199"]
    }

    val_results = {
        "ipv4": [
            ValidationResult(valid=True, artifact="198.51.100.45", artifact_type="ipv4", properties={"is_global": True}),
            ValidationResult(valid=True, artifact="10.0.0.1", artifact_type="ipv4", properties={"is_global": False, "is_private": True})
        ]
    }

    intel_results = {
        "domains": [
            ThreatIntelResponse(
                provider="MockVT",
                artifact="phishing-portal.com",
                artifact_type="domain",
                status=LookupStatus.SUCCESS,
                confidence=0.9,
                threat_indicators=[ThreatIndicator(category="phishing", severity="HIGH")]
            )
        ]
    }

    raw_text = "Alert: email from attacker[at]malicious-bank[dot]com link hxxps://phishing-portal[.]com/login"

    assessment = scorer.assess(
        evidence=evidence,
        validation_results=val_results,
        intel_results=intel_results,
        raw_text=raw_text
    )

    assert assessment.total_score >= 60.0
    assert assessment.severity in ("HIGH", "CRITICAL")
    assert assessment.confidence > 0.5
    assert len(assessment.findings) >= 3


def test_rule_failure_isolation():
    """Test that a crashing rule does not halt RiskScorer assessment."""
    registry = RuleRegistry()
    baseline = len(registry.get_all_rules())
    registry.register_rule(CrashingTestRule())

    scorer = RiskScorer(registry=registry)
    evidence = {"ipv4": ["198.51.100.45"]}

    # Assessment should complete safely
    assessment = scorer.assess(evidence=evidence)
    assert assessment.total_score >= 0.0
    assert len(assessment.applied_rules) == baseline + 1


def test_clean_high_confidence_intel_is_not_flagged():
    """A clean verdict (high confidence, no indicators) from two providers must not score as malicious."""
    clean = [
        ThreatIntelResponse(provider=p, artifact="example.com", artifact_type="domain",
                            status=LookupStatus.SUCCESS, confidence=0.8)
        for p in ("VirusTotal", "OtherIntel")
    ]
    assessment = RiskScorer().assess(evidence={"domains": ["example.com"]}, intel_results={"domains": clean})
    matched = {r.rule_id for r in assessment.applied_rules if r.matched}
    assert "RULE_INT_001" not in matched
    assert "RULE_INT_002" not in matched
