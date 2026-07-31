"""
ReconIQ Risk Engine Package

Purpose:
Deterministic, explainable risk scoring engine for cybersecurity threat assessments.

Responsibilities:
- Evaluate active detection rules against normalized, validated, and enriched evidence
- Provide centralized numeric weight definitions and severity mapping helpers
- Calculate statistical confidence ratings independently from risk scores
- Expose RiskScorer facade for end-to-end deterministic assessment

Philosophy:
ReconIQ Risk Engine operates with ZERO machine learning or AI models.
Every risk score is 100% explainable, deterministic, reproducible, and auditable.

Extension Guide for Custom Rules:
1. Subclass `BaseRule` in `app/risk_engine/rules.py` (or custom module).
2. Define `rule_id`, `name`, `description`, `weight`, and `severity`.
3. Implement `evaluate(self, context: Dict[str, Any]) -> Tuple[bool, List[RiskFinding], Dict[str, Any]]`.
4. Register instance with `RuleRegistry.register_rule()`.
"""

from app.risk_engine.models import (
    RiskFinding,
    AppliedRule,
    RiskSummary,
    RiskAssessment
)
from app.risk_engine.weights import RiskWeights, map_score_to_severity
from app.risk_engine.confidence import ConfidenceEngine
from app.risk_engine.rules import (
    BaseRule,
    RuleRegistry,
    InvalidURLRule,
    InvalidDomainRule,
    InvalidEmailRule,
    ProviderMaliciousRule,
    ProviderConsensusRule,
    ProviderUnavailableRule,
    DefangedIndicatorDetectedRule,
    MultipleSuspiciousArtifactsRule,
    PublicIPPresentRule
)
from app.risk_engine.scorer import RiskScorer

__all__ = [
    "RiskScorer",
    "RuleRegistry",
    "BaseRule",
    "ConfidenceEngine",
    "RiskWeights",
    "map_score_to_severity",
    "RiskFinding",
    "AppliedRule",
    "RiskSummary",
    "RiskAssessment",
    "InvalidURLRule",
    "InvalidDomainRule",
    "InvalidEmailRule",
    "ProviderMaliciousRule",
    "ProviderConsensusRule",
    "ProviderUnavailableRule",
    "DefangedIndicatorDetectedRule",
    "MultipleSuspiciousArtifactsRule",
    "PublicIPPresentRule",
]
