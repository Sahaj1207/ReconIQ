"""
ReconIQ Risk Scorer Engine

Purpose:
Primary deterministic risk scoring facade.
Executes enabled risk rules, aggregates weighted scores, caps final risk ratings (0-100),
calculates confidence, and maps scores to standard platform severity levels.

IMPORTANT:
This engine is 100% deterministic, explainable, and reproducible.
No machine learning or AI models are involved in risk scoring decisions.

Responsibilities:
- Evaluate active detection rules against normalized, validated, and enriched evidence
- Isolate rule execution exceptions to guarantee full rule suite completion
- Prevent duplicate rule scoring
- Cap final aggregated score strictly between 0.0 and 100.0
- Map score ranges to standard severity levels (INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL)
- Generate structured RiskAssessment reports with complete audit trail

Severity Scale:
  0–19   : INFORMATIONAL
 20–39   : LOW
 40–59   : MEDIUM
 60–79   : HIGH
 80–100  : CRITICAL

Future Extension Notes:
- Dynamic rule weighting configuration based on organization risk tolerance policies.
"""

import time
import logging
from typing import Dict, Any, Optional, List, Set

from app.risk_engine.models import RiskAssessment, RiskFinding, AppliedRule
from app.risk_engine.rules import RuleRegistry, BaseRule
from app.risk_engine.weights import map_score_to_severity
from app.risk_engine.confidence import ConfidenceEngine
from app.knowledge.mitre_attack import resolve_techniques
from app.knowledge.cwe import resolve_cwes
from app.knowledge.taxonomy import rank_categories

logger = logging.getLogger(__name__)


class RiskScorer:
    """
    Primary Risk Engine facade orchestrating deterministic threat evaluation.
    """

    def __init__(self, registry: Optional[RuleRegistry] = None) -> None:
        """
        Initializes RiskScorer with custom or default RuleRegistry.

        Args:
            registry (Optional[RuleRegistry]): Custom RuleRegistry instance.
        """
        self.registry = registry or RuleRegistry()

    def assess(
        self,
        evidence: Dict[str, Any],
        validation_results: Optional[Dict[str, Any]] = None,
        intel_results: Optional[Dict[str, Any]] = None,
        raw_text: str = "",
        ingestion: Optional[Dict[str, Any]] = None
    ) -> RiskAssessment:
        """
        Executes deterministic risk assessment on accumulated investigation evidence.

        Args:
            evidence (Dict[str, Any]): Normalized evidence dictionary.
            validation_results (Optional[Dict[str, Any]]): Structural validation results.
            intel_results (Optional[Dict[str, Any]]): Threat intelligence lookup responses.
            raw_text (str): Optional raw input text for payload analysis rules.

        Returns:
            RiskAssessment: Standardized risk assessment report.
        """
        start_time = time.perf_counter()

        context = {
            "evidence": evidence or {},
            "validation_results": validation_results or {},
            "intel_results": intel_results or {},
            "raw_text": raw_text or "",
            "ingestion": ingestion or {}
        }

        enabled_rules = self.registry.get_enabled_rules()
        logger.info(f"Starting deterministic risk assessment across {len(enabled_rules)} enabled rules")

        raw_score = 0.0
        findings: List[RiskFinding] = []
        applied_rules: List[AppliedRule] = []
        evaluated_rule_ids: Set[str] = set()
        category_weights: Dict[str, float] = {}

        # Evaluate rules sequentially with failure isolation
        for rule in enabled_rules:
            if rule.id in evaluated_rule_ids:
                logger.warning(f"Prevented duplicate evaluation for rule ID [{rule.id}]")
                continue

            evaluated_rule_ids.add(rule.id)

            try:
                rule_start = time.perf_counter()
                matched, rule_findings, evidence_ctx = rule.evaluate(context)
                rule_latency = round((time.perf_counter() - rule_start) * 1000, 2)

                applied = AppliedRule(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    description=rule.description,
                    weight=rule.weight,
                    severity=rule.severity,
                    matched=matched,
                    evidence_context=evidence_ctx
                )
                applied_rules.append(applied)

                if matched:
                    raw_score += rule.weight
                    for finding in rule_findings:
                        self._enrich_finding(finding, rule)
                        for category in finding.categories:
                            category_weights[category] = category_weights.get(category, 0.0) + max(rule.weight, 1.0)
                    findings.extend(rule_findings)
                    logger.debug(
                        f"Rule [{rule.id}: {rule.name}] MATCHED (+{rule.weight} pts, {rule_latency}ms)"
                    )
                else:
                    logger.debug(f"Rule [{rule.id}: {rule.name}] Did not match ({rule_latency}ms)")

            except Exception as exc:
                # Rule execution failure boundary: Log error and continue evaluating remaining rules
                logger.error(
                    f"Rule [{rule.id}: {rule.name}] execution exception: {exc}",
                    exc_info=True
                )
                applied_rules.append(AppliedRule(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    description=rule.description,
                    weight=rule.weight,
                    severity=rule.severity,
                    matched=False,
                    evidence_context={"error": str(exc)}
                ))

        # Score Capping (0.0 to 100.0)
        total_score = round(max(0.0, min(100.0, raw_score)), 2)

        # Severity Mapping
        severity = map_score_to_severity(total_score)

        # Confidence Calculation
        confidence = ConfidenceEngine.calculate_confidence(
            evidence=evidence or {},
            validation_results=validation_results,
            intel_results=intel_results
        )

        # Artifact Breakdown Calculation
        artifact_breakdown = {
            category: len(items)
            for category, items in (evidence or {}).items()
            if isinstance(items, list)
        }

        execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        triggered_count = sum(1 for a in applied_rules if a.matched)

        logger.info(
            f"Risk Assessment completed | Raw Score: {raw_score} -> Capped Score: {total_score} | "
            f"Severity: {severity} | Confidence: {confidence} | Rules Triggered: {triggered_count}/{len(enabled_rules)} | "
            f"Latency: {execution_time_ms}ms"
        )

        threat_categories = rank_categories(category_weights)
        if total_score < 20.0 or not threat_categories:
            classification = "no_threat_identified"
        else:
            classification = threat_categories[0]
        # Order techniques by the score contribution of the findings that evidence them
        techniques = resolve_techniques(
            t["id"] for f in sorted(findings, key=lambda f: -f.score_impact) for t in f.mitre_techniques
        )

        return RiskAssessment(
            total_score=total_score,
            classification=classification,
            threat_categories=threat_categories,
            mitre_techniques=techniques,
            severity=severity,
            confidence=confidence,
            findings=findings,
            applied_rules=applied_rules,
            artifact_breakdown=artifact_breakdown,
            execution_time_ms=execution_time_ms
        )

    @staticmethod
    def _enrich_finding(finding: RiskFinding, rule: BaseRule) -> None:
        """Attaches rule provenance and knowledge-base references to a finding."""
        finding.rule_id = finding.rule_id or rule.id
        if not finding.categories:
            finding.categories = list(getattr(rule, "categories", []))
        if not finding.mitre_techniques:
            finding.mitre_techniques = resolve_techniques(getattr(rule, "mitre", []))
        if not finding.cwes:
            finding.cwes = resolve_cwes(getattr(rule, "cwe", []))
