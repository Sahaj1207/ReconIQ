"""
ReconIQ Risk Confidence Engine

Purpose:
Calculates statistical confidence ratings (0.0 to 1.0) independently from risk scoring.

Responsibilities:
- Evaluate threat intelligence provider consensus and query success rates
- Factor in structural validation pass/fail ratios across extracted evidence
- Calculate confidence based on evidence density and findings corroboration

Future Extension Notes:
- Dynamic confidence decay based on threat intelligence record freshness timestamps.
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class ConfidenceEngine:
    """
    Independent confidence calculator for risk assessments.
    """

    @classmethod
    def calculate_confidence(
        cls,
        evidence: Dict[str, Any],
        validation_results: Optional[Dict[str, Any]] = None,
        intel_results: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Calculates confidence rating between 0.0 and 1.0.

        Args:
            evidence (Dict[str, Any]): Raw or normalized evidence dictionary.
            validation_results (Optional[Dict[str, Any]]): Validation results dictionary.
            intel_results (Optional[Dict[str, Any]]): Threat intelligence lookup responses.

        Returns:
            float: Confidence score bounded between 0.0 and 1.0.
        """
        # Base baseline confidence for evidence presence
        base_confidence = 0.5

        total_artifacts = sum(
            len(v) for v in evidence.values()
            if isinstance(v, list)
        ) if evidence else 0

        if total_artifacts == 0:
            return 0.0

        # Factor 1: Validation Quality (weight ~0.25)
        validation_score = 0.25
        if validation_results:
            val_items = [
                item for sublist in validation_results.values()
                if isinstance(sublist, list) for item in sublist
            ]
            if val_items:
                valid_count = sum(
                    1 for item in val_items
                    if getattr(item, "valid", True) is True or (isinstance(item, dict) and item.get("valid"))
                )
                valid_ratio = valid_count / len(val_items)
                validation_score = 0.25 * valid_ratio

        # Factor 2: Threat Intelligence Coverage & Consensus (weight ~0.35)
        intel_score = 0.0
        if intel_results:
            intel_items = [
                res for sublist in intel_results.values()
                if isinstance(sublist, list) for res in sublist
            ]
            if intel_items:
                # Count successful lookups
                success_count = sum(
                    1 for res in intel_items
                    if getattr(res, "status", None) == "SUCCESS" or (isinstance(res, dict) and res.get("status") == "SUCCESS")
                )
                coverage_ratio = success_count / len(intel_items)

                # Count providers that reported non-zero confidence or findings
                provider_confidences = [
                    getattr(res, "confidence", 0.0) if hasattr(res, "confidence") else res.get("confidence", 0.0)
                    for res in intel_items
                ]
                avg_provider_confidence = (
                    sum(provider_confidences) / len(provider_confidences)
                    if provider_confidences else 0.0
                )

                intel_score = (0.2 * coverage_ratio) + (0.15 * avg_provider_confidence)
            else:
                intel_score = 0.1
        else:
            # Baseline when threat intel is not yet run
            intel_score = 0.15

        # Factor 3: Evidence Density (weight ~0.10)
        density_score = min(0.10, total_artifacts * 0.02)

        total_confidence = base_confidence * 0.3 + validation_score + intel_score + density_score
        clamped_confidence = max(0.0, min(1.0, round(total_confidence, 2)))

        logger.debug(
            f"Confidence calculated: {clamped_confidence} "
            f"(Val: {round(validation_score, 2)}, Intel: {round(intel_score, 2)}, Density: {round(density_score, 2)})"
        )

        return clamped_confidence
