"""
ReconIQ Modular Investigation Steps

Purpose:
Defines abstract interface and concrete modular steps for individual investigation pipeline stages.

Responsibilities:
- Provide clean execution contracts for individual steps (ExtractEvidenceStep, EnrichIntelStep, EvaluateRiskStep)
- Standardize step input validation and output propagation

Future Implementation Notes:
- Dynamic step registration via configuration or feature flags.

TODO:
- [ ] Implement BasePipelineStep abstract class.
- [ ] Add ExtractEvidenceStep implementation.
- [ ] Add ThreatIntelEnrichmentStep implementation.
- [ ] Add RiskAssessmentStep implementation.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any


class BasePipelineStep(ABC):
    """Abstract base class for individual pipeline steps."""

    @property
    @abstractmethod
    def step_name(self) -> str:
        """Unique identifier for the step."""
        pass

    @abstractmethod
    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes step logic modifying or enriching investigation context.

        Args:
            context (Dict[str, Any]): Active investigation context.

        Returns:
            Dict[str, Any]: Updated context.
        """
        pass
