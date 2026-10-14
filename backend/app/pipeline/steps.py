"""
ReconIQ Pipeline Step Abstractions

Purpose:
Modular abstractions for individual pipeline execution steps:
- EvidenceCollectionStep
- NormalizationStep
- ValidationStep
- ThreatIntelStep
- RiskAssessmentStep

Responsibilities:
- Provide clean execution contract via BasePipelineStep abstract class
- Execute stage logic independently using specialized system components
- Update InvestigationContext state without exposing raw internal errors or keys

Future Extension Notes:
- Extension guide: Subclass BasePipelineStep, implement name and async execute(context),
  and register step with InvestigationPipeline orchestrator.
"""

from abc import ABC, abstractmethod
import logging
from typing import Dict, Any, Optional

from app.pipeline.context import InvestigationContext
from app.ingestion.collector import EvidenceCollector
from app.utils.normalizer import Normalizer
from app.validators.validator import Validator
from app.integrations.manager import ThreatIntelManager
from app.risk_engine.scorer import RiskScorer

logger = logging.getLogger(__name__)


class BasePipelineStep(ABC):
    """
    Abstract Base Class for all Investigation Pipeline Steps.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns unique identifier name for the pipeline step."""
        pass

    @abstractmethod
    async def execute(self, context: InvestigationContext) -> None:
        """
        Executes step logic modifying or enriching InvestigationContext state.

        Args:
            context (InvestigationContext): Active investigation context.
        """
        pass


class EvidenceCollectionStep(BasePipelineStep):
    """
    Step 1: Artifact & Input Ingestion / Evidence Collection
    """

    def __init__(self, collector: Optional[EvidenceCollector] = None) -> None:
        self.collector = collector or EvidenceCollector()

    @property
    def name(self) -> str:
        return "evidence_collection"

    async def execute(self, context: InvestigationContext) -> None:
        logger.debug(f"[{context.investigation_id}] Executing EvidenceCollectionStep")
        response = self.collector.collect(context.raw_input)
        if response and response.results:
            context.collected_evidence = response.results.model_dump()
        else:
            context.collected_evidence = {}


class NormalizationStep(BasePipelineStep):
    """
    Step 2: Canonical Evidence Normalization
    """

    @property
    def name(self) -> str:
        return "normalization"

    async def execute(self, context: InvestigationContext) -> None:
        logger.debug(f"[{context.investigation_id}] Executing NormalizationStep")
        if not context.collected_evidence:
            context.normalized_evidence = {}
            return

        normalized = Normalizer.normalize_all(context.collected_evidence)
        context.normalized_evidence = normalized or {}


class ValidationStep(BasePipelineStep):
    """
    Step 3: Structural Format & Syntax Validation
    """

    @property
    def name(self) -> str:
        return "validation"

    async def execute(self, context: InvestigationContext) -> None:
        logger.debug(f"[{context.investigation_id}] Executing ValidationStep")
        evidence_to_validate = context.normalized_evidence or context.collected_evidence
        if not evidence_to_validate:
            context.validation_results = {}
            return

        validated = Validator.validate_all(evidence_to_validate)
        context.validation_results = validated or {}


class ThreatIntelStep(BasePipelineStep):
    """
    Step 4: Threat Intelligence Enrichment Lookups
    """

    def __init__(self, manager: Optional[ThreatIntelManager] = None) -> None:
        if manager:
            self.manager = manager
        else:
            # Register every configured threat intel provider
            from app.integrations.registry import build_default_manager
            self.manager = build_default_manager()

    @property
    def name(self) -> str:
        return "threat_intelligence"

    async def execute(self, context: InvestigationContext) -> None:
        logger.debug(f"[{context.investigation_id}] Executing ThreatIntelStep")
        evidence_to_enrich = context.validation_results or context.normalized_evidence or context.collected_evidence
        if not evidence_to_enrich:
            context.threat_intelligence = {}
            return

        intel_data = await self.manager.lookup_all(evidence_to_enrich)
        context.threat_intelligence = intel_data or {}


class RiskAssessmentStep(BasePipelineStep):
    """
    Step 5: Deterministic Risk Engine Evaluation & Scoring
    """

    def __init__(self, scorer: Optional[RiskScorer] = None) -> None:
        self.scorer = scorer or RiskScorer()

    @property
    def name(self) -> str:
        return "risk_assessment"

    async def execute(self, context: InvestigationContext) -> None:
        logger.debug(f"[{context.investigation_id}] Executing RiskAssessmentStep")
        raw_text_content = context.raw_input.content if hasattr(context.raw_input, "content") else str(context.raw_input)

        assessment = self.scorer.assess(
            evidence=context.normalized_evidence or context.collected_evidence,
            validation_results=context.validation_results,
            intel_results=context.threat_intelligence,
            raw_text=raw_text_content,
            ingestion=(context.raw_input.metadata or {}).get("analysis") if hasattr(context.raw_input, "metadata") else None
        )
        context.risk_assessment = assessment


class SummaryStep(BasePipelineStep):
    """
    Step 6: Analyst summary.

    Runs after scoring and reads a snapshot of the finished assessment. Its output is stored in
    a separate field and cannot modify evidence, findings or the score.
    """

    @property
    def name(self) -> str:
        return "summary"

    async def execute(self, context: InvestigationContext) -> None:
        from app.analyst import generate_report
        snapshot = context.to_result(status="success").model_dump(mode="json")
        context.analyst_report = generate_report(snapshot).model_dump()
