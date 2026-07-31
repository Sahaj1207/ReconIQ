"""
ReconIQ Investigation Pipeline Orchestrator

Purpose:
Main orchestration engine coordinating multi-stage threat investigations.

Responsibilities:
- Instantiate and execute ordered pipeline steps (EvidenceCollection -> Normalization -> Validation -> ThreatIntel -> RiskAssessment)
- Provide exception isolation boundaries to ensure recoverable stage failures do not crash the investigation
- Collect per-stage and end-to-end execution timing telemetry
- Enforce security sanitization on logged error messages
- Produce standardized InvestigationResult response objects

IMPORTANT:
The InvestigationPipeline orchestrator contains NO domain business logic.
It strictly coordinates execution across specialized pipeline step components.

Future Extension Notes:
- Dynamic step registration via configuration files or feature flags.
- Asynchronous DAG step execution for parallel independent stages.
"""

import time
import logging
from typing import List, Optional, Union

from app.ingestion.ingested_input import IngestedInput
from app.pipeline.models import (
    InvestigationRequest,
    InvestigationResult,
    StageStatus
)
from app.pipeline.context import InvestigationContext, sanitize_sensitive_data
from app.pipeline.steps import (
    BasePipelineStep,
    EvidenceCollectionStep,
    NormalizationStep,
    ValidationStep,
    ThreatIntelStep,
    RiskAssessmentStep
)

logger = logging.getLogger(__name__)


class InvestigationPipeline:
    """
    Primary Orchestrator for ReconIQ Threat Investigations.
    """

    def __init__(self, steps: Optional[List[BasePipelineStep]] = None) -> None:
        """
        Initializes InvestigationPipeline with custom or default ordered steps.

        Args:
            steps (Optional[List[BasePipelineStep]]): Ordered list of pipeline step instances.
        """
        if steps is not None:
            self.steps = steps
        else:
            # Default ordered investigation pipeline stages
            self.steps = [
                EvidenceCollectionStep(),
                NormalizationStep(),
                ValidationStep(),
                ThreatIntelStep(),
                RiskAssessmentStep(),
            ]

    async def run(
        self,
        payload: Union[InvestigationRequest, IngestedInput, str]
    ) -> InvestigationResult:
        """
        Executes end-to-end investigation pipeline on provided payload.

        Args:
            payload (Union[InvestigationRequest, IngestedInput, str]): Input payload object or text string.

        Returns:
            InvestigationResult: Complete structured investigation response DTO.
        """
        # Step 1: Standardize payload into IngestedInput model
        if isinstance(payload, InvestigationRequest):
            ingested_input = IngestedInput.from_text(
                text=payload.text,
                metadata={"refang": payload.refang, **payload.metadata}
            )
        elif isinstance(payload, str):
            ingested_input = IngestedInput.from_text(text=payload)
        elif isinstance(payload, IngestedInput):
            ingested_input = payload
        else:
            raise TypeError("Unsupported payload type provided to InvestigationPipeline")

        # Step 2: Instantiate InvestigationContext state container
        context = InvestigationContext(
            raw_input=ingested_input,
            metadata=ingested_input.metadata
        )

        logger.info(
            f"[{context.investigation_id}] Pipeline execution started | "
            f"Source: [{ingested_input.source_type}] | Length: {len(ingested_input.content)} chars | "
            f"Stages: {len(self.steps)}"
        )

        completed_count = 0
        failed_count = 0

        # Step 3: Sequentially execute pipeline stages with exception isolation
        for step in self.steps:
            stage_start = time.perf_counter()
            logger.info(f"[{context.investigation_id}] Stage [{step.name}] started")

            try:
                await step.execute(context)
                duration_ms = (time.perf_counter() - stage_start) * 1000

                context.record_stage(
                    stage_name=step.name,
                    status=StageStatus.COMPLETED,
                    duration_ms=duration_ms
                )
                completed_count += 1
                logger.info(f"[{context.investigation_id}] Stage [{step.name}] completed in {round(duration_ms, 2)}ms")

            except Exception as exc:
                duration_ms = (time.perf_counter() - stage_start) * 1000
                failed_count += 1

                # Sanitize error detail to prevent leaking secrets/paths
                clean_err_msg = sanitize_sensitive_data(str(exc))
                logger.error(
                    f"[{context.investigation_id}] Stage [{step.name}] failed ({round(duration_ms, 2)}ms): {clean_err_msg}"
                )

                context.record_stage(
                    stage_name=step.name,
                    status=StageStatus.FAILED,
                    duration_ms=duration_ms,
                    error=clean_err_msg
                )
                context.add_error(f"Stage '{step.name}' failed: {clean_err_msg}")

        # Step 4: Determine overall pipeline status
        if failed_count == 0:
            overall_status = "success"
        elif completed_count > 0:
            overall_status = "partial_success"
        else:
            overall_status = "failed"

        total_duration = round((time.perf_counter() - context.start_time) * 1000, 2)
        logger.info(
            f"[{context.investigation_id}] Investigation completed | Status: {overall_status} | "
            f"Stages Completed: {completed_count}/{len(self.steps)} | Total Duration: {total_duration}ms"
        )

        # Step 5: Package and return final InvestigationResult DTO
        return context.to_result(status=overall_status)
