"""
ReconIQ Investigation Pipeline Package

Purpose:
Orchestration layer coordinating multi-stage cybersecurity threat investigations.

Responsibilities:
- Provide InvestigationPipeline single entrypoint facade
- Manage InvestigationContext state container and telemetry metrics
- Provide BasePipelineStep interface for pluggable stage components

Lifecycle of an Investigation:
1. Receive InvestigationRequest or text payload
2. Instantiate InvestigationContext (UUID, timestamp, raw payload)
3. Execute Stage 1: EvidenceCollectionStep
4. Execute Stage 2: NormalizationStep
5. Execute Stage 3: ValidationStep
6. Execute Stage 4: ThreatIntelStep
7. Execute Stage 5: RiskAssessmentStep
8. Package findings into structured InvestigationResult DTO

Extension Guide for Adding Future Pipeline Stages:
1. Create new step class inheriting from `BasePipelineStep` in `app/pipeline/steps.py`.
2. Implement `name` property and `async execute(context: InvestigationContext)`.
3. Add step instance to `self.steps` list in `InvestigationPipeline`.
"""

from app.pipeline.models import (
    StageStatus,
    StageMetric,
    InvestigationRequest,
    InvestigationResult
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
from app.pipeline.investigation import InvestigationPipeline

__all__ = [
    "InvestigationPipeline",
    "InvestigationContext",
    "InvestigationRequest",
    "InvestigationResult",
    "StageStatus",
    "StageMetric",
    "BasePipelineStep",
    "EvidenceCollectionStep",
    "NormalizationStep",
    "ValidationStep",
    "ThreatIntelStep",
    "RiskAssessmentStep",
    "sanitize_sensitive_data",
]
