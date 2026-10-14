"""
ReconIQ Investigation Service

Purpose:
Application orchestration service for handling evidence collection and full pipeline investigation operations.

Responsibilities:
- Bridge API request endpoints to EvidenceCollector and InvestigationPipeline orchestrator
- Handle logging and error boundaries for request processing
"""

from typing import Union
from app.ingestion.collector import EvidenceCollector
from app.ingestion.ingested_input import IngestedInput
from app.pipeline.investigation import InvestigationPipeline
from app.pipeline.models import InvestigationRequest, InvestigationResult
from app.schemas.evidence import EvidenceCollectionRequest, EvidenceCollectionResponse


class InvestigationService:
    """
    Service coordinating ingestion and investigation tasks.
    """

    def __init__(self) -> None:
        self.collector = EvidenceCollector()
        self.pipeline = InvestigationPipeline()

    def extract_evidence(self, payload: EvidenceCollectionRequest) -> EvidenceCollectionResponse:
        """
        Processes evidence extraction request via EvidenceCollector.

        Args:
            payload (EvidenceCollectionRequest): API request payload.

        Returns:
            EvidenceCollectionResponse: Structured extraction result object.
        """
        ingested_input = IngestedInput.from_text(
            text=payload.text,
            metadata={"refang": payload.refang}
        )
        return self.collector.collect(ingested_input)

    async def investigate(self, payload: Union[InvestigationRequest, EvidenceCollectionRequest, str]) -> InvestigationResult:
        """
        Executes complete end-to-end investigation pipeline.

        Args:
            payload (Union[InvestigationRequest, EvidenceCollectionRequest, str]): Input payload object or text string.

        Returns:
            InvestigationResult: Complete structured investigation response DTO.
        """
        if isinstance(payload, EvidenceCollectionRequest):
            req = InvestigationRequest(
                text=payload.text,
                refang=payload.refang
            )
        else:
            req = payload
        return await self.pipeline.run(req)

    async def investigate_ingested(self, ingested: IngestedInput) -> InvestigationResult:
        """Runs the pipeline on an already-parsed IngestedInput (file uploads)."""
        return await self.pipeline.run(ingested)
