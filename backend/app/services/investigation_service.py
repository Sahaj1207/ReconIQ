"""
ReconIQ Investigation Service

Purpose:
Application orchestration service for handling evidence collection and full pipeline investigation operations.

Responsibilities:
- Bridge API request endpoints to EvidenceCollector and InvestigationPipeline orchestrator
- Handle logging and error boundaries for request processing
"""

import logging
from typing import Optional, Union

from fastapi.concurrency import run_in_threadpool

from app.core.config import settings
from app.db.repository import InvestigationRepository
from app.ingestion.collector import EvidenceCollector
from app.ingestion.ingested_input import IngestedInput
from app.pipeline.investigation import InvestigationPipeline
from app.pipeline.models import InvestigationRequest, InvestigationResult
from app.schemas.evidence import EvidenceCollectionRequest, EvidenceCollectionResponse


class InvestigationService:
    """
    Service coordinating ingestion and investigation tasks.
    """

    def __init__(self, repository: Optional[InvestigationRepository] = None) -> None:
        self.collector = EvidenceCollector()
        self.pipeline = InvestigationPipeline()
        self.repository = repository or InvestigationRepository()

    async def _persist(self, result: InvestigationResult) -> InvestigationResult:
        """Stores the result for history; a storage failure never fails the investigation."""
        if settings.PERSIST_INVESTIGATIONS:
            try:
                await run_in_threadpool(self.repository.save, result)
            except Exception as exc:
                logging.getLogger(__name__).error(f"Failed to persist investigation {result.investigation_id}: {exc}")
                result.warnings.append("Investigation could not be saved to history")
        return result

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
        return await self._persist(await self.pipeline.run(req))

    async def investigate_ingested(self, ingested: IngestedInput) -> InvestigationResult:
        """Runs the pipeline on an already-parsed IngestedInput (file uploads)."""
        return await self._persist(await self.pipeline.run(ingested))
