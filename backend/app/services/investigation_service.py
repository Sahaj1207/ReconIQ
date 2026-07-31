"""
ReconIQ Investigation Service

Purpose:
Application orchestration service for handling evidence collection and investigation operations.

Responsibilities:
- Bridge API request endpoints to the EvidenceCollector facade
- Handle logging and error boundaries for request processing

Future Implementation Notes:
- Connect EvidenceCollector output to Risk Engine and Threat Intel asynchronous lookup queues.

TODO:
- [ ] Connect pipeline execution trigger when full investigation flow is enabled.
"""

from app.ingestion.collector import EvidenceCollector
from app.ingestion.ingested_input import IngestedInput
from app.schemas.evidence import EvidenceCollectionRequest, EvidenceCollectionResponse


class InvestigationService:
    """
    Service coordinating ingestion and investigation tasks.
    """

    def __init__(self) -> None:
        self.collector = EvidenceCollector()

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
