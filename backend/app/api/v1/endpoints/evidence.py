"""
ReconIQ Evidence Extraction Endpoint

HTTP POST /api/v1/evidence/extract
Ingests raw threat text and returns extracted Indicators of Compromise (IOCs).
"""

from fastapi import APIRouter, HTTPException, status
from app.schemas.evidence import EvidenceCollectionRequest, EvidenceCollectionResponse
from app.services.investigation_service import InvestigationService

router = APIRouter()
service = InvestigationService()


@router.post(
    "/extract",
    response_model=EvidenceCollectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Extract Indicators of Compromise (IOCs)",
    description="Ingests plain or defanged threat text and extracts categorized IPv4, IPv6, URLs, Domains, Emails, and Phone Numbers."
)
async def extract_evidence(payload: EvidenceCollectionRequest) -> EvidenceCollectionResponse:
    """
    Extracts structured technical evidence from raw text payload.
    """
    try:
        return service.extract_evidence(payload)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Evidence extraction processing failure: {str(exc)}"
        )
