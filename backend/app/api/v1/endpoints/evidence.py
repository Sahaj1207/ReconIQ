"""
ReconIQ Evidence & Investigation Endpoints

HTTP Endpoints:
- POST /api/v1/evidence/extract : Extract raw IOC evidence
- POST /api/v1/evidence/investigate : Run full end-to-end investigation pipeline
"""

from fastapi import APIRouter, HTTPException, status
from app.schemas.evidence import EvidenceCollectionRequest, EvidenceCollectionResponse
from app.pipeline.models import InvestigationRequest, InvestigationResult
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


@router.post(
    "/investigate",
    response_model=InvestigationResult,
    status_code=status.HTTP_200_OK,
    summary="Execute Full Threat Investigation Pipeline",
    description="Executes full end-to-end investigation: Evidence Collection -> Normalization -> Validation -> Threat Intel -> Deterministic Risk Engine."
)
async def run_investigation(payload: InvestigationRequest) -> InvestigationResult:
    """
    Executes full end-to-end ReconIQ investigation pipeline.
    """
    try:
        return await service.investigate(payload)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation pipeline processing failure: {str(exc)}"
        )
