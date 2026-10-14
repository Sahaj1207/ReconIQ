"""
ReconIQ Evidence & Investigation Endpoints

HTTP Endpoints:
- POST /api/v1/evidence/extract : Extract raw IOC evidence
- POST /api/v1/evidence/investigate : Run full end-to-end investigation pipeline
- POST /api/v1/evidence/investigate/file : Investigate an uploaded file (.eml, PDF, image/QR, APK, text, binary)
"""

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status
from app.core.config import settings
from app.ingestion.parsers import UnsupportedFileError, ingest_file
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


@router.post(
    "/investigate/file",
    response_model=InvestigationResult,
    status_code=status.HTTP_200_OK,
    summary="Investigate an Uploaded File",
    description="Parses an uploaded email (.eml), PDF, image (QR / OCR), Android APK, text or binary file, "
                "then runs the full investigation pipeline on the extracted evidence and file fingerprint."
)
async def run_file_investigation(
    file: UploadFile = File(..., description="File to investigate"),
    refang: bool = Form(default=True),
) -> InvestigationResult:
    limit = settings.MAX_UPLOAD_MB * 1024 * 1024
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds the {settings.MAX_UPLOAD_MB} MB upload limit"
        )
    try:
        ingested = ingest_file(file.filename or "upload", data, refang=refang)
    except UnsupportedFileError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    try:
        return await service.investigate_ingested(ingested)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation pipeline processing failure: {str(exc)}"
        )
