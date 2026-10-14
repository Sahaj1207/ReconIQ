"""
ReconIQ Evidence & Investigation Endpoints

HTTP Endpoints:
- POST /api/v1/evidence/extract : Extract raw IOC evidence
- POST /api/v1/evidence/investigate : Run full end-to-end investigation pipeline
- POST /api/v1/evidence/investigate/file : Investigate an uploaded file (.eml, PDF, image/QR, APK, text, binary)
- POST /api/v1/evidence/jobs : Start a background investigation; poll GET /api/v1/jobs/{job_id}
- POST /api/v1/evidence/jobs/file : Start a background investigation of an uploaded file
"""

from typing import Any, Dict

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from app.auth.principal import Principal, client_ip, require_role
from app.core.config import settings
from app.ingestion.ingested_input import IngestedInput
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
async def extract_evidence(payload: EvidenceCollectionRequest,
                           _: Principal = Depends(require_role("analyst"))) -> EvidenceCollectionResponse:
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
async def run_investigation(payload: InvestigationRequest, request: Request,
                            principal: Principal = Depends(require_role("analyst"))) -> InvestigationResult:
    """
    Executes full end-to-end ReconIQ investigation pipeline.
    """
    try:
        return await service.investigate(payload, owner=principal, ip=client_ip(request))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation pipeline processing failure: {str(exc)}"
        )


async def _ingest_upload(file: UploadFile, refang: bool) -> IngestedInput:
    """Reads an upload within the size limit and parses it; parse errors are the client's (422)."""
    limit = settings.MAX_UPLOAD_MB * 1024 * 1024
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(
            status_code=413,  # Content Too Large
            detail=f"File exceeds the {settings.MAX_UPLOAD_MB} MB upload limit"
        )
    try:
        return await run_in_threadpool(ingest_file, file.filename or "upload", data, refang)
    except UnsupportedFileError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post(
    "/investigate/file",
    response_model=InvestigationResult,
    status_code=status.HTTP_200_OK,
    summary="Investigate an Uploaded File",
    description="Parses an uploaded email (.eml), PDF, image (QR / OCR), Android APK, text or binary file, "
                "then runs the full investigation pipeline on the extracted evidence and file fingerprint."
)
async def run_file_investigation(
    request: Request,
    file: UploadFile = File(..., description="File to investigate"),
    refang: bool = Form(default=True),
    principal: Principal = Depends(require_role("analyst")),
) -> InvestigationResult:
    ingested = await _ingest_upload(file, refang)
    try:
        return await service.investigate_ingested(ingested, owner=principal, ip=client_ip(request))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation pipeline processing failure: {str(exc)}"
        )


async def _start_job(ingested: IngestedInput, background: BackgroundTasks, request: Request,
                     principal: Principal) -> Dict[str, Any]:
    job = await run_in_threadpool(service.create_job, ingested, principal)
    background.add_task(service.run_job, job["job_id"], ingested, principal, client_ip(request))
    return job


@router.post(
    "/jobs",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a Background Investigation",
    description="Queues the investigation and returns immediately. Poll GET /api/v1/jobs/{job_id} for per-stage "
                "progress; when status is 'succeeded', fetch the result from /api/v1/investigations/{investigation_id}."
)
async def start_investigation_job(payload: InvestigationRequest, request: Request, background: BackgroundTasks,
                                  principal: Principal = Depends(require_role("analyst"))) -> Dict[str, Any]:
    ingested = IngestedInput.from_text(payload.text, metadata={"refang": payload.refang, **payload.metadata})
    return await _start_job(ingested, background, request, principal)


@router.post(
    "/jobs/file",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a Background File Investigation",
    description="Parses the upload now (so unsupported or oversized files fail fast), then investigates in the background."
)
async def start_file_investigation_job(
    request: Request,
    background: BackgroundTasks,
    file: UploadFile = File(..., description="File to investigate"),
    refang: bool = Form(default=True),
    principal: Principal = Depends(require_role("analyst")),
) -> Dict[str, Any]:
    ingested = await _ingest_upload(file, refang)
    return await _start_job(ingested, background, request, principal)
