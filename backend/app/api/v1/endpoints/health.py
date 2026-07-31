"""
ReconIQ Health Check Endpoint

HTTP GET /api/v1/health
Returns system operational status, version, and active environment.
"""

from fastapi import APIRouter, status
from app.core.config import settings
from app.schemas.health import HealthResponse

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="System Health Telemetry",
    description="Returns API status, backend version, and runtime environment details."
)
async def health_check() -> HealthResponse:
    """
    Returns platform health status.
    """
    return HealthResponse(
        status="healthy",
        app_name=settings.APP_NAME,
        version="0.1.0",
        environment=settings.ENVIRONMENT
    )
