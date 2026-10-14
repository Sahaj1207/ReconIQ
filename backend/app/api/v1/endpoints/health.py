"""
ReconIQ Health Check Endpoint

HTTP GET /api/v1/health
Returns system operational status, version, and active environment.
"""

from fastapi import APIRouter, status
from fastapi.concurrency import run_in_threadpool
from app import __version__
from app.db.database import database_error, init_db
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
    Returns platform health status. The API itself stays up when the database is down, so the
    database is reported separately (status becomes "degraded").
    """
    try:
        await run_in_threadpool(init_db)  # no-op once migrations have succeeded
        db_error = None
    except Exception:
        db_error = database_error() or "unknown error"
    return HealthResponse(
        status="degraded" if db_error else "healthy",
        app_name=settings.APP_NAME,
        version=__version__,
        environment=settings.ENVIRONMENT,
        database="unavailable" if db_error else "ok",
        database_error=db_error,
    )
