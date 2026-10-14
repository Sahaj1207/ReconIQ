"""
ReconIQ Central v1 API Router

Health is public; every other router requires an API key when API_KEYS is configured.
"""

from fastapi import APIRouter, Depends
from app.api.v1.endpoints import evidence, health, investigations, system
from app.core.security import require_api_key

api_router = APIRouter()
protected = [Depends(require_api_key)]

api_router.include_router(health.router, tags=["Health"])
api_router.include_router(evidence.router, prefix="/evidence", tags=["Evidence Collector"], dependencies=protected)
api_router.include_router(investigations.router, prefix="/investigations", tags=["Investigations"], dependencies=protected)
api_router.include_router(system.router, prefix="/system", tags=["System"], dependencies=protected)
