"""
ReconIQ Central v1 API Router

Includes version 1 endpoint routers for evidence collection and system health telemetry.
"""

from fastapi import APIRouter
from app.api.v1.endpoints import evidence, health, investigations

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health"])
api_router.include_router(evidence.router, prefix="/evidence", tags=["Evidence Collector"])
api_router.include_router(investigations.router, prefix="/investigations", tags=["Investigations"])
