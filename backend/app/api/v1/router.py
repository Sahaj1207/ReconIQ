"""
ReconIQ Central v1 API Router

Health and sign-in are public. Every other router resolves a principal (session token, API key,
or the implicit local admin when authentication is disabled); endpoints enforce roles.
"""

from fastapi import APIRouter, Depends
from app.api.v1.endpoints import auth, evidence, health, investigations, system
from app.auth.principal import current_principal

api_router = APIRouter()
protected = [Depends(current_principal)]

api_router.include_router(health.router, tags=["Health"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(auth.users_router, prefix="/users", tags=["Users"], dependencies=protected)
api_router.include_router(auth.audit_router, prefix="/audit", tags=["Audit"], dependencies=protected)
api_router.include_router(evidence.router, prefix="/evidence", tags=["Evidence Collector"], dependencies=protected)
api_router.include_router(investigations.router, prefix="/investigations", tags=["Investigations"], dependencies=protected)
api_router.include_router(system.router, prefix="/system", tags=["System"], dependencies=protected)
