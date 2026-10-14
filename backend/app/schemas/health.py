"""
ReconIQ Health Check Schemas

Pydantic DTO for system telemetry and health status endpoints.
"""

from typing import Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check status telemetry response."""
    status: str = Field(default="healthy", description="System operational status")
    app_name: str = Field(..., description="Platform name")
    version: str = Field(..., description="Backend application version")
    environment: str = Field(..., description="Active runtime environment")
    database: str = Field(default="ok", description="'ok' or 'unavailable'")
    database_error: Optional[str] = Field(default=None, description="Why the database is unavailable (no credentials)")
