"""
ReconIQ Health Check Schemas

Pydantic DTO for system telemetry and health status endpoints.
"""

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check status telemetry response."""
    status: str = Field(default="healthy", description="System operational status")
    app_name: str = Field(..., description="Platform name")
    version: str = Field(..., description="Backend application version")
    environment: str = Field(..., description="Active runtime environment")
