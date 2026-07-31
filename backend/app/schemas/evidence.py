"""
ReconIQ Evidence Schemas

Defines API requests and responses for the Ingestion & Evidence Collection system.
"""

from typing import Optional
from pydantic import BaseModel, Field
from app.schemas.ioc import IOCResults, IOCSummary


class EvidenceCollectionRequest(BaseModel):
    """Request payload for extracting evidence/IOCs from raw text."""
    text: str = Field(
        ...,
        min_length=1,
        max_length=500000,
        description="Raw threat text snippet or log payload containing potential indicators",
        examples=["Alert: suspicious email from test[at]example[dot]com with link hxxps://bad-site[.]com"]
    )
    refang: bool = Field(
        default=True,
        description="Whether to refang defanged indicators (e.g. hxxps -> https, [.] -> .)"
    )


class EvidenceCollectionResponse(BaseModel):
    """Structured response object containing extracted artifacts and extraction telemetry."""
    status: str = Field(default="success", description="Status of the extraction operation")
    execution_time_ms: float = Field(..., description="Extraction execution latency in milliseconds")
    summary: IOCSummary = Field(..., description="Count breakdowns of extracted indicators")
    results: IOCResults = Field(..., description="Categorized lists of extracted indicators")
