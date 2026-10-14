"""
ReconIQ Investigation Pipeline Models

Purpose:
Reusable Pydantic v2 Data Transfer Objects (DTOs) for the Investigation Pipeline Orchestrator.

Responsibilities:
- Define request and response structures for investigations
- Track stage execution metrics, durations, status codes, warnings, and errors

Future Extension Notes:
- Standardized STIX 2.1 Investigation Bundle export schemas.
"""

from enum import Enum
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class StageStatus(str, Enum):
    """Pipeline stage execution status."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class StageMetric(BaseModel):
    """
    Execution metric for an individual pipeline stage.
    """
    stage_name: str = Field(..., description="Name of the pipeline stage")
    status: StageStatus = Field(..., description="Stage execution status")
    duration_ms: float = Field(..., description="Stage execution latency in milliseconds")
    error: Optional[str] = Field(default=None, description="Sanitized error details if stage failed")


class InvestigationRequest(BaseModel):
    """
    API Request model for initiating a threat investigation.
    """
    text: str = Field(
        ...,
        min_length=1,
        max_length=500000,
        description="Raw threat text snippet, email content, or log payload",
        examples=["Alert: phishing email from test[at]example[dot]com containing link hxxps://bad-site[.]com"]
    )
    source_type: str = Field(default="raw_text", description="Ingestion channel source type")
    refang: bool = Field(default=True, description="Whether to refang defanged indicators")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Optional request metadata")


class InvestigationResult(BaseModel):
    """
    Complete structured response object returned by InvestigationPipeline.
    """
    investigation_id: str = Field(..., description="Unique UUID identifier for the investigation")
    status: str = Field(..., description="Overall investigation status ('success', 'partial_success', 'failed')")
    duration_ms: float = Field(..., description="Total end-to-end pipeline execution time in milliseconds")
    pipeline_version: str = Field(default="1.0.0", description="Version of the investigation pipeline engine")
    source_type: str = Field(default="raw_text", description="Ingestion channel the evidence arrived through")
    source_name: Optional[str] = Field(default=None, description="Original filename for file submissions")
    input_preview: str = Field(default="", description="First characters of the analysed text")
    ingestion: Dict[str, Any] = Field(default_factory=dict, description="Structured file / email analysis from ingestion parsers")
    evidence_summary: Optional[Dict[str, Any]] = Field(default=None, description="Summary counts of extracted evidence")
    validation_summary: Optional[Dict[str, Any]] = Field(default=None, description="Summary of structural validation results")
    threat_summary: Optional[Dict[str, Any]] = Field(default=None, description="Summary of threat intelligence findings")
    risk_summary: Optional[Dict[str, Any]] = Field(default=None, description="Summary of deterministic risk assessment")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Raw extracted evidence artifacts")
    normalized_evidence: Dict[str, Any] = Field(default_factory=dict, description="Normalized canonical evidence artifacts")
    validation_results: Dict[str, Any] = Field(default_factory=dict, description="Categorized structural validation DTOs")
    threat_intelligence: Dict[str, Any] = Field(default_factory=dict, description="Categorized threat intel provider responses")
    risk_assessment: Optional[Dict[str, Any]] = Field(default=None, description="Full RiskAssessment report DTO")
    analyst_report: Optional[Dict[str, Any]] = Field(default=None, description="AI Analyst narrative (explanatory only)")
    warnings: List[str] = Field(default_factory=list, description="Accumulated non-fatal warnings")
    errors: List[str] = Field(default_factory=list, description="Accumulated sanitized stage execution errors")
    execution_metrics: List[StageMetric] = Field(default_factory=list, description="Per-stage execution timing & telemetry")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of investigation completion"
    )
