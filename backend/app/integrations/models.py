"""
ReconIQ Threat Intelligence Response Models

Purpose:
Reusable Pydantic v2 data models for external threat intelligence provider metadata and responses.

Responsibilities:
- Standardize provider responses across diverse intelligence sources
- Encapsulate status, confidence ratings, threat indicators, raw payloads, and execution latency

Future Extension Notes:
- Standardized STIX 2.1 indicator mappings.
"""

from enum import Enum
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class LookupStatus(str, Enum):
    """Execution status for threat intelligence lookups."""
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"


class ProviderMetadata(BaseModel):
    """
    Metadata declaration for a Threat Intelligence provider plugin.
    """
    provider_name: str = Field(..., description="Unique name of the provider (e.g. VirusTotal, AbuseIPDB)")
    provider_version: str = Field(default="1.0.0", description="Version of the provider integration client")
    supported_artifact_types: List[str] = Field(
        default_factory=list,
        description="Supported artifact types (e.g. ['url', 'domain', 'ipv4', 'ipv6', 'email', 'hash'])"
    )
    rate_limit_info: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional rate limit quota info (e.g. requests per minute, daily limits)"
    )


class ThreatIndicator(BaseModel):
    """
    Individual threat indicator / rule match extracted from provider intelligence.
    """
    category: str = Field(..., description="Threat category (e.g. phishing, malware, spam)")
    severity: str = Field(default="UNKNOWN", description="Severity level reported by provider")
    description: Optional[str] = Field(default=None, description="Detailed threat description")
    tags: List[str] = Field(default_factory=list, description="Keywords or tags attached to the threat")


class ThreatIntelResponse(BaseModel):
    """
    Standardized Threat Intelligence Response DTO returned by all providers.
    """
    provider: str = Field(..., description="Name of the provider returning intelligence")
    artifact: str = Field(..., description="Target artifact string queried")
    artifact_type: str = Field(..., description="Category of target artifact")
    status: LookupStatus = Field(default=LookupStatus.SUCCESS, description="Lookup execution status")
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Normalized confidence score (0.0 = low/no data, 1.0 = absolute consensus)"
    )
    threat_indicators: List[ThreatIndicator] = Field(
        default_factory=list,
        description="List of detected threat indicators or findings"
    )
    raw_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Raw provider JSON response payload for deep inspection"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp when lookup completed"
    )
    latency_ms: float = Field(default=0.0, description="Lookup latency in milliseconds")
    error_message: Optional[str] = Field(default=None, description="Error details if lookup failed or was rate limited")
