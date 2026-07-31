"""
ReconIQ Threat Intelligence Integrations Framework Package

Purpose:
Enterprise-grade, provider-agnostic Threat Intelligence Framework enabling ReconIQ to communicate
with external intelligence providers through a unified async interface.

Responsibilities:
- Provide BaseThreatIntelProvider abstract class contract
- Provide ThreatIntelManager facade for plugin registration, concurrent lookup dispatching, and response aggregation
- Provide Pydantic v2 response DTO models and custom framework exception classes

Extension Guide for Future Providers:
1. Subclass `BaseThreatIntelProvider`.
2. Override `metadata` with provider details (name, version, supported artifact types).
3. Implement specific lookup methods (`lookup_url`, `lookup_domain`, `lookup_ip`, `lookup_email`, `lookup_hash`).
4. Register the provider instance into `ThreatIntelManager` via `manager.register_provider()`.
"""

from app.integrations.base import BaseThreatIntelProvider
from app.integrations.manager import ThreatIntelManager
from app.integrations.models import (
    LookupStatus,
    ProviderMetadata,
    ThreatIndicator,
    ThreatIntelResponse
)
from app.integrations.exceptions import (
    ThreatIntelError,
    ProviderUnavailableError,
    RateLimitExceededError,
    InvalidArtifactError
)

__all__ = [
    "BaseThreatIntelProvider",
    "ThreatIntelManager",
    "LookupStatus",
    "ProviderMetadata",
    "ThreatIndicator",
    "ThreatIntelResponse",
    "ThreatIntelError",
    "ProviderUnavailableError",
    "RateLimitExceededError",
    "InvalidArtifactError",
]
