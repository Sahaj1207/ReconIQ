"""
ReconIQ Threat Intelligence Framework Exceptions

Purpose:
Custom framework-level exception classes for external threat intelligence providers.

Responsibilities:
- Provide structured exception hierarchy for threat intel lookups, rate limits, and provider outages
- Prevent unhandled provider errors from propagating to the investigation pipeline

Future Extension Notes:
- Add HTTP status code mappings for external provider API responses.
"""


class ThreatIntelError(Exception):
    """Base exception class for all Threat Intelligence Framework errors."""
    def __init__(self, message: str, provider_name: str = "unknown") -> None:
        super().__init__(message)
        self.message = message
        self.provider_name = provider_name


class ProviderUnavailableError(ThreatIntelError):
    """Raised when an external threat intel provider API is unreachable or offline."""
    pass


class RateLimitExceededError(ThreatIntelError):
    """Raised when a provider API rate limit quota has been exceeded."""
    pass


class InvalidArtifactError(ThreatIntelError):
    """Raised when an artifact type is invalid or unsupported by a provider."""
    pass
