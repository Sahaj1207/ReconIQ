"""
ReconIQ Base Threat Intelligence Provider Interface

Purpose:
Abstract Base Class interface for all ReconIQ Threat Intelligence Provider plugins.

Responsibilities:
- Define standard async lookup methods (lookup_url, lookup_domain, lookup_ip, lookup_email, lookup_hash)
- Enforce ProviderMetadata declarations (provider_name, version, supported types)
- Provide central lookup() dispatcher for dynamic artifact types

Future Extension Notes:
- Plugin registry for auto-discovery of third-party integration modules.

Extension Guide for Future Providers:
1. Subclass BaseThreatIntelProvider.
2. Override the `metadata` property with provider specifications.
3. Implement specific lookup methods (e.g. lookup_url, lookup_domain) or override central lookup().
4. Register instance with ThreatIntelManager.
"""

from abc import ABC, abstractmethod
import time
import logging
from typing import Dict, Any, Optional

from app.integrations.models import (
    ProviderMetadata,
    ThreatIntelResponse,
    LookupStatus
)
from app.integrations.exceptions import (
    ThreatIntelError,
    InvalidArtifactError
)

logger = logging.getLogger(__name__)


class BaseThreatIntelProvider(ABC):
    """
    Abstract Base Class for all external Threat Intelligence API clients.
    """

    @property
    @abstractmethod
    def metadata(self) -> ProviderMetadata:
        """Returns ProviderMetadata declaration object."""
        pass

    async def lookup(self, artifact: str, artifact_type: str) -> ThreatIntelResponse:
        """
        Central async dispatcher routing artifacts to specific type lookup methods.

        Args:
            artifact (str): The artifact string to query.
            artifact_type (str): Type category ('url', 'domain', 'ipv4', 'ipv6', 'email', 'hash').

        Returns:
            ThreatIntelResponse: Standardized threat intelligence response DTO.
        """
        start_time = time.perf_counter()
        normalized_type = artifact_type.lower().strip()

        if normalized_type not in self.metadata.supported_artifact_types:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ThreatIntelResponse(
                provider=self.metadata.provider_name,
                artifact=artifact,
                artifact_type=artifact_type,
                status=LookupStatus.UNSUPPORTED,
                confidence=0.0,
                latency_ms=latency_ms,
                error_message=f"Artifact type '{artifact_type}' is unsupported by provider '{self.metadata.provider_name}'"
            )

        try:
            if normalized_type == "url":
                res = await self.lookup_url(artifact)
            elif normalized_type == "domain":
                res = await self.lookup_domain(artifact)
            elif normalized_type in ("ipv4", "ipv6", "ip"):
                res = await self.lookup_ip(artifact)
            elif normalized_type == "email":
                res = await self.lookup_email(artifact)
            elif normalized_type in ("hash", "md5", "sha1", "sha256"):
                res = await self.lookup_hash(artifact)
            else:
                raise InvalidArtifactError(
                    f"Unknown artifact type '{artifact_type}'",
                    provider_name=self.metadata.provider_name
                )

            res.latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return res

        except ThreatIntelError as tie:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.warning(f"Provider '{self.metadata.provider_name}' threat error on '{artifact}': {tie.message}")
            return ThreatIntelResponse(
                provider=self.metadata.provider_name,
                artifact=artifact,
                artifact_type=artifact_type,
                status=LookupStatus.FAILED,
                confidence=0.0,
                latency_ms=latency_ms,
                error_message=tie.message
            )
        except Exception as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.error(f"Unhandled provider error in '{self.metadata.provider_name}' for '{artifact}': {exc}", exc_info=True)
            return ThreatIntelResponse(
                provider=self.metadata.provider_name,
                artifact=artifact,
                artifact_type=artifact_type,
                status=LookupStatus.FAILED,
                confidence=0.0,
                latency_ms=latency_ms,
                error_message=f"Unhandled provider exception: {str(exc)}"
            )

    async def lookup_url(self, url: str) -> ThreatIntelResponse:
        """Default fallback method for URL lookups."""
        return self._unsupported_response(url, "url")

    async def lookup_domain(self, domain: str) -> ThreatIntelResponse:
        """Default fallback method for Domain lookups."""
        return self._unsupported_response(domain, "domain")

    async def lookup_ip(self, ip: str) -> ThreatIntelResponse:
        """Default fallback method for IP lookups."""
        return self._unsupported_response(ip, "ipv4")

    async def lookup_email(self, email: str) -> ThreatIntelResponse:
        """Default fallback method for Email lookups."""
        return self._unsupported_response(email, "email")

    async def lookup_hash(self, file_hash: str) -> ThreatIntelResponse:
        """Default fallback method for File Hash lookups."""
        return self._unsupported_response(file_hash, "hash")

    def _unsupported_response(self, artifact: str, artifact_type: str) -> ThreatIntelResponse:
        """Helper generating default unsupported response."""
        return ThreatIntelResponse(
            provider=self.metadata.provider_name,
            artifact=artifact,
            artifact_type=artifact_type,
            status=LookupStatus.UNSUPPORTED,
            confidence=0.0,
            error_message=f"Specific lookup method for '{artifact_type}' not implemented by provider"
        )
