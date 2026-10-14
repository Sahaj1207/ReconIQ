"""
ReconIQ Threat Intelligence Manager

Purpose:
Orchestrates provider registrations, lookup dispatching, concurrent provider execution,
and response aggregation across external threat intelligence clients.

Responsibilities:
- Register and unregister threat intel provider plugins
- Dispatch lookups concurrently using asyncio.gather across providers supporting target artifact types
- Isolate provider exceptions to guarantee partial intelligence returns even if a provider fails
- Collect performance latency telemetry and provide structured audit logging

Future Extension Notes:
- Connection pooling, async rate limit throttling queues, and Redis lookup caching.
"""

import time
import asyncio
import logging
from typing import List, Dict, Optional, Any, Union

from app.integrations.base import BaseThreatIntelProvider
from app.integrations.models import ThreatIntelResponse, LookupStatus

logger = logging.getLogger(__name__)


class ThreatIntelManager:
    """
    Central Manager for Threat Intelligence provider plugins.
    """

    def __init__(self, providers: Optional[List[BaseThreatIntelProvider]] = None) -> None:
        """
        Initializes ThreatIntelManager with optional list of providers.

        Args:
            providers (Optional[List[BaseThreatIntelProvider]]): Initial provider clients.
        """
        self._providers: Dict[str, BaseThreatIntelProvider] = {}
        if providers:
            for p in providers:
                self.register_provider(p)

    def register_provider(self, provider: BaseThreatIntelProvider) -> None:
        """
        Registers a new threat intel provider plugin.

        Args:
            provider (BaseThreatIntelProvider): Subclass instance of BaseThreatIntelProvider.
        """
        if not isinstance(provider, BaseThreatIntelProvider):
            raise TypeError("Provider must implement BaseThreatIntelProvider interface.")

        name = provider.metadata.provider_name
        self._providers[name] = provider
        logger.info(
            f"Registered Threat Intel Provider: [{name} v{provider.metadata.provider_version}] | "
            f"Supported Artifacts: {provider.metadata.supported_artifact_types}"
        )

    def unregister_provider(self, provider_name: str) -> bool:
        """
        Unregisters a threat intel provider plugin by name.

        Args:
            provider_name (str): Name of the provider to remove.

        Returns:
            bool: True if provider was removed, False if not found.
        """
        if provider_name in self._providers:
            del self._providers[provider_name]
            logger.info(f"Unregistered Threat Intel Provider: [{provider_name}]")
            return True
        logger.warning(f"Attempted to unregister unknown provider: [{provider_name}]")
        return False

    def get_provider(self, provider_name: str) -> Optional[BaseThreatIntelProvider]:
        """
        Retrieves a registered provider instance by name.

        Args:
            provider_name (str): Provider name string.

        Returns:
            Optional[BaseThreatIntelProvider]: Provider instance or None.
        """
        return self._providers.get(provider_name)

    def _normalize_type(self, artifact_type: str) -> str:
        """Helper to map plural category names (e.g. domains -> domain, urls -> url)."""
        s = artifact_type.lower().strip()
        category_map = {
            "domains": "domain",
            "urls": "url",
            "emails": "email",
            "phone_numbers": "phone",
            "phones": "phone",
            "hashes": "hash",
        }
        return category_map.get(s, s)

    def get_providers_for_artifact(self, artifact_type: str) -> List[BaseThreatIntelProvider]:
        """
        Retrieves all registered providers supporting the given artifact type.

        Args:
            artifact_type (str): Category string (e.g. 'url', 'urls', 'ipv4', 'domain', 'domains').

        Returns:
            List[BaseThreatIntelProvider]: List of supporting provider instances.
        """
        target_type = self._normalize_type(artifact_type)
        supporting = []
        for p in self._providers.values():
            types = [self._normalize_type(t) for t in p.metadata.supported_artifact_types]
            if target_type in types or "all" in types:
                supporting.append(p)
        return supporting

    async def lookup_artifact(self, artifact: str, artifact_type: str) -> List[ThreatIntelResponse]:
        """
        Dispatches async lookups concurrently across all providers supporting the artifact type.

        Args:
            artifact (str): Artifact string to query.
            artifact_type (str): Artifact type category.

        Returns:
            List[ThreatIntelResponse]: Aggregated provider responses.
        """
        start_time = time.perf_counter()
        supporting_providers = self.get_providers_for_artifact(artifact_type)

        if not supporting_providers:
            logger.debug(f"No providers registered supporting artifact type '{artifact_type}' for '{artifact}'")
            return []

        logger.info(
            f"Dispatching threat intel lookup for [{artifact_type}] '{artifact}' "
            f"across {len(supporting_providers)} providers"
        )

        # Launch lookups concurrently via asyncio.gather with return_exceptions=True
        # Providers expect singular types (e.g. "url"), not pipeline categories ("urls").
        provider_type = self._normalize_type(artifact_type)
        tasks = [p.lookup(artifact, provider_type) for p in supporting_providers]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        responses: List[ThreatIntelResponse] = []
        for provider, res in zip(supporting_providers, raw_results):
            if isinstance(res, Exception):
                logger.error(
                    f"Provider [{provider.metadata.provider_name}] raised unhandled error during lookup: {res}",
                    exc_info=True
                )
                responses.append(ThreatIntelResponse(
                    provider=provider.metadata.provider_name,
                    artifact=artifact,
                    artifact_type=artifact_type,
                    status=LookupStatus.FAILED,
                    confidence=0.0,
                    error_message=f"Unhandled exception: {str(res)}"
                ))
            elif isinstance(res, ThreatIntelResponse):
                responses.append(res)

        total_latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        successful_count = sum(1 for r in responses if r.status == LookupStatus.SUCCESS)
        logger.info(
            f"Completed threat intel lookup for '{artifact}' | Providers: {len(responses)} | "
            f"Successful: {successful_count} | Latency: {total_latency_ms}ms"
        )

        return responses

    async def lookup_all(self, evidence: Dict[str, Any]) -> Dict[str, List[ThreatIntelResponse]]:
        """
        Runs lookups for all categorized artifacts in an evidence dictionary.

        Args:
            evidence (Dict[str, Any]): Dictionary containing artifact lists or ValidationResult objects.

        Returns:
            Dict[str, List[ThreatIntelResponse]]: Categorized responses dictionary.
        """
        start_time = time.perf_counter()
        aggregated: Dict[str, List[ThreatIntelResponse]] = {}

        for category, items in evidence.items():
            aggregated[category] = []
            for item in items:
                # Support string artifacts or ValidationResult objects
                artifact_str = item.artifact if hasattr(item, "artifact") else str(item)
                # Skip invalid items if item is ValidationResult and invalid
                if hasattr(item, "valid") and not item.valid:
                    continue

                responses = await self.lookup_artifact(artifact_str, category)
                aggregated[category].extend(responses)

        total_latency = round((time.perf_counter() - start_time) * 1000, 2)
        total_responses = sum(len(v) for v in aggregated.values())

        logger.info(
            f"Threat Intel Manager lookup_all completed | Categories: {len(aggregated)} | "
            f"Total Responses: {total_responses} | Total Duration: {total_latency}ms"
        )

        return aggregated
