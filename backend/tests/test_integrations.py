"""
ReconIQ Threat Intelligence Framework Unit Tests
"""

import pytest
from typing import Dict, Any
from app.integrations.base import BaseThreatIntelProvider
from app.integrations.manager import ThreatIntelManager
from app.integrations.models import (
    ProviderMetadata,
    ThreatIntelResponse,
    ThreatIndicator,
    LookupStatus
)
from app.integrations.exceptions import (
    ThreatIntelError,
    ProviderUnavailableError,
    RateLimitExceededError,
    InvalidArtifactError
)


# --- Mock Provider Implementations for Testing ---

class MockVirusTotalProvider(BaseThreatIntelProvider):
    """Synthetic mock provider simulating VirusTotal lookups."""
    @property
    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            provider_name="MockVirusTotal",
            provider_version="1.0.0",
            supported_artifact_types=["url", "domain", "ipv4", "hash"]
        )

    async def lookup_domain(self, domain: str) -> ThreatIntelResponse:
        return ThreatIntelResponse(
            provider=self.metadata.provider_name,
            artifact=domain,
            artifact_type="domain",
            status=LookupStatus.SUCCESS,
            confidence=0.9,
            threat_indicators=[
                ThreatIndicator(category="phishing", severity="HIGH", description="Domain flagged in malicious DB")
            ],
            raw_data={"positives": 15, "total": 90}
        )

    async def lookup_ip(self, ip: str) -> ThreatIntelResponse:
        return ThreatIntelResponse(
            provider=self.metadata.provider_name,
            artifact=ip,
            artifact_type="ipv4",
            status=LookupStatus.SUCCESS,
            confidence=0.85,
            threat_indicators=[
                ThreatIndicator(category="c2", severity="CRITICAL", description="Known C2 IP node")
            ]
        )


class MockAbuseIPDBProvider(BaseThreatIntelProvider):
    """Synthetic mock provider simulating AbuseIPDB lookups."""
    @property
    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            provider_name="MockAbuseIPDB",
            provider_version="1.0.0",
            supported_artifact_types=["ipv4", "ipv6"]
        )

    async def lookup_ip(self, ip: str) -> ThreatIntelResponse:
        return ThreatIntelResponse(
            provider=self.metadata.provider_name,
            artifact=ip,
            artifact_type="ipv4",
            status=LookupStatus.SUCCESS,
            confidence=0.95,
            raw_data={"abuseConfidenceScore": 100}
        )


class FailingMockProvider(BaseThreatIntelProvider):
    """Synthetic mock provider that simulates network failure / exception."""
    @property
    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            provider_name="FailingProvider",
            provider_version="1.0.0",
            supported_artifact_types=["ipv4", "domain"]
        )

    async def lookup(self, artifact: str, artifact_type: str) -> ThreatIntelResponse:
        raise ProviderUnavailableError("Simulated API connection failure", provider_name=self.metadata.provider_name)


# --- Unit Test Cases ---

def test_provider_registration_and_removal():
    """Test registering and unregistering providers in ThreatIntelManager."""
    manager = ThreatIntelManager()
    vt_provider = MockVirusTotalProvider()

    manager.register_provider(vt_provider)
    assert manager.get_provider("MockVirusTotal") is not None
    assert len(manager.get_providers_for_artifact("domain")) == 1

    # Unregister
    removed = manager.unregister_provider("MockVirusTotal")
    assert removed is True
    assert manager.get_provider("MockVirusTotal") is None
    assert len(manager.get_providers_for_artifact("domain")) == 0


@pytest.mark.asyncio
async def test_multi_provider_lookup_aggregation():
    """Test lookups dispatched across multiple supporting providers."""
    vt = MockVirusTotalProvider()
    abuse = MockAbuseIPDBProvider()
    manager = ThreatIntelManager([vt, abuse])

    responses = await manager.lookup_artifact("198.51.100.45", "ipv4")

    assert len(responses) == 2
    providers_returned = {r.provider for r in responses}
    assert "MockVirusTotal" in providers_returned
    assert "MockAbuseIPDB" in providers_returned
    assert all(r.status == LookupStatus.SUCCESS for r in responses)


@pytest.mark.asyncio
async def test_provider_failure_isolation():
    """Test that a failing provider does not crash manager and returns partial results from working providers."""
    vt = MockVirusTotalProvider()
    failing = FailingMockProvider()
    manager = ThreatIntelManager([vt, failing])

    responses = await manager.lookup_artifact("malicious-site.com", "domain")

    assert len(responses) == 2
    vt_res = next(r for r in responses if r.provider == "MockVirusTotal")
    failing_res = next(r for r in responses if r.provider == "FailingProvider")

    assert vt_res.status == LookupStatus.SUCCESS
    assert vt_res.confidence == 0.9

    assert failing_res.status == LookupStatus.FAILED
    assert "Simulated API connection failure" in failing_res.error_message


@pytest.mark.asyncio
async def test_unsupported_artifact_type():
    """Test querying a provider with an unsupported artifact type."""
    abuse = MockAbuseIPDBProvider()
    res = await abuse.lookup("https://example.com", "url")

    assert res.status == LookupStatus.UNSUPPORTED
    assert "unsupported" in res.error_message.lower()


def test_exception_classes():
    """Test custom exception instantiations."""
    err = RateLimitExceededError("Rate limit 100/min exceeded", provider_name="MockVT")
    assert isinstance(err, ThreatIntelError)
    assert err.provider_name == "MockVT"
    assert "Rate limit" in str(err)


@pytest.mark.asyncio
async def test_lookup_all_facade():
    """Test lookup_all() manager facade on evidence dictionary."""
    vt = MockVirusTotalProvider()
    abuse = MockAbuseIPDBProvider()
    manager = ThreatIntelManager([vt, abuse])

    evidence = {
        "ipv4": ["198.51.100.45"],
        "domains": ["malicious-site.com"],
        "urls": []
    }

    results = await manager.lookup_all(evidence)

    assert "ipv4" in results
    assert "domains" in results
    assert len(results["ipv4"]) == 2  # VT + AbuseIPDB
    assert len(results["domains"]) == 1  # VT only


@pytest.mark.asyncio
async def test_manager_normalizes_plural_categories_before_provider_lookup():
    """Pipeline categories like 'urls' must reach providers as 'url', not be rejected as unsupported."""
    manager = ThreatIntelManager()
    manager.register_provider(MockVirusTotalProvider())
    results = await manager.lookup_all({"domains": ["example.com"]})
    assert [r.status for r in results["domains"]] == [LookupStatus.SUCCESS]
