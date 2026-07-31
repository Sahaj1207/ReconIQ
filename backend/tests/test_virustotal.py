"""
ReconIQ VirusTotal Provider Unit Tests
"""

import pytest
import time
import httpx
from app.integrations.providers.virustotal import VirusTotalProvider
from app.integrations.models import LookupStatus


@pytest.mark.asyncio
async def test_virustotal_successful_domain_lookup():
    """Test successful 200 OK domain lookup on VirusTotal."""
    mock_payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 12,
                    "suspicious": 2,
                    "harmless": 70,
                    "undetected": 5
                },
                "reputation": -15,
                "tags": ["phishing", "malware"],
                "categories": {"Forcepoint": "phishing"}
            }
        }
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert "x-apikey" in request.headers
        assert request.headers["x-apikey"] == "test_api_key_123"
        return httpx.Response(200, json=mock_payload)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = VirusTotalProvider(api_key="test_api_key_123")
        res = await provider._execute_request(
            endpoint="https://www.virustotal.com/api/v3/domains/malicious-site.com",
            artifact="malicious-site.com",
            artifact_type="domain",
            client=client
        )

    assert res.status == LookupStatus.SUCCESS
    assert res.confidence >= 0.5
    assert len(res.threat_indicators) >= 2
    categories = [ind.category for ind in res.threat_indicators]
    assert "Malicious Detection" in categories
    assert "Phishing" in categories or "Known Malware" in categories


@pytest.mark.asyncio
async def test_virustotal_404_not_found():
    """Test 404 Not Found response (unseen artifact)."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = VirusTotalProvider(api_key="test_api_key_123")
        res = await provider._execute_request(
            endpoint="https://www.virustotal.com/api/v3/domains/clean-site.com",
            artifact="clean-site.com",
            artifact_type="domain",
            client=client
        )

    assert res.status == LookupStatus.SUCCESS
    assert res.confidence == 0.5
    assert res.raw_data.get("status") == "not_found"


@pytest.mark.asyncio
async def test_virustotal_401_unauthorized():
    """Test 401 Unauthorized API key response."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"code": "WrongCredentialsError"}})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = VirusTotalProvider(api_key="invalid_key")
        res = await provider._execute_request(
            endpoint="https://www.virustotal.com/api/v3/domains/test.com",
            artifact="test.com",
            artifact_type="domain",
            client=client
        )

    assert res.status == LookupStatus.FAILED
    assert "authentication error" in res.error_message.lower()


@pytest.mark.asyncio
async def test_virustotal_429_rate_limited():
    """Test 429 Rate Limited response."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": {"code": "QuotaExceededError"}})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = VirusTotalProvider(api_key="test_key")
        res = await provider._execute_request(
            endpoint="https://www.virustotal.com/api/v3/domains/test.com",
            artifact="test.com",
            artifact_type="domain",
            client=client
        )

    assert res.status == LookupStatus.RATE_LIMITED
    assert "rate limit" in res.error_message.lower()


@pytest.mark.asyncio
async def test_virustotal_cache_hit_and_expiration():
    """Test in-memory cache hit and expiration."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"harmless": 50}}}})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = VirusTotalProvider(api_key="test_key", cache_ttl=0.2)

        # 1st request -> Cache miss (calls API)
        res1 = await provider._execute_request("https://www.virustotal.com/api/v3/domains/cached.com", "cached.com", "domain", client=client)
        assert call_count == 1
        assert res1.status == LookupStatus.SUCCESS

        # 2nd request -> Cache hit (no API call)
        res2 = await provider._execute_request("https://www.virustotal.com/api/v3/domains/cached.com", "cached.com", "domain", client=client)
        assert call_count == 1  # count unchanged!
        assert res2.status == LookupStatus.SUCCESS

        # Wait for cache TTL expiration
        time.sleep(0.25)

        # 3rd request -> Cache expired (calls API again)
        res3 = await provider._execute_request("https://www.virustotal.com/api/v3/domains/cached.com", "cached.com", "domain", client=client)
        assert call_count == 2


@pytest.mark.asyncio
async def test_virustotal_retry_on_500():
    """Test transient retry logic on HTTP 500 server error."""
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(500, text="Internal Server Error")
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"harmless": 20}}}})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = VirusTotalProvider(api_key="test_key", max_retries=2)
        res = await provider._execute_request("https://www.virustotal.com/api/v3/domains/retry.com", "retry.com", "domain", client=client)

    assert attempts == 2
    assert res.status == LookupStatus.SUCCESS


@pytest.mark.asyncio
async def test_virustotal_timeout():
    """Test timeout handling."""
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("Read timeout")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = VirusTotalProvider(api_key="test_key", max_retries=0)
        res = await provider._execute_request("https://www.virustotal.com/api/v3/domains/timeout.com", "timeout.com", "domain", client=client)

    assert res.status == LookupStatus.UNAVAILABLE
    assert "Network failure" in res.error_message or "timeout" in res.error_message.lower()


@pytest.mark.asyncio
async def test_virustotal_malformed_json():
    """Test malformed JSON response handling."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="{invalid_json}")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = VirusTotalProvider(api_key="test_key")
        res = await provider._execute_request("https://www.virustotal.com/api/v3/domains/malformed.com", "malformed.com", "domain", client=client)

    assert res.status == LookupStatus.FAILED
    assert "Malformed VirusTotal JSON" in res.error_message


@pytest.mark.asyncio
async def test_virustotal_unsupported_email():
    """Test UNSUPPORTED response for email lookup."""
    provider = VirusTotalProvider(api_key="test_key")
    res = await provider.lookup_email("user@example.com")

    assert res.status == LookupStatus.UNSUPPORTED
    assert res.provider == "VirusTotal"
