"""
Shared HTTP plumbing for threat-intelligence providers.

Gives every provider the same in-memory TTL cache, sliding-window rate limiting, bounded retries
on 5xx / network errors, and uniform error-to-ThreatIntelResponse mapping, so individual provider
modules only describe endpoints and how to interpret payloads.
"""

import asyncio
import logging
import time
from typing import Any, Dict, Optional, Tuple

import httpx

from app.integrations.base import BaseThreatIntelProvider
from app.integrations.models import LookupStatus, ThreatIntelResponse
from app.integrations.providers.virustotal import CacheEntry, SlidingWindowRateLimiter

logger = logging.getLogger(__name__)

HttpResult = Tuple[Optional[int], Any, float, Optional[str]]  # status, json, latency_ms, error


class HTTPThreatIntelProvider(BaseThreatIntelProvider):
    """Base class for JSON-over-HTTP providers."""

    name = "HTTPProvider"
    requires_key = True

    def __init__(
        self,
        api_key: str = "",
        timeout: float = 8.0,
        cache_ttl: float = 900.0,
        max_requests_per_minute: int = 30,
        max_retries: int = 1,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.max_retries = max_retries
        self._transport = transport  # injectable for tests (httpx.MockTransport)
        self._cache: Dict[str, CacheEntry] = {}
        self._rate_limiter = SlidingWindowRateLimiter(max_requests=max_requests_per_minute, window_seconds=60.0)

    @property
    def configured(self) -> bool:
        return bool(self.api_key) or not self.requires_key

    # --- response helpers ---

    def response(self, artifact: str, artifact_type: str, **kwargs: Any) -> ThreatIntelResponse:
        return ThreatIntelResponse(provider=self.name, artifact=artifact, artifact_type=artifact_type, **kwargs)

    def failure(self, artifact: str, artifact_type: str, status: LookupStatus, message: str, latency_ms: float = 0.0) -> ThreatIntelResponse:
        return self.response(artifact, artifact_type, status=status, confidence=0.0, latency_ms=latency_ms, error_message=message)

    # --- cached request execution ---

    async def cached_lookup(self, artifact: str, artifact_type: str, fetch) -> ThreatIntelResponse:
        """
        Runs `fetch()` (an async callable returning a ThreatIntelResponse) behind cache, key and
        rate-limit guards. Only successful responses are cached.
        """
        key = f"{artifact_type}:{artifact}"
        entry = self._cache.get(key)
        if entry and not entry.is_expired():
            return entry.response
        if not self.configured:
            return self.failure(artifact, artifact_type, LookupStatus.UNAVAILABLE, f"{self.name} is not configured")
        if not self._rate_limiter.allow_request():
            return self.failure(artifact, artifact_type, LookupStatus.RATE_LIMITED, f"{self.name} local rate limit reached")
        res = await fetch()
        if res.status == LookupStatus.SUCCESS:
            self._cache[key] = CacheEntry(res, self.cache_ttl)
        return res

    async def request_json(self, method: str, url: str, **kwargs: Any) -> HttpResult:
        """Performs an HTTP request with bounded retries. Never raises."""
        start = time.perf_counter()
        error: Optional[str] = None
        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout, transport=self._transport) as client:
                    resp = await client.request(method, url, headers={"User-Agent": "ReconIQ-ThreatIntel/1.0", **kwargs.pop("headers", {})}, **kwargs)
                latency = round((time.perf_counter() - start) * 1000, 2)
                if resp.status_code >= 500 and attempt < self.max_retries:
                    await asyncio.sleep(0.4 * (attempt + 1))
                    continue
                try:
                    body = resp.json()
                except ValueError:
                    body = None
                return resp.status_code, body, latency, None
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                error = f"Network failure: {type(exc).__name__}"
                if attempt < self.max_retries:
                    await asyncio.sleep(0.4 * (attempt + 1))
            except httpx.HTTPError as exc:
                error = f"HTTP error: {type(exc).__name__}"
                break
        return None, None, round((time.perf_counter() - start) * 1000, 2), error

    def map_http_failure(self, artifact: str, artifact_type: str, status: Optional[int], latency: float, error: Optional[str]) -> ThreatIntelResponse:
        """Translates a non-success HTTP outcome into a standard failure response."""
        if status is None:
            return self.failure(artifact, artifact_type, LookupStatus.UNAVAILABLE, error or f"{self.name} unreachable", latency)
        if status in (401, 403):
            return self.failure(artifact, artifact_type, LookupStatus.FAILED, f"{self.name} rejected the API key (HTTP {status})", latency)
        if status == 429:
            return self.failure(artifact, artifact_type, LookupStatus.RATE_LIMITED, f"{self.name} quota exceeded (HTTP 429)", latency)
        return self.failure(artifact, artifact_type, LookupStatus.FAILED, f"{self.name} returned HTTP {status}", latency)
