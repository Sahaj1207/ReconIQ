"""
ReconIQ VirusTotal v3 Threat Intelligence Provider

Purpose:
Production-grade VirusTotal v3 REST API integration client implementing BaseThreatIntelProvider.

Architecture:
- Inherits from BaseThreatIntelProvider
- Communicates asynchronously via httpx.AsyncClient with timeout and transient retry support
- Provider-side sliding-window rate limiter (e.g. 4 requests/min default for free tier)
- In-memory TTL cache with configurable expiration
- Exception boundary mapping 401, 403, 404, 429, 5xx, timeouts, and connection errors to ThreatIntelResponse
- Normalizes VirusTotal v3 detection engine statistics into standardized ThreatIndicator DTOs

API Endpoints Used:
- GET https://www.virustotal.com/api/v3/domains/{domain}
- GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
- GET https://www.virustotal.com/api/v3/urls/{url_id} (base64 URL identifier)
- GET https://www.virustotal.com/api/v3/files/{file_hash}

Authentication:
- Header: x-apikey: <VIRUSTOTAL_API_KEY> (retrieved from environment variable VIRUSTOTAL_API_KEY)

Caching Behavior:
- In-memory key: 'virustotal:<artifact_type>:<artifact>'
- Cache hit returns cached ThreatIntelResponse with zero network latency
- Cache duration configurable (default: 300 seconds)

Rate Limiting:
- Enforces sliding window limit (default: 4 requests per 60 seconds)
- Exceeding limit immediately returns a LookupStatus.RATE_LIMITED ThreatIntelResponse without crashing
"""

import os
import re
import time
import base64
import asyncio
import logging
from typing import Dict, Any, Optional, List, Tuple
import httpx

from app.core.config import settings
from app.integrations.base import BaseThreatIntelProvider
from app.integrations.models import (
    ProviderMetadata,
    ThreatIntelResponse,
    ThreatIndicator,
    LookupStatus
)

logger = logging.getLogger(__name__)

# Engines that must agree before a VirusTotal detection counts as a malicious verdict
MIN_ENGINES_FOR_VERDICT = 3

# (indicator category, label pattern, severity when corroborated, description, tags)
THREAT_LABELS = [
    ("Phishing", re.compile(r"phishing"), "HIGH", "Categorized as phishing threat infrastructure", ["phishing"]),
    ("Known Malware", re.compile(r"malware|trojan"), "CRITICAL", "Associated with known malware distribution", ["malware"]),
    ("C2 / Botnet", re.compile(r"\bc2\b|botnet|command and control"), "CRITICAL",
     "Identified as Command & Control or Botnet infrastructure", ["c2", "botnet"]),
]


class CacheEntry:
    """In-memory cache entry wrapper."""
    def __init__(self, response: ThreatIntelResponse, ttl_seconds: float) -> None:
        self.response = response
        self.expires_at = time.time() + ttl_seconds

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class SlidingWindowRateLimiter:
    """Sliding-window rate limiter tracking requests per minute."""
    def __init__(self, max_requests: int = 4, window_seconds: float = 60.0) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.timestamps: List[float] = []

    def allow_request(self) -> bool:
        now = time.time()
        self.timestamps = [t for t in self.timestamps if now - t < self.window_seconds]
        if len(self.timestamps) >= self.max_requests:
            return False
        self.timestamps.append(now)
        return True


class VirusTotalProvider(BaseThreatIntelProvider):
    """
    Enterprise VirusTotal v3 Threat Intelligence Provider Client.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        cache_ttl: float = 300.0,
        max_requests_per_minute: int = 4,
        max_retries: int = 2
    ) -> None:
        """
        Initializes VirusTotalProvider instance.

        Args:
            api_key (Optional[str]): VirusTotal API key. Defaults to VIRUSTOTAL_API_KEY env var or settings.
            timeout (float): HTTP request timeout in seconds.
            cache_ttl (float): In-memory cache TTL in seconds.
            max_requests_per_minute (int): Sliding window rate limit cap.
            max_retries (int): Retries for transient 5xx or connection errors.
        """
        self.api_key = api_key or getattr(settings, "VIRUSTOTAL_API_KEY", "") or os.getenv("VIRUSTOTAL_API_KEY", "")
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.max_retries = max_retries
        self._cache: Dict[str, CacheEntry] = {}
        self._rate_limiter = SlidingWindowRateLimiter(max_requests=max_requests_per_minute, window_seconds=60.0)

    @property
    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            provider_name="VirusTotal",
            provider_version="1.0.0",
            supported_artifact_types=["url", "domain", "ipv4", "ipv6", "hash"],
            rate_limit_info={
                "requests_per_minute": self._rate_limiter.max_requests,
                "window_seconds": self._rate_limiter.window_seconds
            }
        )

    def _get_cache_key(self, artifact_type: str, artifact: str) -> str:
        return f"virustotal:{artifact_type.lower()}:{artifact.strip()}"

    def _get_from_cache(self, cache_key: str) -> Optional[ThreatIntelResponse]:
        entry = self._cache.get(cache_key)
        if entry:
            if not entry.is_expired():
                logger.info(f"[CACHE HIT] VirusTotal provider returning cached response for key '{cache_key}'")
                # Return cached object copy with fresh latency notation
                cached_res = entry.response.model_copy()
                cached_res.latency_ms = 0.0
                return cached_res
            else:
                logger.debug(f"[CACHE EXPIRED] Removing expired key '{cache_key}'")
                del self._cache[cache_key]
        logger.debug(f"[CACHE MISS] VirusTotal provider key '{cache_key}'")
        return None

    def _set_cache(self, cache_key: str, response: ThreatIntelResponse) -> None:
        if response.status in (LookupStatus.SUCCESS, LookupStatus.PARTIAL):
            self._cache[cache_key] = CacheEntry(response, self.cache_ttl)

    async def lookup_url(self, url: str) -> ThreatIntelResponse:
        """Looks up URL reputation on VirusTotal v3 API."""
        try:
            url_id = base64.urlsafe_b64encode(url.strip().encode("utf-8")).decode("utf-8").strip("=")
            endpoint = f"{self.BASE_URL}/urls/{url_id}"
            return await self._execute_request(endpoint=endpoint, artifact=url, artifact_type="url")
        except Exception as exc:
            return self._error_response(url, "url", f"URL encoding error: {str(exc)}")

    async def lookup_domain(self, domain: str) -> ThreatIntelResponse:
        """Looks up domain reputation on VirusTotal v3 API."""
        endpoint = f"{self.BASE_URL}/domains/{domain.strip().lower()}"
        return await self._execute_request(endpoint=endpoint, artifact=domain, artifact_type="domain")

    async def lookup_ip(self, ip: str) -> ThreatIntelResponse:
        """Looks up IP address reputation on VirusTotal v3 API."""
        endpoint = f"{self.BASE_URL}/ip_addresses/{ip.strip()}"
        return await self._execute_request(endpoint=endpoint, artifact=ip, artifact_type="ipv4")

    async def lookup_hash(self, file_hash: str) -> ThreatIntelResponse:
        """Looks up file hash reputation on VirusTotal v3 API."""
        endpoint = f"{self.BASE_URL}/files/{file_hash.strip()}"
        return await self._execute_request(endpoint=endpoint, artifact=file_hash, artifact_type="hash")

    async def lookup_email(self, email: str) -> ThreatIntelResponse:
        """Email lookups are unsupported by VirusTotal."""
        return ThreatIntelResponse(
            provider=self.metadata.provider_name,
            artifact=email,
            artifact_type="email",
            status=LookupStatus.UNSUPPORTED,
            confidence=0.0,
            error_message="VirusTotal API does not support email reputation lookups directly"
        )

    async def _execute_request(
        self,
        endpoint: str,
        artifact: str,
        artifact_type: str,
        client: Optional[httpx.AsyncClient] = None
    ) -> ThreatIntelResponse:
        """
        Executes HTTP request with caching, rate-limiting, retries, and error handling.
        """
        cache_key = self._get_cache_key(artifact_type, artifact)
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached

        # Check API key configuration
        if not self.api_key:
            logger.warning(f"VirusTotal lookup skipped: VIRUSTOTAL_API_KEY is not configured")
            return ThreatIntelResponse(
                provider=self.metadata.provider_name,
                artifact=artifact,
                artifact_type=artifact_type,
                status=LookupStatus.FAILED,
                confidence=0.0,
                error_message="VirusTotal API key missing. Set VIRUSTOTAL_API_KEY in environment."
            )

        # Check rate limiter
        if not self._rate_limiter.allow_request():
            logger.warning(f"[RATE LIMITED] VirusTotal provider rate limit window exceeded for '{artifact}'")
            return ThreatIntelResponse(
                provider=self.metadata.provider_name,
                artifact=artifact,
                artifact_type=artifact_type,
                status=LookupStatus.RATE_LIMITED,
                confidence=0.0,
                error_message="VirusTotal provider rate limit exceeded (4 requests/min cap)"
            )

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ReconIQ-ThreatIntel/1.0"
        }

        start_time = time.perf_counter()
        logger.info(f"VirusTotal lookup started | Endpoint: [{endpoint}] | Artifact: '{artifact}'")

        # Execute HTTP request with retry logic
        attempt = 0
        response_obj: Optional[httpx.Response] = None
        error_detail: Optional[str] = None

        async def _do_fetch(c: httpx.AsyncClient) -> httpx.Response:
            return await c.get(endpoint, headers=headers, timeout=self.timeout)

        while attempt <= self.max_retries:
            attempt += 1
            try:
                if client is not None:
                    response_obj = await _do_fetch(client)
                else:
                    async with httpx.AsyncClient() as http_client:
                        response_obj = await _do_fetch(http_client)

                if response_obj.status_code < 500:
                    break  # Non-server error (2xx, 4xx) -> proceed to handle status code

                logger.warning(f"VirusTotal 5xx server error (status {response_obj.status_code}), attempt {attempt}/{self.max_retries + 1}")
                if attempt <= self.max_retries:
                    await asyncio.sleep(0.5 * attempt)

            except (httpx.TimeoutException, httpx.NetworkError) as net_err:
                error_detail = f"Network failure: {str(net_err)}"
                logger.warning(f"VirusTotal network error on attempt {attempt}/{self.max_retries + 1}: {net_err}")
                if attempt <= self.max_retries:
                    await asyncio.sleep(0.5 * attempt)
            except Exception as exc:
                error_detail = f"Request exception: {str(exc)}"
                break

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        if response_obj is None:
            return ThreatIntelResponse(
                provider=self.metadata.provider_name,
                artifact=artifact,
                artifact_type=artifact_type,
                status=LookupStatus.UNAVAILABLE,
                confidence=0.0,
                latency_ms=latency_ms,
                error_message=error_detail or "Failed to connect to VirusTotal API"
            )

        status_code = response_obj.status_code
        logger.info(f"VirusTotal HTTP status: {status_code} | Latency: {latency_ms}ms")

        # Status Code Handlers
        if status_code in (401, 403):
            return ThreatIntelResponse(
                provider=self.metadata.provider_name,
                artifact=artifact,
                artifact_type=artifact_type,
                status=LookupStatus.FAILED,
                confidence=0.0,
                latency_ms=latency_ms,
                error_message=f"VirusTotal API authentication error (HTTP {status_code}): Invalid or forbidden API key"
            )
        elif status_code == 429:
            return ThreatIntelResponse(
                provider=self.metadata.provider_name,
                artifact=artifact,
                artifact_type=artifact_type,
                status=LookupStatus.RATE_LIMITED,
                confidence=0.0,
                latency_ms=latency_ms,
                error_message="VirusTotal API rate limit quota exceeded (HTTP 429)"
            )
        elif status_code == 404:
            # 404 means artifact is not in VirusTotal dataset (unseen/clean)
            res = ThreatIntelResponse(
                provider=self.metadata.provider_name,
                artifact=artifact,
                artifact_type=artifact_type,
                status=LookupStatus.SUCCESS,
                confidence=0.5,
                latency_ms=latency_ms,
                raw_data={"status": "not_found", "message": "Artifact not found in VirusTotal dataset"}
            )
            self._set_cache(cache_key, res)
            return res
        elif status_code != 200:
            return ThreatIntelResponse(
                provider=self.metadata.provider_name,
                artifact=artifact,
                artifact_type=artifact_type,
                status=LookupStatus.FAILED,
                confidence=0.0,
                latency_ms=latency_ms,
                error_message=f"VirusTotal returned error status HTTP {status_code}"
            )

        # Parse 200 OK JSON payload
        try:
            json_data = response_obj.json()
            data_attr = json_data.get("data", {}).get("attributes", {})
        except Exception as json_err:
            return ThreatIntelResponse(
                provider=self.metadata.provider_name,
                artifact=artifact,
                artifact_type=artifact_type,
                status=LookupStatus.FAILED,
                confidence=0.0,
                latency_ms=latency_ms,
                error_message=f"Malformed VirusTotal JSON payload: {str(json_err)}"
            )

        # Extract indicators & confidence
        indicators, confidence = self._parse_attributes(data_attr)

        res = ThreatIntelResponse(
            provider=self.metadata.provider_name,
            artifact=artifact,
            artifact_type=artifact_type,
            status=LookupStatus.SUCCESS,
            confidence=confidence,
            threat_indicators=indicators,
            raw_data=json_data,
            latency_ms=latency_ms
        )

        self._set_cache(cache_key, res)
        return res

    def _parse_attributes(self, attributes: Dict[str, Any]) -> Tuple[List[ThreatIndicator], float]:
        """Parses VT v3 attributes dictionary into ThreatIndicator DTOs and confidence rating."""
        indicators: List[ThreatIndicator] = []

        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = sum(stats.values()) if stats else 1

        reputation = attributes.get("reputation", 0)
        tags = attributes.get("tags", [])
        categories = attributes.get("categories", {})

        # Confidence Calculation
        if malicious > 0:
            confidence = min(1.0, round(0.5 + (malicious / max(1, total_engines)) * 0.5, 2))
        elif suspicious > 0:
            confidence = 0.6
        else:
            confidence = 0.8  # Clean / harmless consensus

        # Generate Indicators. One or two engines out of ~90 is a weak signal (single-engine detections
        # are a common source of false positives), so it is reported as LOW and never as a verdict.
        if malicious >= MIN_ENGINES_FOR_VERDICT:
            indicators.append(ThreatIndicator(
                category="Malicious Detection",
                severity="HIGH" if malicious < 5 else "CRITICAL",
                description=f"Flagged as malicious by {malicious} security engine(s) on VirusTotal",
                tags=tags
            ))
        elif malicious > 0:
            indicators.append(ThreatIndicator(
                category="Malicious Detection",
                severity="LOW",
                description=f"Flagged as malicious by {malicious} security engine(s) on VirusTotal "
                            f"(below the {MIN_ENGINES_FOR_VERDICT}-engine threshold; isolated detections are often false positives)",
                tags=tags
            ))

        if suspicious > 0:
            indicators.append(ThreatIndicator(
                category="Suspicious Detection",
                severity="MEDIUM" if suspicious >= MIN_ENGINES_FOR_VERDICT else "LOW",
                description=f"Flagged as suspicious by {suspicious} engine(s) on VirusTotal",
                tags=[]
            ))

        if reputation < 0:
            indicators.append(ThreatIndicator(
                category="Low Reputation",
                severity="MEDIUM",
                description=f"VirusTotal community reputation score is negative ({reputation})",
                tags=[]
            ))

        # Threat categories. `categories` holds one label per categorisation vendor, so a single vendor's
        # label is a weak signal; VirusTotal's own tags or agreement between vendors make it a verdict.
        labels = [str(v).lower() for v in (categories.values() if isinstance(categories, dict) else categories)]
        tag_text = " ".join(tags).lower()
        for category, pattern, severity, description, ind_tags in THREAT_LABELS:
            vendors = sum(1 for label in labels if pattern.search(label))
            tagged = bool(pattern.search(tag_text))
            if not (vendors or tagged):
                continue
            strong = tagged or vendors >= 2
            indicators.append(ThreatIndicator(
                category=category,
                severity=severity if strong else "LOW",
                description=description if strong else f"{description} by 1 categorisation vendor only",
                tags=ind_tags
            ))

        votes = attributes.get("total_votes", {})
        if votes.get("malicious", 0) > votes.get("harmless", 0):
            indicators.append(ThreatIndicator(
                category="Community Flagged",
                severity="LOW",
                description=f"VirusTotal community votes flagged as malicious ({votes.get('malicious')} votes)",
                tags=[]
            ))

        return indicators, confidence

    def _error_response(self, artifact: str, artifact_type: str, message: str) -> ThreatIntelResponse:
        return ThreatIntelResponse(
            provider=self.metadata.provider_name,
            artifact=artifact,
            artifact_type=artifact_type,
            status=LookupStatus.FAILED,
            confidence=0.0,
            error_message=message
        )
