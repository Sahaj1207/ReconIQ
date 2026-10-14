"""
Have I Been Pwned v3 provider — breach exposure context for email addresses.

Endpoint: GET https://haveibeenpwned.com/api/v3/breachedaccount/{email} (header `hibp-api-key`)
Breach exposure is context, not maliciousness, so indicators are INFORMATIONAL and never flag.
"""

import urllib.parse

from app.integrations.http_provider import HTTPThreatIntelProvider
from app.integrations.models import LookupStatus, ProviderMetadata, ThreatIndicator, ThreatIntelResponse


class HIBPProvider(HTTPThreatIntelProvider):
    name = "Have I Been Pwned"
    URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"

    def __init__(self, *args, **kwargs) -> None:
        kwargs.setdefault("max_requests_per_minute", 10)
        super().__init__(*args, **kwargs)

    @property
    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(provider_name=self.name, supported_artifact_types=["email"])

    async def lookup_email(self, email: str) -> ThreatIntelResponse:
        async def fetch() -> ThreatIntelResponse:
            status, body, latency, error = await self.request_json(
                "GET", self.URL + urllib.parse.quote(email), params={"truncateResponse": "true"},
                headers={"hibp-api-key": self.api_key})
            if status == 404:
                return self.response(email, "email", status=LookupStatus.SUCCESS, confidence=0.0, latency_ms=latency,
                                     raw_data={"breaches": []})
            if status != 200 or not isinstance(body, list):
                return self.map_http_failure(email, "email", status, latency, error)
            names = [b.get("Name") for b in body if isinstance(b, dict)]
            indicators = [ThreatIndicator(category="Breach Exposure", severity="INFORMATIONAL",
                                          description=f"Address appears in {len(names)} known breach(es)", tags=names[:10])]
            return self.response(email, "email", status=LookupStatus.SUCCESS, confidence=0.0,
                                 threat_indicators=indicators, latency_ms=latency, raw_data={"breaches": names})
        return await self.cached_lookup(email, "email", fetch)
