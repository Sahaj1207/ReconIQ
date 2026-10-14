"""
Google Safe Browsing v4 Lookup API provider — phishing, malware and unwanted-software URLs.

Endpoint: POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key=...
"""

from app.integrations.http_provider import HTTPThreatIntelProvider
from app.integrations.models import LookupStatus, ProviderMetadata, ThreatIndicator, ThreatIntelResponse

THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


class SafeBrowsingProvider(HTTPThreatIntelProvider):
    name = "Google Safe Browsing"
    URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    @property
    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(provider_name=self.name, supported_artifact_types=["url", "domain"])

    async def _check(self, artifact: str, artifact_type: str, target: str) -> ThreatIntelResponse:
        async def fetch() -> ThreatIntelResponse:
            payload = {
                "client": {"clientId": "reconiq", "clientVersion": "1.0.0"},
                "threatInfo": {"threatTypes": THREAT_TYPES, "platformTypes": ["ANY_PLATFORM"],
                               "threatEntryTypes": ["URL"], "threatEntries": [{"url": target}]},
            }
            status, body, latency, error = await self.request_json("POST", self.URL, params={"key": self.api_key}, json=payload)
            if status != 200 or not isinstance(body, dict):
                return self.map_http_failure(artifact, artifact_type, status, latency, error)
            matches = body.get("matches", [])
            indicators = [ThreatIndicator(
                category=m.get("threatType", "THREAT").replace("_", " ").title(),
                severity="CRITICAL" if m.get("threatType") == "MALWARE" else "HIGH",
                description=f"Google Safe Browsing match: {m.get('threatType')} on {m.get('platformType')}",
                tags=[m.get("threatType", "").lower()],
            ) for m in matches]
            return self.response(artifact, artifact_type, status=LookupStatus.SUCCESS, confidence=0.95 if matches else 0.6,
                                 threat_indicators=indicators, latency_ms=latency, raw_data={"matches": matches})
        return await self.cached_lookup(artifact, artifact_type, fetch)

    async def lookup_url(self, url: str) -> ThreatIntelResponse:
        return await self._check(url, "url", url)

    async def lookup_domain(self, domain: str) -> ThreatIntelResponse:
        return await self._check(domain, "domain", f"http://{domain}/")
