"""
AbuseIPDB v2 provider — crowd-sourced IP abuse reputation.

Endpoint: GET https://api.abuseipdb.com/api/v2/check  (header `Key`)
"""

from app.integrations.http_provider import HTTPThreatIntelProvider
from app.integrations.models import LookupStatus, ProviderMetadata, ThreatIndicator, ThreatIntelResponse


class AbuseIPDBProvider(HTTPThreatIntelProvider):
    name = "AbuseIPDB"
    URL = "https://api.abuseipdb.com/api/v2/check"

    @property
    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(provider_name=self.name, supported_artifact_types=["ipv4", "ipv6"],
                                rate_limit_info={"daily_free_quota": 1000})

    async def lookup_ip(self, ip: str) -> ThreatIntelResponse:
        async def fetch() -> ThreatIntelResponse:
            status, body, latency, error = await self.request_json(
                "GET", self.URL, params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self.api_key, "Accept": "application/json"},
            )
            if status != 200 or not isinstance(body, dict):
                return self.map_http_failure(ip, "ipv4", status, latency, error)
            data = body.get("data", {})
            score = int(data.get("abuseConfidenceScore") or 0)
            indicators = []
            if score >= 25:
                indicators.append(ThreatIndicator(
                    category="Abusive IP",
                    severity="CRITICAL" if score >= 90 else "HIGH" if score >= 60 else "MEDIUM",
                    description=f"AbuseIPDB confidence of abuse {score}% from {data.get('totalReports', 0)} reports",
                    tags=["abuse"],
                ))
            if data.get("isTor"):
                indicators.append(ThreatIndicator(category="Tor Exit Node", severity="LOW",
                                                  description="Address is a Tor exit node", tags=["tor"]))
            return self.response(ip, "ipv4", status=LookupStatus.SUCCESS, confidence=round(score / 100, 2),
                                 threat_indicators=indicators, latency_ms=latency, raw_data={
                                     k: data.get(k) for k in ("abuseConfidenceScore", "totalReports", "countryCode",
                                                              "isp", "domain", "usageType", "isTor", "lastReportedAt")})
        return await self.cached_lookup(ip, "ipv4", fetch)
