"""
Shodan InternetDB provider (keyless) — open ports, CPEs, known CVEs and tags for an IP.

Endpoint: GET https://internetdb.shodan.io/{ip}
"""

from app.integrations.http_provider import HTTPThreatIntelProvider
from app.integrations.models import LookupStatus, ProviderMetadata, ThreatIndicator, ThreatIntelResponse

MALICIOUS_TAGS = {"malware", "c2", "compromised", "botnet", "scanner", "honeypot"}


class ShodanInternetDBProvider(HTTPThreatIntelProvider):
    name = "Shodan InternetDB"
    requires_key = False
    URL = "https://internetdb.shodan.io/"

    @property
    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(provider_name=self.name, supported_artifact_types=["ipv4", "ipv6"])

    async def lookup_ip(self, ip: str) -> ThreatIntelResponse:
        async def fetch() -> ThreatIntelResponse:
            status, body, latency, error = await self.request_json("GET", self.URL + ip)
            if status == 404:
                return self.response(ip, "ipv4", status=LookupStatus.SUCCESS, confidence=0.3, latency_ms=latency,
                                     raw_data={"status": "no_data"})
            if status != 200 or not isinstance(body, dict):
                return self.map_http_failure(ip, "ipv4", status, latency, error)
            tags = [t.lower() for t in body.get("tags", [])]
            vulns = body.get("vulns", [])
            indicators = []
            bad = sorted(MALICIOUS_TAGS.intersection(tags) - {"honeypot"})
            if bad:
                indicators.append(ThreatIndicator(category="Malicious Host Tag", severity="HIGH",
                                                  description=f"Shodan tags: {', '.join(bad)}", tags=bad))
            if vulns:
                indicators.append(ThreatIndicator(category="Exposed Vulnerabilities", severity="LOW",
                                                  description=f"{len(vulns)} known CVE(s) exposed, e.g. {', '.join(vulns[:3])}",
                                                  tags=["cve"]))
            return self.response(ip, "ipv4", status=LookupStatus.SUCCESS, confidence=0.6 if bad else 0.4,
                                 threat_indicators=indicators, latency_ms=latency, raw_data=body)
        return await self.cached_lookup(ip, "ipv4", fetch)
