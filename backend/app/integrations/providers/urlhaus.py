"""
abuse.ch URLhaus provider — malware distribution URLs, hosts and payload hashes.

Endpoints (POST, header `Auth-Key`): /v1/url/, /v1/host/, /v1/payload/
"""

from app.integrations.http_provider import HTTPThreatIntelProvider
from app.integrations.models import LookupStatus, ProviderMetadata, ThreatIndicator, ThreatIntelResponse


class URLhausProvider(HTTPThreatIntelProvider):
    name = "URLhaus"
    BASE = "https://urlhaus-api.abuse.ch/v1/"

    @property
    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(provider_name=self.name, supported_artifact_types=["url", "domain", "ipv4", "hash"])

    async def _query(self, artifact: str, artifact_type: str, endpoint: str, form: dict) -> ThreatIntelResponse:
        async def fetch() -> ThreatIntelResponse:
            status, body, latency, error = await self.request_json(
                "POST", self.BASE + endpoint, data=form, headers={"Auth-Key": self.api_key})
            if status != 200 or not isinstance(body, dict):
                return self.map_http_failure(artifact, artifact_type, status, latency, error)
            qs = body.get("query_status")
            if qs in ("no_results", "invalid_url", "invalid_host"):
                return self.response(artifact, artifact_type, status=LookupStatus.SUCCESS, confidence=0.5,
                                     latency_ms=latency, raw_data={"query_status": qs})
            if qs != "ok":
                return self.failure(artifact, artifact_type, LookupStatus.FAILED, f"URLhaus query_status={qs}", latency)
            indicators = []
            if endpoint == "url/":
                indicators.append(ThreatIndicator(
                    category="Malware URL", severity="CRITICAL" if body.get("url_status") == "online" else "HIGH",
                    description=f"Listed on URLhaus as {body.get('threat', 'malware')} ({body.get('url_status')})",
                    tags=body.get("tags") or []))
            elif endpoint == "host/":
                count = int(body.get("url_count") or 0)
                if count:
                    indicators.append(ThreatIndicator(category="Malware Host", severity="HIGH",
                                                      description=f"Host served {count} malware URL(s) on URLhaus", tags=["malware"]))
            else:
                indicators.append(ThreatIndicator(category="Known Malware Payload", severity="CRITICAL",
                                                  description=f"Payload known to URLhaus: {body.get('signature') or body.get('file_type')}",
                                                  tags=["malware"]))
            return self.response(artifact, artifact_type, status=LookupStatus.SUCCESS, confidence=0.9 if indicators else 0.5,
                                 threat_indicators=indicators, latency_ms=latency,
                                 raw_data={k: v for k, v in body.items() if k not in ("urls", "payloads")})
        return await self.cached_lookup(artifact, artifact_type, fetch)

    async def lookup_url(self, url: str) -> ThreatIntelResponse:
        return await self._query(url, "url", "url/", {"url": url})

    async def lookup_domain(self, domain: str) -> ThreatIntelResponse:
        return await self._query(domain, "domain", "host/", {"host": domain})

    async def lookup_ip(self, ip: str) -> ThreatIntelResponse:
        return await self._query(ip, "ipv4", "host/", {"host": ip})

    async def lookup_hash(self, file_hash: str) -> ThreatIntelResponse:
        field = "sha256_hash" if len(file_hash) == 64 else "md5_hash"
        if len(file_hash) not in (32, 64):
            return self._unsupported_response(file_hash, "hash")
        return await self._query(file_hash, "hash", "payload/", {field: file_hash})
