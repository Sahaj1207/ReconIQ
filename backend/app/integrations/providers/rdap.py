"""
RDAP registration-data provider (keyless) — domain age, registrar and status.

Endpoint: GET https://rdap.org/domain/{domain} (bootstraps to the authoritative registry)
Domain age feeds RULE_INT_004 (newly registered domain); this provider emits no verdict itself.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.integrations.http_provider import HTTPThreatIntelProvider
from app.integrations.models import LookupStatus, ProviderMetadata, ThreatIntelResponse
from app.risk_engine.content_rules import registrable_domain


def _registrar(body: Dict[str, Any]) -> Optional[str]:
    for entity in body.get("entities", []):
        if "registrar" in entity.get("roles", []):
            for item in (entity.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    return item[3]
            return entity.get("handle")
    return None


class RDAPProvider(HTTPThreatIntelProvider):
    name = "RDAP"
    requires_key = False
    URL = "https://rdap.org/domain/"

    @property
    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(provider_name=self.name, supported_artifact_types=["domain"])

    async def lookup_domain(self, domain: str) -> ThreatIntelResponse:
        reg = registrable_domain(domain)

        async def fetch() -> ThreatIntelResponse:
            status, body, latency, error = await self.request_json("GET", self.URL + reg, follow_redirects=True)
            if status == 404:
                return self.response(domain, "domain", status=LookupStatus.SUCCESS, confidence=0.0, latency_ms=latency,
                                     raw_data={"registrable_domain": reg, "status": "not_registered"})
            if status != 200 or not isinstance(body, dict):
                return self.map_http_failure(domain, "domain", status, latency, error)
            events = {e.get("eventAction"): e.get("eventDate") for e in body.get("events", [])}
            registered = events.get("registration")
            age_days = None
            if registered:
                try:
                    created = datetime.fromisoformat(registered.replace("Z", "+00:00"))
                    age_days = (datetime.now(timezone.utc) - created).days
                except ValueError:
                    pass
            return self.response(domain, "domain", status=LookupStatus.SUCCESS, confidence=0.0, latency_ms=latency, raw_data={
                "registrable_domain": reg,
                "registered": registered,
                "expires": events.get("expiration"),
                "domain_age_days": age_days,
                "registrar": _registrar(body),
                "status": body.get("status", []),
            })
        res = await self.cached_lookup(reg, "domain", fetch)
        # Cache is keyed by registrable domain; report against the artifact actually queried
        return res.model_copy(update={"artifact": domain})
