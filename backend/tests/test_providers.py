"""
Threat-intel provider tests using httpx.MockTransport (no network).
"""

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.integrations.models import LookupStatus
from app.integrations.providers.abuseipdb import AbuseIPDBProvider
from app.integrations.providers.shodan_internetdb import ShodanInternetDBProvider
from app.integrations.providers.rdap import RDAPProvider
from app.integrations.providers.urlhaus import URLhausProvider
from app.integrations.providers.safe_browsing import SafeBrowsingProvider
from app.integrations.providers.hibp import HIBPProvider
from app.integrations.registry import provider_status, build_default_manager
from app.risk_engine.rules import is_flagged_malicious


def transport(handler):
    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_abuseipdb_flags_abusive_ip():
    def handler(request):
        assert request.headers["Key"] == "k"
        assert request.url.params["ipAddress"] == "185.220.101.47"
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": 100, "totalReports": 900, "isTor": True}})
    res = await AbuseIPDBProvider(api_key="k", transport=transport(handler)).lookup("185.220.101.47", "ipv4")
    assert res.status == LookupStatus.SUCCESS
    assert res.confidence == 1.0
    assert {i.category for i in res.threat_indicators} == {"Abusive IP", "Tor Exit Node"}
    assert is_flagged_malicious(res)


@pytest.mark.asyncio
async def test_abuseipdb_failure_mapping_and_cache():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(401, json={})
    p = AbuseIPDBProvider(api_key="bad", transport=transport(handler))
    res = await p.lookup("8.8.8.8", "ipv4")
    assert res.status == LookupStatus.FAILED and "rejected the API key" in res.error_message


@pytest.mark.asyncio
async def test_unconfigured_provider_is_unavailable():
    res = await AbuseIPDBProvider(api_key="").lookup("8.8.8.8", "ipv4")
    assert res.status == LookupStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_network_failure_is_unavailable():
    def handler(request):
        raise httpx.ConnectError("boom")
    res = await ShodanInternetDBProvider(transport=transport(handler), max_retries=0).lookup("1.2.3.4", "ipv4")
    assert res.status == LookupStatus.UNAVAILABLE


@pytest.mark.asyncio
async def test_shodan_internetdb():
    def handler(request):
        if request.url.path == "/9.9.9.9":
            return httpx.Response(404, json={"detail": "No information available"})
        return httpx.Response(200, json={"ports": [443], "tags": ["c2"], "vulns": ["CVE-2021-44228"], "hostnames": []})
    p = ShodanInternetDBProvider(transport=transport(handler))
    hit = await p.lookup("45.33.32.156", "ipv4")
    assert is_flagged_malicious(hit)
    clean = await p.lookup("9.9.9.9", "ipv4")
    assert clean.status == LookupStatus.SUCCESS and not clean.threat_indicators


@pytest.mark.asyncio
async def test_rdap_domain_age_uses_registrable_domain():
    created = (datetime.now(timezone.utc) - timedelta(days=4)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def handler(request):
        assert request.url.path == "/domain/evil-new.com"
        return httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": created}],
                                         "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "NameCheap"]]]}]})
    res = await RDAPProvider(transport=transport(handler)).lookup("login.evil-new.com", "domain")
    assert res.artifact == "login.evil-new.com"
    assert res.raw_data["domain_age_days"] == 4
    assert res.raw_data["registrar"] == "NameCheap"
    assert not is_flagged_malicious(res)


@pytest.mark.asyncio
async def test_urlhaus_url_and_no_results():
    def handler(request):
        body = request.content.decode()
        if "clean" in body:
            return httpx.Response(200, json={"query_status": "no_results"})
        return httpx.Response(200, json={"query_status": "ok", "url_status": "online", "threat": "malware_download", "tags": ["emotet"]})
    p = URLhausProvider(api_key="k", transport=transport(handler))
    bad = await p.lookup("http://bad.example/x.exe", "url")
    assert bad.threat_indicators[0].severity == "CRITICAL"
    ok = await p.lookup("http://clean.example/", "url")
    assert ok.status == LookupStatus.SUCCESS and not ok.threat_indicators


@pytest.mark.asyncio
async def test_safe_browsing_match():
    def handler(request):
        return httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM"}]})
    res = await SafeBrowsingProvider(api_key="k", transport=transport(handler)).lookup("phish.example", "domain")
    assert res.threat_indicators[0].category == "Social Engineering"
    assert is_flagged_malicious(res)


@pytest.mark.asyncio
async def test_hibp_is_context_not_verdict():
    def handler(request):
        return httpx.Response(200, json=[{"Name": "Adobe"}, {"Name": "LinkedIn"}])
    res = await HIBPProvider(api_key="k", transport=transport(handler)).lookup("a@b.com", "email")
    assert res.raw_data["breaches"] == ["Adobe", "LinkedIn"]
    assert not is_flagged_malicious(res)


def test_registry_reports_status_and_skips_unconfigured():
    names = {p["name"]: p for p in provider_status()}
    assert names["VirusTotal"]["enabled"] is False  # no key in tests
    assert names["RDAP"]["requires_key"] is False
    assert build_default_manager().get_providers_for_artifact("url") == []
