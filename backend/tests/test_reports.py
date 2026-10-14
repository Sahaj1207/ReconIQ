"""
Report export tests: STIX 2.1 structure, Markdown defanging, PDF rendering.
"""

import pytest

from tests.test_ingestion import build_eml

TEXT = ("URGENT: account suspended. Verify your password at hxxps://paypal-account-security[.]xyz/signin "
        "or download hxxp://update-cdn[.]net/a/stage2.exe from 45.33.32.156 hash 44d88612fea8a8f36de82e1278abb02f")


@pytest.fixture
async def investigation(async_client):
    return (await async_client.post("/api/v1/evidence/investigate", json={"text": TEXT})).json()


@pytest.mark.asyncio
async def test_stix_bundle(async_client, investigation):
    res = await async_client.get(f"/api/v1/investigations/{investigation['investigation_id']}/report", params={"format": "stix"})
    assert res.status_code == 200 and "stix" in res.headers["content-type"]
    bundle = res.json()
    by_type = {}
    for obj in bundle["objects"]:
        by_type.setdefault(obj["type"], []).append(obj)
    assert bundle["type"] == "bundle"
    assert {"identity", "report", "url", "domain-name", "ipv4-addr", "file", "indicator", "attack-pattern", "relationship"} <= set(by_type)
    report = by_type["report"][0]
    ids = {o["id"] for o in bundle["objects"]}
    assert set(report["object_refs"]) <= ids
    assert all(o["spec_version"] == "2.1" for o in bundle["objects"] if o["type"] != "bundle")
    patterns = {i["pattern"] for i in by_type["indicator"]}
    assert "[url:value = 'http://update-cdn.net/a/stage2.exe']" in patterns
    file_obj = by_type["file"][0]
    assert file_obj["hashes"] == {"MD5": "44d88612fea8a8f36de82e1278abb02f"}
    # Deterministic SCO ids: same value -> same id across exports
    again = (await async_client.get(f"/api/v1/investigations/{investigation['investigation_id']}/report", params={"format": "stix"})).json()
    assert {o["id"] for o in again["objects"] if o["type"] == "url"} == {o["id"] for o in by_type["url"]}


@pytest.mark.asyncio
async def test_markdown_report_is_defanged(async_client, investigation):
    res = await async_client.get(f"/api/v1/investigations/{investigation['investigation_id']}/report", params={"format": "markdown"})
    md = res.text
    assert res.status_code == 200 and md.startswith("# ReconIQ Investigation Report")
    assert "paypal-account-security[.]xyz" in md
    assert "https://paypal-account-security.xyz" not in md
    assert "## MITRE ATT&CK" in md and "T1105" in md


@pytest.mark.asyncio
async def test_pdf_report(async_client, investigation):
    res = await async_client.get(f"/api/v1/investigations/{investigation['investigation_id']}/report", params={"format": "pdf"})
    assert res.status_code == 200 and res.headers["content-type"] == "application/pdf"
    assert res.content.startswith(b"%PDF-") and len(res.content) > 2000


@pytest.mark.asyncio
async def test_email_reports_render(async_client):
    inv = (await async_client.post("/api/v1/evidence/investigate/file",
                                   files={"file": ("m.eml", build_eml(), "message/rfc822")})).json()
    for fmt in ("markdown", "pdf"):
        res = await async_client.get(f"/api/v1/investigations/{inv['investigation_id']}/report", params={"format": fmt})
        assert res.status_code == 200
    assert "## Email Analysis" in (await async_client.get(
        f"/api/v1/investigations/{inv['investigation_id']}/report", params={"format": "markdown"})).text


@pytest.mark.asyncio
async def test_report_errors(async_client):
    assert (await async_client.get("/api/v1/investigations/nope/report")).status_code == 404
