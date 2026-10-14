"""
Investigation history persistence and API tests (in-memory SQLite).
"""

import pytest

PHISH = "URGENT: account suspended. Verify your password at hxxps://paypal-account-security[.]xyz/signin"


@pytest.mark.asyncio
async def test_investigation_is_saved_listed_fetched_and_deleted(async_client):
    created = (await async_client.post("/api/v1/evidence/investigate", json={"text": PHISH})).json()
    inv_id = created["investigation_id"]

    listing = (await async_client.get("/api/v1/investigations", params={"q": "paypal"})).json()
    item = next(i for i in listing["items"] if i["investigation_id"] == inv_id)
    assert item["severity"] == "CRITICAL" and item["classification"] == "credential_harvesting"

    low = (await async_client.get("/api/v1/investigations", params={"severity": "low"})).json()["items"]
    assert inv_id not in {i["investigation_id"] for i in low}
    full = (await async_client.get(f"/api/v1/investigations/{inv_id}")).json()
    assert full["risk_assessment"]["total_score"] == created["risk_assessment"]["total_score"]
    assert full["analyst_report"]["generated_by"] == "template"

    stats = (await async_client.get("/api/v1/investigations/stats")).json()
    assert stats["total"] >= 1 and stats["by_severity"]["CRITICAL"] >= 1

    assert (await async_client.delete(f"/api/v1/investigations/{inv_id}")).status_code == 204
    assert (await async_client.get(f"/api/v1/investigations/{inv_id}")).status_code == 404
    assert (await async_client.delete(f"/api/v1/investigations/{inv_id}")).status_code == 404


@pytest.mark.asyncio
async def test_severity_filter_validation(async_client):
    assert (await async_client.get("/api/v1/investigations", params={"severity": "bogus"})).status_code == 422
