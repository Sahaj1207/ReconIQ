"""
API key authentication, rate limiting, security headers and capabilities tests.
"""

import pytest

from app.core.config import settings


@pytest.mark.asyncio
async def test_auth_disabled_by_default(async_client):
    assert (await async_client.get("/api/v1/investigations")).status_code == 200


@pytest.mark.asyncio
async def test_api_key_required_when_configured(async_client, monkeypatch):
    monkeypatch.setattr(settings, "API_KEYS", "alpha-key, beta-key")
    assert (await async_client.get("/api/v1/investigations")).status_code == 401
    assert (await async_client.get("/api/v1/investigations", headers={"X-API-Key": "wrong"})).status_code == 401
    assert (await async_client.get("/api/v1/investigations", headers={"X-API-Key": "beta-key"})).status_code == 200
    assert (await async_client.get("/api/v1/investigations", headers={"Authorization": "Bearer alpha-key"})).status_code == 200
    # Health stays public for load balancers
    assert (await async_client.get("/api/v1/health")).status_code == 200


@pytest.mark.asyncio
async def test_rate_limit(async_client, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 3)
    monkeypatch.setattr(settings, "API_KEYS", "rate-limit-test-client")
    headers = {"X-API-Key": "rate-limit-test-client"}
    codes = [(await async_client.get("/api/v1/investigations", headers=headers)).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    limited = await async_client.get("/api/v1/investigations", headers=headers)
    assert int(limited.headers["Retry-After"]) >= 1
    assert (await async_client.get("/api/v1/health", headers=headers)).status_code == 200


@pytest.mark.asyncio
async def test_security_headers_and_version(async_client):
    res = await async_client.get("/api/v1/health")
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.json()["version"] == "1.0.0"


@pytest.mark.asyncio
async def test_capabilities(async_client):
    caps = (await async_client.get("/api/v1/system/capabilities")).json()
    assert caps["analyst"]["mode"] == "template"
    assert caps["ingestion"]["qr_decoding"] is True
    assert {p["name"] for p in caps["threat_intel"]} >= {"VirusTotal", "AbuseIPDB", "RDAP"}
    assert len(caps["rules"]) == 35


@pytest.mark.asyncio
async def test_rate_limited_response_keeps_cors_headers(async_client, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 1)
    monkeypatch.setattr(settings, "API_KEYS", "cors-test-client")
    headers = {"X-API-Key": "cors-test-client", "Origin": "http://localhost:5173"}
    await async_client.get("/api/v1/investigations", headers=headers)
    limited = await async_client.get("/api/v1/investigations", headers=headers)
    assert limited.status_code == 429
    assert limited.headers["access-control-allow-origin"] == "http://localhost:5173"


@pytest.mark.asyncio
async def test_health_reports_database_failure_without_going_down(async_client, monkeypatch):
    from app.api.v1.endpoints import health
    from app.db import database

    def broken():
        raise RuntimeError("boom")
    monkeypatch.setattr(health, "init_db", broken)
    monkeypatch.setattr(database, "_db_error", "OperationalError: connection to server failed")
    body = (await async_client.get("/api/v1/health")).json()
    assert body["status"] == "degraded" and body["database"] == "unavailable"
    assert body["database_error"].startswith("OperationalError")


def test_database_errors_never_include_credentials():
    from app.db.database import describe_error
    msg = describe_error(RuntimeError('cannot connect to postgresql://user:hunter2@db.example.com:6543/postgres password=hunter2'))
    assert "hunter2" not in msg and msg.startswith("RuntimeError: cannot connect")
