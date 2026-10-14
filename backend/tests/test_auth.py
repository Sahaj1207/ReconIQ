"""
User accounts, roles, ownership and audit log tests.
"""

import uuid

import pytest

from app.api.v1.endpoints import auth as auth_endpoints
from app.core.config import settings

PHISH = "URGENT: account suspended. Verify your password at hxxps://paypal-account-security[.]xyz/signin"


def email(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


@pytest.fixture
def auth_on(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "BOOTSTRAP_ADMIN_EMAIL", "")
    monkeypatch.setattr(settings, "SIGNUP_ROLE", "analyst")


async def signup(client, address, password="correct-horse-1"):
    res = await client.post("/api/v1/auth/register", json={"email": address, "password": password, "name": "T"})
    assert res.status_code == 201, res.text
    body = res.json()
    return {"Authorization": f"Bearer {body['access_token']}"}, body["user"]


async def make_admin(client, monkeypatch):
    admin_email = email("admin")
    monkeypatch.setattr(settings, "BOOTSTRAP_ADMIN_EMAIL", admin_email)
    headers, user = await signup(client, admin_email)
    assert user["role"] == "admin"
    return headers, user


@pytest.mark.asyncio
async def test_auth_required_when_enabled(async_client, auth_on):
    assert (await async_client.get("/api/v1/investigations")).status_code == 401
    assert (await async_client.get("/api/v1/health")).status_code == 200
    cfg = (await async_client.get("/api/v1/auth/config")).json()
    assert cfg["auth_required"] is True and cfg["signup_open"] is True


@pytest.mark.asyncio
async def test_bootstrap_admin_and_signup_roles(async_client, auth_on, monkeypatch):
    admin_headers, _ = await make_admin(async_client, monkeypatch)
    analyst_headers, analyst = await signup(async_client, email("analyst"))
    assert analyst["role"] == "analyst"
    me = (await async_client.get("/api/v1/auth/me", headers=analyst_headers)).json()
    assert me["role"] == "analyst" and me["user"]["email"] == analyst["email"]
    # duplicate email
    dup = await async_client.post("/api/v1/auth/register", json={"email": analyst["email"], "password": "another-pass-1"})
    assert dup.status_code == 409


@pytest.mark.asyncio
async def test_login_and_bad_credentials(async_client, auth_on):
    address = email("login")
    await signup(async_client, address, password="s3cret-password")
    bad = await async_client.post("/api/v1/auth/login", json={"email": address, "password": "nope-nope"})
    assert bad.status_code == 401
    ok = await async_client.post("/api/v1/auth/login", json={"email": address.upper(), "password": "s3cret-password"})
    assert ok.status_code == 200 and ok.json()["user"]["last_login_at"]
    garbage = await async_client.get("/api/v1/investigations", headers={"Authorization": "Bearer not-a-token"})
    assert garbage.status_code == 401


@pytest.mark.asyncio
async def test_signup_disabled_and_short_password(async_client, auth_on, monkeypatch):
    monkeypatch.setattr(settings, "SIGNUP_ROLE", "disabled")
    res = await async_client.post("/api/v1/auth/register", json={"email": email("closed"), "password": "long-enough-1"})
    assert res.status_code == 403
    monkeypatch.setattr(settings, "SIGNUP_ROLE", "analyst")
    res = await async_client.post("/api/v1/auth/register", json={"email": email("short"), "password": "short"})
    assert res.status_code == 422


def test_first_user_becomes_admin_without_bootstrap(monkeypatch):
    monkeypatch.setattr(settings, "BOOTSTRAP_ADMIN_EMAIL", "")
    monkeypatch.setattr(auth_endpoints.users, "count", lambda **kw: 0)
    assert auth_endpoints._signup_role("first@example.com") == "admin"
    monkeypatch.setattr(auth_endpoints.users, "count", lambda **kw: 3)
    assert auth_endpoints._signup_role("later@example.com") == "analyst"


@pytest.mark.asyncio
async def test_roles_ownership_and_audit(async_client, auth_on, monkeypatch):
    admin_headers, _ = await make_admin(async_client, monkeypatch)
    a1_headers, a1 = await signup(async_client, email("a1"))
    a2_headers, _ = await signup(async_client, email("a2"))

    # admin creates a viewer; viewer can read but not investigate
    viewer_email = email("viewer")
    created = await async_client.post("/api/v1/users", headers=admin_headers,
                                      json={"email": viewer_email, "password": "viewer-pass-1", "role": "viewer"})
    assert created.status_code == 201
    viewer_login = (await async_client.post("/api/v1/auth/login", json={"email": viewer_email, "password": "viewer-pass-1"})).json()
    viewer_headers = {"Authorization": f"Bearer {viewer_login['access_token']}"}
    assert (await async_client.post("/api/v1/evidence/investigate", headers=viewer_headers, json={"text": PHISH})).status_code == 403
    assert (await async_client.get("/api/v1/investigations", headers=viewer_headers)).status_code == 200

    inv = (await async_client.post("/api/v1/evidence/investigate", headers=a1_headers, json={"text": PHISH})).json()
    inv_id = inv["investigation_id"]
    full = (await async_client.get(f"/api/v1/investigations/{inv_id}", headers=viewer_headers)).json()
    assert full["owner_email"] == a1["email"]
    mine = (await async_client.get("/api/v1/investigations", headers=a2_headers, params={"mine": "true"})).json()
    assert inv_id not in {i["investigation_id"] for i in mine["items"]}

    # another analyst can't delete it; the admin can
    assert (await async_client.delete(f"/api/v1/investigations/{inv_id}", headers=a2_headers)).status_code == 403
    assert (await async_client.delete(f"/api/v1/investigations/{inv_id}", headers=admin_headers)).status_code == 204

    # non-admins can't manage users or read the audit log
    assert (await async_client.get("/api/v1/users", headers=a1_headers)).status_code == 403
    assert (await async_client.get("/api/v1/audit", headers=a1_headers)).status_code == 403
    actions = {e["action"] for e in (await async_client.get("/api/v1/audit", headers=admin_headers,
                                                             params={"limit": 200})).json()["items"]}
    assert {"user.registered", "user.created", "auth.login", "investigation.created", "investigation.deleted"} <= actions


@pytest.mark.asyncio
async def test_user_management_guards(async_client, auth_on, monkeypatch):
    admin_headers, admin = await make_admin(async_client, monkeypatch)
    _, analyst = await signup(async_client, email("managed"))

    promoted = await async_client.patch(f"/api/v1/users/{analyst['id']}", headers=admin_headers, json={"role": "viewer"})
    assert promoted.json()["role"] == "viewer"
    assert (await async_client.delete(f"/api/v1/users/{admin['id']}", headers=admin_headers)).status_code == 409
    deactivated = await async_client.patch(f"/api/v1/users/{analyst['id']}", headers=admin_headers, json={"is_active": False})
    assert deactivated.json()["is_active"] is False
    login = await async_client.post("/api/v1/auth/login", json={"email": analyst["email"], "password": "correct-horse-1"})
    assert login.status_code == 401
    assert (await async_client.delete(f"/api/v1/users/{analyst['id']}", headers=admin_headers)).status_code == 204


@pytest.mark.asyncio
async def test_change_password(async_client, auth_on):
    headers, user = await signup(async_client, email("pw"), password="first-password")
    wrong = await async_client.post("/api/v1/auth/change-password", headers=headers,
                                    json={"current_password": "nope", "new_password": "second-password"})
    assert wrong.status_code == 400
    ok = await async_client.post("/api/v1/auth/change-password", headers=headers,
                                 json={"current_password": "first-password", "new_password": "second-password"})
    assert ok.status_code == 204
    login = await async_client.post("/api/v1/auth/login", json={"email": user["email"], "password": "second-password"})
    assert login.status_code == 200


def test_password_hashing():
    from app.auth.passwords import hash_password, verify_password
    h = hash_password("hunter22-long")
    assert h.startswith("scrypt$") and verify_password("hunter22-long", h)
    assert not verify_password("wrong", h) and not verify_password("x", "garbage")
