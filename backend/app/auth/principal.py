"""
Request principals and role checks.

A principal is resolved from (in order) a session JWT, an API key, or — when authentication is
not required — an implicit local administrator so single-user/dev setups keep working.
"""

import hmac
from dataclasses import dataclass
from typing import Callable, Optional

from fastapi import Depends, HTTPException, Request, status

from app.core.config import settings

ROLES = ["viewer", "analyst", "admin"]


@dataclass(frozen=True)
class Principal:
    id: Optional[str]
    email: Optional[str]
    role: str
    kind: str  # "user" | "api_key" | "local"

    def has(self, role: str) -> bool:
        return ROLES.index(self.role) >= ROLES.index(role)


LOCAL_ADMIN = Principal(id=None, email=None, role="admin", kind="local")


def configured_keys() -> list:
    return [k.strip() for k in settings.API_KEYS.split(",") if k.strip()]


def auth_required() -> bool:
    return settings.AUTH_ENABLED or bool(configured_keys())


def extract_credential(request: Request) -> Optional[str]:
    key = request.headers.get("x-api-key")
    if key:
        return key.strip()
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def _unauthorized(detail: str = "Sign in required") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers={"WWW-Authenticate": "Bearer"})


def resolve_principal(request: Request) -> Principal:
    from app.auth.tokens import decode_token
    from app.auth.repository import UserRepository

    credential = extract_credential(request)
    if credential:
        if any(hmac.compare_digest(credential.encode(), k.encode()) for k in configured_keys()):
            role = settings.API_KEY_ROLE if settings.API_KEY_ROLE in ROLES else "analyst"
            return Principal(id=None, email="api-key", role=role, kind="api_key")
        claims = decode_token(credential)
        if claims:
            user = UserRepository().get(claims.get("sub", ""))
            if user and user["is_active"]:
                return Principal(id=user["id"], email=user["email"], role=user["role"], kind="user")
        raise _unauthorized("Invalid or expired credentials")
    if auth_required():
        raise _unauthorized()
    return LOCAL_ADMIN


async def current_principal(request: Request) -> Principal:
    principal = resolve_principal(request)
    request.state.principal = principal
    return principal


def require_role(role: str) -> Callable:
    async def checker(principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.has(role):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Requires the {role} role")
        return principal
    return checker


def client_ip(request: Request) -> Optional[str]:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None
