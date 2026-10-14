"""
ReconIQ Authentication & User Management Endpoints

- POST /api/v1/auth/register          : self sign-up (role per SIGNUP_ROLE; BOOTSTRAP_ADMIN_EMAIL becomes admin)
- POST /api/v1/auth/login             : exchange email + password for a session token
- GET  /api/v1/auth/me                : current principal
- POST /api/v1/auth/change-password   : change own password
- GET/POST/PATCH/DELETE /api/v1/users : admin user management
- GET  /api/v1/audit                  : admin audit log
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field, field_validator

from app.auth.passwords import MIN_PASSWORD_LENGTH, hash_password, verify_password
from app.auth.principal import Principal, auth_required, client_ip, current_principal, require_role
from app.auth.repository import AuditRepository, UserRepository
from app.auth.tokens import issue_token
from app.core.config import settings

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

router = APIRouter()
users_router = APIRouter()
audit_router = APIRouter()
users = UserRepository()
audit = AuditRepository()


class Credentials(BaseModel):
    email: str = Field(..., max_length=320)
    password: str = Field(..., min_length=1, max_length=256)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_RE.match(v):
            raise ValueError("Enter a valid email address")
        return v


class Registration(Credentials):
    name: str = Field(default="", max_length=120)
    password: str = Field(..., min_length=MIN_PASSWORD_LENGTH, max_length=256)


class NewUser(Registration):
    role: str = Field(default="analyst", pattern="^(viewer|analyst|admin)$")


class UserUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=120)
    role: Optional[str] = Field(default=None, pattern="^(viewer|analyst|admin)$")
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=MIN_PASSWORD_LENGTH, max_length=256)


class PasswordChange(BaseModel):
    current_password: str = Field(..., max_length=256)
    new_password: str = Field(..., min_length=MIN_PASSWORD_LENGTH, max_length=256)


def _signup_role(email: str) -> Optional[str]:
    """Role for a self-registering email, or None when sign-up is closed for it."""
    bootstrap = settings.BOOTSTRAP_ADMIN_EMAIL.strip().lower()
    if bootstrap and email == bootstrap:
        return "admin"
    if not bootstrap and users.count() == 0:
        return "admin"  # no designated admin: the first account administers the site
    return settings.SIGNUP_ROLE if settings.SIGNUP_ROLE in ("viewer", "analyst") else None


def _session(user: Dict[str, Any]) -> Dict[str, Any]:
    return {**issue_token(user["id"], user["role"]), "user": user}


@router.post("/register", status_code=status.HTTP_201_CREATED, summary="Create an account")
def register(body: Registration, request: Request) -> Dict[str, Any]:
    role = _signup_role(body.email)
    if role is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Sign-up is closed; ask an administrator for an account")
    if users.get_by_email(body.email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists")
    user = users.create(body.email, body.name.strip(), hash_password(body.password), role)
    # Registering signs the user in, so it counts as their first sign-in.
    user = users.update(user["id"], last_login_at=datetime.now(timezone.utc))
    audit.record("user.registered", actor=Principal(user["id"], user["email"], role, "user"),
                 target_type="user", target_id=user["id"], detail={"role": role}, ip=client_ip(request))
    return _session(user)


@router.post("/login", summary="Sign in")
def login(body: Credentials, request: Request) -> Dict[str, Any]:
    record = users.get_by_email(body.email, include_hash=True)
    if not record or not verify_password(body.password, record["password_hash"]) or not record["is_active"]:
        audit.record("auth.login_failed", detail={"email": body.email}, ip=client_ip(request))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    user = users.update(record["id"], last_login_at=datetime.now(timezone.utc))
    audit.record("auth.login", actor=Principal(user["id"], user["email"], user["role"], "user"), ip=client_ip(request))
    return _session(user)


@router.get("/me", summary="Current user")
def me(principal: Principal = Depends(current_principal)) -> Dict[str, Any]:
    user = users.get(principal.id) if principal.id else None
    return {"kind": principal.kind, "role": principal.role, "email": principal.email, "user": user}


@router.get("/config", summary="Public sign-in configuration")
def auth_config() -> Dict[str, Any]:
    return {
        "auth_required": auth_required(),
        "signup_open": settings.SIGNUP_ROLE in ("viewer", "analyst"),
        "signup_role": settings.SIGNUP_ROLE,
        "min_password_length": MIN_PASSWORD_LENGTH,
    }


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT, summary="Change own password")
def change_password(body: PasswordChange, request: Request, principal: Principal = Depends(current_principal)) -> Response:
    if principal.kind != "user":
        raise HTTPException(status_code=400, detail="Only signed-in users have passwords")
    record = users.get_by_email(principal.email, include_hash=True)
    if not record or not verify_password(body.current_password, record["password_hash"]):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    users.update(principal.id, password_hash=hash_password(body.new_password))
    audit.record("user.password_changed", actor=principal, target_type="user", target_id=principal.id, ip=client_ip(request))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Admin: users ---

def _guard_last_admin(user_id: str, new_role: Optional[str] = None, deactivate: bool = False, deleting: bool = False) -> None:
    target = users.get(user_id)
    if not target or target["role"] != "admin" or not target["is_active"]:
        return
    losing_admin = deleting or deactivate or (new_role is not None and new_role != "admin")
    if losing_admin and users.count(role="admin", active_only=True) <= 1:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Cannot remove the last active administrator")


@users_router.get("", summary="List users")
def list_users(_: Principal = Depends(require_role("admin"))) -> Dict[str, Any]:
    items = users.list()
    return {"total": len(items), "items": items}


@users_router.post("", status_code=status.HTTP_201_CREATED, summary="Create a user")
def create_user(body: NewUser, request: Request, admin: Principal = Depends(require_role("admin"))) -> Dict[str, Any]:
    if users.get_by_email(body.email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists")
    user = users.create(body.email, body.name.strip(), hash_password(body.password), body.role)
    audit.record("user.created", actor=admin, target_type="user", target_id=user["id"],
                 detail={"email": user["email"], "role": body.role}, ip=client_ip(request))
    return user


@users_router.patch("/{user_id}", summary="Update a user")
def update_user(user_id: str, body: UserUpdate, request: Request, admin: Principal = Depends(require_role("admin"))) -> Dict[str, Any]:
    _guard_last_admin(user_id, new_role=body.role, deactivate=body.is_active is False)
    fields = body.model_dump(exclude={"password"}, exclude_none=True)
    if body.password:
        fields["password_hash"] = hash_password(body.password)
    user = users.update(user_id, **fields)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    audit.record("user.updated", actor=admin, target_type="user", target_id=user_id,
                 detail={k: v for k, v in body.model_dump(exclude_none=True).items() if k != "password"} |
                        ({"password_reset": True} if body.password else {}), ip=client_ip(request))
    return user


@users_router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a user")
def delete_user(user_id: str, request: Request, admin: Principal = Depends(require_role("admin"))) -> Response:
    if user_id == admin.id:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="You can't delete your own account")
    _guard_last_admin(user_id, deleting=True)
    if not users.delete(user_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    audit.record("user.deleted", actor=admin, target_type="user", target_id=user_id, ip=client_ip(request))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Admin: audit log ---

@audit_router.get("", summary="Audit log")
def audit_log(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    action: Optional[str] = Query(None, max_length=64),
    _: Principal = Depends(require_role("admin")),
) -> Dict[str, Any]:
    return audit.list(limit=limit, offset=offset, action=action)
