"""
User and audit-log persistence.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select

from app.db.database import session_scope
from app.db.models import AuditEvent, User


def _user_dict(u: User, include_hash: bool = False) -> Dict[str, Any]:
    d = {
        "id": u.id, "email": u.email, "name": u.name, "role": u.role, "is_active": u.is_active,
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
    }
    if include_hash:
        d["password_hash"] = u.password_hash
    return d


class UserRepository:
    def count(self, role: Optional[str] = None, active_only: bool = False) -> int:
        stmt = select(func.count()).select_from(User)
        if role:
            stmt = stmt.where(User.role == role)
        if active_only:
            stmt = stmt.where(User.is_active.is_(True))
        with session_scope() as s:
            return s.scalar(stmt) or 0

    def get(self, user_id: str) -> Optional[Dict[str, Any]]:
        with session_scope() as s:
            u = s.get(User, user_id)
            return _user_dict(u) if u else None

    def get_by_email(self, email: str, include_hash: bool = False) -> Optional[Dict[str, Any]]:
        with session_scope() as s:
            u = s.scalar(select(User).where(User.email == email.lower()))
            return _user_dict(u, include_hash) if u else None

    def create(self, email: str, name: str, password_hash: str, role: str) -> Dict[str, Any]:
        user = User(id=str(uuid.uuid4()), email=email.lower(), name=name, password_hash=password_hash, role=role,
                    is_active=True, created_at=datetime.now(timezone.utc))
        with session_scope() as s:
            s.add(user)
            s.flush()
            return _user_dict(user)

    def update(self, user_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
        with session_scope() as s:
            u = s.get(User, user_id)
            if not u:
                return None
            for key, value in fields.items():
                if value is not None:
                    setattr(u, key, value)
            s.flush()
            return _user_dict(u)

    def delete(self, user_id: str) -> bool:
        with session_scope() as s:
            u = s.get(User, user_id)
            if not u:
                return False
            s.delete(u)
            return True

    def list(self) -> List[Dict[str, Any]]:
        with session_scope() as s:
            return [_user_dict(u) for u in s.scalars(select(User).order_by(User.created_at)).all()]


class AuditRepository:
    def record(self, action: str, actor=None, target_type: Optional[str] = None, target_id: Optional[str] = None,
               detail: Optional[Dict[str, Any]] = None, ip: Optional[str] = None) -> None:
        event = AuditEvent(
            created_at=datetime.now(timezone.utc), action=action,
            actor_id=getattr(actor, "id", None), actor_email=getattr(actor, "email", None),
            target_type=target_type, target_id=target_id, detail=detail or {}, ip=ip,
        )
        with session_scope() as s:
            s.add(event)

    def list(self, limit: int = 50, offset: int = 0, action: Optional[str] = None) -> Dict[str, Any]:
        stmt = select(AuditEvent)
        if action:
            stmt = stmt.where(AuditEvent.action == action)
        with session_scope() as s:
            total = s.scalar(select(func.count()).select_from(stmt.subquery())) or 0
            rows = s.scalars(stmt.order_by(AuditEvent.id.desc()).limit(limit).offset(offset)).all()
            return {"total": total, "items": [{
                "id": e.id, "created_at": e.created_at.isoformat(), "actor_id": e.actor_id, "actor_email": e.actor_email,
                "action": e.action, "target_type": e.target_type, "target_id": e.target_id, "detail": e.detail, "ip": e.ip,
            } for e in rows]}
