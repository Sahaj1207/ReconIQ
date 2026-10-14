"""
Signed session tokens (JWT, HS256).
"""

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt

from app.core.config import settings

logger = logging.getLogger(__name__)
_ephemeral_secret: Optional[str] = None


def _secret() -> str:
    global _ephemeral_secret
    if settings.JWT_SECRET:
        return settings.JWT_SECRET
    if _ephemeral_secret is None:
        _ephemeral_secret = secrets.token_urlsafe(48)
        logger.warning("JWT_SECRET is not set; using a per-process secret (sessions reset on restart). "
                       "Set JWT_SECRET in production, especially on multi-instance or serverless hosting.")
    return _ephemeral_secret


def issue_token(user_id: str, role: str) -> Dict[str, Any]:
    expires = datetime.now(timezone.utc) + timedelta(hours=settings.JWT_EXPIRE_HOURS)
    token = jwt.encode({"sub": user_id, "role": role, "exp": expires, "iat": datetime.now(timezone.utc)},
                       _secret(), algorithm="HS256")
    return {"access_token": token, "token_type": "bearer", "expires_at": expires.isoformat()}


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, _secret(), algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
