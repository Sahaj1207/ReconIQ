"""
API security: optional API-key authentication and per-client rate limiting.

- Authentication is enabled when API_KEYS (comma-separated) is non-empty. Clients send
  `X-API-Key: <key>` or `Authorization: Bearer <key>`. Keys are compared in constant time.
- Rate limiting applies a sliding window per client (API key, else IP) to /api/v1 routes,
  except health. RATE_LIMIT_PER_MINUTE=0 disables it. State is in-process; use a shared
  store (e.g. Redis) when running several replicas.
"""

import hashlib
import hmac
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import settings


def configured_keys() -> list:
    return [k.strip() for k in settings.API_KEYS.split(",") if k.strip()]


def extract_key(request: Request) -> Optional[str]:
    key = request.headers.get("x-api-key")
    if key:
        return key.strip()
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


async def require_api_key(request: Request) -> None:
    """FastAPI dependency guarding protected routers."""
    keys = configured_keys()
    if not keys:
        return
    supplied = extract_key(request)
    if not supplied or not any(hmac.compare_digest(supplied.encode(), k.encode()) for k in keys):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )


class RateLimitMiddleware(BaseHTTPMiddleware):
    EXEMPT_SUFFIXES = ("/health",)

    def __init__(self, app) -> None:
        super().__init__(app)
        self.hits: Dict[str, Deque[float]] = defaultdict(deque)

    def client_id(self, request: Request) -> str:
        key = extract_key(request)
        if key:
            return "key:" + hashlib.sha256(key.encode()).hexdigest()[:16]
        return "ip:" + (request.client.host if request.client else "unknown")

    async def dispatch(self, request: Request, call_next):
        limit = settings.RATE_LIMIT_PER_MINUTE
        path = request.url.path
        if limit <= 0 or not path.startswith(settings.API_V1_STR) or path.endswith(self.EXEMPT_SUFFIXES) \
                or request.method == "OPTIONS":
            return await call_next(request)

        now = time.monotonic()
        window = self.hits[self.client_id(request)]
        while window and now - window[0] >= 60:
            window.popleft()
        if len(window) >= limit:
            retry_after = int(60 - (now - window[0])) + 1
            return JSONResponse({"detail": f"Rate limit exceeded ({limit} requests/minute)"}, status_code=429,
                                headers={"Retry-After": str(retry_after)})
        window.append(now)
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, limit - len(window)))
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response
