"""
API security: optional API-key authentication and per-client rate limiting.

- Authentication and roles live in app.auth; this module only identifies clients by credential.
- Rate limiting applies a sliding window per client (API key, else IP) to /api/v1 routes,
  except health. RATE_LIMIT_PER_MINUTE=0 disables it. State is in-process; use a shared
  store (e.g. Redis) when running several replicas.
"""

import hashlib
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import settings


def extract_key(request: Request) -> Optional[str]:
    """Credential used to identify a client for rate limiting (API key or session token)."""
    from app.auth.principal import extract_credential
    return extract_credential(request)


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
