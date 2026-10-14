"""
ReconIQ - Enterprise Threat Analysis Platform
Tagline: Evidence. Intelligence. Trust.

FastAPI Application Entrypoint
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.logging import setup_logging
from app.api.v1.router import api_router
from app.db import init_db
from app import __version__
from app.core.security import RateLimitMiddleware, SecurityHeadersMiddleware

# Setup structured logging
setup_logging()
logger = logging.getLogger("reconiq.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown lifespan context.
    """
    logger.info(f"Starting {settings.APP_NAME} v{__version__} in [{settings.ENVIRONMENT}] environment.")
    init_db()
    logger.info("Deterministic Threat Investigation Engine initialized.")
    yield
    logger.info("Shutting down ReconIQ backend services.")


app = FastAPI(
    title=settings.APP_NAME,
    description="ReconIQ Enterprise Threat Analysis Platform. Evidence. Intelligence. Trust.",
    version=__version__,
    debug=settings.DEBUG,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# CORS is added last so it is the outermost layer: rate-limit (429) and auth errors
# still carry CORS headers and reach the browser as readable responses.
# Configure CORS Middleware
if settings.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# Register API v1 Router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/", tags=["Root"])
async def root():
    """Root info endpoint."""
    return {
        "app": settings.APP_NAME,
        "tagline": settings.TAGLINE,
        "version": __version__,
        "documentation": "/docs",
        "api_v1": f"{settings.API_V1_STR}/evidence/extract"
    }
