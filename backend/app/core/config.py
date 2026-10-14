"""
ReconIQ Core Configuration Module

Provides environment-based settings management via Pydantic BaseSettings.
Handles platform settings, API prefixes, CORS origins, and threat intel API keys.
"""

from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application Settings for ReconIQ.
    
    Reads configuration from environment variables or .env file.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "ReconIQ - Threat Analysis Platform"
    TAGLINE: str = "Evidence. Intelligence. Trust."
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    API_V1_STR: str = "/api/v1"
    LOG_LEVEL: str = "INFO"

    # User accounts. AUTH_ENABLED requires sign-in (or an API key) for everything except health/auth.
    AUTH_ENABLED: bool = False
    JWT_SECRET: str = ""
    JWT_EXPIRE_HOURS: int = 12
    # This email always becomes an admin when it registers
    BOOTSTRAP_ADMIN_EMAIL: str = ""
    # Role given to self-registered users: "analyst", "viewer", or "disabled" (admin invites only)
    SIGNUP_ROLE: str = "analyst"

    # API security: comma-separated keys enable auth; 0 disables rate limiting
    API_KEYS: str = ""
    API_KEY_ROLE: str = "analyst"
    RATE_LIMIT_PER_MINUTE: int = 60

    # Persistence (SQLite by default; use postgresql+psycopg://... in production)
    DATABASE_URL: str = ""
    # Injected by Vercel's Supabase / Neon integrations; used when DATABASE_URL is unset
    POSTGRES_URL: str = ""
    PERSIST_INVESTIGATIONS: bool = True

    # Upload limits
    MAX_UPLOAD_MB: int = 15

    # CORS Configuration
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    # Threat Intelligence Integrations (a provider is enabled when its key is set)
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    URLHAUS_AUTH_KEY: str = ""
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    HIBP_API_KEY: str = ""
    # Keyless providers (Shodan InternetDB, RDAP) make outbound calls; disable for air-gapped use
    INTEL_KEYLESS_PROVIDERS: bool = True
    INTEL_TIMEOUT_SECONDS: float = 8.0
    INTEL_MAX_ARTIFACTS_PER_CATEGORY: int = 25
    INTEL_CONCURRENCY: int = 8


    @property
    def database_url(self) -> str:
        """Effective SQLAlchemy URL: DATABASE_URL, else POSTGRES_URL, else a local SQLite file."""
        from app.db.urls import normalize_database_url
        if not (self.DATABASE_URL or self.POSTGRES_URL) and self.serverless:
            # The deployment bundle is read-only. /tmp works but is per-instance and wiped on cold starts,
            # so history and job polling are unreliable until a database is connected.
            import logging
            logging.getLogger(__name__).warning("No DATABASE_URL or POSTGRES_URL on serverless hosting; using ephemeral /tmp SQLite")
            return "sqlite:////tmp/reconiq.db"
        return normalize_database_url(self.DATABASE_URL or self.POSTGRES_URL or "sqlite:///./reconiq.db")

    @property
    def serverless(self) -> bool:
        import os
        return bool(os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"))


# Global Singleton Settings Instance
settings = Settings()
