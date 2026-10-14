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


# Global Singleton Settings Instance
settings = Settings()
