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

    # Future Threat Intelligence Integrations (Placeholders)
    # TODO: Add authentication & key storage when integration providers are implemented.
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    SHODAN_API_KEY: str = ""


# Global Singleton Settings Instance
settings = Settings()
