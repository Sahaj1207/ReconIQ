"""
ReconIQ Structured Security Audit Logger

Configures Python standard logging with structured formatting
for auditability across threat analysis workflows.
"""

import logging
import sys
from app.core.config import settings


def setup_logging() -> None:
    """
    Initializes system-wide logging with level and format.
    
    Log Level: Derived from Settings (DEBUG/INFO/WARNING/ERROR)
    Output: sys.stdout
    """
    log_format = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    logging.basicConfig(
        level=log_level,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

    # Silence overly verbose third-party loggers if necessary
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)


# Export setup function
__all__ = ["setup_logging"]
