"""
ReconIQ System Capabilities Endpoint

GET /api/v1/system/capabilities : what this deployment can do (providers, analyst, ingestion, limits).
"""

from typing import Any, Dict

from fastapi import APIRouter

from app import __version__
from app.analyst import analyst_mode
from app.core.config import settings
from app.auth.principal import Principal, auth_required, require_role
from fastapi import Depends
from app.ingestion.parsers.image_parser import ocr_available
from app.integrations.registry import provider_status
from app.risk_engine.rules import RuleRegistry

router = APIRouter()


def _qr_available() -> bool:
    try:
        import cv2  # noqa: F401
        return True
    except ImportError:
        return False


@router.get("/capabilities", summary="Deployment Capabilities")
def capabilities(_: Principal = Depends(require_role("viewer"))) -> Dict[str, Any]:
    rules = RuleRegistry().get_all_rules()
    return {
        "version": __version__,
        "environment": settings.ENVIRONMENT,
        "auth_enabled": auth_required(),
        "signup_role": settings.SIGNUP_ROLE,
        "rate_limit_per_minute": settings.RATE_LIMIT_PER_MINUTE,
        "persistence": settings.PERSIST_INVESTIGATIONS,
        "analyst": {"mode": analyst_mode(), "model": settings.ANALYST_MODEL if analyst_mode() == "claude" else None},
        "ingestion": {
            "max_upload_mb": settings.MAX_UPLOAD_MB,
            "qr_decoding": _qr_available(),
            "ocr": ocr_available(),
            "file_types": ["eml", "pdf", "png", "jpg", "gif", "webp", "bmp", "apk", "txt", "log", "csv", "json", "html", "any binary (hash only)"],
        },
        "threat_intel": provider_status(),
        "rules": [{"id": r.id, "name": r.name, "severity": r.severity, "weight": r.weight, "enabled": r.enabled} for r in rules],
    }
