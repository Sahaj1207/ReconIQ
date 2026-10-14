"""
ReconIQ AI Analyst

Explains completed deterministic assessments in natural language. Uses Claude when
ANTHROPIC_API_KEY is configured, otherwise Gemini when GEMINI_API_KEY is configured (both
require ANALYST_ENABLED). Without a key, or on any model failure, it produces a deterministic
template narrative. Never influences scoring.
"""

import logging
from typing import Any, Dict, Optional

import anthropic

from app.analyst.models import AnalystReport
from app.analyst.template import build_template_report
from app.core.config import settings

logger = logging.getLogger(__name__)


def analyst_mode() -> str:
    """'claude', 'gemini' or 'template'. Claude wins when both keys are set."""
    if not settings.ANALYST_ENABLED:
        return "template"
    if settings.ANTHROPIC_API_KEY:
        return "claude"
    if settings.GEMINI_API_KEY:
        return "gemini"
    return "template"


def analyst_model() -> Optional[str]:
    return {"claude": settings.ANALYST_MODEL, "gemini": settings.GEMINI_MODEL}.get(analyst_mode())


async def _claude(result: Dict[str, Any]) -> AnalystReport:
    from app.analyst.claude_analyst import generate_claude_report
    try:
        return await generate_claude_report(result)
    except anthropic.AuthenticationError:
        note = "Claude rejected the configured API key; showing the deterministic summary."
    except anthropic.RateLimitError:
        note = "Claude rate limit reached; showing the deterministic summary."
    except anthropic.APIStatusError as exc:
        note = f"Claude API error (HTTP {exc.status_code}); showing the deterministic summary."
    except anthropic.APIConnectionError:
        note = "Could not reach the Claude API; showing the deterministic summary."
    except (RuntimeError, ValueError, KeyError) as exc:
        note = f"Claude report unavailable ({exc}); showing the deterministic summary."
    logger.warning(f"AI analyst fell back to template: {note}")
    return build_template_report(result, note=note)


async def _gemini(result: Dict[str, Any]) -> AnalystReport:
    from app.analyst.gemini_analyst import GeminiError, generate_gemini_report
    try:
        return await generate_gemini_report(result)
    except GeminiError as exc:
        if exc.status in (401, 403) or (exc.status == 400 and "key" in str(exc).lower()):
            note = "Gemini rejected the configured API key; showing the deterministic summary."
        elif exc.status == 429:
            note = "Gemini rate limit reached; showing the deterministic summary."
        else:
            note = f"Gemini report unavailable ({exc}); showing the deterministic summary."
    except (ValueError, KeyError, TypeError) as exc:
        note = f"Gemini report unavailable ({type(exc).__name__}); showing the deterministic summary."
    logger.warning(f"AI analyst fell back to template: {note}")
    return build_template_report(result, note=note)


async def generate_report(result: Dict[str, Any]) -> AnalystReport:
    mode = analyst_mode()
    if mode == "claude":
        return await _claude(result)
    if mode == "gemini":
        return await _gemini(result)
    return build_template_report(result)


__all__ = ["AnalystReport", "generate_report", "analyst_mode", "analyst_model", "build_template_report"]
