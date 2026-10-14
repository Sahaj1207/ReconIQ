"""
ReconIQ AI Analyst

Explains completed deterministic assessments in natural language. Uses Claude when
ANTHROPIC_API_KEY is configured and ANALYST_ENABLED is true; otherwise (or on any model
failure) produces a deterministic template narrative. Never influences scoring.
"""

import logging
from typing import Any, Dict

import anthropic

from app.analyst.models import AnalystReport
from app.analyst.template import build_template_report
from app.core.config import settings

logger = logging.getLogger(__name__)


def analyst_mode() -> str:
    return "claude" if settings.ANALYST_ENABLED and settings.ANTHROPIC_API_KEY else "template"


async def generate_report(result: Dict[str, Any]) -> AnalystReport:
    if analyst_mode() == "template":
        return build_template_report(result)

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


__all__ = ["AnalystReport", "generate_report", "analyst_mode", "build_template_report"]
