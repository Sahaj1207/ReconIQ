"""
ReconIQ Analyst Summary

Explains each completed deterministic assessment in plain language: an executive summary,
the key findings and recommended actions, all derived from the scored evidence. It never
influences scoring.
"""

from typing import Any, Dict

from app.analyst.models import AnalystReport
from app.analyst.template import build_template_report


def generate_report(result: Dict[str, Any]) -> AnalystReport:
    return build_template_report(result)


__all__ = ["AnalystReport", "generate_report", "build_template_report"]
