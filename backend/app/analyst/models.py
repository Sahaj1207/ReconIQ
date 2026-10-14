"""
AI Analyst report model.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class AnalystReport(BaseModel):
    """Human-readable explanation of a completed, deterministic assessment."""
    summary: str = Field(..., description="Two-to-four sentence executive summary")
    key_findings: List[str] = Field(default_factory=list, description="Most important evidence, most severe first")
    recommended_actions: List[str] = Field(default_factory=list, description="Concrete next steps for the analyst")
    generated_by: str = Field(..., description="'claude' or 'template'")
    model: Optional[str] = Field(default=None, description="Model that wrote the narrative, when generated_by='claude'")
    note: Optional[str] = Field(default=None, description="Why a template was used instead of the model, if applicable")
    disclaimer: str = Field(
        default="The verdict, score and severity come from ReconIQ's deterministic rule engine. "
                "This narrative only explains that evidence and cannot change the assessment.",
    )
