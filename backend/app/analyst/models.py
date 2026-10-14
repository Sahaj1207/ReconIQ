"""
Analyst summary model.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class AnalystReport(BaseModel):
    """Human-readable explanation of a completed, deterministic assessment."""
    summary: str = Field(..., description="Two-to-four sentence executive summary")
    key_findings: List[str] = Field(default_factory=list, description="Most important evidence, most severe first")
    recommended_actions: List[str] = Field(default_factory=list, description="Concrete next steps for the analyst")
    generated_by: str = Field(default="template", description="Always 'template' (deterministic)")
    note: Optional[str] = Field(default=None, description="Extra context about the summary, if any")
    disclaimer: str = Field(
        default="The verdict, score and severity come from ReconIQ's deterministic rule engine. "
                "This summary only explains that evidence.",
    )
