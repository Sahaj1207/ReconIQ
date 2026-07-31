"""
ReconIQ Investigation Context

Purpose:
Holds the state, extracted evidence, threat intelligence responses, rule matches, and risk scores
as an investigation proceeds through pipeline stages.

Responsibilities:
- Provide unified mutable context object across pipeline steps
- Thread safety and state immutability snapshots for audit logs

Future Implementation Notes:
- Serializable to JSON/STIX 2.1 format for external system export.

TODO:
- [ ] Implement InvestigationContext Pydantic state container.
- [ ] Add snapshot method for intermediate state auditing.
"""

from typing import Dict, Any, List
from pydantic import BaseModel, Field


class InvestigationContext(BaseModel):
    """
    Placeholder Investigation Context State Holder.
    """
    investigation_id: str = Field(default="", description="Unique UUID for active investigation")
    raw_input: str = Field(default="", description="Raw ingested input")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Extracted evidence artifacts")
    enrichment_data: Dict[str, Any] = Field(default_factory=dict, description="Threat intel provider results")
    risk_assessment: Dict[str, Any] = Field(default_factory=dict, description="Risk Engine outputs")
    ai_summary: Optional[str] = Field(default=None, description="AI Analyst explanation text")
