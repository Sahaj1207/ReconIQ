"""
Analyst summary tests: the deterministic summary explains the scored evidence and never changes it.
"""

import pytest

from app.analyst import build_template_report, generate_report
from app.pipeline.investigation import InvestigationPipeline

PHISH = "URGENT: account suspended. Verify your password at hxxps://paypal-account-security[.]xyz/signin"


@pytest.mark.asyncio
async def test_summary_is_grounded_in_findings():
    result = await InvestigationPipeline().run(PHISH)
    report = result.analyst_report
    assert report["generated_by"] == "template"
    assert "credential harvesting" in report["summary"]
    assert any("Brand Lookalike" in k for k in report["key_findings"])
    assert any("Reset credentials" in a for a in report["recommended_actions"])
    assert [s.stage_name for s in result.execution_metrics][-1] == "summary"


@pytest.mark.asyncio
async def test_summary_cannot_change_the_assessment():
    result = (await InvestigationPipeline().run(PHISH)).model_dump(mode="json")
    before = dict(result["risk_assessment"])
    generate_report(result)
    assert result["risk_assessment"] == before


def test_clean_input_gets_minimal_actions():
    report = build_template_report({"risk_assessment": {"total_score": 0, "severity": "INFORMATIONAL",
                                                        "classification": "no_threat_identified", "findings": []},
                                    "evidence_summary": {}, "source_type": "raw_text"})
    assert "no rule produced evidence" in report.summary
    assert report.recommended_actions == ["No action required beyond normal monitoring; re-submit if new context emerges."]


def test_unavailable_intel_is_called_out():
    report = build_template_report({
        "risk_assessment": {"total_score": 10, "severity": "INFORMATIONAL", "classification": "no_threat_identified",
                            "findings": []},
        "threat_intelligence": {"urls": [{"provider": "VirusTotal", "status": "RATE_LIMITED"}]},
    })
    assert any("re-run once providers are reachable" in a for a in report.recommended_actions)
