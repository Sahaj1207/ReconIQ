"""
ReconIQ Phase 7 Investigation Pipeline Orchestrator Unit & Integration Tests
"""

import pytest
from typing import Dict, Any
from app.ingestion.ingested_input import IngestedInput
from app.pipeline.models import InvestigationRequest, StageStatus
from app.pipeline.context import InvestigationContext, sanitize_sensitive_data
from app.pipeline.steps import BasePipelineStep
from app.pipeline.investigation import InvestigationPipeline


# --- Mock Failing Pipeline Steps ---

class FailingStep(BasePipelineStep):
    """Pipeline step that simulates an unhandled stage crash."""
    def __init__(self, step_name: str, error_msg: str = "Simulated stage failure") -> None:
        self._name = step_name
        self.error_msg = error_msg

    @property
    def name(self) -> str:
        return self._name

    async def execute(self, context: InvestigationContext) -> None:
        raise RuntimeError(self.error_msg)


# --- Test Cases ---

@pytest.mark.asyncio
async def test_successful_full_investigation():
    """Test successful end-to-end execution of all 5 pipeline stages."""
    pipeline = InvestigationPipeline()
    payload = "CRITICAL ALERT: Phishing email from attacker[at]malicious-bank[dot]com link hxxps://phishing-portal[.]com/login IP 198.51.100.45"

    result = await pipeline.run(payload)

    assert result.status == "success"
    assert result.duration_ms > 0.0
    assert result.investigation_id is not None
    assert len(result.execution_metrics) == 5

    # Check stage ordering
    stage_names = [m.stage_name for m in result.execution_metrics]
    assert stage_names == [
        "evidence_collection",
        "normalization",
        "validation",
        "threat_intelligence",
        "risk_assessment"
    ]
    assert all(m.status == StageStatus.COMPLETED for m in result.execution_metrics)

    # Check evidence & risk outputs
    assert len(result.evidence.get("ipv4", [])) >= 1
    assert result.risk_assessment is not None
    assert result.risk_assessment.get("total_score", 0.0) >= 40.0


@pytest.mark.asyncio
async def test_stage_failure_isolation():
    """Test that a failure in one stage logs the error, marks stage FAILED, and allows remaining stages to continue."""
    failing_norm = FailingStep("normalization", "Normalization engine memory fault api_key=secret_12345")
    pipeline = InvestigationPipeline(steps=[
        InvestigationPipeline().steps[0],  # EvidenceCollectionStep
        failing_norm,                       # Failing NormalizationStep
        InvestigationPipeline().steps[2],  # ValidationStep
        InvestigationPipeline().steps[4],  # RiskAssessmentStep
    ])

    result = await pipeline.run("IP 192.168.1.1")

    assert result.status == "partial_success"
    assert len(result.errors) == 1
    assert "Normalization engine memory fault" in result.errors[0]
    # Verify API key sanitization
    assert "secret_12345" not in result.errors[0]
    assert "[REDACTED]" in result.errors[0]

    # Verify stage metrics recorded failure correctly
    norm_metric = next(m for m in result.execution_metrics if m.stage_name == "normalization")
    assert norm_metric.status == StageStatus.FAILED
    assert "[REDACTED]" in norm_metric.error


@pytest.mark.asyncio
async def test_security_data_sanitization():
    """Test that sensitive API keys and headers are redacted from error logs and context."""
    raw_error = "Authorization: Bearer secret_token_xyz123 failed on x-apikey: vt_secret_abc987"
    clean_error = sanitize_sensitive_data(raw_error)

    assert "secret_token_xyz123" not in clean_error
    assert "vt_secret_abc987" not in clean_error
    assert "[REDACTED]" in clean_error


@pytest.mark.asyncio
async def test_partial_investigation_result_dto():
    """Test result DTO generation when some stages fail."""
    pipeline = InvestigationPipeline(steps=[
        FailingStep("evidence_collection", "Collection error"),
        FailingStep("normalization", "Normalization error"),
    ])

    result = await pipeline.run("Test input")

    assert result.status == "failed"
    assert len(result.errors) == 2
    assert result.evidence == {}
    assert result.risk_assessment is None


@pytest.mark.asyncio
async def test_api_investigate_endpoint(async_client):
    """Integration test for POST /api/v1/evidence/investigate endpoint."""
    payload = {
        "text": "Phishing email from test[at]example[dot]com containing link hxxps://bad-site[.]com and IP 198.51.100.45",
        "refang": True
    }
    response = await async_client.post("/api/v1/evidence/investigate", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["status"] in ("success", "partial_success")
    assert data["investigation_id"] is not None
    assert data["duration_ms"] > 0.0
    assert "risk_summary" in data
    assert data["risk_summary"]["total_score"] >= 40.0
