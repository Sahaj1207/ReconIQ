"""
AI Analyst tests: deterministic template, Claude path (mocked client) and fallbacks.
"""

import json
from types import SimpleNamespace

import pytest

from app.analyst import analyst_mode, generate_report
from app.analyst import claude_analyst
from app.analyst.claude_analyst import build_evidence_brief
from app.core.config import settings
from app.pipeline.investigation import InvestigationPipeline

PHISH = "URGENT: account suspended. Verify your password at hxxps://paypal-account-security[.]xyz/signin"


async def phish_result():
    return (await InvestigationPipeline().run(PHISH)).model_dump(mode="json")


class FakeMessages:
    def __init__(self, response):
        self.response = response
        self.calls = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


def fake_client(monkeypatch, response):
    messages = FakeMessages(response)
    client = SimpleNamespace(messages=messages, beta=SimpleNamespace(messages=messages))
    monkeypatch.setattr(claude_analyst.anthropic, "AsyncAnthropic", lambda **kw: client)
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "sk-test")
    return messages


def text_response(payload, stop_reason="end_turn"):
    return SimpleNamespace(stop_reason=stop_reason, model="claude-opus-5-5",
                           content=[SimpleNamespace(type="thinking"), SimpleNamespace(type="text", text=json.dumps(payload))])


@pytest.mark.asyncio
async def test_template_report_is_default_and_grounded():
    assert analyst_mode() == "template"
    result = await InvestigationPipeline().run(PHISH)
    report = result.analyst_report
    assert report["generated_by"] == "template"
    assert "credential harvesting" in report["summary"]
    assert any("Brand Lookalike" in k for k in report["key_findings"])
    assert any("Reset credentials" in a for a in report["recommended_actions"])


@pytest.mark.asyncio
async def test_claude_report_uses_schema_fallbacks_and_cannot_change_score(monkeypatch):
    result = await phish_result()
    messages = fake_client(monkeypatch, text_response(
        {"summary": "Critical phishing.", "key_findings": ["Lookalike domain"], "recommended_actions": ["Block it"]}))
    report = await generate_report(result)
    assert report.generated_by == "claude" and report.summary == "Critical phishing."
    call = messages.calls[0]
    assert call["model"] == "claude-opus-5-5"
    assert call["fallbacks"] == "default" and call["betas"] == ["server-side-fallback-2026-07-01"]
    assert call["output_config"]["format"]["type"] == "json_schema"
    assert "thinking" not in call  # Opus 5.5 rejects explicit disabled thinking; adaptive is implicit


@pytest.mark.asyncio
@pytest.mark.parametrize("response", [
    text_response({}, stop_reason="refusal"),
    SimpleNamespace(stop_reason="end_turn", model="m", content=[SimpleNamespace(type="text", text="not json")]),
])
async def test_claude_failures_fall_back_to_template(monkeypatch, response):
    fake_client(monkeypatch, response)
    report = await generate_report(await phish_result())
    assert report.generated_by == "template"
    assert report.note


@pytest.mark.asyncio
async def test_evidence_brief_contains_only_scored_evidence():
    brief = build_evidence_brief(await phish_result())
    assert brief["assessment"]["classification"] == "credential_harvesting"
    assert len(brief["input_preview"]) <= 600
    assert all("rule_id" not in f for f in brief["findings"])
