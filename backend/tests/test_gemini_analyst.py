"""
Gemini analyst: request shape, parsing, provider selection and fallbacks (HTTP mocked, offline).
"""

import json

import httpx
import pytest

from app.analyst import analyst_mode, analyst_model, generate_report
from app.analyst import gemini_analyst
from app.core.config import settings
from app.pipeline.investigation import InvestigationPipeline

PHISH = "URGENT: account suspended. Verify your password at hxxps://paypal-account-security[.]xyz/signin"
REPORT = {
    "summary": "Credential phishing lure impersonating PayPal.",
    "key_findings": ["Lookalike domain paypal-account-security.xyz"],
    "recommended_actions": ["Block the domain", "Reset affected credentials"],
}


async def phish_result():
    return (await InvestigationPipeline().run(PHISH)).model_dump(mode="json")


@pytest.fixture
def gemini_on(monkeypatch):
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "")
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.setattr(settings, "GEMINI_MODEL", "gemini-3.7-flash")
    monkeypatch.setattr(settings, "GEMINI_FALLBACK_MODEL", "gemini-3.6-flash")
    monkeypatch.setattr(settings, "ANALYST_ENABLED", True)
    monkeypatch.setattr(gemini_analyst, "RETRY_DELAYS", (0.0, 0.0))


def mock_gemini(monkeypatch, handler):
    """Routes the analyst's httpx client through `handler(request) -> httpx.Response`."""
    seen = []
    real_client = httpx.AsyncClient

    def wrapped(request):
        seen.append(request)
        return handler(request)

    monkeypatch.setattr(gemini_analyst.httpx, "AsyncClient",
                        lambda **kw: real_client(transport=httpx.MockTransport(wrapped), **kw))
    return seen


def ok_response(payload=REPORT, finish="STOP"):
    return httpx.Response(200, json={
        "candidates": [{"content": {"parts": [{"text": json.dumps(payload)}]}, "finishReason": finish}],
        "modelVersion": "gemini-3.7-flash",
    })


def test_mode_selection_prefers_claude_then_gemini(monkeypatch):
    monkeypatch.setattr(settings, "ANALYST_ENABLED", True)
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "")
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "")
    assert analyst_mode() == "template" and analyst_model() is None
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "g")
    assert analyst_mode() == "gemini" and analyst_model() == settings.GEMINI_MODEL
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "a")
    assert analyst_mode() == "claude"
    monkeypatch.setattr(settings, "ANALYST_ENABLED", False)
    assert analyst_mode() == "template"


@pytest.mark.asyncio
async def test_gemini_writes_report_with_key_in_header_not_url(gemini_on, monkeypatch):
    seen = mock_gemini(monkeypatch, lambda req: ok_response())
    report = await generate_report(await phish_result())
    assert report.generated_by == "gemini" and report.model == "gemini-3.7-flash"
    assert report.summary == REPORT["summary"] and report.recommended_actions == REPORT["recommended_actions"]

    req = seen[0]
    assert req.url.path.endswith("/models/gemini-3.7-flash:generateContent")
    assert req.headers["x-goog-api-key"] == "test-gemini-key" and "test-gemini-key" not in str(req.url)
    body = json.loads(req.content)
    assert body["generationConfig"]["responseMimeType"] == "application/json"
    assert "deterministic rule engine" in body["systemInstruction"]["parts"][0]["text"]
    brief = json.loads(body["contents"][0]["parts"][0]["text"])
    assert brief["assessment"]["severity"] == "CRITICAL"  # the model sees the verdict, it doesn't make it


@pytest.mark.asyncio
@pytest.mark.parametrize("response, expected_note", [
    (httpx.Response(403, json={"error": {"message": "API key not valid"}}), "rejected the configured API key"),
    (httpx.Response(429, json={}), "rate limit"),
    (httpx.Response(500, json={}), "HTTP 500"),
    (httpx.Response(200, json={"promptFeedback": {"blockReason": "SAFETY"}}), "blocked"),
    (ok_response(finish="MAX_TOKENS"), "truncated"),
    (httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "not json"}]}, "finishReason": "STOP"}]}),
     "JSONDecodeError"),
])
async def test_gemini_failures_fall_back_to_template(gemini_on, monkeypatch, response, expected_note):
    mock_gemini(monkeypatch, lambda req: response)
    result = await phish_result()
    report = await generate_report(result)
    assert report.generated_by == "template" and expected_note in report.note
    assert "test-gemini-key" not in report.note


@pytest.mark.asyncio
async def test_unreachable_gemini_falls_back(gemini_on, monkeypatch):
    def boom(request):
        raise httpx.ConnectError("no route", request=request)
    mock_gemini(monkeypatch, boom)
    report = await generate_report(await phish_result())
    assert report.generated_by == "template" and "could not reach" in report.note


@pytest.mark.asyncio
async def test_capabilities_report_gemini(gemini_on, async_client):
    caps = (await async_client.get("/api/v1/system/capabilities")).json()
    assert caps["analyst"] == {"mode": "gemini", "model": "gemini-3.7-flash"}


@pytest.mark.asyncio
async def test_overloaded_model_is_retried(gemini_on, monkeypatch):
    result = await phish_result()
    replies = iter([httpx.Response(503, json={}), httpx.Response(503, json={}), ok_response()])
    seen = mock_gemini(monkeypatch, lambda req: next(replies))
    report = await generate_report(result)
    assert report.generated_by == "gemini" and len(seen) == 3
    assert all("gemini-3.7-flash" in r.url.path for r in seen)


@pytest.mark.asyncio
@pytest.mark.parametrize("primary_status, primary_calls", [(503, 3), (404, 1)])
async def test_fallback_model_used_when_primary_unavailable(gemini_on, monkeypatch, primary_status, primary_calls):
    def handler(req):
        if "gemini-3.7-flash" in req.url.path:
            return httpx.Response(primary_status, json={})
        return httpx.Response(200, json={
            "candidates": [{"content": {"parts": [{"text": json.dumps(REPORT)}]}, "finishReason": "STOP"}],
            "modelVersion": "gemini-3.6-flash",
        })
    result = await phish_result()
    seen = mock_gemini(monkeypatch, handler)
    report = await generate_report(result)
    assert report.generated_by == "gemini" and report.model == "gemini-3.6-flash"
    assert sum("gemini-3.7-flash" in r.url.path for r in seen) == primary_calls


@pytest.mark.asyncio
async def test_bad_key_is_not_retried_or_sent_to_fallback(gemini_on, monkeypatch):
    result = await phish_result()
    seen = mock_gemini(monkeypatch, lambda req: httpx.Response(403, json={}))
    report = await generate_report(result)
    assert report.generated_by == "template" and len(seen) == 1
