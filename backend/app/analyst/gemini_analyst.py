"""
Gemini-backed analyst narrative (Google Gemini API, REST via httpx).

Same contract as the Claude analyst: the model sees only the structured, already-scored
evidence, returns schema-constrained JSON, and can never alter the deterministic verdict.
"""

import asyncio
import json
import logging
import re
import time
from typing import Any, Dict, List

import httpx

from app.analyst.claude_analyst import SYSTEM_PROMPT, build_evidence_brief
from app.analyst.models import AnalystReport
from app.core.config import settings

logger = logging.getLogger(__name__)

API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

# Gemini's responseSchema uses the OpenAPI subset (no additionalProperties).
RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "summary": {"type": "STRING"},
        "key_findings": {"type": "ARRAY", "items": {"type": "STRING"}},
        "recommended_actions": {"type": "ARRAY", "items": {"type": "STRING"}},
    },
    "required": ["summary", "key_findings", "recommended_actions"],
}


# "Overloaded" / transient server errors worth retrying; quota (429) and client errors are not.
RETRYABLE_STATUSES = {500, 502, 503, 504}
RETRY_DELAYS = (1.0, 2.0)  # seconds before the 2nd and 3rd attempt on the same model


class GeminiError(RuntimeError):
    """A Gemini API failure; `status` is the HTTP status when the API answered."""

    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


def _api_error(res: httpx.Response) -> GeminiError:
    """GeminiError carrying Google's own status and message (e.g. UNAVAILABLE: model overloaded)."""
    detail = ""
    try:
        err = (res.json() or {}).get("error") or {}
        reason = " ".join(str(x) for x in (err.get("status"), err.get("message")) if x)
        # Google's messages don't echo keys, but never let anything key-shaped reach the UI
        detail = re.sub(r"AIza[0-9A-Za-z_\-]{20,}", "[key]", reason)[:200]
    except ValueError:
        pass
    message = f"Gemini API error (HTTP {res.status_code})" + (f": {detail}" if detail else "")
    return GeminiError(message, res.status_code)


def _models() -> List[str]:
    """Primary model, then the fallback (if set and different)."""
    models = [settings.GEMINI_MODEL]
    if settings.GEMINI_FALLBACK_MODEL and settings.GEMINI_FALLBACK_MODEL != settings.GEMINI_MODEL:
        models.append(settings.GEMINI_FALLBACK_MODEL)
    return models


async def _post(client: httpx.AsyncClient, model: str, body: Dict[str, Any], timeout: float) -> httpx.Response:
    try:
        return await client.post(
            API_URL.format(model=model),
            headers={"x-goog-api-key": settings.GEMINI_API_KEY},  # header, so the key never appears in URLs or logs
            json=body,
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise GeminiError(f"could not reach the Gemini API ({type(exc).__name__})") from exc


async def _call_with_retries(body: Dict[str, Any]) -> httpx.Response:
    """
    Tries the primary model (retrying transient 5xx errors), then the fallback model. Every attempt
    shares one overall budget of ANALYST_TIMEOUT_SECONDS so the request fits the hosting time limit.
    """
    deadline = time.monotonic() + settings.ANALYST_TIMEOUT_SECONDS
    last_error = GeminiError("Gemini API was not called")
    async with httpx.AsyncClient() as client:
        for model in _models():
            for attempt in range(len(RETRY_DELAYS) + 1):
                remaining = deadline - time.monotonic()
                if remaining <= 1:
                    raise last_error
                res = await _post(client, model, body, timeout=remaining)
                if res.status_code == 200:
                    return res
                last_error = _api_error(res)
                if res.status_code == 404:
                    break  # unknown model name: no point retrying it, try the fallback
                if res.status_code not in RETRYABLE_STATUSES:
                    raise last_error  # bad key, quota, bad request: the fallback model won't help
                if attempt < len(RETRY_DELAYS):
                    logger.info(f"Gemini {model} returned HTTP {res.status_code}; retrying")
                    await asyncio.sleep(min(RETRY_DELAYS[attempt], max(0.0, deadline - time.monotonic() - 1)))
            logger.warning(f"Gemini {model} unavailable ({last_error}); trying the next model if any")
            last_error = GeminiError(f"{last_error} [{model}]", last_error.status)
    raise last_error


async def generate_gemini_report(result: Dict[str, Any]) -> AnalystReport:
    """Calls Gemini for the narrative. Raises on API errors or blocked output so the caller can fall back."""
    body = {
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": json.dumps(build_evidence_brief(result), default=str)}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": RESPONSE_SCHEMA,
            "maxOutputTokens": 8192,
        },
    }
    res = await _call_with_retries(body)
    data = res.json()
    block = (data.get("promptFeedback") or {}).get("blockReason")
    if block:
        raise GeminiError(f"Gemini blocked the request ({block})")
    candidates = data.get("candidates") or []
    if not candidates:
        raise GeminiError("Gemini returned no candidates")
    candidate = candidates[0]
    finish = candidate.get("finishReason")
    if finish == "MAX_TOKENS":
        raise GeminiError("model output was truncated")
    if finish not in (None, "STOP"):
        raise GeminiError(f"model stopped early ({finish})")
    text = "".join(p.get("text", "") for p in (candidate.get("content") or {}).get("parts", []))
    if not text:
        raise GeminiError("Gemini returned no text")

    report = json.loads(text)
    return AnalystReport(
        summary=report["summary"],
        key_findings=report.get("key_findings", [])[:8],
        recommended_actions=report.get("recommended_actions", [])[:6],
        generated_by="gemini",
        model=data.get("modelVersion") or settings.GEMINI_MODEL,
    )
