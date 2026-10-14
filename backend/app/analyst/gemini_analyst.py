"""
Gemini-backed analyst narrative (Google Gemini API, REST via httpx).

Same contract as the Claude analyst: the model sees only the structured, already-scored
evidence, returns schema-constrained JSON, and can never alter the deterministic verdict.
"""

import json
import logging
from typing import Any, Dict

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


class GeminiError(RuntimeError):
    """A Gemini API failure; `status` is the HTTP status when the API answered."""

    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


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
    try:
        async with httpx.AsyncClient(timeout=settings.ANALYST_TIMEOUT_SECONDS) as client:
            res = await client.post(
                API_URL.format(model=settings.GEMINI_MODEL),
                headers={"x-goog-api-key": settings.GEMINI_API_KEY},  # header, so the key never appears in URLs or logs
                json=body,
            )
    except httpx.HTTPError as exc:
        raise GeminiError(f"could not reach the Gemini API ({type(exc).__name__})") from exc

    if res.status_code != 200:
        raise GeminiError(f"Gemini API error (HTTP {res.status_code})", res.status_code)

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
