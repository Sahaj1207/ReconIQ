"""
Background investigation jobs: per-stage progress, polling, ownership and failure handling.

httpx's ASGITransport waits for Starlette background tasks, so a job has finished by the time
the POST returns; progress ordering is checked directly through the pipeline callback.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import update

from app.api.v1.endpoints import evidence
from app.core.config import settings
from app.db.database import session_scope
from app.db.jobs import JobRepository
from app.db.models import InvestigationJob
from app.pipeline.investigation import InvestigationPipeline
from app.pipeline.models import StageStatus

PHISH = "URGENT: account suspended. Verify your password at hxxps://paypal-account-security[.]xyz/signin"
STAGES = ["evidence_collection", "normalization", "validation", "threat_intelligence", "risk_assessment", "ai_analyst"]


@pytest.mark.asyncio
async def test_pipeline_reports_each_stage_start_and_finish():
    events = []
    await InvestigationPipeline().run(PHISH, on_stage=lambda name, st, ms, err: events.append((name, st)))
    expected = [e for name in STAGES for e in ((name, StageStatus.RUNNING), (name, StageStatus.COMPLETED))]
    assert events == expected


@pytest.mark.asyncio
async def test_failing_progress_callback_does_not_fail_investigation():
    def boom(*_):
        raise RuntimeError("progress store down")
    result = await InvestigationPipeline().run(PHISH, on_stage=boom)
    assert result.status == "success"


@pytest.mark.asyncio
async def test_text_job_runs_in_background_and_links_result(async_client):
    res = await async_client.post("/api/v1/evidence/jobs", json={"text": PHISH})
    assert res.status_code == 202
    started = res.json()
    assert started["status"] == "queued" and [s["stage_name"] for s in started["stages"]] == STAGES
    assert all(s["status"] == "PENDING" for s in started["stages"]) and started["progress"] == 0

    job = (await async_client.get(f"/api/v1/jobs/{started['job_id']}")).json()
    assert job["status"] == "succeeded" and job["progress"] == 100
    assert all(s["status"] == "COMPLETED" for s in job["stages"])
    assert job["created_at"].endswith("+00:00")

    result = (await async_client.get(f"/api/v1/investigations/{job['investigation_id']}")).json()
    assert result["risk_assessment"]["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_file_job_and_upload_errors_fail_fast(async_client):
    res = await async_client.post("/api/v1/evidence/jobs/file", files={"file": ("lure.txt", PHISH.encode(), "text/plain")})
    assert res.status_code == 202
    job = (await async_client.get(f"/api/v1/jobs/{res.json()['job_id']}")).json()
    assert job["status"] == "succeeded" and job["source_name"] == "lure.txt"

    too_big = b"x" * (settings.MAX_UPLOAD_MB * 1024 * 1024 + 1)
    res = await async_client.post("/api/v1/evidence/jobs/file", files={"file": ("big.txt", too_big, "text/plain")})
    assert res.status_code == 413


@pytest.mark.asyncio
async def test_job_records_failure_when_result_cannot_be_saved(async_client, monkeypatch):
    def broken_save(*_args, **_kwargs):
        raise RuntimeError("database unavailable")
    monkeypatch.setattr(evidence.service.repository, "save", broken_save)
    started = (await async_client.post("/api/v1/evidence/jobs", json={"text": PHISH})).json()
    job = (await async_client.get(f"/api/v1/jobs/{started['job_id']}")).json()
    assert job["status"] == "failed" and job["investigation_id"] is None
    assert "database" not in job["error"]  # internal details stay in the server log


@pytest.mark.asyncio
async def test_unknown_job_is_404(async_client):
    assert (await async_client.get(f"/api/v1/jobs/{uuid.uuid4()}")).status_code == 404


@pytest.mark.asyncio
async def test_jobs_are_private_to_their_owner(async_client, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "BOOTSTRAP_ADMIN_EMAIL", "")
    monkeypatch.setattr(settings, "SIGNUP_ROLE", "analyst")

    async def signup():
        address = f"jobs-{uuid.uuid4().hex[:8]}@example.com"
        body = (await async_client.post("/api/v1/auth/register",
                                        json={"email": address, "password": "correct-horse-1", "name": "J"})).json()
        return {"Authorization": f"Bearer {body['access_token']}"}

    owner, other = await signup(), await signup()
    job_id = (await async_client.post("/api/v1/evidence/jobs", json={"text": PHISH}, headers=owner)).json()["job_id"]
    assert (await async_client.get(f"/api/v1/jobs/{job_id}", headers=owner)).status_code == 200
    assert (await async_client.get(f"/api/v1/jobs/{job_id}", headers=other)).status_code == 404
    assert (await async_client.get(f"/api/v1/jobs/{job_id}")).status_code == 401


def test_progress_and_stale_job_detection():
    repo = JobRepository()
    job = repo.create(["a", "b"])
    repo.record_stage(job["job_id"], "a", "RUNNING")
    assert repo.get(job["job_id"])["current_stage"] == "a"
    repo.record_stage(job["job_id"], "a", "COMPLETED", 12.5)
    mid = repo.get(job["job_id"])
    assert mid["status"] == "running" and mid["progress"] == 50

    with session_scope() as s:  # simulate a worker that died mid-run
        s.execute(update(InvestigationJob).where(InvestigationJob.id == job["job_id"])
                  .values(updated_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    assert repo.get(job["job_id"])["status"] == "failed"
