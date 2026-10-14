"""
Investigation job repository: background runs and their per-stage progress.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import update

from app.db.database import session_scope
from app.db.models import InvestigationJob

FINISHED = ("succeeded", "failed")
# A job still "running" after this long lost its worker (restart, serverless freeze).
STALE_AFTER = timedelta(minutes=10)


def _job_dict(job: InvestigationJob) -> Dict[str, Any]:
    status = job.status
    error = job.error
    if status not in FINISHED and job.updated_at and datetime.now(timezone.utc) - job.updated_at > STALE_AFTER:
        status, error = "failed", "The investigation stopped responding; please run it again"
    return {
        "job_id": job.id,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "updated_at": job.updated_at.isoformat() if job.updated_at else None,
        "status": status,
        "source_type": job.source_type,
        "source_name": job.source_name,
        "stages": job.stages or [],
        "current_stage": job.current_stage,
        "progress": job.progress,
        "investigation_id": job.investigation_id,
        "error": error,
        "owner_id": job.owner_id,
    }


class JobRepository:
    def create(self, stage_names: List[str], source_type: str = "raw_text",
               source_name: Optional[str] = None, owner=None) -> Dict[str, Any]:
        job = InvestigationJob(
            id=str(uuid.uuid4()),
            status="queued",
            source_type=source_type,
            source_name=source_name,
            stages=[{"stage_name": n, "status": "PENDING", "duration_ms": 0.0, "error": None} for n in stage_names],
            progress=0,
            owner_id=getattr(owner, "id", None),
        )
        with session_scope() as s:
            s.add(job)
            s.flush()
            return _job_dict(job)

    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        with session_scope() as s:
            job = s.get(InvestigationJob, job_id)
            return _job_dict(job) if job else None

    def record_stage(self, job_id: str, stage_name: str, status: str,
                     duration_ms: float = 0.0, error: Optional[str] = None) -> None:
        with session_scope() as s:
            job = s.get(InvestigationJob, job_id)
            if not job:
                return
            stages = [dict(st) for st in job.stages or []]
            for st in stages:
                if st["stage_name"] == stage_name:
                    st.update(status=status, duration_ms=round(duration_ms, 2), error=error)
            done = sum(st["status"] in ("COMPLETED", "FAILED", "SKIPPED") for st in stages)
            job.stages = stages  # reassign so the JSON column is marked dirty
            job.status = "running"
            job.current_stage = stage_name if status == "RUNNING" else job.current_stage
            job.progress = int(done * 100 / max(1, len(stages)))
            job.updated_at = datetime.now(timezone.utc)

    def finish(self, job_id: str, investigation_id: str) -> None:
        self._set(job_id, status="succeeded", progress=100, current_stage=None, investigation_id=investigation_id)

    def fail(self, job_id: str, error: str) -> None:
        self._set(job_id, status="failed", current_stage=None, error=error)

    def _set(self, job_id: str, **fields: Any) -> None:
        with session_scope() as s:
            s.execute(update(InvestigationJob).where(InvestigationJob.id == job_id)
                      .values(updated_at=datetime.now(timezone.utc), **fields))
