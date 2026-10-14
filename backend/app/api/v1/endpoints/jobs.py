"""
ReconIQ Background Job Endpoints

- GET /api/v1/jobs/{job_id} : poll a background investigation's status and per-stage progress
"""

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth.principal import Principal, require_role
from app.db.jobs import JobRepository

router = APIRouter()
repository = JobRepository()


@router.get("/{job_id}", summary="Get Investigation Job Progress")
def get_job(job_id: str, principal: Principal = Depends(require_role("viewer"))) -> Dict[str, Any]:
    job = repository.get(job_id)
    # Other users' jobs are reported as missing rather than forbidden, so IDs can't be probed.
    if job is None or (job["owner_id"] and job["owner_id"] != principal.id and not principal.has("admin")):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    return job
