"""
ReconIQ Investigation History Endpoints

- GET    /api/v1/investigations          : paginated, filterable history
- GET    /api/v1/investigations/stats    : dashboard aggregates
- GET    /api/v1/investigations/{id}     : full stored investigation result
- DELETE /api/v1/investigations/{id}     : remove an investigation
- GET    /api/v1/investigations/{id}/report?format=json|stix|markdown|pdf : export
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse

from app.reports import build_stix_bundle, render_markdown, render_pdf

from app.db.repository import InvestigationRepository

router = APIRouter()
repository = InvestigationRepository()


@router.get("", summary="List Investigations")
def list_investigations(
    limit: int = Query(25, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None, pattern="^(?i)(critical|high|medium|low|informational)$"),
    q: Optional[str] = Query(None, max_length=200, description="Search preview, filename, classification or ID"),
) -> Dict[str, Any]:
    return repository.list(limit=limit, offset=offset, severity=severity, q=q)


@router.get("/stats", summary="Investigation Statistics")
def investigation_stats() -> Dict[str, Any]:
    return repository.stats()


def load_or_404(investigation_id: str) -> Dict[str, Any]:
    result = repository.get(investigation_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    return result


@router.get("/{investigation_id}", summary="Get Investigation")
def get_investigation(investigation_id: str) -> Dict[str, Any]:
    return load_or_404(investigation_id)


@router.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete Investigation")
def delete_investigation(investigation_id: str) -> Response:
    if not repository.delete(investigation_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{investigation_id}/report", summary="Export Investigation Report")
def export_report(
    investigation_id: str,
    format: str = Query("json", pattern="^(json|stix|markdown|pdf)$"),
) -> Response:
    result = load_or_404(investigation_id)
    stem = f"reconiq-{investigation_id[:8]}"
    if format == "stix":
        return JSONResponse(build_stix_bundle(result), media_type="application/stix+json;version=2.1",
                            headers={"Content-Disposition": f'attachment; filename="{stem}.stix.json"'})
    if format == "markdown":
        return Response(render_markdown(result), media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{stem}.md"'})
    if format == "pdf":
        return Response(render_pdf(result), media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{stem}.pdf"'})
    return JSONResponse(result, headers={"Content-Disposition": f'attachment; filename="{stem}.json"'})
