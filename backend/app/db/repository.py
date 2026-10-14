"""
Investigation repository: persistence and queries for completed investigations.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import delete, func, or_, select

from app.db.database import session_scope
from app.db.models import InvestigationRecord
from app.pipeline.models import InvestigationResult

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


def _summary(rec: InvestigationRecord) -> Dict[str, Any]:
    return {
        "investigation_id": rec.id,
        "created_at": rec.created_at.isoformat() if rec.created_at else None,
        "status": rec.status,
        "source_type": rec.source_type,
        "source_name": rec.source_name,
        "input_preview": rec.input_preview,
        "score": rec.score,
        "severity": rec.severity,
        "classification": rec.classification,
        "ioc_count": rec.ioc_count,
        "owner_id": rec.owner_id,
        "owner_email": rec.owner_email,
    }


class InvestigationRepository:
    def save(self, result: InvestigationResult, owner=None) -> None:
        risk = result.risk_assessment or {}
        record = InvestigationRecord(
            id=result.investigation_id,
            created_at=datetime.fromisoformat(result.timestamp),
            status=result.status,
            source_type=result.source_type,
            source_name=result.source_name,
            input_preview=result.input_preview,
            score=float(risk.get("total_score", 0.0)),
            severity=risk.get("severity", "INFORMATIONAL"),
            classification=risk.get("classification", "no_threat_identified"),
            ioc_count=sum((result.evidence_summary or {}).values()),
            result=result.model_dump(mode="json"),
            owner_id=getattr(owner, "id", None),
            owner_email=getattr(owner, "email", None) if getattr(owner, "kind", None) == "user" else None,
        )
        with session_scope() as s:
            s.merge(record)

    def get(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        with session_scope() as s:
            rec = s.get(InvestigationRecord, investigation_id)
            if not rec:
                return None
            return {**rec.result, "owner_id": rec.owner_id, "owner_email": rec.owner_email}

    def list(self, limit: int = 25, offset: int = 0, severity: Optional[str] = None,
             q: Optional[str] = None, owner_id: Optional[str] = None) -> Dict[str, Any]:
        stmt = select(InvestigationRecord)
        if owner_id:
            stmt = stmt.where(InvestigationRecord.owner_id == owner_id)
        if severity:
            stmt = stmt.where(InvestigationRecord.severity == severity.upper())
        if q:
            like = f"%{q.lower()}%"
            stmt = stmt.where(or_(
                func.lower(InvestigationRecord.input_preview).like(like),
                func.lower(InvestigationRecord.source_name).like(like),
                func.lower(InvestigationRecord.classification).like(like),
                InvestigationRecord.id.like(like),
            ))
        with session_scope() as s:
            total = s.scalar(select(func.count()).select_from(stmt.subquery())) or 0
            rows = s.scalars(stmt.order_by(InvestigationRecord.created_at.desc()).limit(limit).offset(offset)).all()
            return {"total": total, "items": [_summary(r) for r in rows]}

    def delete(self, investigation_id: str) -> bool:
        with session_scope() as s:
            return s.execute(delete(InvestigationRecord).where(InvestigationRecord.id == investigation_id)).rowcount > 0

    def stats(self) -> Dict[str, Any]:
        since = datetime.now(timezone.utc) - timedelta(days=7)
        with session_scope() as s:
            by_sev = dict(s.execute(select(InvestigationRecord.severity, func.count()).group_by(InvestigationRecord.severity)).all())
            by_cls = s.execute(
                select(InvestigationRecord.classification, func.count())
                .where(InvestigationRecord.classification != "no_threat_identified")
                .group_by(InvestigationRecord.classification).order_by(func.count().desc()).limit(6)
            ).all()
            total = sum(by_sev.values())
            recent = s.scalar(select(func.count()).where(InvestigationRecord.created_at >= since)) or 0
            avg = s.scalar(select(func.avg(InvestigationRecord.score))) or 0.0
        return {
            "total": total,
            "last_7_days": recent,
            "average_score": round(float(avg), 1),
            "by_severity": {sev: by_sev.get(sev, 0) for sev in SEVERITIES},
            "top_classifications": [{"classification": c, "count": n} for c, n in by_cls],
        }
