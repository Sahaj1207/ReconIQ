"""
Persistence models.
"""

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class InvestigationRecord(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True,
                                                 default=lambda: datetime.now(timezone.utc))
    status: Mapped[str] = mapped_column(String(32))
    source_type: Mapped[str] = mapped_column(String(32), index=True)
    source_name: Mapped[str] = mapped_column(String(255), nullable=True)
    input_preview: Mapped[str] = mapped_column(Text, default="")
    score: Mapped[float] = mapped_column(Float, index=True, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), index=True, default="INFORMATIONAL")
    classification: Mapped[str] = mapped_column(String(64), index=True, default="no_threat_identified")
    ioc_count: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[dict] = mapped_column(JSON)
