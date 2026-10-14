"""
ReconIQ Severity Standard

Purpose:
Defines standard platform-wide threat severity levels.
"""

from enum import Enum


class SeverityLevel(str, Enum):
    """Platform severity classification levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

    @classmethod
    def from_score(cls, score: float) -> "SeverityLevel":
        """Maps a 0-100 score onto the platform severity scale."""
        from app.risk_engine.weights import map_score_to_severity
        return cls(map_score_to_severity(score))

    @property
    def rank(self) -> int:
        return ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(self.value)
