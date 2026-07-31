"""
ReconIQ Risk Engine Weights Matrix & Severity Mappings

Purpose:
Centralized numeric risk weight definitions and severity classification rules.

Responsibilities:
- Maintain consistent weight values across all rule evaluation classes
- Provide mapping functions from numeric risk scores to platform severity levels

Severity Scale Mapping:
  0–19   : INFORMATIONAL
 20–39   : LOW
 40–59   : MEDIUM
 60–79   : HIGH
 80–100  : CRITICAL

Future Extension Notes:
- Tenant-configurable custom weight overrides via configuration files.
"""

from typing import Dict


class RiskWeights:
    """
    Centralized severity weights constants.
    """
    INFORMATIONAL = 0.0
    LOW = 10.0
    MEDIUM = 25.0
    HIGH = 50.0
    CRITICAL = 80.0

    @classmethod
    def get_weight_map(cls) -> Dict[str, float]:
        """Returns map of severity names to base weight constants."""
        return {
            "INFORMATIONAL": cls.INFORMATIONAL,
            "LOW": cls.LOW,
            "MEDIUM": cls.MEDIUM,
            "HIGH": cls.HIGH,
            "CRITICAL": cls.CRITICAL,
        }


def map_score_to_severity(score: float) -> str:
    """
    Maps a numeric score (0.0 to 100.0) to a deterministic platform severity string.

    Args:
        score (float): Capped numeric risk score between 0.0 and 100.0.

    Returns:
        str: Severity level string ('INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
    """
    clamped_score = max(0.0, min(100.0, float(score)))

    if clamped_score < 20.0:
        return "INFORMATIONAL"
    elif clamped_score < 40.0:
        return "LOW"
    elif clamped_score < 60.0:
        return "MEDIUM"
    elif clamped_score < 80.0:
        return "HIGH"
    else:
        return "CRITICAL"
