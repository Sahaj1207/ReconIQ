"""
ReconIQ Severity Standard

Purpose:
Defines standard platform-wide threat severity levels and color mappings.

Responsibilities:
- Provide strict Enum for severity ratings across risk engines and reporting DTOs

Future Implementation Notes:
- Configurable severity score bounds per enterprise tenant.

TODO:
- [ ] Implement score-to-severity mapping helper method.
"""

from enum import Enum


class SeverityLevel(str, Enum):
    """Platform severity classification levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
