"""
ReconIQ Pytest Configuration & Fixtures

Provides test client fixtures and sample threat intelligence payload samples for unit & API tests.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.fixture
def sample_threat_text() -> str:
    """Provides a synthetic threat payload containing defanged and standard IOCs."""
    return (
        "CRITICAL ALERT: Phishing email received from attacker[at]malicious-bank[dot]com "
        "directing user to hxxps://phishing-portal[.]com/login?user=123. "
        "C2 IP addresses identified: 198.51.100.45 and IPv6 2001:db8:85a3::8a2e:370:7334. "
        "Contact hotline at +1-800-555-0199 or +44 20 7946 0958."
    )


@pytest.fixture
async def async_client():
    """Provides HTTPX async test client for FastAPI endpoint integration testing."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        yield client
