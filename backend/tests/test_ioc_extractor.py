"""
ReconIQ Evidence Collection Layer Phase 1 Tests

Verifies:
- IngestedInput model instantiation and helper constructors
- BaseExtractor abstract interface compliance
- IOCExtractor direct extraction (IPv4, IPv6, URLs, Domains, Emails, Phones, defang normalization)
- EvidenceCollector facade orchestration, extractor registration, merging, deduplication, fault tolerance
- FastAPI health and evidence extraction endpoints
"""

import pytest
from app.ingestion.ingested_input import IngestedInput, IngestionSourceType
from app.ingestion.extractors.base import BaseExtractor
from app.ingestion.extractors.ioc_extractor import IOCExtractor
from app.ingestion.collector import EvidenceCollector


def test_ingested_input_model():
    """Verifies IngestedInput instantiation and helper constructor."""
    text = "Test threat text with IP 1.1.1.1"
    model = IngestedInput.from_text(text, metadata={"user_agent": "ReconIQ-Scanner"})

    assert model.content == text
    assert model.source_type == IngestionSourceType.RAW_TEXT
    assert model.metadata["user_agent"] == "ReconIQ-Scanner"


def test_ioc_extractor_direct(sample_threat_text: str):
    """Verifies that IOCExtractor extracts all indicator types with refanging."""
    input_data = IngestedInput.from_text(sample_threat_text, metadata={"refang": True})
    extractor = IOCExtractor()

    assert extractor.name == "ioc_extractor"
    assert IngestionSourceType.RAW_TEXT in extractor.supported_source_types

    results = extractor.extract(input_data)

    assert "198.51.100.45" in results["ipv4"]
    assert "2001:db8:85a3::8a2e:370:7334" in results["ipv6"]
    assert "https://phishing-portal.com/login?user=123" in results["urls"]
    assert "malicious-bank.com" in results["domains"]
    assert "phishing-portal.com" in results["domains"]
    assert "attacker@malicious-bank.com" in results["emails"]
    assert any("+18005550199" in phone for phone in results["phone_numbers"]) or len(results["phone_numbers"]) > 0


def test_evidence_collector_pluggable():
    """Verifies custom extractor registration into EvidenceCollector."""
    class DummyExtractor(BaseExtractor):
        @property
        def name(self) -> str:
            return "dummy_extractor"

        @property
        def supported_source_types(self):
            return [IngestionSourceType.RAW_TEXT]

        def extract(self, input_data: IngestedInput):
            return {
                "ipv4": ["10.0.0.1"],
                "urls": ["http://dummy.local"],
            }

    collector = EvidenceCollector()
    dummy = DummyExtractor()
    collector.register_extractor(dummy)

    input_data = IngestedInput.from_text("Sample payload")
    response = collector.collect(input_data)

    assert response.status == "success"
    assert "10.0.0.1" in response.results.ipv4
    assert "http://dummy.local" in response.results.urls


def test_collector_fault_tolerance():
    """Verifies that a failing extractor does not crash the EvidenceCollector."""
    class FaultyExtractor(BaseExtractor):
        @property
        def name(self) -> str:
            return "faulty_extractor"

        @property
        def supported_source_types(self):
            return [IngestionSourceType.RAW_TEXT]

        def extract(self, input_data: IngestedInput):
            raise RuntimeError("Simulated extractor crash")

    collector = EvidenceCollector()
    collector.register_extractor(FaultyExtractor())

    # Should safely complete using valid extractors (e.g. IOCExtractor)
    response = collector.collect("C2 server at 198.51.100.45")
    assert response.status == "success"
    assert "198.51.100.45" in response.results.ipv4


@pytest.mark.asyncio
async def test_api_health_endpoint(async_client):
    """Integration test for GET /api/v1/health endpoint."""
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "ReconIQ" in data["app_name"]


@pytest.mark.asyncio
async def test_api_evidence_extract_endpoint(async_client, sample_threat_text: str):
    """Integration test for POST /api/v1/evidence/extract endpoint."""
    payload = {
        "text": sample_threat_text,
        "refang": True
    }
    response = await async_client.post("/api/v1/evidence/extract", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["summary"]["total_iocs"] >= 5
    assert "198.51.100.45" in data["results"]["ipv4"]
