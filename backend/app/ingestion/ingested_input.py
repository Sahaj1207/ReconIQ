"""
ReconIQ Ingested Input Model

Purpose:
Reusable data model representing incoming investigation payloads entering the ReconIQ platform.

Responsibilities:
- Encapsulate raw input payload (plain text, file byte streams, metadata headers)
- Track source channel via IngestionSourceType enum
- Provide helper constructors for seamless instantiation from text or API requests

Future Implementation Notes:
- Extend support for file streams, mime-type detection, SHA256 checksum generation, and payload size validation.
"""

from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class IngestionSourceType(str, Enum):
    """Supported source channels for input ingestion."""
    RAW_TEXT = "raw_text"
    PDF_FILE = "pdf_file"
    EMAIL = "email"
    QR_CODE = "qr_code"
    OCR_TEXT = "ocr_text"
    IMAGE = "image"
    APK_FILE = "apk_file"
    BROWSER_UPLOAD = "browser_upload"


class IngestedInput(BaseModel):
    """
    Unified Ingestion Payload container passed to the EvidenceCollector.
    """
    content: str = Field(
        ...,
        description="Raw string content or text payload to be analyzed"
    )
    source_type: IngestionSourceType = Field(
        default=IngestionSourceType.RAW_TEXT,
        description="Originating source channel of the input payload"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional metadata key-values (e.g. filename, headers, user_agent, timestamp)"
    )

    @classmethod
    def from_text(cls, text: str, metadata: Optional[Dict[str, Any]] = None) -> "IngestedInput":
        """
        Convenience constructor for creating IngestedInput from raw text.

        Args:
            text (str): Input text string.
            metadata (Optional[Dict[str, Any]]): Optional metadata context dictionary.

        Returns:
            IngestedInput: Instantiated input model object.
        """
        return cls(
            content=text,
            source_type=IngestionSourceType.RAW_TEXT,
            metadata=metadata or {}
        )
