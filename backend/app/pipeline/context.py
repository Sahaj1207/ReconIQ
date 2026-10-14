"""
ReconIQ Investigation Context

Purpose:
Holds the state, extracted evidence, normalized artifacts, validation results, threat intelligence,
risk assessments, stage telemetry, warnings, and errors as an investigation proceeds through pipeline stages.

Responsibilities:
- Provide unified mutable context object across pipeline steps
- Record per-stage execution metrics, timing, warnings, and errors
- Enforce security sanitization to prevent leaking API keys, headers, or internal tracebacks
- Convert state to structured InvestigationResult DTO

Future Extension Notes:
- Serializable state snapshots for Redis session persistence and pause/resume capabilities.
"""

import re
import uuid
import time
import logging
from typing import Dict, Any, List, Optional

from app.ingestion.ingested_input import IngestedInput
from app.pipeline.models import (
    StageMetric,
    StageStatus,
    InvestigationResult
)

logger = logging.getLogger(__name__)


def sanitize_sensitive_data(message: str) -> str:
    """
    Sanitizes string messages to remove API keys, authorization tokens,
    passwords, and internal filesystem stack traces before logging or storing.

    Args:
        message (str): Raw string message.

    Returns:
        str: Cleaned, sanitized message.
    """
    if not message:
        return ""

    sanitized = message

    # Redact Bearer tokens e.g. Bearer xyz123
    sanitized = re.sub(
        r'(?i)\b(bearer)\s+[\w\-]{8,}',
        r'\1 [REDACTED]',
        sanitized
    )

    # Redact key=value or key: value pairs
    sanitized = re.sub(
        r'(?i)(api[_-]?key|token|password|secret|authorization)\s*[:=]\s*["\']?[\w\-]{8,}["\']?',
        r'\1=[REDACTED]',
        sanitized
    )
    sanitized = re.sub(
        r'(?i)(x-apikey)\s*:\s*[\w\-]{8,}',
        r'\1: [REDACTED]',
        sanitized
    )

    # Redact raw Windows / POSIX absolute file path stack traces if present
    sanitized = re.sub(r'File\s+"[^"]+",\s+line\s+\d+,\s+in\s+\w+', '[STACK TRACE REDACTED]', sanitized)

    return sanitized


class InvestigationContext:
    """
    State container passed between all investigation pipeline steps.
    """

    def __init__(
        self,
        raw_input: IngestedInput,
        investigation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Initializes InvestigationContext.

        Args:
            raw_input (IngestedInput): Ingested input payload.
            investigation_id (Optional[str]): Unique UUID string. Generated if not provided.
            metadata (Optional[Dict[str, Any]]): Execution metadata dictionary.
        """
        self.investigation_id = investigation_id or str(uuid.uuid4())
        self.start_time = time.perf_counter()
        self.raw_input = raw_input
        self.execution_metadata = metadata or {}

        # Pipeline Stage Artifact Containers
        self.collected_evidence: Dict[str, Any] = {}
        self.normalized_evidence: Dict[str, Any] = {}
        self.validation_results: Dict[str, Any] = {}
        self.threat_intelligence: Dict[str, Any] = {}
        self.risk_assessment: Optional[Any] = None

        # Telemetry & Diagnostics
        self.stage_metrics: List[StageMetric] = []
        self.warnings: List[str] = []
        self.errors: List[str] = []

    def add_warning(self, message: str) -> None:
        """Adds a sanitized warning message."""
        clean_msg = sanitize_sensitive_data(message)
        self.warnings.append(clean_msg)
        logger.warning(f"[{self.investigation_id}] Pipeline Warning: {clean_msg}")

    def add_error(self, message: str) -> None:
        """Adds a sanitized error message."""
        clean_msg = sanitize_sensitive_data(message)
        self.errors.append(clean_msg)
        logger.error(f"[{self.investigation_id}] Pipeline Error: {clean_msg}")

    def record_stage(
        self,
        stage_name: str,
        status: StageStatus,
        duration_ms: float,
        error: Optional[str] = None
    ) -> None:
        """
        Records telemetry metric for a pipeline stage.

        Args:
            stage_name (str): Stage identifier name.
            status (StageStatus): Stage status enum.
            duration_ms (float): Stage latency in milliseconds.
            error (Optional[str]): Optional stage error message.
        """
        clean_err = sanitize_sensitive_data(error) if error else None
        metric = StageMetric(
            stage_name=stage_name,
            status=status,
            duration_ms=round(duration_ms, 2),
            error=clean_err
        )
        self.stage_metrics.append(metric)

    def to_result(self, status: str = "success") -> InvestigationResult:
        """
        Transforms context state into a final InvestigationResult DTO.

        Args:
            status (str): Overall investigation status ('success', 'partial_success', 'failed').

        Returns:
            InvestigationResult: Populated investigation result object.
        """
        total_duration_ms = round((time.perf_counter() - self.start_time) * 1000, 2)

        # Build summaries
        evidence_summary = {
            category: len(items)
            for category, items in self.collected_evidence.items()
            if isinstance(items, list)
        } if self.collected_evidence else None

        val_summary = {
            category: len(items)
            for category, items in self.validation_results.items()
            if isinstance(items, list)
        } if self.validation_results else None

        threat_summary = {
            category: len(items)
            for category, items in self.threat_intelligence.items()
            if isinstance(items, list)
        } if self.threat_intelligence else None

        risk_summary = None
        risk_dto = None
        if self.risk_assessment:
            if hasattr(self.risk_assessment, "model_dump"):
                risk_dto = self.risk_assessment.model_dump()
            elif isinstance(self.risk_assessment, dict):
                risk_dto = self.risk_assessment

            if risk_dto:
                risk_summary = {
                    "total_score": risk_dto.get("total_score", 0.0),
                    "severity": risk_dto.get("severity", "INFORMATIONAL"),
                    "confidence": risk_dto.get("confidence", 0.0),
                    "findings_count": len(risk_dto.get("findings", []))
                }

        # Convert validation results items to dictionaries for clean JSON serialization
        serialized_validation: Dict[str, Any] = {}
        for cat, items in self.validation_results.items():
            if isinstance(items, list):
                serialized_validation[cat] = [
                    item.model_dump() if hasattr(item, "model_dump") else item
                    for item in items
                ]

        # Convert threat intelligence items to dictionaries for clean JSON serialization
        serialized_intel: Dict[str, Any] = {}
        for cat, items in self.threat_intelligence.items():
            if isinstance(items, list):
                serialized_intel[cat] = [
                    item.model_dump() if hasattr(item, "model_dump") else item
                    for item in items
                ]

        return InvestigationResult(
            investigation_id=self.investigation_id,
            status=status,
            duration_ms=total_duration_ms,
            pipeline_version="1.0.0",
            source_type=getattr(self.raw_input.source_type, "value", str(self.raw_input.source_type)),
            source_name=self.raw_input.metadata.get("filename"),
            input_preview=(self.raw_input.content or "")[:280],
            ingestion=self.raw_input.metadata.get("analysis") or {},
            evidence_summary=evidence_summary,
            validation_summary=val_summary,
            threat_summary=threat_summary,
            risk_summary=risk_summary,
            evidence=self.collected_evidence,
            normalized_evidence=self.normalized_evidence,
            validation_results=serialized_validation,
            threat_intelligence=serialized_intel,
            risk_assessment=risk_dto,
            warnings=self.warnings,
            errors=self.errors,
            execution_metrics=self.stage_metrics
        )
