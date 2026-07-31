"""
ReconIQ Ingestion Package

Multi-source artifact ingestion system responsible for handling raw text, emails,
QR codes, OCR, PDFs, APKs, browser uploads, and file metadata extraction.

Contains the EvidenceCollector facade and granular extractor implementations.
"""

from app.ingestion.collector import EvidenceCollector

__all__ = ["EvidenceCollector"]
