"""
ReconIQ File & Message Parsers

Turns uploaded files into an IngestedInput: analysable text for the IOC extractor plus a
structured `analysis` block (email headers, file fingerprint, QR payloads, APK permissions,
PDF active content) consumed by the deterministic risk rules.
"""

import os
from typing import Any, Dict

from app.ingestion.ingested_input import IngestedInput, IngestionSourceType
from app.ingestion.parsers.file_info import fingerprint
from app.ingestion.parsers.email_parser import parse_eml
from app.ingestion.parsers.pdf_parser import parse_pdf
from app.ingestion.parsers.image_parser import parse_image
from app.ingestion.parsers.apk_parser import parse_apk


class UnsupportedFileError(ValueError):
    """Raised when an uploaded file cannot be ingested."""


TEXT_EXTENSIONS = {".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm", ".md", ".ioc"}


def ingest_file(filename: str, data: bytes, refang: bool = True) -> IngestedInput:
    """
    Parses an uploaded file into an IngestedInput.

    The file's own hashes are seeded as indicators so they reach threat-intel hash lookups.
    """
    if not data:
        raise UnsupportedFileError("Uploaded file is empty")

    info = fingerprint(filename, data)
    ext = info["extension"]
    analysis: Dict[str, Any] = {"file": info}
    text = ""

    if ext in (".eml",) or (info["kind"] == "text" and data[:4096].lower().find(b"\nreceived:") >= 0):
        text, analysis["email"] = parse_eml(data)
        source = IngestionSourceType.EMAIL
    elif ext == ".msg":
        raise UnsupportedFileError("Outlook .msg files are not supported yet; save the message as .eml and retry")
    elif info["kind"] == "pdf":
        text, info["pdf"] = parse_pdf(data)
        source = IngestionSourceType.PDF_FILE
    elif info["kind"] == "image":
        text, image_analysis = parse_image(data)
        info.update(image_analysis)
        source = IngestionSourceType.QR_CODE if image_analysis["qr_payloads"] else IngestionSourceType.IMAGE
    elif info["kind"] == "apk" or ext == ".apk":
        text, info["apk"] = parse_apk(data)
        source = IngestionSourceType.APK_FILE
    elif info["kind"] == "text" or ext in TEXT_EXTENSIONS:
        text = data.decode("utf-8", errors="replace")
        source = IngestionSourceType.BROWSER_UPLOAD
    else:
        # Opaque binary: analyse its fingerprint only (hash lookups + file-type rules)
        source = IngestionSourceType.BROWSER_UPLOAD

    return IngestedInput(
        content=text,
        source_type=source,
        metadata={
            "refang": refang,
            "filename": os.path.basename(filename or "upload"),
            "analysis": analysis,
            "seed_indicators": {"hashes": [info["sha256"]] + [
                a["sha256"] for a in (analysis.get("email") or {}).get("attachments", [])
            ]},
        },
    )


__all__ = ["ingest_file", "UnsupportedFileError", "parse_eml", "parse_pdf", "parse_image", "parse_apk", "fingerprint"]
