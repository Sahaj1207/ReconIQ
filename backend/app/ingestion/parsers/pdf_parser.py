"""
PDF parser: text, document metadata, embedded link targets, active-content markers, and QR codes /
OCR text in embedded images (QR "quishing" PDFs often carry the lure only as an image).
"""

import io
import re
from typing import Any, Dict, List, Tuple

from app.ingestion.parsers.image_parser import decode_qr, ocr_available, run_ocr

ACTIVE_MARKERS = [b"/JavaScript", b"/JS", b"/Launch", b"/OpenAction", b"/AA", b"/EmbeddedFile", b"/SubmitForm", b"/RichMedia"]
MAX_PAGES = 200
# Embedded image limits: QR decoding is cheap, OCR is not
MAX_IMAGES = 25
MAX_OCR_IMAGES = 5
MAX_IMAGE_BYTES = 8 * 1024 * 1024
MIN_IMAGE_SIDE = 40  # skip icons, bullets and tracking pixels


def _active_content(data: bytes) -> List[str]:
    found = []
    for marker in ACTIVE_MARKERS:
        # Match whole PDF names only (/JS but not /JSON)
        if re.search(re.escape(marker) + rb"(?![A-Za-z])", data):
            found.append(marker.decode())
    return found


def _scan_images(reader, analysis: Dict[str, Any]) -> List[str]:
    """QR-decodes (and OCRs, when Tesseract is available) images embedded in the first pages."""
    images: Dict[str, Any] = {"scanned": 0, "qr_payloads": [], "ocr_characters": 0}
    analysis["images"] = images
    texts: List[str] = []
    ocr = ocr_available()
    ocr_done = 0
    for page in reader.pages[:MAX_PAGES]:
        try:
            page_images = list(page.images)
        except Exception:  # unsupported filters / broken XObjects
            continue
        for image in page_images:
            if images["scanned"] >= MAX_IMAGES:
                images["truncated"] = True
                return texts
            try:
                data = image.data
                width, height = image.image.size if image.image is not None else (0, 0)
            except Exception:
                continue
            if not data or len(data) > MAX_IMAGE_BYTES or min(width, height) < MIN_IMAGE_SIDE:
                continue
            images["scanned"] += 1
            for payload in decode_qr(data):
                if payload not in images["qr_payloads"]:
                    images["qr_payloads"].append(payload)
                    texts.append(payload)
            if ocr and ocr_done < MAX_OCR_IMAGES:
                ocr_done += 1
                try:
                    ocr_text = run_ocr(data)
                    images["ocr_characters"] += len(ocr_text.strip())
                    texts.append(ocr_text)
                except Exception:
                    images.setdefault("notes", []).append("OCR failed on an embedded image")
    return texts


def parse_pdf(data: bytes, scan_images: bool = True) -> Tuple[str, Dict[str, Any]]:
    """Returns (extracted_text, pdf_analysis). Never raises on malformed PDFs."""
    analysis: Dict[str, Any] = {"pages": 0, "metadata": {}, "links": [], "active_content": _active_content(data)}
    try:
        from pypdf import PdfReader
    except ImportError:
        analysis["error"] = "pypdf is not installed; PDF text extraction unavailable"
        return "", analysis

    texts: List[str] = []
    image_texts: List[str] = []
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            try:
                reader.decrypt("")
            except Exception:
                analysis["error"] = "PDF is encrypted"
                return "", analysis
        analysis["pages"] = len(reader.pages)
        meta = reader.metadata or {}
        analysis["metadata"] = {k.lstrip("/"): str(v) for k, v in meta.items() if v}
        links = set()
        for page in reader.pages[:MAX_PAGES]:
            texts.append(page.extract_text() or "")
            for annot in page.get("/Annots") or []:
                try:
                    action = annot.get_object().get("/A") or {}
                    uri = action.get("/URI")
                    if uri:
                        links.add(str(uri))
                except Exception:
                    continue
        analysis["links"] = sorted(links)
        if scan_images:
            image_texts = _scan_images(reader, analysis)
    except Exception as exc:  # malformed / hostile PDFs must not crash ingestion
        analysis["error"] = f"PDF parsing failed: {type(exc).__name__}"

    text = "\n".join(t for t in texts if t.strip())
    if analysis["links"]:
        text += "\n\nLinks:\n" + "\n".join(analysis["links"])
    if image_texts:
        text += "\n\nFrom embedded images:\n" + "\n".join(t for t in image_texts if t.strip())
    return text, analysis
