"""
PDF parser: text, document metadata, embedded link targets and active-content markers.
"""

import io
import re
from typing import Any, Dict, List, Tuple

ACTIVE_MARKERS = [b"/JavaScript", b"/JS", b"/Launch", b"/OpenAction", b"/AA", b"/EmbeddedFile", b"/SubmitForm", b"/RichMedia"]
MAX_PAGES = 200


def _active_content(data: bytes) -> List[str]:
    found = []
    for marker in ACTIVE_MARKERS:
        # Match whole PDF names only (/JS but not /JSON)
        if re.search(re.escape(marker) + rb"(?![A-Za-z])", data):
            found.append(marker.decode())
    return found


def parse_pdf(data: bytes) -> Tuple[str, Dict[str, Any]]:
    """Returns (extracted_text, pdf_analysis). Never raises on malformed PDFs."""
    analysis: Dict[str, Any] = {"pages": 0, "metadata": {}, "links": [], "active_content": _active_content(data)}
    try:
        from pypdf import PdfReader
    except ImportError:
        analysis["error"] = "pypdf is not installed; PDF text extraction unavailable"
        return "", analysis

    texts: List[str] = []
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
    except Exception as exc:  # malformed / hostile PDFs must not crash ingestion
        analysis["error"] = f"PDF parsing failed: {type(exc).__name__}"

    text = "\n".join(t for t in texts if t.strip())
    if analysis["links"]:
        text += "\n\nLinks:\n" + "\n".join(analysis["links"])
    return text, analysis
