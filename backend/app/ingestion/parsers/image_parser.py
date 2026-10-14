"""
Image parser: QR code decoding (OpenCV) and optional OCR (Tesseract via pytesseract).
"""

import shutil
from typing import Any, Dict, List, Tuple


def decode_qr(data: bytes) -> List[str]:
    """Decodes every QR code in the image. Returns [] when OpenCV is unavailable or none found."""
    try:
        import cv2
        import numpy as np
    except ImportError:
        return []
    image = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        return []
    detector = cv2.QRCodeDetector()
    payloads: List[str] = []
    try:
        ok, decoded, _, _ = detector.detectAndDecodeMulti(image)
        if ok:
            payloads.extend(p for p in decoded if p)
    except cv2.error:
        pass
    if not payloads:
        try:
            single, _, _ = detector.detectAndDecode(image)
            if single:
                payloads.append(single)
        except cv2.error:
            pass
    return list(dict.fromkeys(payloads))


def ocr_available() -> bool:
    try:
        import pytesseract  # noqa: F401
    except ImportError:
        return False
    return shutil.which("tesseract") is not None


def run_ocr(data: bytes) -> str:
    import io
    import pytesseract
    from PIL import Image
    return pytesseract.image_to_string(Image.open(io.BytesIO(data)))


def parse_image(data: bytes) -> Tuple[str, Dict[str, Any]]:
    """Returns (text from QR payloads + OCR, image_analysis)."""
    analysis: Dict[str, Any] = {"qr_payloads": decode_qr(data), "ocr": {"available": ocr_available(), "characters": 0}}
    text_parts = list(analysis["qr_payloads"])
    if analysis["ocr"]["available"]:
        try:
            ocr_text = run_ocr(data)
            analysis["ocr"]["characters"] = len(ocr_text.strip())
            text_parts.append(ocr_text)
        except Exception as exc:
            analysis["ocr"]["error"] = f"OCR failed: {type(exc).__name__}"
    else:
        analysis["ocr"]["note"] = "Install tesseract-ocr and pytesseract to extract text from images"
    return "\n".join(t for t in text_parts if t and t.strip()), analysis
