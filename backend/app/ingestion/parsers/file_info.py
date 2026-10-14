"""
Generic file fingerprinting: hashes, size, magic-byte type detection and risk classification.
"""

import hashlib
import os
from typing import Any, Dict

# (magic prefix, detected kind, mime)
MAGIC_SIGNATURES = [
    (b"%PDF-", "pdf", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image", "image/png"),
    (b"\xff\xd8\xff", "image", "image/jpeg"),
    (b"GIF87a", "image", "image/gif"),
    (b"GIF89a", "image", "image/gif"),
    (b"BM", "image", "image/bmp"),
    (b"RIFF", "riff", "application/octet-stream"),
    (b"MZ", "pe", "application/x-msdownload"),
    (b"\x7fELF", "elf", "application/x-elf"),
    (b"PK\x03\x04", "zip", "application/zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "application/x-ole-storage"),
    (b"Rar!", "archive", "application/x-rar-compressed"),
    (b"7z\xbc\xaf\x27\x1c", "archive", "application/x-7z-compressed"),
]

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".msi", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".hta", ".jar", ".apk", ".dll", ".iso", ".img", ".lnk", ".docm", ".xlsm", ".pptm", ".dotm", ".xlam",
    ".one", ".cpl", ".reg", ".chm", ".sh", ".elf", ".dmg", ".pkg", ".appx", ".msix",
}
DANGEROUS_KINDS = {"pe", "elf"}


def fingerprint(filename: str, data: bytes) -> Dict[str, Any]:
    """Returns hashes, size, detected type and whether the file type is inherently high-risk."""
    ext = os.path.splitext(filename or "")[1].lower()
    kind, mime = "unknown", "application/octet-stream"
    for magic, k, m in MAGIC_SIGNATURES:
        if data.startswith(magic):
            kind, mime = k, m
            break
    if kind == "riff" and data[8:12] == b"WEBP":
        kind, mime = "image", "image/webp"
    if kind == "zip" and ext == ".apk":
        kind, mime = "apk", "application/vnd.android.package-archive"
    if kind == "unknown":
        try:
            data[:4096].decode("utf-8")
            kind, mime = "text", "text/plain"
        except UnicodeDecodeError:
            pass

    extension_mismatch = bool(kind in DANGEROUS_KINDS and ext not in DANGEROUS_EXTENSIONS)
    return {
        "filename": filename,
        "extension": ext,
        "size": len(data),
        "kind": kind,
        "mime": mime,
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "dangerous": ext in DANGEROUS_EXTENSIONS or kind in DANGEROUS_KINDS,
        "extension_mismatch": extension_mismatch,
    }
