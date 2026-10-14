"""
ReconIQ File & Message Parsers

Turns uploaded files into an IngestedInput: analysable text for the IOC extractor plus a
structured `analysis` block (email headers, file fingerprint, QR payloads, APK permissions,
PDF active content, Office macros, archive contents) consumed by the deterministic risk rules.

Containers are inspected recursively: ZIP members, email attachments (.eml and Outlook .msg)
and Office packages, all under one shared budget (depth, entry count and decompressed bytes)
so hostile archives cannot exhaust memory or time.
"""

import io
import os
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from app.ingestion.ingested_input import IngestedInput, IngestionSourceType
from app.ingestion.parsers.file_info import fingerprint
from app.ingestion.parsers.email_parser import parse_eml
from app.ingestion.parsers.msg_parser import MsgParseError, parse_msg
from app.ingestion.parsers.office_parser import analyze_ole_document, analyze_ooxml, is_ooxml
from app.ingestion.parsers.pdf_parser import parse_pdf
from app.ingestion.parsers.image_parser import parse_image
from app.ingestion.parsers.apk_parser import parse_apk


class UnsupportedFileError(ValueError):
    """Raised when an uploaded file cannot be ingested."""


TEXT_EXTENSIONS = {".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm", ".md", ".ioc"}

# Archive safety limits (shared across the whole inspection tree)
MAX_ARCHIVE_DEPTH = 3            # archive nesting levels that are opened
MAX_ARCHIVE_ENTRIES = 500        # members examined in total
MAX_ENTRY_BYTES = 20 * 1024 * 1024
MAX_TOTAL_BYTES = 100 * 1024 * 1024
BOMB_RATIO = 100                 # uncompressed:compressed ratio treated as a decompression bomb
MAX_MEMBER_TEXT_CHARS = 200_000  # text pulled from members into the analysed content
MAX_LISTED_MEMBERS = 100


@dataclass
class _Inspection:
    """Budget and roll-up shared by every level of a recursive inspection."""
    entries: int = 0
    total_bytes: int = 0
    text_chars: int = 0
    hashes: List[str] = field(default_factory=list)
    macros: List[Dict[str, Any]] = field(default_factory=list)
    archives: List[Dict[str, Any]] = field(default_factory=list)
    external_links: List[str] = field(default_factory=list)

    def take_text(self, text: str) -> str:
        room = MAX_MEMBER_TEXT_CHARS - self.text_chars
        if room <= 0 or not text.strip():
            return ""
        text = text[:room]
        self.text_chars += len(text)
        return text


def _office(path: str, analysis: Dict[str, Any], insp: _Inspection) -> Dict[str, Any]:
    macros = analysis.get("macros") or {}
    if macros.get("present"):
        insp.macros.append({"file": path, **macros})
    insp.external_links.extend(analysis.get("external_links") or [])
    return analysis


def _inspect_zip(path: str, data: bytes, depth: int, insp: _Inspection) -> Tuple[str, Dict[str, Any]]:
    """Lists and inspects a (non-Office) ZIP archive within the shared budget."""
    archive: Dict[str, Any] = {"path": path, "depth": depth, "entries": 0, "members": [], "encrypted": [],
                               "dangerous": [], "nested_archives": 0, "limits_exceeded": []}
    insp.archives.append(archive)
    texts: List[str] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError, OSError):
        archive["error"] = "Archive could not be opened"
        return "", archive

    def limit(reason: str) -> None:
        if reason not in archive["limits_exceeded"]:
            archive["limits_exceeded"].append(reason)

    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            archive["entries"] += 1
            member_path = f"{path}/{info.filename}"
            if insp.entries >= MAX_ARCHIVE_ENTRIES:
                limit(f"more than {MAX_ARCHIVE_ENTRIES} entries; the rest were not inspected")
                break
            insp.entries += 1
            entry: Dict[str, Any] = {"name": info.filename, "size": info.file_size, "compressed_size": info.compress_size}
            if len(archive["members"]) < MAX_LISTED_MEMBERS:
                archive["members"].append(entry)
            if info.flag_bits & 0x1:
                entry["encrypted"] = True
                archive["encrypted"].append(info.filename)
                # The name alone still reveals a risky type inside a password-protected archive
                if fingerprint(info.filename, b"")["dangerous"]:
                    archive["dangerous"].append(info.filename)
                continue
            if info.file_size > MAX_ENTRY_BYTES:
                limit(f"entry larger than {MAX_ENTRY_BYTES // (1024 * 1024)} MB skipped")
                continue
            if info.file_size > 1024 * 1024 and info.file_size > BOMB_RATIO * max(1, info.compress_size):
                limit("compression ratio suggests a decompression bomb")
                continue
            if insp.total_bytes + info.file_size > MAX_TOTAL_BYTES:
                limit(f"more than {MAX_TOTAL_BYTES // (1024 * 1024)} MB uncompressed; the rest were not inspected")
                break
            try:
                with zf.open(info) as fh:
                    member = fh.read(MAX_ENTRY_BYTES + 1)  # headers can lie about sizes
            except Exception:
                entry["error"] = "could not be extracted"
                continue
            if len(member) > MAX_ENTRY_BYTES:
                limit(f"entry larger than {MAX_ENTRY_BYTES // (1024 * 1024)} MB skipped")
                continue
            insp.total_bytes += len(member)
            text, member_info = _inspect_member(member_path, info.filename, member, depth, insp)
            entry.update({k: member_info[k] for k in ("kind", "sha256", "dangerous") if k in member_info})
            if member_info.get("dangerous"):
                archive["dangerous"].append(info.filename)
            if member_info.get("kind") == "zip" and "office" not in member_info:
                archive["nested_archives"] += 1
            if text:
                texts.append(f"--- {member_path} ---\n{text}")
    return "\n\n".join(texts), archive


def _inspect_member(path: str, filename: str, data: bytes, depth: int, insp: _Inspection) -> Tuple[str, Dict[str, Any]]:
    """Fingerprints an embedded file (archive member or attachment) and inspects it if it is a container."""
    info = fingerprint(filename, data)
    insp.hashes.append(info["sha256"])
    text = ""
    kind, ext = info["kind"], info["extension"]
    if kind == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                if is_ooxml(zf):
                    info["office"] = _office(path, analyze_ooxml(zf), insp)
        except (zipfile.BadZipFile, ValueError, OSError):
            pass
        if "office" not in info:
            if depth < MAX_ARCHIVE_DEPTH:
                text, _ = _inspect_zip(path, data, depth + 1, insp)
            else:
                insp.archives.append({"path": path, "depth": depth + 1, "entries": 0, "members": [], "encrypted": [],
                                      "dangerous": [], "nested_archives": 0,
                                      "limits_exceeded": [f"nested deeper than {MAX_ARCHIVE_DEPTH} levels; not opened"]})
    elif kind == "ole":
        try:
            text, email_info = parse_msg(data)
            text = insp.take_text(text)
            info["email_subject"] = email_info.get("subject")
            for att in email_info.get("attachments", []):
                _inspect_member(f"{path}/{att['filename']}", att["filename"], att.pop("_data", b""), depth, insp)
        except MsgParseError:
            info["office"] = _office(path, analyze_ole_document(data), insp)
    elif kind == "pdf":
        pdf_text, _ = parse_pdf(data, scan_images=False)
        text = insp.take_text(pdf_text)
    elif ext == ".eml":
        eml_text, email_info = parse_eml(data)
        text = insp.take_text(eml_text)
        for att in email_info.get("attachments", []):
            _inspect_member(f"{path}/{att['filename']}", att["filename"], att.pop("_data", b""), depth, insp)
    elif kind == "text" or ext in TEXT_EXTENSIONS:
        text = insp.take_text(data.decode("utf-8", errors="replace"))
    return text, info


def _inspect_attachments(email_info: Dict[str, Any], insp: _Inspection) -> List[str]:
    texts = []
    for att in email_info.get("attachments", []):
        data = att.pop("_data", b"")
        name = att.get("filename") or "attachment"
        text, member_info = _inspect_member(f"attachment:{name}", name, data, 0, insp)
        if "office" in member_info:
            att["office"] = member_info["office"]
        if text:
            texts.append(f"--- attachment: {name} ---\n{text}")
    return texts


def ingest_file(filename: str, data: bytes, refang: bool = True) -> IngestedInput:
    """
    Parses an uploaded file into an IngestedInput.

    The file's own hashes (and those of embedded files) are seeded as indicators so they reach
    threat-intel hash lookups.
    """
    if not data:
        raise UnsupportedFileError("Uploaded file is empty")

    info = fingerprint(filename, data)
    ext = info["extension"]
    analysis: Dict[str, Any] = {"file": info}
    insp = _Inspection()
    text = ""
    extra_texts: List[str] = []

    if ext in (".eml",) or (info["kind"] == "text" and data[:4096].lower().find(b"\nreceived:") >= 0):
        text, analysis["email"] = parse_eml(data)
        extra_texts = _inspect_attachments(analysis["email"], insp)
        source = IngestionSourceType.EMAIL
    elif ext == ".msg" or info["kind"] == "ole":
        try:
            text, analysis["email"] = parse_msg(data)
            extra_texts = _inspect_attachments(analysis["email"], insp)
            source = IngestionSourceType.EMAIL
        except MsgParseError as exc:
            if ext == ".msg":
                raise UnsupportedFileError(str(exc)) from exc
            info["office"] = _office(info["filename"], analyze_ole_document(data), insp)
            source = IngestionSourceType.BROWSER_UPLOAD
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
    elif info["kind"] == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                office = is_ooxml(zf) and analyze_ooxml(zf)
        except (zipfile.BadZipFile, ValueError, OSError):
            office = None
        if office:
            info["office"] = _office(info["filename"], office, insp)
        else:
            text, _ = _inspect_zip(info["filename"], data, 1, insp)
        source = IngestionSourceType.BROWSER_UPLOAD
    elif info["kind"] == "text" or ext in TEXT_EXTENSIONS:
        text = data.decode("utf-8", errors="replace")
        source = IngestionSourceType.BROWSER_UPLOAD
    else:
        # Opaque binary: analyse its fingerprint only (hash lookups + file-type rules)
        source = IngestionSourceType.BROWSER_UPLOAD

    if extra_texts:
        text = "\n\n".join([text, *extra_texts])
    if insp.external_links:
        links = sorted(set(insp.external_links))
        info.setdefault("office", {})["external_links"] = links
        text += "\n\nExternal links:\n" + "\n".join(links)
    if insp.macros:
        analysis["macros"] = insp.macros
    if insp.archives:
        analysis["archives"] = insp.archives

    return IngestedInput(
        content=text,
        source_type=source,
        metadata={
            "refang": refang,
            "filename": os.path.basename(filename or "upload"),
            "analysis": analysis,
            "seed_indicators": {"hashes": list(dict.fromkeys([info["sha256"]] + [
                a["sha256"] for a in (analysis.get("email") or {}).get("attachments", [])
            ] + insp.hashes))},
        },
    )


__all__ = ["ingest_file", "UnsupportedFileError", "parse_eml", "parse_msg", "parse_pdf", "parse_image", "parse_apk",
           "fingerprint"]
