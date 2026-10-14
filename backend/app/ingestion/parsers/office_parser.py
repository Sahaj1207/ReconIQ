"""
Office document parser: VBA macro detection for OOXML (.docm/.xlsm/...) and legacy OLE (.doc/.xls),
plus external relationship targets (remote templates, linked content) in OOXML packages.

Macro source is decompressed (MS-OVBA 2.4.1) so auto-execution entry points and suspicious
calls can be reported. Nothing is ever executed.
"""

import io
import re
import struct
import zipfile
from typing import Any, Dict, List, Optional, Tuple

MAX_VBA_PROJECT_BYTES = 10 * 1024 * 1024
MAX_MODULES = 50
MAX_SOURCE_CHARS = 200_000  # per module, for keyword scanning only

AUTOEXEC = [
    "AutoOpen", "Auto_Open", "AutoExec", "AutoClose", "Auto_Close", "AutoNew", "Document_Open", "Document_Close",
    "Document_New", "Document_BeforeClose", "Workbook_Open", "Workbook_Activate", "Workbook_BeforeClose",
    "Presentation_Open",
]
# Regex fragments grouped by the behaviour they indicate
SUSPICIOUS = {
    "shell execution": [r"Shell", r"WScript\.Shell", r"ShellExecute", r"cmd\.exe", r"powershell"],
    "object creation": [r"CreateObject", r"GetObject", r"CallByName"],
    "download": [r"URLDownloadToFile", r"MSXML2\.XMLHTTP", r"WinHttp\.WinHttpRequest", r"XMLHTTP"],
    "file write": [r"ADODB\.Stream", r"SaveToFile", r"Scripting\.FileSystemObject"],
    "native API": [r"Declare\s+(?:PtrSafe\s+)?(?:Function|Sub)", r"VirtualAlloc", r"RtlMoveMemory", r"CreateThread"],
    "obfuscation": [r"StrReverse", r"Chr[BW]?\$?(?=\()", r"FromBase64String", r"Environ"],
}
_AUTOEXEC_RE = re.compile(r"\b(?:Sub|Function)\s+(" + "|".join(AUTOEXEC) + r")\b", re.IGNORECASE)
_SUSPICIOUS_RE = {
    group: re.compile(r"(?<![\w.])(?:" + "|".join(terms) + r")(?!\w)", re.IGNORECASE)
    for group, terms in SUSPICIOUS.items()
}
_EXTERNAL_REL_RE = re.compile(rb'<Relationship\b[^>]*\bTargetMode="External"[^>]*>', re.IGNORECASE)
_TARGET_RE = re.compile(rb'\bTarget="([^"]+)"', re.IGNORECASE)


def empty_macros() -> Dict[str, Any]:
    return {"present": False, "modules": [], "autoexec": [], "suspicious": []}


def decompress_vba(data: bytes) -> bytes:
    """Decompresses an MS-OVBA CompressedContainer. Raises ValueError on malformed input."""
    if not data or data[0] != 0x01:
        raise ValueError("not a VBA compressed container")
    out = bytearray()
    pos = 1
    while pos + 2 <= len(data):
        header = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if header & 0x7000 != 0x3000:
            raise ValueError("bad chunk signature")
        chunk_end = min(len(data), pos + (header & 0x0FFF) + 1)
        if not header & 0x8000:  # raw chunk: 4096 literal bytes
            out += data[pos:pos + 4096]
            pos += 4096
            continue
        chunk_start = len(out)
        while pos < chunk_end:
            flags = data[pos]
            pos += 1
            for bit in range(8):
                if pos >= chunk_end:
                    break
                if not flags & (1 << bit):
                    out.append(data[pos])
                    pos += 1
                    continue
                if pos + 2 > chunk_end:
                    raise ValueError("truncated copy token")
                token = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                bit_count = max((len(out) - chunk_start - 1).bit_length(), 4)
                offset = (token >> (16 - bit_count)) + 1
                length = (token & (0xFFFF >> bit_count)) + 3
                if offset > len(out) - chunk_start:
                    raise ValueError("copy token points before chunk")
                for _ in range(length):
                    out.append(out[-offset])
    return bytes(out)


def _dir_modules(dir_stream: bytes) -> List[Tuple[str, int]]:
    """Parses the decompressed VBA 'dir' stream into (module stream name, source offset) pairs."""
    modules: List[Tuple[str, int]] = []
    name: Optional[str] = None
    pos = 0
    while pos + 6 <= len(dir_stream):
        rec_id, size = struct.unpack_from("<HI", dir_stream, pos)
        pos += 6
        if rec_id == 0x0009:  # PROJECTVERSION: the size field is reserved and the payload is 6 bytes
            size = 6
        payload = dir_stream[pos:pos + size]
        pos += size
        if rec_id == 0x001A:  # MODULESTREAMNAME
            name = payload.decode("latin-1")
        elif rec_id == 0x0031 and name is not None and len(payload) == 4:  # MODULEOFFSET
            modules.append((name, struct.unpack("<I", payload)[0]))
            name = None
        elif rec_id == 0x0010:  # terminator
            break
    return modules


def _scan_source(source: str, macros: Dict[str, Any]) -> None:
    for match in _AUTOEXEC_RE.finditer(source):
        if match.group(1) not in macros["autoexec"]:
            macros["autoexec"].append(match.group(1))
    seen = {s.lower() for s in macros["suspicious"]}
    for group, pattern in _SUSPICIOUS_RE.items():
        for match in pattern.finditer(source):
            entry = f"{group}: {match.group(0)}"
            if entry.lower() not in seen:
                seen.add(entry.lower())
                macros["suspicious"].append(entry)


def analyze_vba_project(data: bytes) -> Dict[str, Any]:
    """Inspects an OLE file (vbaProject.bin, .doc, .xls) for VBA projects. Never raises."""
    macros = empty_macros()
    try:
        import olefile
    except ImportError:
        macros["error"] = "olefile is not installed; macro detection unavailable"
        return macros
    if len(data) > MAX_VBA_PROJECT_BYTES:
        macros["error"] = "VBA project too large to inspect"
        return macros
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception:
        return macros
    try:
        streams = ole.listdir(streams=True, storages=False)
        roots = sorted({tuple(p[:-1]) for p in streams if len(p) >= 2 and p[-1].lower() == "dir" and p[-2].upper() == "VBA"})
        for root in roots:
            macros["present"] = True
            try:
                modules = _dir_modules(decompress_vba(ole.openstream(list(root) + ["dir"]).read()))
            except Exception:
                macros.setdefault("notes", []).append("VBA directory could not be decoded")
                continue
            for name, offset in modules[:MAX_MODULES]:
                macros["modules"].append(name)
                try:
                    raw = ole.openstream(list(root) + [name]).read()
                    source = decompress_vba(raw[offset:]).decode("latin-1")[:MAX_SOURCE_CHARS]
                except Exception:
                    macros.setdefault("notes", []).append(f"Source of module '{name}' could not be decoded")
                    continue
                _scan_source(source, macros)
    except Exception as exc:  # hostile containers must not crash ingestion
        macros["error"] = f"VBA inspection failed: {type(exc).__name__}"
    finally:
        ole.close()
    return macros


def is_ooxml(zf: zipfile.ZipFile) -> bool:
    return "[Content_Types].xml" in zf.namelist()


def analyze_ooxml(zf: zipfile.ZipFile) -> Dict[str, Any]:
    """Macro and external-link analysis of an OOXML package (already opened as a zip)."""
    macros = empty_macros()
    links: List[str] = []
    for info in zf.infolist():
        lower = info.filename.lower()
        if lower.endswith("vbaproject.bin") and info.file_size <= MAX_VBA_PROJECT_BYTES:
            macros = analyze_vba_project(zf.read(info))
            macros["present"] = True  # a vbaProject part is a macro project even if it can't be decoded
        elif lower.endswith(".rels") and info.file_size <= 1024 * 1024:
            for rel in _EXTERNAL_REL_RE.findall(zf.read(info)):
                target = _TARGET_RE.search(rel)
                if target:
                    links.append(target.group(1).decode("utf-8", errors="replace").replace("&amp;", "&"))
    return {"format": "ooxml", "macros": macros, "external_links": sorted(set(links))}


def analyze_ole_document(data: bytes) -> Dict[str, Any]:
    """Macro analysis of a legacy OLE Office document (.doc, .xls, .ppt)."""
    return {"format": "ole", "macros": analyze_vba_project(data), "external_links": []}
