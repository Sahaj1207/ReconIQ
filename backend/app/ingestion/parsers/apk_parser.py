"""
Android APK parser.

Decodes the binary AndroidManifest.xml (AXML) enough to recover the package name and requested
permissions, and scans DEX bytecode string tables for embedded URLs and IPs.
"""

import io
import re
import struct
import zipfile
from typing import Any, Dict, List, Optional, Tuple

RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_ELEMENT_TYPE = 0x0102
UTF8_FLAG = 1 << 8

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG", "android.permission.PROCESS_OUTGOING_CALLS", "android.permission.CALL_PHONE",
    "android.permission.READ_CONTACTS", "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.READ_PHONE_STATE",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE", "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.WRITE_SETTINGS",
}
MAX_DEX_BYTES = 30 * 1024 * 1024
URL_BYTES_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,300}")


def _read_string_pool(buf: bytes, offset: int) -> List[str]:
    _, header_size, _, count, _, flags, strings_start, _ = struct.unpack_from("<HHIIIIII", buf, offset)
    is_utf8 = bool(flags & UTF8_FLAG)
    offsets = struct.unpack_from(f"<{count}I", buf, offset + header_size)
    base = offset + strings_start
    strings = []
    for rel in offsets:
        pos = base + rel
        try:
            if is_utf8:
                # char length (1-2 bytes) then byte length (1-2 bytes)
                n = buf[pos]; pos += 2 if n & 0x80 else 1
                n = buf[pos]
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | buf[pos + 1]; pos += 2
                else:
                    pos += 1
                strings.append(buf[pos:pos + n].decode("utf-8", errors="replace"))
            else:
                n = struct.unpack_from("<H", buf, pos)[0]; pos += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", buf, pos)[0]; pos += 2
                strings.append(buf[pos:pos + n * 2].decode("utf-16-le", errors="replace"))
        except (IndexError, struct.error):
            strings.append("")
    return strings


def parse_axml_manifest(buf: bytes) -> Tuple[Optional[str], List[str]]:
    """Returns (package_name, permissions) from a binary AndroidManifest.xml."""
    strings: List[str] = []
    package: Optional[str] = None
    permissions: List[str] = []
    offset = 8  # skip XML file header
    while offset + 8 <= len(buf):
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", buf, offset)
        if chunk_size < 8:
            break
        if chunk_type == RES_STRING_POOL_TYPE and not strings:
            strings = _read_string_pool(buf, offset)
        elif chunk_type == RES_XML_START_ELEMENT_TYPE and strings:
            name_idx = struct.unpack_from("<I", buf, offset + 20)[0]
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", buf, offset + 24)
            element = strings[name_idx] if name_idx < len(strings) else ""
            attrs_at = offset + 16 + attr_start
            for i in range(attr_count):
                a = attrs_at + i * attr_size
                _, a_name, a_raw = struct.unpack_from("<III", buf, a)
                attr_name = strings[a_name] if a_name < len(strings) else ""
                value = strings[a_raw] if a_raw != 0xFFFFFFFF and a_raw < len(strings) else None
                if element == "manifest" and attr_name == "package" and value:
                    package = value
                elif element in ("uses-permission", "uses-permission-sdk-23") and attr_name == "name" and value:
                    permissions.append(value)
        offset += chunk_size
    return package, sorted(set(permissions))


def parse_apk(data: bytes) -> Tuple[str, Dict[str, Any]]:
    """Returns (text of embedded URLs, apk_analysis)."""
    analysis: Dict[str, Any] = {"package": None, "permissions": [], "dangerous_permissions": [], "embedded_urls": []}
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        analysis["error"] = "Not a valid APK/ZIP archive"
        return "", analysis

    names = archive.namelist()
    analysis["file_count"] = len(names)
    analysis["has_native_code"] = any(n.startswith("lib/") and n.endswith(".so") for n in names)
    if "AndroidManifest.xml" in names:
        try:
            package, perms = parse_axml_manifest(archive.read("AndroidManifest.xml"))
            analysis["package"] = package
            analysis["permissions"] = perms
            analysis["dangerous_permissions"] = [p for p in perms if p in DANGEROUS_PERMISSIONS]
        except (struct.error, IndexError) as exc:
            analysis["error"] = f"Manifest decoding failed: {type(exc).__name__}"

    urls = set()
    budget = MAX_DEX_BYTES
    for name in names:
        if re.fullmatch(r"classes\d*\.dex", name) and budget > 0:
            dex = archive.read(name)[:budget]
            budget -= len(dex)
            urls.update(m.decode("ascii", errors="ignore") for m in URL_BYTES_RE.findall(dex))
    # Drop schema/namespace noise that every Android app embeds
    analysis["embedded_urls"] = sorted(u for u in urls if "schemas.android.com" not in u and "w3.org" not in u)[:500]
    return "\n".join(analysis["embedded_urls"]), analysis
