"""
Outlook .msg parser (MS-OXMSG): an OLE compound file whose MAPI properties live in
`__substg1.0_<tag><type>` streams. Produces the same email analysis as the .eml parser, so the
email rules apply unchanged. Internet headers (PR_TRANSPORT_MESSAGE_HEADERS) supply SPF/DKIM/
DMARC verdicts, relays, Reply-To and Return-Path when the message came from the internet.
"""

import email
import email.policy
import io
from email.message import EmailMessage
from typing import Any, Dict, List, Optional, Tuple

from app.ingestion.parsers.email_parser import assemble_email, html_to_text, link_texts
from app.ingestion.parsers.file_info import fingerprint

MAX_ATTACHMENTS = 50
MAX_RECIPIENTS = 100

# MAPI property tags (without the type suffix)
SUBJECT, BODY, HTML_BODY, HEADERS = "0037", "1000", "1013", "007D"
SENDER_NAME, SENDER_EMAIL, SENDER_SMTP = "0C1A", "0C1F", "5D01"
SENT_REPR_NAME, SENT_REPR_EMAIL, SENT_REPR_SMTP = "0042", "0065", "5D02"
INTERNET_MESSAGE_ID = "1035"
RECIP_EMAIL, RECIP_SMTP = "3003", "39FE"
ATTACH_DATA, ATTACH_LONG_NAME, ATTACH_NAME, ATTACH_MIME = "3701", "3707", "3704", "370E"


class MsgParseError(ValueError):
    """Raised when the data is not a readable Outlook message."""


def is_msg(ole) -> bool:
    """True when an open OLE file has the MSG property layout."""
    return ole.exists("__properties_version1.0") and any(
        path[0].startswith("__substg1.0_") for path in ole.listdir(streams=True, storages=False)
    )


def _prop(ole, storage: List[str], tag: str) -> Optional[Any]:
    """Reads a property as str (PT_UNICODE / PT_STRING8) or bytes (PT_BINARY); None if absent."""
    for ptype in ("001F", "001E", "0102"):
        path = storage + [f"__substg1.0_{tag}{ptype}"]
        if not ole.exists(path):
            continue
        raw = ole.openstream(path).read()
        if ptype == "001F":
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if ptype == "001E":
            return raw.decode("cp1252", errors="replace").rstrip("\x00")
        return raw
    return None


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def _storages(ole, prefix: str, limit: int) -> List[str]:
    names = sorted({path[0] for path in ole.listdir(streams=False, storages=True) if path[0].startswith(prefix)})
    return names[:limit]


def parse_msg(data: bytes) -> Tuple[str, Dict[str, Any]]:
    """
    Parses raw .msg bytes.

    Returns:
        (analysable_text, email_analysis)
    """
    try:
        import olefile
        ole = olefile.OleFileIO(io.BytesIO(data))
    except ImportError as exc:
        raise MsgParseError("olefile is not installed; Outlook .msg files cannot be read") from exc
    except Exception as exc:
        raise MsgParseError("File is not a valid Outlook .msg message") from exc

    try:
        if not is_msg(ole):
            raise MsgParseError("File is not a valid Outlook .msg message")

        headers_text = _text(_prop(ole, [], HEADERS))
        headers: EmailMessage = email.message_from_string(headers_text, policy=email.policy.default)  # type: ignore[assignment]

        # Prefer SMTP addresses: PR_SENDER_EMAIL_ADDRESS may be an Exchange DN (/O=ORG/OU=...).
        sender = _text(_prop(ole, [], SENDER_SMTP) or _prop(ole, [], SENT_REPR_SMTP))
        if "@" not in sender:
            sender = next((a for a in (_text(_prop(ole, [], SENDER_EMAIL)), _text(_prop(ole, [], SENT_REPR_EMAIL)))
                           if "@" in a), "")
        display_name = _text(_prop(ole, [], SENDER_NAME) or _prop(ole, [], SENT_REPR_NAME))
        if not sender and headers.get("From"):
            display_name, sender = email.utils.parseaddr(str(headers["From"]))

        to_addrs = []
        for recip in _storages(ole, "__recip_version1.0_", MAX_RECIPIENTS):
            address = _text(_prop(ole, [recip], RECIP_SMTP) or _prop(ole, [recip], RECIP_EMAIL))
            if "@" in address:
                to_addrs.append(address)

        text_parts: List[str] = []
        links: List[str] = []
        anchors: List[Dict[str, str]] = []
        body = _text(_prop(ole, [], BODY))
        if body.strip():
            text_parts.append(body)
        html_body = _text(_prop(ole, [], HTML_BODY))
        if html_body.strip():
            visible, hrefs = html_to_text(html_body)
            if not body.strip():
                text_parts.append(visible)
            links.extend(hrefs)
            anchors.extend(link_texts(html_body))

        attachments: List[Dict[str, Any]] = []
        notes: List[str] = []
        for att in _storages(ole, "__attach_version1.0_", MAX_ATTACHMENTS):
            name = _text(_prop(ole, [att], ATTACH_LONG_NAME) or _prop(ole, [att], ATTACH_NAME)) or "attachment"
            payload = _prop(ole, [att], ATTACH_DATA)
            if not isinstance(payload, bytes):
                notes.append(f"Attachment '{name}' is an embedded object or message and was not inspected")
                continue
            info = fingerprint(name, payload)
            info["content_type"] = _text(_prop(ole, [att], ATTACH_MIME)) or None
            info["_data"] = payload  # consumed by deep inspection, removed before the result is stored
            attachments.append(info)

        subject = _text(_prop(ole, [], SUBJECT))
        text, analysis = assemble_email(headers, subject, display_name, sender, to_addrs, text_parts, links,
                                        attachments, anchors)
        if not analysis["message_id"]:
            analysis["message_id"] = _text(_prop(ole, [], INTERNET_MESSAGE_ID)) or None
        analysis["format"] = "msg"
        analysis["has_internet_headers"] = bool(headers_text.strip())
        if notes:
            analysis["notes"] = notes
        return text, analysis
    finally:
        ole.close()
