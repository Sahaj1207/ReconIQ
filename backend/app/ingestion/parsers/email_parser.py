"""
RFC 5322 (.eml) email parser.

Extracts analysable text (subject + bodies + link targets), sender identity, routing domains,
SPF/DKIM/DMARC verdicts, relay IPs and attachment fingerprints.
"""

import email
import email.policy
import html
import ipaddress
import re
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from typing import Any, Dict, List, Optional, Tuple

from app.ingestion.parsers.file_info import fingerprint

AUTH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
RECEIVED_IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]|\((?:[^()]*?)(\d{1,3}(?:\.\d{1,3}){3})\)")
HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
ANCHOR_RE = re.compile(r"""<a\b[^>]*?href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a\s*>""", re.IGNORECASE | re.DOTALL)
# Visible link text that itself looks like a URL or hostname, e.g. "https://paypal.com" or "www.paypal.com"
URLISH_TEXT_RE = re.compile(r"^(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:[/:?#]\S*)?$", re.IGNORECASE)
MAX_LINK_TEXTS = 50
TAG_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>|<[^>]+>", re.IGNORECASE | re.DOTALL)


def _domain(address: Optional[str]) -> Optional[str]:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[-1].strip(" >").lower() or None


def html_to_text(markup: str) -> Tuple[str, List[str]]:
    """Strips tags and returns (visible text, href targets)."""
    links = [html.unescape(h) for h in HREF_RE.findall(markup) if not h.lower().startswith(("mailto:", "#", "cid:"))]
    text = html.unescape(TAG_RE.sub(" ", markup))
    return re.sub(r"[ \t\r\f\v]+", " ", text), links


def link_texts(markup: str) -> List[Dict[str, str]]:
    """Anchors whose visible text looks like a URL or hostname, paired with their real target."""
    pairs: List[Dict[str, str]] = []
    for href, inner in ANCHOR_RE.findall(markup):
        text = html.unescape(TAG_RE.sub("", inner)).strip()
        if URLISH_TEXT_RE.match(text) and href.lower().startswith(("http://", "https://")):
            pairs.append({"text": text, "href": html.unescape(href)})
            if len(pairs) >= MAX_LINK_TEXTS:
                break
    return pairs


def _authentication(msg: EmailMessage) -> Dict[str, str]:
    verdicts: Dict[str, str] = {}
    for header in msg.get_all("Authentication-Results", []) or []:
        for mech, result in AUTH_RESULT_RE.findall(str(header)):
            verdicts.setdefault(mech.lower(), result.lower())
    if "spf" not in verdicts:
        received_spf = msg.get("Received-SPF")
        if received_spf:
            verdicts["spf"] = str(received_spf).split()[0].lower()
    return verdicts


def _received_ips(msg: EmailMessage) -> List[str]:
    ips: List[str] = []
    for header in msg.get_all("Received", []) or []:
        for a, b in RECEIVED_IP_RE.findall(str(header)):
            ip = a or b
            try:
                if ipaddress.ip_address(ip).is_global and ip not in ips:
                    ips.append(ip)
            except ValueError:
                continue
    return ips


def parse_eml(data: bytes) -> Tuple[str, Dict[str, Any]]:
    """
    Parses raw .eml bytes.

    Returns:
        (analysable_text, email_analysis)
    """
    msg: EmailMessage = email.message_from_bytes(data, policy=email.policy.default)  # type: ignore[assignment]

    display_name, from_addr = parseaddr(str(msg.get("From", "")))
    to_addrs = [a for _, a in getaddresses([str(v) for v in msg.get_all("To", []) or []]) if a]

    text_parts: List[str] = []
    links: List[str] = []
    anchors: List[Dict[str, str]] = []
    attachments: List[Dict[str, Any]] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if disposition == "attachment" or (filename and disposition != "inline"):
            payload = part.get_payload(decode=True) or b""
            info = fingerprint(filename or "attachment", payload)
            info["content_type"] = part.get_content_type()
            info["_data"] = payload  # consumed by deep inspection, removed before the result is stored
            attachments.append(info)
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except (LookupError, KeyError, AssertionError):
            content = (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
        if not isinstance(content, str):
            continue
        if ctype == "text/html":
            visible, hrefs = html_to_text(content)
            text_parts.append(visible)
            links.extend(hrefs)
            anchors.extend(link_texts(content))
        elif ctype.startswith("text/"):
            text_parts.append(content)

    subject = str(msg.get("Subject", "") or "")
    return assemble_email(msg, subject, display_name, from_addr, to_addrs, text_parts, links, attachments, anchors)


def assemble_email(headers: EmailMessage, subject: str, display_name: str, from_addr: str, to_addrs: List[str],
                   text_parts: List[str], links: List[str], attachments: List[Dict[str, Any]],
                   anchors: List[Dict[str, str]]) -> Tuple[str, Dict[str, Any]]:
    """Builds (analysable_text, email_analysis) from parsed parts; shared by .eml and Outlook .msg."""
    _, reply_to = parseaddr(str(headers.get("Reply-To", "")))
    _, return_path = parseaddr(str(headers.get("Return-Path", "")))
    analysis = {
        "subject": subject,
        "from": from_addr or None,
        "display_name": display_name or None,
        "from_domain": _domain(from_addr),
        "to": to_addrs,
        "reply_to": reply_to or None,
        "reply_to_domain": _domain(reply_to),
        "return_path": return_path or None,
        "return_path_domain": _domain(return_path),
        "date": str(headers.get("Date", "") or "") or None,
        "message_id": str(headers.get("Message-ID", "") or "") or None,
        "authentication": _authentication(headers),
        "received_ips": _received_ips(headers),
        "links": sorted(set(links)),
        "link_texts": anchors[:MAX_LINK_TEXTS],
        "attachments": attachments,
    }

    header_lines = [f"Subject: {subject}", f"From: {display_name} <{from_addr}>"]
    if reply_to:
        header_lines.append(f"Reply-To: {reply_to}")
    body = "\n\n".join(p.strip() for p in text_parts if p.strip())
    link_block = "\n".join(analysis["links"])
    relay_block = "\n".join(analysis["received_ips"])
    text = "\n".join(header_lines) + "\n\n" + body + ("\n\nLinks:\n" + link_block if link_block else "") \
        + ("\n\nRelays:\n" + relay_block if relay_block else "")
    return text, analysis
