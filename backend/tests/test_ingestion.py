"""
File / message ingestion parser tests (fixtures are generated in-process).
"""

import io
import struct
import zipfile
from email.message import EmailMessage

import pytest

from app.ingestion.parsers import UnsupportedFileError, ingest_file
from app.ingestion.parsers.apk_parser import parse_axml_manifest
from app.ingestion.parsers.pdf_parser import _active_content
from app.ingestion.ingested_input import IngestionSourceType


def build_eml() -> bytes:
    msg = EmailMessage()
    msg["From"] = '"PayPal Security" <alerts@contoso-mail.com>'
    msg["To"] = "victim@example.com"
    msg["Reply-To"] = "collect@evil-mail.ru"
    msg["Subject"] = "Urgent: account suspended"
    msg["Authentication-Results"] = "mx.example.com; spf=fail smtp.mailfrom=contoso-mail.com; dkim=none; dmarc=fail"
    msg["Received"] = "from mail.evil (unknown [185.220.101.47]) by mx.example.com"
    msg.set_content("Verify your password within 24 hours.")
    msg.add_alternative('<p>Click <a href="https://paypal-verify.xyz/login">here</a></p>', subtype="html")
    msg.add_attachment(b"MZ\x90\x00fake", maintype="application", subtype="octet-stream", filename="invoice.exe")
    return msg.as_bytes()


def build_axml(package: str, permissions) -> bytes:
    strings = ["manifest", "package", package, "uses-permission", "name", *permissions]
    idx = {s: i for i, s in enumerate(strings)}
    data = b""
    offsets = []
    for s in strings:
        offsets.append(len(data))
        data += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
    data += b"\x00" * (-len(data) % 4)
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    pool = struct.pack("<HHIIIIII", 0x0001, header_size, strings_start + len(data), len(strings), 0, 0, strings_start, 0)
    pool += struct.pack(f"<{len(offsets)}I", *offsets) + data

    def element(name, attrs):
        body = struct.pack("<II", 1, 0xFFFFFFFF) + struct.pack("<II", 0xFFFFFFFF, idx[name])
        body += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)
        for a_name, a_val in attrs:
            body += struct.pack("<III", 0xFFFFFFFF, idx[a_name], idx[a_val]) + struct.pack("<HBBI", 8, 0, 3, idx[a_val])
        return struct.pack("<HHI", 0x0102, 16, 8 + len(body)) + body

    chunks = pool + element("manifest", [("package", package)])
    for perm in permissions:
        chunks += element("uses-permission", [("name", perm)])
    return struct.pack("<HHI", 0x0003, 8, 8 + len(chunks)) + chunks


def build_apk() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", build_axml("com.evil.app", [
            "android.permission.INTERNET", "android.permission.READ_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE"]))
        z.writestr("classes.dex", b"dex\n035\x00....https://c2.evil-app.top/gate.php\x00http://schemas.android.com/apk/res/android\x00")
    return buf.getvalue()


def build_qr_png(payload: str) -> bytes:
    cv2 = pytest.importorskip("cv2")
    img = cv2.QRCodeEncoder.create().encode(payload)
    img = cv2.resize(img, (img.shape[1] * 8, img.shape[0] * 8), interpolation=cv2.INTER_NEAREST)
    img = cv2.copyMakeBorder(img, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    return cv2.imencode(".png", img)[1].tobytes()


def build_pdf() -> bytes:
    fpdf = pytest.importorskip("fpdf")
    pdf = fpdf.FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", size=12)
    pdf.cell(text="Pay invoice at https://pay-invoice.top/now", link="https://pay-invoice.top/now")
    return bytes(pdf.output())


def test_eml_parsing_extracts_headers_links_and_attachments():
    ingested = ingest_file("message.eml", build_eml())
    email = ingested.metadata["analysis"]["email"]
    assert ingested.source_type == IngestionSourceType.EMAIL
    assert email["from_domain"] == "contoso-mail.com"
    assert email["reply_to_domain"] == "evil-mail.ru"
    assert email["authentication"] == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    assert email["received_ips"] == ["185.220.101.47"]
    assert "https://paypal-verify.xyz/login" in email["links"]
    assert email["attachments"][0]["dangerous"] is True
    assert "paypal-verify.xyz" in ingested.content


def test_axml_manifest_decoding():
    package, perms = parse_axml_manifest(build_axml("com.x.y", ["android.permission.CAMERA"]))
    assert package == "com.x.y"
    assert perms == ["android.permission.CAMERA"]


def test_apk_parsing():
    ingested = ingest_file("app.apk", build_apk())
    apk = ingested.metadata["analysis"]["file"]["apk"]
    assert ingested.source_type == IngestionSourceType.APK_FILE
    assert apk["package"] == "com.evil.app"
    assert set(apk["dangerous_permissions"]) == {"android.permission.READ_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE"}
    assert apk["embedded_urls"] == ["https://c2.evil-app.top/gate.php"]


def test_qr_image_parsing():
    ingested = ingest_file("flyer.png", build_qr_png("https://quish.example/login"))
    assert ingested.source_type == IngestionSourceType.QR_CODE
    assert ingested.metadata["analysis"]["file"]["qr_payloads"] == ["https://quish.example/login"]


def test_pdf_parsing_and_active_content():
    ingested = ingest_file("invoice.pdf", build_pdf())
    pdf = ingested.metadata["analysis"]["file"]["pdf"]
    assert ingested.source_type == IngestionSourceType.PDF_FILE
    assert "https://pay-invoice.top/now" in pdf["links"]
    assert _active_content(b"<< /OpenAction 3 0 R /JS (app.alert(1)) /JSON >>") == ["/JS", "/OpenAction"]


def test_binary_and_rejections():
    exe = ingest_file("setup.exe", b"MZ\x90\x00" + b"\x00" * 64)
    assert exe.metadata["analysis"]["file"]["dangerous"] is True
    assert exe.metadata["seed_indicators"]["hashes"][0] == exe.metadata["analysis"]["file"]["sha256"]
    with pytest.raises(UnsupportedFileError):
        ingest_file("empty.txt", b"")
    with pytest.raises(UnsupportedFileError):
        ingest_file("mail.msg", b"\xd0\xcf\x11\xe0")


@pytest.mark.asyncio
async def test_file_investigation_endpoint(async_client):
    files = {"file": ("message.eml", build_eml(), "message/rfc822")}
    res = await async_client.post("/api/v1/evidence/investigate/file", files=files)
    assert res.status_code == 200
    body = res.json()
    assert body["source_type"] == "email"
    assert body["source_name"] == "message.eml"
    ids = {f["rule_id"] for f in body["risk_assessment"]["findings"]}
    assert {"RULE_EML_001", "RULE_EML_002", "RULE_EML_003", "RULE_FIL_001", "RULE_CNT_001"} <= ids
    assert len(body["evidence"]["hashes"]) == 2  # the .eml itself + its attachment


@pytest.mark.asyncio
async def test_file_endpoint_rejects_unsupported(async_client):
    res = await async_client.post("/api/v1/evidence/investigate/file", files={"file": ("x.msg", b"\xd0\xcf", "application/octet-stream")})
    assert res.status_code == 422
