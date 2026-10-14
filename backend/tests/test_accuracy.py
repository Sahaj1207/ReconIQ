"""
Detection accuracy on a labelled benign / malicious sample set, fully offline.

A sample counts as flagged when its score reaches MEDIUM (>= 40), the point where the UI tells an
analyst to act. Text and .eml samples live in samples/labeled_samples.json; binary samples (Office
macros, ZIP, Outlook .msg, QR-code PDF) are generated here.

This is a small hand-made regression set, not a benchmark: it guards against rule changes that
start missing known-bad patterns or flagging ordinary mail. Grow it with real (sanitised) samples.
"""

import io
import json
from pathlib import Path
from typing import Callable, List, Tuple

import pytest

from app.ingestion.ingested_input import IngestedInput
from app.ingestion.parsers import ingest_file
from app.pipeline.investigation import InvestigationPipeline
from tests.ole_writer import build_ole
from tests.test_file_types import BENIGN_MACRO, build_docm, build_msg, build_pdf_with_qr, build_zip

FLAG_THRESHOLD = 40.0
MIN_ACCURACY = 0.95
MIN_PRECISION = 0.95
MIN_RECALL = 0.90
SAMPLES = json.loads((Path(__file__).parent / "samples" / "labeled_samples.json").read_text(encoding="utf-8"))["samples"]


def _benign_msg() -> bytes:
    def utf16(text: str) -> bytes:
        return text.encode("utf-16-le")
    return build_ole({
        "__properties_version1.0": b"\0" * 32,
        "__substg1.0_0037001F": utf16("Lunch on Friday?"),
        "__substg1.0_1000001F": utf16("Hi Sam, a few of us are going to the new place on Main Street on Friday. Want to join?"),
        "__substg1.0_0C1A001F": utf16("Alex Chen"),
        "__substg1.0_5D01001F": utf16("alex.chen@example.com"),
    })


def _benign_pdf() -> bytes:
    fpdf = pytest.importorskip("fpdf")
    pdf = fpdf.FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", size=12)
    pdf.multi_cell(0, 8, "Quarterly report. Revenue grew 4% on the prior quarter. Details are in the appendix.")
    return bytes(pdf.output())


PHISH_MSG_HEADERS = ("Received: from mail.payroll-notices.top (unknown [185.220.101.47]) by mx.example.com\r\n"
                     "Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=payroll-notices.top\r\n\r\n")

# (id, label, filename, builder)
BINARY_SAMPLES: List[Tuple[str, str, str, Callable[[], bytes]]] = [
    ("mal-docm-dropper", "malicious", "Invoice_0921.docm", lambda: build_docm()),
    ("mal-zip-exe", "malicious", "scan_results.zip", lambda: build_zip({"scan_results.pdf.exe": b"MZ\x90\x00stub"})),
    ("mal-msg-phish", "malicious", "Payroll.msg", lambda: build_msg(
        '<a href="https://payroll-verify.top/login">https://portal.office.com/payroll</a>', headers=PHISH_MSG_HEADERS)),
    ("mal-pdf-quishing", "malicious", "parking_fine.pdf", lambda: build_pdf_with_qr("https://pay-parking-fine.top/ticket")),
    ("ben-docx", "benign", "minutes.docx", lambda: build_zip({"[Content_Types].xml": "<Types/>", "word/document.xml": "<w:document/>"})),
    ("ben-xlsm-formatting-macro", "benign", "timesheet.xlsm", lambda: build_docm(BENIGN_MACRO)),
    ("ben-zip-docs", "benign", "handover.zip", lambda: build_zip({"notes.txt": "Handover notes for the night shift.", "rota.csv": "mon,alex\ntue,sam"})),
    ("ben-msg-internal", "benign", "Lunch.msg", _benign_msg),
    ("ben-pdf-report", "benign", "q3_report.pdf", _benign_pdf),
]


def _ingest(sample: dict) -> IngestedInput:
    if sample["kind"] == "eml":
        return ingest_file(f"{sample['id']}.eml", sample["content"].encode("utf-8"))
    return IngestedInput.from_text(sample["content"], metadata={"refang": True})


@pytest.mark.asyncio
async def test_detection_accuracy_on_labelled_samples():
    pytest.importorskip("cv2")  # the quishing PDF needs QR encoding
    pipeline = InvestigationPipeline()
    cases = [(s["id"], s["label"], _ingest(s)) for s in SAMPLES]
    cases += [(sid, label, ingest_file(name, build())) for sid, label, name, build in BINARY_SAMPLES]

    rows, tp, fp, tn, fn = [], 0, 0, 0, 0
    for sid, label, ingested in cases:
        risk = (await pipeline.run(ingested)).risk_assessment
        flagged = risk["total_score"] >= FLAG_THRESHOLD
        malicious = label == "malicious"
        tp += flagged and malicious
        fp += flagged and not malicious
        tn += not flagged and not malicious
        fn += not flagged and malicious
        mark = "ok  " if flagged == malicious else "MISS"
        rules = ",".join(sorted({f["rule_id"] for f in risk["findings"]}))
        rows.append(f"{mark} {label:9} {risk['total_score']:5.1f} {risk['severity']:13} {sid:32} {rules}")

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    report = (f"\n{total} samples: accuracy {accuracy:.1%}, precision {precision:.1%}, recall {recall:.1%} "
              f"(TP {tp}, FP {fp}, TN {tn}, FN {fn})\n" + "\n".join(rows))
    print(report)

    assert sum(1 for _, label, _ in cases if label == "malicious") >= 15
    assert sum(1 for _, label, _ in cases if label == "benign") >= 15
    assert accuracy >= MIN_ACCURACY, report
    assert precision >= MIN_PRECISION, report
    assert recall >= MIN_RECALL, report


def test_sample_ids_are_unique_and_labelled():
    ids = [s["id"] for s in SAMPLES] + [b[0] for b in BINARY_SAMPLES]
    assert len(ids) == len(set(ids))
    assert all(s["label"] in ("benign", "malicious") and s["kind"] in ("text", "eml") for s in SAMPLES)
    assert all(sid.startswith(("mal-", "ben-")) and sid[:3] == label[:3] for sid, label, *_ in
               [(s["id"], s["label"]) for s in SAMPLES] + [(b[0], b[1]) for b in BINARY_SAMPLES])
