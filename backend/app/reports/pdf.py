"""
Executive PDF report (fpdf2, core fonts; indicators defanged).
"""

from typing import Any, Dict, List, Tuple

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from fpdf.fonts import FontFace

from app.reports.common import defang, indicator_rows, matched_rules
from app.reports.markdown import defang_inline

SEVERITY_COLORS: Dict[str, Tuple[int, int, int]] = {
    "CRITICAL": (225, 29, 72), "HIGH": (234, 88, 12), "MEDIUM": (202, 138, 4),
    "LOW": (2, 132, 199), "INFORMATIONAL": (100, 116, 139),
}
INK = (15, 23, 42)
MUTED = (100, 116, 139)
LINE = (226, 232, 240)


def _t(text: Any) -> str:
    """Core PDF fonts are Latin-1; replace anything outside it."""
    s = str(text if text is not None else "")
    s = s.replace("—", "-").replace("–", "-").replace("’", "'").replace("“", '"').replace("”", '"')
    return s.encode("latin-1", errors="replace").decode("latin-1")


class ReportPDF(FPDF):
    def header(self) -> None:
        self.set_font("helvetica", "B", 10)
        self.set_text_color(*INK)
        self.cell(0, 6, "ReconIQ", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(*LINE)
        self.line(self.l_margin, self.get_y() + 1, self.w - self.r_margin, self.get_y() + 1)
        self.ln(5)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 6, _t(f"Evidence. Intelligence. Trust.   Page {self.page_no()}"), align="C")

    def section(self, title: str) -> None:
        self.ln(3)
        self.set_font("helvetica", "B", 12)
        self.set_text_color(*INK)
        self.cell(0, 8, _t(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def para(self, text: str, size: int = 10, color=INK, style: str = "") -> None:
        self.set_font("helvetica", style, size)
        self.set_text_color(*color)
        self.multi_cell(0, 5, _t(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def bullets(self, items: List[str], numbered: bool = False) -> None:
        self.set_font("helvetica", "", 10)
        self.set_text_color(*INK)
        for i, item in enumerate(items, 1):
            self.multi_cell(0, 5, _t(f"{i}. {item}" if numbered else f"- {item}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def table(self, headers: List[str], rows: List[List[str]], widths: List[int]) -> None:
        self.set_font("helvetica", "", 8.5)
        self.set_draw_color(*LINE)
        self.set_text_color(*INK)
        self.set_fill_color(248, 250, 252)
        with super().table(col_widths=widths, text_align="LEFT", line_height=4.6,
                           borders_layout="HORIZONTAL_LINES", cell_fill_color=(248, 250, 252),
                           cell_fill_mode="ROWS", headings_style=FontFace(emphasis="BOLD", fill_color=(241, 245, 249))) as table:
            head = table.row()
            for h in headers:
                head.cell(_t(h))
            for r in rows:
                row = table.row()
                for value in r:
                    row.cell(_t(value))


def render_pdf(result: Dict[str, Any]) -> bytes:
    risk = result.get("risk_assessment") or {}
    report = result.get("analyst_report") or {}
    severity = risk.get("severity", "INFORMATIONAL")
    color = SEVERITY_COLORS.get(severity, MUTED)

    pdf = ReportPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.set_margins(16, 14, 16)
    pdf.add_page()

    pdf.set_font("helvetica", "B", 18)
    pdf.set_text_color(*INK)
    pdf.cell(0, 10, "Investigation Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.para(f"{result['investigation_id']}  |  {result.get('timestamp', '')[:19].replace('T', ' ')} UTC  |  "
             f"Source: {result.get('source_name') or result.get('source_type', 'raw_text')}", size=8.5, color=MUTED)
    pdf.ln(3)

    # Verdict band
    y = pdf.get_y()
    pdf.set_fill_color(*color)
    pdf.rect(pdf.l_margin, y, 3, 20, style="F")
    pdf.set_xy(pdf.l_margin + 7, y + 1)
    pdf.set_font("helvetica", "B", 22)
    pdf.set_text_color(*color)
    pdf.cell(28, 10, f"{risk.get('total_score', 0):.0f}")
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, _t(f"{severity} risk  -  {risk.get('classification', 'n/a').replace('_', ' ').title()}"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_x(pdf.l_margin + 7)
    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(*MUTED)
    techniques = risk.get("mitre_techniques", [])
    pdf.cell(0, 6, _t(f"Score / 100   |   Confidence {round((risk.get('confidence') or 0) * 100)}%   |   "
                      f"{len(risk.get('findings', []))} findings   |   {len(techniques)} ATT&CK techniques"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_y(y + 24)

    if report:
        pdf.section("Analyst Summary")
        pdf.para(report.get("summary", ""))
        if report.get("key_findings"):
            pdf.ln(1)
            pdf.para("Key findings", style="B")
            pdf.bullets([defang_inline(k) for k in report["key_findings"]])
        if report.get("recommended_actions"):
            pdf.ln(1)
            pdf.para("Recommended actions", style="B")
            pdf.bullets(report["recommended_actions"], numbered=True)
        pdf.ln(1)
        pdf.para(report.get("disclaimer", ""), size=8, color=MUTED, style="I")

    findings = sorted(risk.get("findings", []), key=lambda f: -f.get("score_impact", 0))
    pdf.section("Findings")
    if findings:
        pdf.table(["Finding", "Severity", "Pts"],
                  [[f"{f['title']}: {defang_inline(f['description'])}", f.get("severity", ""), f"+{f.get('score_impact', 0):g}"]
                   for f in findings], [130, 30, 18])
    else:
        pdf.para("No rules produced findings.", color=MUTED)

    if techniques:
        pdf.section("MITRE ATT&CK")
        pdf.table(["ID", "Technique", "Tactic"], [[t["id"], t["name"], t["tactic"]] for t in techniques], [24, 100, 54])

    rows = indicator_rows(result)
    pdf.section("Indicators (defanged)")
    if rows:
        pdf.table(["Type", "Indicator", "Valid", "Threat intel"],
                  [[t, defang(v), val, intel] for t, v, val, intel in rows[:150]], [18, 92, 18, 50])
    else:
        pdf.para("No indicators extracted.", color=MUTED)

    email = (result.get("ingestion") or {}).get("email")
    if email:
        pdf.section("Email Analysis")
        auth = ", ".join(f"{k.upper()}={v}" for k, v in (email.get("authentication") or {}).items()) or "not present"
        pdf.table(["Field", "Value"], [
            ["Subject", email.get("subject") or ""],
            ["From", f"{email.get('display_name') or ''} <{defang(email.get('from') or '')}>"],
            ["Reply-To", defang(email.get("reply_to") or "-")],
            ["Authentication", auth],
            ["Attachments", ", ".join(a.get("filename", "") for a in email.get("attachments", [])) or "none"],
        ], [40, 138])

    pdf.section("Rule Audit (matched)")
    matched = matched_rules(result)
    if matched:
        pdf.table(["Rule", "Name", "Weight"], [[r["rule_id"], r["rule_name"], f"{r['weight']:g}"] for r in matched], [32, 128, 18])
    else:
        pdf.para("No rules matched.", color=MUTED)

    return bytes(pdf.output())
