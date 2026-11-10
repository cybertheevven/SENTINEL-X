"""Professional PDF report (ReportLab)."""
from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

from sentinel_x.core.case import Case
from sentinel_x.reporting import graph as graph_mod
from sentinel_x.reporting import json_report

NAVY = colors.HexColor("#0B1B2B")
TEAL = colors.HexColor("#00B8A9")
GREY = colors.HexColor("#E9EEF2")
SEV_COLOR = {"Critical": "#B00020", "High": "#E65100", "Medium": "#F9A825",
             "Low": "#2E7D32", "Informational": "#546E7A"}

_ss = getSampleStyleSheet()
BODY = ParagraphStyle("body", parent=_ss["BodyText"], fontSize=9, leading=12)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=7.5, leading=9.5)
H1 = ParagraphStyle("h1", parent=_ss["Heading1"], textColor=NAVY, fontSize=15, spaceBefore=10, spaceAfter=6)
H2 = ParagraphStyle("h2", parent=_ss["Heading2"], textColor=NAVY, fontSize=11.5)


def P(text, style=BODY):
    return Paragraph(escape(str(text)), style)


def table(rows, widths, header=True):
    data = [[c if not isinstance(c, str) else P(c, SMALL) for c in r] for r in rows]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#B0BEC5")),
             ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GREY]),
             ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), NAVY)]
        data[0] = [Paragraph(f'<font color="white"><b>{escape(str(c.text if hasattr(c, "text") else c))}</b></font>',
                             SMALL) for c in rows[0]]
        t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle(style))
    return t


def ts(v):
    return str(v).replace("T", " ").replace("+00:00", "Z")


def _sev(sev):
    return Paragraph(f'<font color="{SEV_COLOR.get(sev, "#000000")}"><b>{escape(sev)}</b></font>', SMALL)


def _logo(canvas, x, y, size):
    """Shield + eye, drawn natively (same design as docs/assets/logo.svg)."""
    k = size / 120.0
    canvas.saveState()
    canvas.translate(x, y)
    canvas.scale(k, k)
    canvas.setStrokeColor(TEAL)
    canvas.setFillColor(colors.HexColor("#06121F"))
    canvas.setLineWidth(4)
    pth = canvas.beginPath()
    pth.moveTo(60, 112); pth.lineTo(104, 96); pth.lineTo(104, 60)
    pth.curveTo(104, 34, 84, 16, 60, 6); pth.curveTo(36, 16, 16, 34, 16, 60)
    pth.lineTo(16, 96); pth.close()
    canvas.drawPath(pth, stroke=1, fill=1)
    eye = canvas.beginPath()
    eye.moveTo(26, 60); eye.curveTo(40, 80, 80, 80, 94, 60); eye.curveTo(80, 40, 40, 40, 26, 60); eye.close()
    canvas.drawPath(eye, stroke=1, fill=0)
    canvas.circle(60, 60, 13, stroke=1, fill=0)
    canvas.setFillColor(TEAL)
    canvas.circle(60, 60, 5, stroke=0, fill=1)
    canvas.restoreState()


def _cover(canvas, doc):
    w, h = A4
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, w, h, stroke=0, fill=1)
    canvas.setFillColor(TEAL)
    canvas.rect(0, h * 0.58, w, 3, stroke=0, fill=1)
    _logo(canvas, 25 * mm, h * 0.74, 22 * mm)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 38)
    canvas.drawString(25 * mm, h * 0.66, "SENTINEL-X")
    canvas.setFont("Helvetica", 15)
    canvas.drawString(25 * mm, h * 0.62, "Digital Forensics & Incident Investigation Report")
    canvas.setFont("Helvetica", 11)
    canvas.drawString(25 * mm, h * 0.50, f"Case: {doc.case_name}")
    canvas.drawString(25 * mm, h * 0.47, f"Generated: {doc.generated}")
    canvas.drawString(25 * mm, h * 0.44, f"Tool: {doc.tool}")
    canvas.setFont("Helvetica-Oblique", 9)
    canvas.drawString(25 * mm, 18 * mm, "CONFIDENTIAL - for authorized recipients only. Defensive analysis of evidence the analyst is legally permitted to examine.")
    canvas.restoreState()


def _page(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(TEAL)
    canvas.rect(0, A4[1] - 8 * mm, A4[0], 1.2, stroke=0, fill=1)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#546E7A"))
    canvas.drawString(15 * mm, 8 * mm, f"SENTINEL-X | Case {doc.case_name}")
    canvas.drawRightString(A4[0] - 15 * mm, 8 * mm, f"Page {doc.page}")
    canvas.restoreState()


def generate(case: Case, out: Path) -> Path:
    r = json_report.collect(case)
    an = r["analysis"]
    ia = an["initial_access"]
    findings = an["findings"]

    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"SENTINEL-X Report - {case.name}", author="SENTINEL-X")
    doc.case_name, doc.generated, doc.tool = case.name, r["report_generated_at"], r["tool"]
    W = A4[0] - 30 * mm
    s: list = [PageBreak()]

    # Executive summary
    sev_count: dict[str, int] = {}
    for f in findings:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1
    s += [P("1. Executive Summary", H1),
          P(f"{an['stats']['total_requests']} web requests from {an['stats']['unique_ips']} unique IP addresses "
            f"were analyzed ({ts(an['stats']['first_event'])} to {ts(an['stats']['last_event'])}). "
            f"{len(findings)} findings were produced: "
            + (", ".join(f"{v} {k}" for k, v in sev_count.items()) or "none") + "."),
          Spacer(1, 4), P(f"Initial access: {ia['summary']}. Confidence: {ia['confidence']}. "
                          "This is a hypothesis derived from the findings, not a confirmed fact."),
          Spacer(1, 4),
          P("Classification legend - Observed: directly present in evidence. Inferred: conclusion from several "
            "indicators. Unknown: cannot be established with the available evidence. Severity (impact) and "
            "confidence (strength of evidence) are independent.", SMALL)]

    kp = [[Paragraph(f'<font size="17" color="#0B1B2B"><b>{v}</b></font><br/><font size="7.5" color="#546E7A">{escape(l)}</font>', BODY)
           for v, l in ((len(findings), "FINDINGS"), (sev_count.get("Critical", 0) + sev_count.get("High", 0), "CRITICAL + HIGH"),
                        (len({f["ip"] for f in findings}), "SOURCE IPs"), (len(r["evidence"]), "EVIDENCE FILES"))]]
    kt = Table(kp, colWidths=[W / 4] * 4)
    kt.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, TEAL), ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#B0BEC5")),
                            ("BACKGROUND", (0, 0), (-1, -1), GREY), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    s += [Spacer(1, 8), kt]

    # Evidence inventory
    s += [P("2. Evidence Inventory & SHA-256", H1)]
    fmt = {x["evidence_id"]: x.get("format", "?") for x in an["parse_stats"]}
    rows = [["ID", "File", "Format", "Size", "SHA-256", "Collected (UTC)"]]
    for e in r["evidence"]:
        rows.append([e["evidence_id"], e["filename"], fmt.get(e["evidence_id"], "?"), str(e["size_bytes"]), e["sha256"], ts(e["collected_at"])])
    s.append(table(rows, [15 * mm, 26 * mm, 14 * mm, 14 * mm, W - 15 * mm - 26 * mm - 14 * mm - 14 * mm - 28 * mm, 28 * mm]))
    ok = all(v["ok"] for v in an["integrity"])
    s += [Spacer(1, 4), P("Integrity check before analysis: " + ("all SHA-256 hashes matched." if ok else "FAILED."))]
    if an["unsupported_evidence"]:
        s.append(P("Unsupported/unrecognized format (not analyzed): " + ", ".join(an["unsupported_evidence"])))

    # Initial access
    s += [P("3. Initial Access Analysis", H1), P(ia["summary"])]
    fs = ia["first_suspicious_event"]
    if fs:
        s.append(P(f"First suspicious event: {fs['finding_id']} at {ts(fs['timestamp'])} from {fs['ip']} "
                   f"targeting {fs['target']} ({fs['evidence_id']}, line {fs['line']})."))
        s.append(P("Supporting findings: " + ", ".join(ia["supporting_findings"])))
    s.append(P("Contradicting / limiting evidence: " + (" ".join(ia["contradicting_evidence"]) or "none identified")))
    s.append(P("Missing evidence: " + "; ".join(ia["missing_evidence"])))
    for c in ia.get("confirmed_access", []):
        s.append(P(f"Confirmed (Observed) login after failures: {c['finding_id']} user '{c['user']}' from {c['ip']} at "
                   f"{ts(c['timestamp'])} ({c['evidence_id']}:{c['line']})."))
    s += [Spacer(1, 6), P("Attack path reconstruction", H2)]
    drawing = graph_mod.render_drawing(an["graph"], W)
    s.append(drawing if drawing else P("No attack path is supported by the available evidence."))
    s.append(P("Stages are ordered by first-seen time; a chain is a reconstruction aid, not proof that one actor did every step.", SMALL))

    # Timeline
    s += [P("4. Attack Timeline", H1)]
    if an["timeline"]:
        rows = [["Time", "Phase", "Finding", "IP", "Summary"]]
        for t in an["timeline"]:
            rows.append([ts(t["timestamp"]), t["phase"], f"{t['finding_id']} ({t['evidence_id']}:{t['line']})",
                         t["ip"], t["summary"]])
        s.append(table(rows, [34 * mm, 30 * mm, 28 * mm, 24 * mm, W - 116 * mm]))
    else:
        s.append(P("No timeline phases are supported by the available evidence."))

    # Findings
    s += [PageBreak(), P("5. Findings & Confidence Levels", H1)]
    if findings:
        rows = [["ID", "Type", "Time", "Evidence", "IP", "Sev.", "Confidence / Class", "Reason"]]
        for f in findings:
            rows.append([f["id"], f["type"], ts(f["timestamp"]), f"{f['evidence_id']}:{f['line']}", f["ip"],
                         _sev(f["severity"]), f"{f['confidence']} / {f['classification']}", f["description"]])
        s.append(table(rows, [13 * mm, 26 * mm, 26 * mm, 17 * mm, 21 * mm, 14 * mm, 22 * mm, W - 139 * mm]))
    else:
        s.append(P("No findings."))

    # IOC
    s += [P("6. Indicators of Compromise (local extraction)", H1)]
    for title, key in (("IP addresses", "ip_addresses"), ("User-Agents", "user_agents"), ("URLs / paths", "urls")):
        s.append(P(title, H2))
        items = an["iocs"][key]
        if items:
            s.append(table([["Value", "Related findings"]] + [[i["value"], ", ".join(i["findings"])] for i in items[:40]],
                           [W * 0.5, W * 0.5]))
        else:
            s.append(P("None."))
    s.append(P(an["iocs"]["note"], SMALL))

    # Remediation
    s += [P("7. Remediation Recommendations", H1)]
    if an["remediation"]:
        s.append(table([["Priority", "Action", "Findings"]] + [[x["priority"], x["action"], ", ".join(x["findings"])] for x in an["remediation"]],
                       [20 * mm, W - 20 * mm - 40 * mm, 40 * mm]))
        s.append(P("Generic defensive guidance derived from finding types; validate in your environment.", SMALL))
    else:
        s.append(P("No remediation items: no findings."))

    # AI
    s += [P("8. AI Investigation Summary (optional, unverified unless checked)", H1)]
    ai = r["ai_investigation"]
    if ai and ai["status"] == "ok":
        s.append(P(f"Model: {ai['model']} (local). Citation check: "
                   + ("valid" if ai["citation_check"]["valid"] else "FAILED - " + ai.get("warning", ""))))
        for para in ai["text"].split("\n"):
            if para.strip():
                s.append(P(para))
    else:
        s.append(P("Not generated (AI step not run or Ollama unavailable). All other sections are rule-based."))

    s += [P("9. Limitations", H1)] + [P("- " + l) for l in r["limitations"]]
    doc.build(s, onFirstPage=_cover, onLaterPages=_page)
    return out
