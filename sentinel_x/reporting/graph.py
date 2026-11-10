"""Attack-path graph: one horizontal chain per source IP, stages ordered by first-seen time.

The same model feeds the HTML dashboard (SVG) and the PDF (ReportLab drawing).
Only stages supported by findings appear."""
from __future__ import annotations

from xml.sax.saxutils import escape

from sentinel_x.timeline.builder import ORDER, PHASE_OF

SEV_RANK = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
DARK = {"Critical": "#ff4d6d", "High": "#ff8c42", "Medium": "#ffd166", "Low": "#06d6a0", "Informational": "#8aa0b4"}
LIGHT = {"Critical": "#B00020", "High": "#E65100", "Medium": "#C79100", "Low": "#2E7D32", "Informational": "#546E7A"}
W, BOX_W, BOX_H, GAP, ROW_H, TOP = 1000, 138, 80, 26, 120, 22
SHORT = {"Initial Access / Exploitation": "Exploitation", "Execution / Persistence indicator": "Persistence/Exec"}
MAX_ROWS = 4


def build(findings: list[dict]) -> dict:
    by_ip: dict[str, dict[str, list[dict]]] = {}
    for f in findings:
        phase = PHASE_OF.get(f["type"])
        if phase:
            by_ip.setdefault(f["ip"], {}).setdefault(phase, []).append(f)
    rows = []
    for ip, phases in by_ip.items():
        stages = []
        for phase, fs in phases.items():
            stages.append({"phase": phase, "count": len(fs), "first_ts": min(x["timestamp"] for x in fs),
                           "severity": max((x["severity"] for x in fs), key=lambda s: SEV_RANK[s]),
                           "types": sorted({x["type"] for x in fs}), "findings": [x["id"] for x in fs][:6]})
        stages.sort(key=lambda s: (s["first_ts"], ORDER.index(s["phase"])))
        top = max(SEV_RANK[s["severity"]] for s in stages)
        rows.append({"ip": ip, "stages": stages, "rank": (top, sum(s["count"] for s in stages))})
    rows.sort(key=lambda r: r["rank"], reverse=True)
    return {"rows": rows[:MAX_ROWS], "omitted_ips": max(0, len(rows) - MAX_ROWS)}


def _fit(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 2] + ".."


def _time(ts: str) -> str:
    return ts[11:19] if len(ts) >= 19 else ts


def layout(graph: dict):
    """Yield (row_index, nodes, edges). Node: dict(x,y,title,sub,sev,kind). Edge: (x1,y,x2,label)."""
    out = []
    for r, row in enumerate(graph["rows"]):
        y = TOP + r * ROW_H
        nodes = [{"x": 20, "y": y, "title": _fit(row["ip"], 17), "sub": "source IP", "sub2": "", "sev": None, "kind": "ip"}]
        edges = []
        for i, st in enumerate(row["stages"], 1):
            x = 20 + i * (BOX_W + GAP)
            nodes.append({"x": x, "y": y, "title": _fit(SHORT.get(st["phase"], st["phase"]), 17),
                          "sub": f"{st['count']} finding(s)", "sub2": f"first {_time(st['first_ts'])}",
                          "sev": st["severity"], "kind": "stage"})
            edges.append((x - GAP, y + BOX_H / 2, x, _time(st["first_ts"])))
        out.append((r, nodes, edges))
    height = TOP + max(1, len(graph["rows"])) * ROW_H
    return out, height


def render_svg(graph: dict) -> str | None:
    if not graph["rows"]:
        return None
    lay, H = layout(graph)
    p = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="100%" role="img" '
         'aria-label="Attack path graph"><defs><marker id="ar" markerWidth="8" markerHeight="8" refX="7" refY="4" '
         'orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#19e3d1"/></marker></defs>']
    for _, nodes, edges in lay:
        for x1, y, x2, label in edges:
            p.append(f'<line x1="{x1}" y1="{y}" x2="{x2 - 2}" y2="{y}" stroke="#19e3d1" stroke-width="1.6" '
                     'stroke-dasharray="4 3" marker-end="url(#ar)"/>')
        for n in nodes:
            color = DARK.get(n["sev"], "#19e3d1")
            p.append(f'<rect x="{n["x"]}" y="{n["y"]}" width="{BOX_W}" height="{BOX_H}" rx="8" fill="#0e1726" '
                     f'stroke="{color}" stroke-width="1.8"/>')
            p.append(f'<text x="{n["x"] + 10}" y="{n["y"] + 24}" fill="#e6f1ff" font-size="12.5" font-weight="700" '
                     f'font-family="monospace">{escape(n["title"])}</text>')
            p.append(f'<text x="{n["x"] + 10}" y="{n["y"] + 42}" fill="#8aa0b4" font-size="10" '
                     f'font-family="monospace">{escape(n["sub"])}</text>')
            p.append(f'<text x="{n["x"] + 10}" y="{n["y"] + 55}" fill="#8aa0b4" font-size="10" '
                     f'font-family="monospace">{escape(n["sub2"])}</text>')
            if n["sev"]:
                p.append(f'<text x="{n["x"] + 10}" y="{n["y"] + 71}" fill="{color}" font-size="9" '
                         f'font-family="monospace">{escape(n["sev"].upper())}</text>')
    if graph["omitted_ips"]:
        p.append(f'<text x="20" y="{H - 4}" fill="#8aa0b4" font-size="10" font-family="monospace">'
                 f'+{graph["omitted_ips"]} more source IP(s) not drawn</text>')
    p.append("</svg>")
    return "".join(p)


def render_drawing(graph: dict, target_width: float):
    """ReportLab Drawing (light theme) scaled to target_width points, or None."""
    if not graph["rows"]:
        return None
    from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
    from reportlab.lib import colors
    lay, H = layout(graph)
    s = target_width / W
    d = Drawing(W, H)
    navy, teal = colors.HexColor("#0B1B2B"), colors.HexColor("#00897B")
    for _, nodes, edges in lay:
        for x1, y, x2, _l in edges:
            yy = H - y
            d.add(Line(x1, yy, x2 - 6, yy, strokeColor=teal, strokeWidth=1.6, strokeDashArray=[4, 3]))
            d.add(Polygon([x2 - 6, yy + 4, x2, yy, x2 - 6, yy - 4], fillColor=teal, strokeColor=teal))
        for n in nodes:
            c = colors.HexColor(LIGHT.get(n["sev"], "#00897B"))
            by = H - n["y"] - BOX_H
            d.add(Rect(n["x"], by, BOX_W, BOX_H, rx=8, ry=8, fillColor=colors.HexColor("#F4F8FB"),
                       strokeColor=c, strokeWidth=1.8))
            d.add(String(n["x"] + 10, by + BOX_H - 24, n["title"], fontName="Helvetica-Bold", fontSize=12, fillColor=navy))
            d.add(String(n["x"] + 10, by + BOX_H - 41, n["sub"], fontName="Helvetica", fontSize=9, fillColor=colors.HexColor("#546E7A")))
            d.add(String(n["x"] + 10, by + BOX_H - 54, n["sub2"], fontName="Helvetica", fontSize=9, fillColor=colors.HexColor("#546E7A")))
            if n["sev"]:
                d.add(String(n["x"] + 10, by + 6, n["sev"].upper(), fontName="Helvetica-Bold", fontSize=8.5, fillColor=c))
    d.scale(s, s)
    d.width, d.height = W * s, H * s
    return d
