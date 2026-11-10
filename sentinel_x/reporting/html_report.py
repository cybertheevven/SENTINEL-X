"""Self-contained HTML dashboard report (no external assets, no JavaScript)."""
from __future__ import annotations

from html import escape as e
from pathlib import Path

from sentinel_x.core.case import Case
from sentinel_x.reporting import assets, graph, json_report

CSS = """
:root{--bg:#070d18;--card:#0e1726;--line:#1c2b45;--txt:#d7e3f4;--mut:#8aa0b4;--acc:#19e3d1;
--Critical:#ff4d6d;--High:#ff8c42;--Medium:#ffd166;--Low:#06d6a0;--Informational:#8aa0b4}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(1200px 600px at 20% -10%,#0d2236,var(--bg));
color:var(--txt);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:22px}
header{display:flex;align-items:center;gap:16px;border-bottom:1px solid var(--line);padding-bottom:14px}
h1{margin:0;font-size:22px;letter-spacing:1px}h1 small{color:var(--mut);font-weight:400;font-size:13px;display:block}
h2{font-size:12px;letter-spacing:2px;color:var(--acc);text-transform:uppercase;margin:0 0 10px}
.grid{display:grid;gap:14px}.k{grid-template-columns:repeat(auto-fit,minmax(170px,1fr));margin:16px 0}
.two{grid-template-columns:1.2fr 1fr}@media(max-width:860px){.two{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;overflow:auto}
.kpi b{display:block;font-size:24px}.kpi span{color:var(--mut);font-size:12px}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;border:1px solid currentColor}
table{border-collapse:collapse;width:100%;font-size:12px}th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase}
code,.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.phases{display:flex;gap:10px;flex-wrap:wrap}.ph{flex:1;min-width:150px;border:1px solid var(--line);border-radius:8px;padding:10px;background:#0b1422}
.ph b{display:block}.ph span{color:var(--mut);font-size:12px}
.term{background:#050a12;border:1px solid var(--line);border-radius:8px;padding:10px;max-height:330px;overflow:auto}
.term div{white-space:pre-wrap;word-break:break-word}.INFO{color:#6fb7ff}.WARN{color:var(--Medium)}.CRIT{color:var(--Critical)}.OK{color:var(--Low)}
ul.todo{margin:0;padding-left:18px}.todo li{margin:5px 0}.note{color:var(--mut);font-size:12px}
footer{margin:22px 0 6px;color:var(--mut);font-size:11px;text-align:center}
@media print{body{background:#fff;color:#000}.card{border-color:#999}}
"""


def chip(sev: str, label: str | None = None) -> str:
    return f'<span class="chip" style="color:var(--{e(sev)})">{e(label or sev)}</span>'


def _ts(v) -> str:
    return e(str(v).replace("T", " ").replace("+00:00", "Z"))


def _log_lines(r: dict) -> list[tuple[str, str]]:
    an = r["analysis"]
    out = [("OK", f"Evidence integrity: {len(an['integrity'])} file(s) verified against SHA-256 manifest"
            if all(v["ok"] for v in an["integrity"]) else "Evidence integrity check FAILED")]
    for st in an["parse_stats"]:
        out.append(("INFO", f"{st['evidence_id']} {st['file']}: format={st.get('format', '?')}, "
                            f"{st['lines']} lines, {st['parsed']} recognized"))
    for f in an["findings"][:60]:
        lvl = "CRIT" if f["severity"] == "Critical" else "WARN" if f["severity"] in ("High", "Medium") else "INFO"
        out.append((lvl, f"{f['id']} {f['type']} ip={f['ip']} ({f['evidence_id']}:{f['line']}) "
                         f"[{f['severity']}/{f['confidence']}/{f['classification']}]"))
    if len(an["findings"]) > 60:
        out.append(("INFO", f"... {len(an['findings']) - 60} more findings in the table below"))
    out.append(("OK", an["initial_access"]["summary"] + f" ({an['initial_access']['confidence']})"))
    return out


def render(case: Case) -> str:
    r = json_report.collect(case)
    an, ia = r["analysis"], r["analysis"]["initial_access"]
    f = an["findings"]
    sev = {s: sum(1 for x in f if x["severity"] == s) for s in ("Critical", "High", "Medium", "Low", "Informational")}
    svg = graph.render_svg(an["graph"])
    ips = len({x["ip"] for x in f})
    p = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
         f"<title>SENTINEL-X - {e(case.name)}</title><style>{CSS}</style></head><body><div class='wrap'>"]
    p.append(f"<header>{assets.logo(54)}<h1>SENTINEL-X<small>Digital Forensics &amp; Incident Investigation | Case "
             f"{e(case.name)} | {_ts(r['report_generated_at'])} | {e(r['tool'])}</small></h1></header>")
    # KPIs
    p.append("<div class='grid k'>")
    p.append(f"<div class='card kpi'><span>INITIAL ACCESS</span><b style='font-size:15px'>{e(ia['summary'])}</b>"
             f"<span>{e(ia['confidence'])} | {e(ia['classification'])}</span></div>")
    p.append(f"<div class='card kpi'><span>FINDINGS</span><b>{len(f)}</b><span>{sev['Critical']} critical, {sev['High']} high, "
             f"{sev['Medium']} medium, {sev['Low']} low</span></div>")
    p.append(f"<div class='card kpi'><span>SOURCE IPs IN FINDINGS</span><b>{ips}</b><span>{an['stats']['total_requests']} web requests, "
             f"{an['auth_stats']['events']} SSH events</span></div>")
    p.append(f"<div class='card kpi'><span>EVIDENCE FILES</span><b>{len(r['evidence'])}</b><span>SHA-256 verified before analysis</span></div>")
    p.append("</div>")
    # attack path
    p.append("<div class='card'><h2>Attack path reconstruction</h2>")
    p.append(svg or "<p class='note'>No attack path is supported by the available evidence.</p>")
    p.append("<p class='note'>Stages appear only when findings support them, ordered by first-seen time. "
             "A chain is a reconstruction aid, not proof that one actor performed every step.</p></div><br>")
    # timeline phases + confirmed access
    phases: dict[str, list[dict]] = {}
    for t in an["timeline"]:
        phases.setdefault(t["phase"], []).append(t)
    p.append("<div class='card'><h2>Attack timeline</h2><div class='phases'>")
    for ph, rows in sorted(phases.items(), key=lambda kv: kv[1][0]["timestamp"]):
        p.append(f"<div class='ph'><b>{e(ph)}</b><span>{_ts(rows[0]['timestamp'])}<br>{len(rows)} finding(s)</span></div>")
    if not phases:
        p.append("<span class='note'>No phase is supported by the evidence.</span>")
    p.append("</div>")
    if ia["confirmed_access"]:
        p.append("<p><b>Confirmed (Observed) successful logins after failures:</b> " + "; ".join(
            f"{e(c['finding_id'])} user <code>{e(str(c['user']))}</code> from <code>{e(c['ip'])}</code> at {_ts(c['timestamp'])} "
            f"({e(c['evidence_id'])}:{c['line']})" for c in ia["confirmed_access"]) + "</p>")
    p.append("</div><br>")
    # terminal + IOC
    p.append("<div class='grid two'><div class='card'><h2>Analysis log (rule-based)</h2><div class='term mono'>")
    for lvl, msg in _log_lines(r):
        p.append(f"<div><span class='{lvl}'>[{lvl}]</span> {e(msg)}</div>")
    p.append("</div></div><div class='card'><h2>Indicators of compromise</h2><table><tr><th>IP</th><th>Findings</th></tr>")
    for i in an["iocs"]["ip_addresses"][:15]:
        p.append(f"<tr><td class='mono'>{e(i['value'])}</td><td>{len(i['findings'])}</td></tr>")
    p.append("</table><p class='note'>" + e(an["iocs"]["note"]) + "</p></div></div><br>")
    # initial access detail
    fs = ia["first_suspicious_event"]
    p.append("<div class='card'><h2>Initial access analysis</h2>")
    p.append(f"<p><b>{e(ia['summary'])}</b> - this is a hypothesis, not a confirmed fact.</p>")
    if fs:
        p.append(f"<p>First suspicious event: <code>{e(fs['finding_id'])}</code> at {_ts(fs['timestamp'])} from "
                 f"<code>{e(fs['ip'])}</code> targeting <code>{e(str(fs['target']))}</code> ({e(fs['evidence_id'])}:{fs['line']}).</p>")
    p.append(f"<p>Contradicting / limiting evidence: {e(' '.join(ia['contradicting_evidence']) or 'none identified')}</p>")
    p.append("<p>Missing evidence:</p><ul class='todo'>" + "".join(f"<li>{e(m)}</li>" for m in ia["missing_evidence"]) + "</ul></div><br>")
    # findings
    p.append("<div class='card'><h2>Findings &amp; confidence</h2><table><tr><th>ID</th><th>Type</th><th>Time</th><th>Evidence</th>"
             "<th>IP</th><th>Severity</th><th>Confidence / Class</th><th>Reason</th></tr>")
    for x in f:
        p.append(f"<tr><td>{e(x['id'])}</td><td class='mono'>{e(x['type'])}</td><td>{_ts(x['timestamp'])}</td>"
                 f"<td class='mono'>{e(x['evidence_id'])}:{x['line']}</td><td class='mono'>{e(x['ip'])}</td><td>{chip(x['severity'])}</td>"
                 f"<td>{e(x['confidence'])} / {e(x['classification'])}</td><td>{e(x['description'])}</td></tr>")
    p.append("</table></div><br>")
    # evidence + remediation
    p.append("<div class='card'><h2>Evidence inventory &amp; SHA-256</h2><table><tr><th>ID</th><th>File</th><th>Format</th><th>Size</th><th>SHA-256</th></tr>")
    fmt = {s["evidence_id"]: s.get("format", "?") for s in an["parse_stats"]}
    for ev in r["evidence"]:
        p.append(f"<tr><td>{e(ev['evidence_id'])}</td><td>{e(ev['filename'])}</td><td>{e(fmt.get(ev['evidence_id'], '?'))}</td>"
                 f"<td>{ev['size_bytes']}</td><td class='mono'>{e(ev['sha256'])}</td></tr>")
    p.append("</table></div><br><div class='card'><h2>Remediation recommendations</h2>")
    p.append("<ul class='todo'>" + "".join(
        f"<li>{chip({'Immediate': 'Critical', 'High': 'High', 'Medium': 'Medium'}[x['priority']], x['priority'])} "
        f"{e(x['action'])} <span class='note'>{e(', '.join(x['findings']))}</span></li>" for x in an["remediation"]) + "</ul>")
    p.append("<p class='note'>Generic defensive guidance derived from finding types. Validate in your environment.</p></div><br>")
    # AI
    ai = r["ai_investigation"]
    p.append("<div class='card'><h2>AI investigation summary (optional)</h2>")
    if ai and ai["status"] == "ok":
        chk = ai["citation_check"]["valid"]
        p.append(f"<p class='note'>Model {e(ai['model'])} (local). Citation check: {'valid' if chk else 'FAILED - treat as unverified'}.</p>")
        p.append("".join(f"<p>{e(line)}</p>" for line in ai["text"].split("\n") if line.strip()))
    else:
        p.append("<p class='note'>Not generated. All other sections are rule-based.</p>")
    p.append("</div><br><div class='card'><h2>Limitations</h2><ul class='todo'>" + "".join(f"<li>{e(l)}</li>" for l in r["limitations"]) + "</ul></div>")
    p.append("<footer>Generated by SENTINEL-X (defensive, read-only analysis). Confidential - authorized recipients only.</footer></div></body></html>")
    return "".join(p)


def write(case: Case, out: Path) -> Path:
    out.write_text(render(case), encoding="utf-8")
    return out
