"""Analysis pipeline: verify evidence -> parse -> detect -> assess -> timeline -> IOC."""
from __future__ import annotations

import json

from sentinel_x import __version__
from sentinel_x.analyzers import auth_detection, correlation, detection, ioc
from sentinel_x.core.case import Case
from sentinel_x.evidence.collector import EvidenceStore, utcnow
from sentinel_x.investigation import initial_access, remediation
from sentinel_x.reporting import graph
from sentinel_x.parsers import auth, detect, web
from sentinel_x.timeline import builder


class AnalysisError(Exception):
    pass


def run_analysis(case: Case, config: dict | None = None) -> dict:
    store = EvidenceStore(case.dir)
    entries = store.entries()
    if not entries:
        raise AnalysisError("No evidence in this case. Run: sentinel-x evidence add ...")
    verification = store.verify()
    bad = [v for v in verification if not v["ok"]]
    if bad:
        raise AnalysisError("Evidence integrity check FAILED: "
                            + "; ".join(f"{v['evidence_id']}: {v['detail']}" for v in bad))

    cfg = config or {}
    web_events, auth_events, parse_stats, unsupported = [], [], [], []
    for e in entries:
        path = store.path_of(e)
        fmt = detect.sniff(path)
        if fmt == "web":
            evs, st = web.parse_file(path, e["evidence_id"], e["filename"])
            web_events.extend(evs)
        elif fmt == "auth":
            evs, st = auth.parse_file(path, e["evidence_id"], e["filename"], cfg.get("auth_year"))
            auth_events.extend(evs)
        else:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                n = sum(1 for line in fh if line.strip())
            st = {"evidence_id": e["evidence_id"], "file": e["filename"], "lines": n, "parsed": 0, "unparsed": n}
            if fmt == "unknown":
                unsupported.append(e["evidence_id"])
        st["format"] = fmt
        parse_stats.append(st)

    raw = detection.Detector(cfg).detect(web_events) + auth_detection.AuthDetector(cfg).detect(auth_events)
    raw += correlation.correlate(raw)
    findings = detection.finalize(raw)
    fdicts = [f.to_dict() for f in findings]
    result = {
        "generated_at": utcnow(),
        "tool_version": __version__,
        "integrity": verification,
        "parse_stats": parse_stats,
        "unsupported_evidence": unsupported,
        "stats": detection.compute_stats(web_events),
        "auth_stats": auth_detection.compute_auth_stats(auth_events),
        "findings": fdicts,
        "initial_access": initial_access.assess(findings, {st["format"] for st in parse_stats}),
        "timeline": builder.build(findings),
        "iocs": ioc.extract(findings),
        "remediation": remediation.build(fdicts),
        "graph": graph.build(fdicts),
    }
    case.analysis_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    case.log("analysis_run", f"{len(web_events)} web + {len(auth_events)} auth events, {len(findings)} findings")
    return result
