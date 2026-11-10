"""sentinel-x command line interface."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sentinel_x import __version__
from sentinel_x.ai import ollama
from sentinel_x.core.case import Case, CaseError, default_home
from sentinel_x.core.pipeline import AnalysisError, run_analysis
from sentinel_x.evidence.collector import EvidenceError, EvidenceStore
from sentinel_x.demo import synthetic
from sentinel_x.reporting import html_report, json_report, pdf_report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel-x",
                                description="SENTINEL-X - AI digital forensics & incident investigation (defensive, read-only).")
    p.add_argument("--version", action="version", version=f"sentinel-x {__version__}")
    p.add_argument("--home", default=None, help="Cases directory (default: $SENTINEL_X_HOME or ~/.sentinel-x/cases)")
    sub = p.add_subparsers(dest="command", required=True)

    case = sub.add_parser("case", help="Manage investigation cases").add_subparsers(dest="action", required=True)
    c = case.add_parser("create"); c.add_argument("--name", required=True)
    case.add_parser("list")

    ev = sub.add_parser("evidence", help="Manage evidence").add_subparsers(dest="action", required=True)
    a = ev.add_parser("add"); a.add_argument("--case", required=True); a.add_argument("--path", required=True)
    for name in ("list", "verify"):
        x = ev.add_parser(name); x.add_argument("--case", required=True)

    an = sub.add_parser("analyze", help="Run automated analysis")
    an.add_argument("--case", required=True)
    an.add_argument("--bruteforce-threshold", type=int)
    an.add_argument("--enum-404-threshold", type=int)
    an.add_argument("--year", type=int, help="Year to assume for syslog timestamps without a year (default: file mtime year)")

    ai = sub.add_parser("ai", help="AI investigation").add_subparsers(dest="action", required=True)
    inv = ai.add_parser("investigate")
    inv.add_argument("--case", required=True)
    inv.add_argument("--host", default=ollama.DEFAULT_HOST)
    inv.add_argument("--model", default=ollama.DEFAULT_MODEL)
    inv.add_argument("--timeout", type=int, default=120)

    rp = sub.add_parser("report", help="Reporting").add_subparsers(dest="action", required=True)
    g = rp.add_parser("generate")
    g.add_argument("--case", required=True)
    g.add_argument("--format", choices=["pdf", "json", "html", "both", "all"], default="all",
                   help="both = pdf+json (legacy); all = pdf+json+html (default)")
    g.add_argument("--output", help="Output file (single format) or directory")
    d = sub.add_parser("demo", help="Run a complete demo on synthetic logs (case + analysis + reports)")
    d.add_argument("--name", default="DEMO")
    d.add_argument("--output-dir", default="sentinel-x-demo", help="Where to put the demo logs and reports")
    return p


def _out(msg: str = "") -> None:
    print(msg)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    home = Path(args.home) if args.home else default_home()
    try:
        return _dispatch(args, home)
    except (CaseError, EvidenceError, AnalysisError, FileNotFoundError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2


def _dispatch(args, home: Path) -> int:
    if args.command == "case":
        if args.action == "create":
            case = Case.create(home, args.name)
            _out(f"[+] Case created: {case.dir}")
        else:
            for n in Case.list_cases(home):
                _out(n)
        return 0

    if args.command == "demo":
        return _demo(args, home)

    case = Case.open(home, args.case)

    if args.command == "evidence":
        store = EvidenceStore(case.dir)
        if args.action == "add":
            added, skipped = store.add_path(args.path)
            for e in added:
                _out(f"[+] {e['evidence_id']}  {e['filename']}  sha256={e['sha256']}")
            for s in skipped:
                _out(f"[=] duplicate skipped: {s}")
            case.log("evidence_added", f"{len(added)} added, {len(skipped)} duplicates")
        elif args.action == "list":
            for e in store.entries():
                _out(f"{e['evidence_id']}  {e['size_bytes']:>10}  {e['sha256'][:16]}...  {e['filename']}")
        else:
            results = store.verify()
            for v in results:
                _out(f"{'[OK]' if v['ok'] else '[FAIL]'} {v['evidence_id']}: {v['detail']}")
            return 0 if all(v["ok"] for v in results) else 1
        return 0

    if args.command == "analyze":
        cfg = {}
        if args.bruteforce_threshold:
            cfg["bruteforce_threshold"] = args.bruteforce_threshold
        if args.enum_404_threshold:
            cfg["enum_404_threshold"] = args.enum_404_threshold
        if args.year:
            cfg["auth_year"] = args.year
        res = run_analysis(case, cfg)
        _out(f"[+] Requests: {res['stats']['total_requests']}  IPs: {res['stats']['unique_ips']}  "
             f"Findings: {len(res['findings'])}")
        for f in res["findings"]:
            _out(f"  {f['id']} [{f['severity']:<13}] {f['type']:<38} {f['ip']:<15} {f['evidence_id']}:{f['line']}")
        _out(f"[+] {res['initial_access']['summary']} ({res['initial_access']['confidence']})")
        if res["unsupported_evidence"]:
            _out("[!] Unsupported format (not parsed): " + ", ".join(res["unsupported_evidence"]))
        return 0

    if args.command == "ai":
        if not case.analysis_file.exists():
            raise AnalysisError("Run 'sentinel-x analyze' first.")
        analysis = json.loads(case.analysis_file.read_text(encoding="utf-8"))
        ids = {e["evidence_id"] for e in EvidenceStore(case.dir).entries()}
        res = ollama.investigate(analysis, ids, args.host, args.model, args.timeout)
        case.ai_file.write_text(json.dumps(res, indent=2), encoding="utf-8")
        case.log("ai_investigation", f"status={res['status']} model={res['model']}")
        if res["status"] != "ok":
            _out(f"[!] {res['error']}")
            _out("[!] Reports can still be generated without the AI section.")
            return 3
        _out(res["text"])
        if "warning" in res:
            _out(f"\n[!] {res['warning']}")
        return 0

    if args.command == "report":
        return _report(case, args.format, Path(args.output) if args.output else None)
    return 1


def _report(case: Case, fmt: str, base: Path | None) -> int:
    case.reports_dir.mkdir(exist_ok=True)
    wanted = {"pdf": ["pdf"], "json": ["json"], "html": ["html"], "both": ["pdf", "json"],
              "all": ["pdf", "json", "html"]}[fmt]
    writers = {"pdf": pdf_report.generate, "json": json_report.write, "html": html_report.write}
    outs = []
    for kind in wanted:
        if base and len(wanted) == 1 and base.suffix:
            target = base
        else:
            target = (base or case.reports_dir) / f"{case.name}_report.{kind}"
            target.parent.mkdir(parents=True, exist_ok=True)
        outs.append(writers[kind](case, target))
    case.log("report_generated", ", ".join(str(o) for o in outs))
    for o in outs:
        _out(f"[+] Report: {o}")
    return 0


def _demo(args, home: Path) -> int:
    out = Path(args.output_dir)
    logs = synthetic.write(out / "logs")
    name = args.name
    if name in Case.list_cases(home):
        from datetime import datetime
        name = f"{name}-{datetime.now():%H%M%S}"
    case = Case.create(home, name)
    store = EvidenceStore(case.dir)
    for f in logs:
        store.add_file(f)
    case.log("evidence_added", f"{len(logs)} synthetic files")
    res = run_analysis(case, {"auth_year": 2026})
    _out(f"[+] Demo case '{name}': {len(res['findings'])} findings; {res['initial_access']['summary']} "
         f"({res['initial_access']['confidence']})")
    _report(case, "all", out / "reports")
    _out(f"[+] Open the dashboard: xdg-open {out / 'reports' / (name + '_report.html')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
