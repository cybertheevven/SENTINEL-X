"""Optional local AI summary through Ollama (stdlib only).

Rules enforced: the model gets ONLY findings (no raw logs), must cite IDs, and every
cited ID is validated afterwards. If Ollama is unreachable the tool degrades gracefully.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

DEFAULT_HOST = os.environ.get("SENTINEL_X_OLLAMA_HOST", "http://localhost:11434")
DEFAULT_MODEL = os.environ.get("SENTINEL_X_MODEL", "llama3.1")

SYSTEM_RULES = """You are a digital forensics assistant. Follow these rules strictly:
- Use ONLY the findings provided. Never invent evidence, IPs, files or events.
- Never present a hypothesis as a fact. Label statements Observed, Inferred or Unknown.
- Every conclusion must cite finding IDs (F-0001) and/or evidence IDs (EV-0001).
- Mention evidence that contradicts or is missing for your conclusions.
- Keep severity and confidence separate. If evidence is insufficient, say so.
Write: 1) Summary 2) Likely sequence 3) What is known vs unknown 4) Next investigation steps."""

ID_RE = re.compile(r"\b(EV-\d{4}|F-\d{4})\b")


def build_prompt(analysis: dict, max_findings: int = 60) -> str:
    slim = [{k: f[k] for k in ("id", "type", "timestamp", "evidence_id", "line", "ip", "severity",
                               "confidence", "classification", "description")}
            for f in analysis["findings"][:max_findings]]
    ia = analysis["initial_access"]
    payload = {"findings": slim, "initial_access_assessment": ia["summary"],
               "initial_access_confidence": ia["confidence"],
               "missing_evidence": ia["missing_evidence"],
               "truncated": len(analysis["findings"]) > max_findings}
    return SYSTEM_RULES + "\n\nDATA (JSON):\n" + json.dumps(payload, indent=1)


def validate_citations(text: str, evidence_ids: set[str], finding_ids: set[str]) -> dict:
    cited = set(ID_RE.findall(text))
    unknown = sorted(c for c in cited if c not in evidence_ids and c not in finding_ids)
    return {"cited": sorted(cited), "unknown_references": unknown,
            "has_citations": bool(cited), "valid": bool(cited) and not unknown}


def generate(prompt: str, host: str = DEFAULT_HOST, model: str = DEFAULT_MODEL, timeout: int = 120) -> dict:
    body = json.dumps({"model": model, "prompt": prompt, "stream": False,
                       "options": {"temperature": 0.1}}).encode()
    req = urllib.request.Request(host.rstrip("/") + "/api/generate", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return {"status": "ok", "model": model, "text": data.get("response", "").strip()}
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, ValueError) as exc:
        return {"status": "unavailable", "model": model, "text": "",
                "error": f"Ollama not reachable at {host}: {exc}"}


def investigate(analysis: dict, evidence_ids: set[str], host: str = DEFAULT_HOST,
                model: str = DEFAULT_MODEL, timeout: int = 120) -> dict:
    result = generate(build_prompt(analysis), host, model, timeout)
    finding_ids = {f["id"] for f in analysis["findings"]}
    if result["status"] == "ok":
        result["citation_check"] = validate_citations(result["text"], evidence_ids, finding_ids)
        if not result["citation_check"]["valid"]:
            result["warning"] = ("AI output has missing or unknown evidence references. "
                                 "Treat it as UNVERIFIED and review manually.")
    return result
