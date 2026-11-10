"""IOC extraction from findings (local only; no external enrichment in the MVP)."""
from __future__ import annotations

from collections import defaultdict

from sentinel_x.core.models import Finding


def extract(findings: list[Finding]) -> dict:
    ips: dict[str, set] = defaultdict(set)
    uas: dict[str, set] = defaultdict(set)
    paths: dict[str, set] = defaultdict(set)
    for f in findings:
        ips[f.ip].add(f.id)
        ua = f.details.get("user_agent")
        if ua and ua != "-":
            uas[ua].add(f.id)
        p = f.details.get("path")
        if p:
            paths[p.split("?")[0]].add(f.id)
    fmt = lambda d: [{"value": k, "findings": sorted(v)} for k, v in sorted(d.items())]
    return {"ip_addresses": fmt(ips), "user_agents": fmt(uas), "urls": fmt(paths),
            "note": "An IP address does not identify a person; geolocation/ASN enrichment is not part of the MVP."}
