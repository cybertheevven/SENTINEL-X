"""SSH authentication analysis. A logged 'Accepted' line is Observed fact (login succeeded);
that the login was malicious is only Inferred from the preceding failures."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from sentinel_x.analyzers.detection import _first_window
from sentinel_x.core.models import AuthEvent, Finding

DEFAULTS = {"ssh_bruteforce_threshold": 5, "ssh_bruteforce_window_s": 300, "ssh_enum_threshold": 3}


class AuthDetector:
    def __init__(self, config: dict | None = None):
        self.cfg = {**DEFAULTS, **(config or {})}

    @staticmethod
    def _f(ev: AuthEvent, ftype, sev, conf, cls, desc, **details) -> Finding:
        details.update({"user": ev.user, "method": ev.method, "source": "ssh"})
        return Finding("", ftype, ev.ts, ev.evidence_id, ev.file, ev.line, ev.ip, sev, conf, cls, desc, details)

    def detect(self, events: list[AuthEvent]) -> list[Finding]:
        out: list[Finding] = []
        thr = self.cfg["ssh_bruteforce_threshold"]
        window = timedelta(seconds=self.cfg["ssh_bruteforce_window_s"])
        by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
        for e in sorted(events, key=lambda x: (x.ts, x.evidence_id, x.line)):
            by_ip[e.ip].append(e)
        for ip, evs in by_ip.items():
            fails = [e for e in evs if e.kind == "failed"]
            idx = _first_window([e.ts for e in fails], thr, window)
            if idx is not None:
                users = sorted({e.user for e in fails})
                out.append(self._f(fails[idx], "ssh_bruteforce_attempts", "High", "High Confidence", "Observed",
                                   f"{len(fails)} failed SSH authentications from one IP; >= {thr} within "
                                   f"{self.cfg['ssh_bruteforce_window_s']}s. Accounts tried: {', '.join(users[:8])}.",
                                   failed_count=len(fails), users_tried=users[:20]))
            for e in evs:
                if e.kind == "accepted" and len([f for f in fails if f.ts <= e.ts]) >= thr:
                    n = len([f for f in fails if f.ts <= e.ts])
                    out.append(self._f(e, "ssh_login_success_after_failures", "High", "High Confidence", "Observed",
                                       f"sshd logged a SUCCESSFUL login for '{e.user}' ({e.method}) after {n} failed "
                                       "attempts from the same IP. The login is recorded fact; attribution of the "
                                       "actor and intent remain inferred.", failed_before=n))
                    break
            invalid = sorted({e.user for e in evs if e.invalid_user or e.kind == "invalid_user"})
            if len(invalid) >= self.cfg["ssh_enum_threshold"]:
                first = next(e for e in evs if e.invalid_user or e.kind == "invalid_user")
                out.append(self._f(first, "ssh_user_enumeration", "Medium", "Medium Confidence", "Observed",
                                   f"{len(invalid)} distinct non-existent usernames tried from one IP "
                                   f"({', '.join(invalid[:6])}).", invalid_users=invalid[:20]))
            for e in evs:
                if e.kind == "accepted" and e.user == "root":
                    out.append(self._f(e, "ssh_root_login", "Medium", "High Confidence", "Observed",
                                       f"Direct root login accepted via {e.method}. Verify this is expected for your policy."))
                    break
        return out


def compute_auth_stats(events: list[AuthEvent]) -> dict:
    if not events:
        return {"events": 0, "failed": 0, "accepted": 0, "unique_ips": 0, "first_event": None, "last_event": None}
    ts = [e.ts for e in events]
    return {"events": len(events), "failed": sum(e.kind == "failed" for e in events),
            "accepted": sum(e.kind == "accepted" for e in events), "unique_ips": len({e.ip for e in events}),
            "first_event": min(ts).isoformat(), "last_event": max(ts).isoformat()}
