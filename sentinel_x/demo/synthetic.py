"""Deterministic SYNTHETIC logs for demos/tests. Uses documentation IP ranges only
(198.51.100.0/24, 203.0.113.0/24) - no real data."""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ATTACKER = "198.51.100.23"
USERS = ["203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.50"]
UA_OK = ["Mozilla/5.0 (X11; Linux x86_64) Firefox/126.0", "Mozilla/5.0 (Windows NT 10.0) Chrome/125.0"]
T0 = datetime(2026, 11, 3, 8, 0, 0, tzinfo=timezone.utc)


def _web(ip, ts, method, path, status, size, ua, ref="-"):
    return f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S %z")}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


def generate_web(seed: int = 7) -> list[str]:
    rnd = random.Random(seed)
    rows = []
    for i in range(120):
        t = T0 + timedelta(seconds=i * 90 + rnd.randint(0, 30))
        rows.append((t, _web(rnd.choice(USERS), t, "GET",
                             rnd.choice(["/", "/index.php", "/products.php?id=3", "/about", "/contact"]),
                             200, rnd.randint(500, 9000), rnd.choice(UA_OK))))
    a = T0 + timedelta(hours=2)
    nikto = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Scanner)"
    for i, p in enumerate(["/admin", "/backup", "/.env", "/.git/config", "/phpmyadmin/"] + [f"/x{n}.php" for n in range(20)]):
        t = a + timedelta(seconds=i)
        rows.append((t, _web(ATTACKER, t, "GET", p, 404 if p.startswith("/x") or p in ("/admin", "/backup") else 403, 280, nikto)))
    b = a + timedelta(minutes=10)
    for i, p in enumerate(["/products.php?id=3'+OR+1=1--", "/products.php?id=3+UNION+SELECT+1,user(),3--",
                           "/download.php?file=../../../../etc/passwd"]):
        t = b + timedelta(seconds=20 * i)
        rows.append((t, _web(ATTACKER, t, "GET", p, 200 if i else 500, 1500, "sqlmap/1.8")))
    c = b + timedelta(minutes=5)
    for i in range(8):
        t = c + timedelta(seconds=6 * i)
        rows.append((t, _web(ATTACKER, t, "POST", "/wp-login.php", 401, 1200, UA_OK[0])))
    t = c + timedelta(seconds=70)
    rows.append((t, _web(ATTACKER, t, "POST", "/wp-login.php", 302, 0, UA_OK[0])))
    t += timedelta(minutes=3)
    rows.append((t, _web(ATTACKER, t, "POST", "/wp-content/uploads/2026/11/shell.php", 200, 40, UA_OK[0])))
    t += timedelta(seconds=30)
    rows.append((t, _web(ATTACKER, t, "GET", "/wp-content/uploads/2026/11/shell.php?cmd=id", 200, 54, UA_OK[0])))
    rows.append((t, "this line is garbage and must not crash the parser"))
    rows.sort(key=lambda r: r[0])
    return [r[1] for r in rows]


def _ssh(ts, pid, msg):
    return f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')} web01 sshd[{pid}]: {msg}"


def generate_auth(seed: int = 11) -> list[str]:
    rnd = random.Random(seed)
    rows = []
    # legitimate admin activity
    for i, h in enumerate((8, 9, 13)):
        t = T0 + timedelta(hours=h - 8, minutes=rnd.randint(0, 20))
        rows.append((t, _ssh(t, 900 + i, f"Accepted publickey for deploy from 203.0.113.10 port {40000 + i} ssh2")))
    t = T0 + timedelta(hours=1)
    rows.append((t, _ssh(t, 950, "Failed password for deploy from 203.0.113.10 port 41000 ssh2")))
    t += timedelta(seconds=9)
    rows.append((t, _ssh(t, 950, "Accepted password for deploy from 203.0.113.10 port 41000 ssh2")))
    # attack: user enumeration + brute force, then success
    s = T0 + timedelta(hours=2, minutes=30)
    for i, user in enumerate(["admin", "oracle", "test", "ubuntu", "root", "root", "root", "deploy", "deploy", "deploy"]):
        t = s + timedelta(seconds=3 * i)
        invalid = user in ("admin", "oracle", "test", "ubuntu")
        if invalid:
            rows.append((t, _ssh(t, 1201 + i, f"Invalid user {user} from {ATTACKER} port {40100 + i}")))
        rows.append((t, _ssh(t, 1201 + i, f"Failed password for {'invalid user ' if invalid else ''}{user} from {ATTACKER} port {40100 + i} ssh2")))
    t = s + timedelta(seconds=40)
    rows.append((t, _ssh(t, 1290, f"Accepted password for deploy from {ATTACKER} port 40990 ssh2")))
    rows.append((t, f"{t.strftime('%b')} {t.day:2d} {t.strftime('%H:%M:%S')} web01 sshd[1290]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)"))
    t2 = T0 + timedelta(hours=3)
    rows.append((t2, f"{t2.strftime('%b')} {t2.day:2d} {t2.strftime('%H:%M:%S')} web01 CRON[2100]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"))
    rows.sort(key=lambda r: r[0])
    return [r[1] for r in rows]


def write(directory: str | Path) -> list[Path]:
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    out = []
    for name, lines in (("access.log", generate_web()), ("auth.log", generate_auth())):
        p = d / name
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        out.append(p)
    return out
