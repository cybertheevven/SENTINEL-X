import sys, tempfile, unittest
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_x.analyzers.auth_detection import AuthDetector
from sentinel_x.analyzers.correlation import correlate
from sentinel_x.analyzers.detection import Detector, finalize
from sentinel_x.parsers import auth, detect, web
from sentinel_x.investigation import initial_access
from tests.helpers import ev


def sshd(sec, msg, day=3, pid=100):
    return f"Nov {day:2d} 10:00:{sec:02d} host sshd[{pid}]: {msg}"


def parse(lines, year=2026):
    out = [auth.parse_line(l, "EV-0002", "auth.log", i, year) for i, l in enumerate(lines, 1)]
    return [e for e in out if e]


class AuthParserTests(unittest.TestCase):
    def test_failed_accepted_invalid(self):
        evs = parse([sshd(1, "Failed password for invalid user bob from 1.2.3.4 port 22 ssh2"),
                     sshd(2, "Accepted publickey for alice from 5.6.7.8 port 22 ssh2: RSA SHA256:abc"),
                     sshd(3, "Invalid user zed from 9.9.9.9 port 5"),
                     sshd(4, "Connection closed by 1.1.1.1")])
        self.assertEqual([e.kind for e in evs], ["failed", "accepted", "invalid_user"])
        self.assertTrue(evs[0].invalid_user)
        self.assertEqual(evs[1].method, "publickey")
        self.assertEqual(evs[0].ts, datetime(2026, 11, 3, 10, 0, 1, tzinfo=timezone.utc))

    def test_iso_format_and_non_sshd_ignored(self):
        l = "2026-11-03T10:00:01.123456+00:00 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
        self.assertEqual(len(parse([l])), 1)
        self.assertEqual(parse(["Nov  3 10:00:01 host CRON[1]: pam_unix(cron:session): session opened"]), [])

    def test_ipv6(self):
        e = parse([sshd(1, "Failed password for root from 2001:db8::1 port 22 ssh2")])[0]
        self.assertEqual(e.ip, "2001:db8::1")

    def test_year_rollover_uses_previous_year(self):
        ref = datetime(2027, 1, 2, tzinfo=timezone.utc)
        h = auth.parse_header("Dec 31 23:59:59 h sshd[1]: x", 2027, ref)
        self.assertEqual(h[0].year, 2026)

    def test_sniff_formats(self):
        with tempfile.TemporaryDirectory() as d:
            a, w, u, e = (Path(d) / n for n in ("a", "w", "u", "e"))
            a.write_text(sshd(1, "Failed password for x from 1.1.1.1 port 1 ssh2") + "\n")
            w.write_text(ev() + "\n")
            u.write_text("hello\nworld\n")
            e.write_text("")
            self.assertEqual([detect.sniff(p) for p in (a, w, u, e)], ["auth", "web", "unknown", "empty"])


def fails(n, ip="9.9.9.9", user="root", start=0):
    return [sshd(start + i, f"Failed password for {user} from {ip} port {1000 + i} ssh2") for i in range(n)]


class AuthDetectionTests(unittest.TestCase):
    def types(self, lines, **cfg):
        return [f.type for f in AuthDetector(cfg).detect(parse(lines))]

    def test_below_threshold_no_finding(self):
        self.assertEqual(self.types(fails(4)), [])

    def test_bruteforce(self):
        self.assertIn("ssh_bruteforce_attempts", self.types(fails(5)))

    def test_success_after_failures_is_observed_high_confidence(self):
        lines = fails(6) + [sshd(20, "Accepted password for deploy from 9.9.9.9 port 1 ssh2")]
        f = [x for x in AuthDetector().detect(parse(lines)) if x.type == "ssh_login_success_after_failures"][0]
        self.assertEqual((f.classification, f.confidence), ("Observed", "High Confidence"))

    def test_legit_login_without_failures_is_clean(self):
        self.assertEqual(self.types([sshd(1, "Accepted publickey for deploy from 203.0.113.10 port 1 ssh2")]), [])

    def test_success_before_failures_not_flagged(self):
        lines = [sshd(0, "Accepted password for deploy from 9.9.9.9 port 1 ssh2")] + fails(6, start=5)
        self.assertNotIn("ssh_login_success_after_failures", self.types(lines))

    def test_user_enumeration_and_root_login(self):
        lines = [sshd(i, f"Invalid user u{i} from 7.7.7.7 port 1") for i in range(3)]
        lines.append(sshd(9, "Accepted password for root from 7.7.7.7 port 1 ssh2"))
        t = self.types(lines)
        self.assertIn("ssh_user_enumeration", t)
        self.assertIn("ssh_root_login", t)

    def test_correlation_with_web_activity(self):
        web_ev = [web.parse_line(ev(ip="9.9.9.9", path="/p.php?id=1'+OR+1=1--"), "EV-0001", "a", 1)]
        raw = Detector().detect(web_ev) + AuthDetector().detect(
            parse(fails(6) + [sshd(20, "Accepted password for deploy from 9.9.9.9 port 1 ssh2")]))
        c = correlate(raw)
        self.assertEqual([x.type for x in c], ["cross_source_correlation"])
        self.assertEqual(c[0].classification, "Inferred")
        self.assertEqual(correlate(AuthDetector().detect(parse(fails(6)))), [])

    def test_initial_access_uses_ssh_and_hides_satisfied_missing_evidence(self):
        fs = finalize(AuthDetector().detect(parse(fails(6) + [sshd(20, "Accepted password for deploy from 9.9.9.9 port 1 ssh2")])))
        res = initial_access.assess(fs, {"auth"})
        self.assertEqual(res["status"], "Hypothesis")
        self.assertEqual(len(res["confirmed_access"]), 1)
        self.assertFalse(any(m.startswith("SSH") for m in res["missing_evidence"]))


if __name__ == "__main__":
    unittest.main()
