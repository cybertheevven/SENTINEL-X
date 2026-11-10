import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_x.analyzers.detection import Detector
from sentinel_x.investigation import initial_access
from sentinel_x.parsers import web
from sentinel_x.timeline import builder
from tests.helpers import ev, synthetic_lines


def run(lines, **cfg):
    events = [web.parse_line(l, "EV-0001", "f", i) for i, l in enumerate(lines, 1)]
    events = [e for e in events if e]
    return Detector(cfg).run(events)


def types(fs):
    return [f.type for f in fs]


class DetectionTests(unittest.TestCase):
    def test_benign_traffic_has_no_findings(self):
        fs = run([ev(path="/"), ev(path="/about"), ev(path="/products.php?id=3")])
        self.assertEqual(fs, [])

    def test_sqli_and_encoded_variant(self):
        fs = run([ev(path="/p.php?id=1'+OR+1=1--"), ev(path="/p.php?id=1%20UNION%20SELECT%201,2")])
        self.assertEqual(types(fs).count("sql_injection_attempt"), 2)
        self.assertTrue(all(f.classification == "Observed" for f in fs))

    def test_traversal_double_encoded(self):
        fs = run([ev(path="/d.php?f=%252e%252e%252f%252e%252e%252fetc/passwd")])
        self.assertIn("path_traversal_attempt", types(fs))

    def test_success_status_does_not_claim_compromise(self):
        f = run([ev(path="/d.php?f=../../etc/passwd", status=200)])[0]
        self.assertIn("does not prove", f.description)

    def test_webshell_detected_and_critical_when_2xx(self):
        fs = run([ev(path="/uploads/s.php?cmd=id", status=200)])
        ws = [f for f in fs if f.type == "possible_web_shell"][0]
        self.assertEqual(ws.severity, "Critical")
        self.assertEqual(ws.confidence, "Medium Confidence")  # severity != confidence

    def test_bruteforce_threshold(self):
        base = [ev(ip="9.9.9.9", ts=f"03/Nov/2026:10:00:{s:02d} +0000", method="POST", path="/wp-login.php", status=401)
                for s in range(4)]
        self.assertNotIn("bruteforce_login_attempts", types(run(base)))
        base.append(ev(ip="9.9.9.9", ts="03/Nov/2026:10:00:10 +0000", method="POST", path="/wp-login.php", status=401))
        self.assertIn("bruteforce_login_attempts", types(run(base)))

    def test_login_success_after_failures_is_inferred_not_observed(self):
        lines = [ev(ip="9.9.9.9", ts=f"03/Nov/2026:10:00:{s:02d} +0000", method="POST", path="/login", status=401)
                 for s in range(6)]
        lines.append(ev(ip="9.9.9.9", ts="03/Nov/2026:10:01:00 +0000", method="POST", path="/login", status=302))
        f = [x for x in run(lines) if x.type == "possible_login_success_after_failures"][0]
        self.assertEqual(f.classification, "Inferred")

    def test_failures_spread_over_time_do_not_trigger(self):
        lines = [ev(ip="9.9.9.9", ts=f"03/Nov/2026:{h:02d}:00:00 +0000", method="POST", path="/login", status=401)
                 for h in range(6)]
        self.assertNotIn("bruteforce_login_attempts", types(run(lines)))

    def test_enumeration(self):
        lines = [ev(ip="8.8.8.8", ts=f"03/Nov/2026:10:00:{s:02d} +0000", path=f"/n{s}", status=404) for s in range(15)]
        self.assertIn("content_enumeration", types(run(lines)))

    def test_ids_are_sequential_and_time_ordered(self):
        fs = run(synthetic_lines())
        self.assertEqual([f.id for f in fs], [f"F-{i:04d}" for i in range(1, len(fs) + 1)])
        self.assertEqual([f.timestamp for f in fs], sorted(f.timestamp for f in fs))

    def test_every_finding_has_evidence_reference(self):
        for f in run(synthetic_lines()):
            self.assertTrue(f.evidence_id.startswith("EV-"))
            self.assertIsNotNone(f.line)


class InitialAccessTests(unittest.TestCase):
    def test_undetermined_without_evidence(self):
        res = initial_access.assess(run([ev(), ev(path="/x")]))
        self.assertEqual(res["status"], "Undetermined")
        self.assertEqual(res["confidence"], "Insufficient Evidence")
        self.assertIn("Undetermined", res["summary"])

    def test_scan_only_is_not_initial_access(self):
        res = initial_access.assess(run([ev(ua="Nikto/2.5")]))
        self.assertEqual(res["status"], "Undetermined")

    def test_synthetic_case_is_hypothesis_with_missing_evidence(self):
        fs = run(synthetic_lines())
        res = initial_access.assess(fs)
        self.assertEqual(res["status"], "Hypothesis")
        self.assertEqual(res["classification"], "Inferred")
        self.assertTrue(res["missing_evidence"])
        self.assertEqual(res["first_suspicious_event"]["ip"], "198.51.100.23")

    def test_timeline_only_contains_supported_phases(self):
        rows = builder.build(run([ev(path="/x.php?id=1%20union%20select%201")]))
        self.assertEqual(builder.phases_present(rows), ["Initial Access / Exploitation"])


if __name__ == "__main__":
    unittest.main()
