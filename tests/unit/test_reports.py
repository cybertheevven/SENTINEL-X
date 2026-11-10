import contextlib, io, json, os, sys, tempfile, unittest
from pathlib import Path
from xml.dom import minidom
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_x.cli.main import main
from sentinel_x.investigation import remediation
from sentinel_x.reporting import graph
from sentinel_x.demo import synthetic
from tests.helpers import ev


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.home = str(self.root / "cases")

    def tearDown(self):
        for p in self.root.rglob("*"):
            if p.is_file():
                os.chmod(p, 0o644)
        self.tmp.cleanup()

    def cli(self, *a):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(["--home", self.home, *a])

    def analyze(self, name, files):
        d = self.root / ("ev_" + name)
        d.mkdir()
        for fname, text in files.items():
            (d / fname).write_text(text, encoding="utf-8")
        self.cli("case", "create", "--name", name)
        self.cli("evidence", "add", "--case", name, "--path", str(d))
        rc = self.cli("analyze", "--case", name, "--year", "2026")
        return rc, json.loads((Path(self.home) / name / "analysis.json").read_text())


class ReportTests(Base):
    def test_demo_command_creates_all_reports(self):
        out = self.root / "demo"
        self.assertEqual(self.cli("demo", "--output-dir", str(out)), 0)
        names = {p.suffix for p in (out / "reports").iterdir()}
        self.assertEqual(names, {".pdf", ".json", ".html"})
        html = (out / "reports" / "DEMO_report.html").read_text()
        for needle in ("SENTINEL-X", "Attack path reconstruction", "Remediation recommendations", "Confirmed (Observed)"):
            self.assertIn(needle, html)

    def test_demo_graph_and_remediation(self):
        d = self.root / "logs"
        synthetic.write(d)
        _, an = self.analyze("G1", {p.name: p.read_text() for p in d.iterdir()})
        rows = an["graph"]["rows"]
        self.assertEqual(len(rows), 1)
        phases = [s["phase"] for s in rows[0]["stages"]]
        self.assertEqual(phases[0], "Reconnaissance")
        self.assertIn("Confirmed Access", phases)
        times = [s["first_ts"] for s in rows[0]["stages"]]
        self.assertEqual(times, sorted(times))
        svg = graph.render_svg(an["graph"])
        minidom.parseString(svg)          # well-formed
        self.assertIsNotNone(graph.render_drawing(an["graph"], 500))
        prios = [r["priority"] for r in an["remediation"]]
        self.assertEqual(prios, sorted(prios, key=["Immediate", "High", "Medium"].index))
        self.assertTrue(an["remediation"][0]["action"].startswith("Preserve evidence"))

    def test_no_findings_means_no_graph_and_no_remediation(self):
        _, an = self.analyze("C1", {"a.log": ev() + "\n"})
        self.assertEqual(an["graph"]["rows"], [])
        self.assertIsNone(graph.render_svg(an["graph"]))
        self.assertEqual(an["remediation"], [])

    def test_html_escapes_attacker_controlled_content(self):
        evil = '/x.php?id=1%27+OR+1=1--<script>alert(1)</script>'
        ua = "<img src=x onerror=alert(2)>"
        _, an = self.analyze("X1", {"a.log": ev(path=evil, ua=ua) + "\n"})
        self.assertTrue(an["findings"])
        self.assertEqual(self.cli("report", "generate", "--case", "X1", "--format", "all"), 0)
        rep = Path(self.home) / "X1" / "reports"
        html = (rep / "X1_report.html").read_text()
        self.assertNotIn("<script>alert", html)
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;", html)
        self.assertTrue((rep / "X1_report.pdf").read_bytes().startswith(b"%PDF"))

    def test_every_finding_type_has_remediation_or_is_known(self):
        covered = set(remediation.RECS)
        for t in ("sql_injection_attempt", "path_traversal_attempt", "possible_web_shell", "bruteforce_login_attempts",
                  "ssh_bruteforce_attempts", "ssh_login_success_after_failures", "cross_source_correlation"):
            self.assertIn(t, covered)


if __name__ == "__main__":
    unittest.main()
