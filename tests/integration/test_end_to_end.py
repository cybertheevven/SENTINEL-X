import contextlib, io, os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import json
from sentinel_x.cli.main import main
from tests.helpers import synthetic_lines, ev


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ev_dir = self.root / "ev"
        self.ev_dir.mkdir()
        self.home = str(self.root / "cases")

    def tearDown(self):
        for p in self.root.rglob("*"):
            if p.is_file():
                os.chmod(p, 0o644)
        self.tmp.cleanup()

    def cli(self, *a):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(["--home", self.home, *a])

    def test_full_workflow_json_and_pdf(self):
        (self.ev_dir / "access.log").write_text("\n".join(synthetic_lines()) + "\n")
        self.assertEqual(self.cli("case", "create", "--name", "I1"), 0)
        self.assertEqual(self.cli("evidence", "add", "--case", "I1", "--path", str(self.ev_dir)), 0)
        self.assertEqual(self.cli("evidence", "verify", "--case", "I1"), 0)
        self.assertEqual(self.cli("analyze", "--case", "I1"), 0)
        self.assertEqual(self.cli("ai", "investigate", "--case", "I1", "--host", "http://127.0.0.1:1", "--timeout", "1"), 3)
        self.assertEqual(self.cli("report", "generate", "--case", "I1", "--format", "both"), 0)
        rep = Path(self.home) / "I1" / "reports"
        pdf = (rep / "I1_report.pdf").read_bytes()
        self.assertTrue(pdf.startswith(b"%PDF"))
        data = json.loads((rep / "I1_report.json").read_text())
        self.assertEqual(data["analysis"]["initial_access"]["status"], "Hypothesis")
        self.assertEqual(data["ai_investigation"]["status"], "unavailable")
        actions = [json.loads(l)["action"] for l in (Path(self.home) / "I1" / "custody.log").read_text().splitlines()]
        self.assertEqual(actions[:3], ["case_created", "evidence_added", "analysis_run"])

    def test_clean_logs_report_undetermined(self):
        (self.ev_dir / "clean.log").write_text("\n".join(ev(path=f"/p{i}") for i in range(5)) + "\n")
        self.cli("case", "create", "--name", "I2")
        self.cli("evidence", "add", "--case", "I2", "--path", str(self.ev_dir))
        self.cli("analyze", "--case", "I2")
        self.assertEqual(self.cli("report", "generate", "--case", "I2", "--format", "pdf"), 0)
        a = json.loads((Path(self.home) / "I2" / "analysis.json").read_text())
        self.assertEqual(a["findings"], [])
        self.assertEqual(a["initial_access"]["summary"], "Initial Access: Undetermined")

    def test_analysis_refuses_tampered_evidence(self):
        (self.ev_dir / "a.log").write_text(ev() + "\n")
        self.cli("case", "create", "--name", "I3")
        self.cli("evidence", "add", "--case", "I3", "--path", str(self.ev_dir))
        wc = next((Path(self.home) / "I3" / "evidence").iterdir())
        os.chmod(wc, 0o644)
        wc.write_text("tampered\n")
        self.assertEqual(self.cli("analyze", "--case", "I3"), 2)

    def test_unknown_format_and_empty_file_do_not_crash(self):
        (self.ev_dir / "weird.txt").write_text("not a web log\nat all\n")
        (self.ev_dir / "empty.log").write_text("")
        self.cli("case", "create", "--name", "I4")
        self.cli("evidence", "add", "--case", "I4", "--path", str(self.ev_dir))
        self.assertEqual(self.cli("analyze", "--case", "I4"), 0)
        a = json.loads((Path(self.home) / "I4" / "analysis.json").read_text())
        self.assertEqual(len(a["unsupported_evidence"]), 1)

    def test_errors_return_exit_code_2(self):
        self.assertEqual(self.cli("analyze", "--case", "missing"), 2)


if __name__ == "__main__":
    unittest.main()
