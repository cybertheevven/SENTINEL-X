import json, sys, unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_x.ai import ollama


ANALYSIS = {"findings": [{"id": "F-0001", "type": "t", "timestamp": "x", "evidence_id": "EV-0001", "line": 1,
                          "ip": "1.1.1.1", "severity": "High", "confidence": "Low Confidence",
                          "classification": "Observed", "description": "d", "details": {"raw": "SECRET"}}],
            "initial_access": {"summary": "s", "confidence": "Low Confidence", "missing_evidence": ["m"]}}


class AITests(unittest.TestCase):
    def test_unavailable_ollama_degrades_gracefully(self):
        r = ollama.generate("hi", host="http://127.0.0.1:1", timeout=1)
        self.assertEqual(r["status"], "unavailable")
        self.assertIn("error", r)

    def test_prompt_contains_rules_and_no_raw_details(self):
        p = ollama.build_prompt(ANALYSIS)
        self.assertIn("Never invent evidence", p)
        self.assertIn("F-0001", p)
        self.assertNotIn("SECRET", p)

    def test_citation_validator_flags_invented_ids(self):
        ok = ollama.validate_citations("See F-0001 and EV-0001.", {"EV-0001"}, {"F-0001"})
        self.assertTrue(ok["valid"])
        bad = ollama.validate_citations("See F-0099 and EV-0001.", {"EV-0001"}, {"F-0001"})
        self.assertFalse(bad["valid"])
        self.assertEqual(bad["unknown_references"], ["F-0099"])
        self.assertFalse(ollama.validate_citations("No ids at all.", {"EV-0001"}, {"F-0001"})["valid"])

    def test_hallucinated_output_gets_warning(self):
        fake = mock.MagicMock()
        fake.__enter__.return_value.read.return_value = json.dumps({"response": "Attack proven, see F-0777"}).encode()
        with mock.patch("urllib.request.urlopen", return_value=fake):
            r = ollama.investigate(ANALYSIS, {"EV-0001"})
        self.assertEqual(r["status"], "ok")
        self.assertIn("UNVERIFIED", r["warning"])


if __name__ == "__main__":
    unittest.main()
