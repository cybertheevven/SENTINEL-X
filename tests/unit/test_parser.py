import sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_x.parsers import web
from tests.helpers import ev


class ParserTests(unittest.TestCase):
    def test_parse_combined_line(self):
        e = web.parse_line(ev(path="/a?b=1", status=404, size=12), "EV-0001", "f", 1)
        self.assertEqual((e.ip, e.path, e.status, e.size), ("203.0.113.5", "/a?b=1", 404, 12))
        self.assertEqual(e.ts.utcoffset().total_seconds(), 0)

    def test_dash_size_and_common_format(self):
        line = '1.2.3.4 - - [03/Nov/2026:10:00:00 +0100] "GET / HTTP/1.1" 304 -'
        e = web.parse_line(line, "EV-0001", "f", 1)
        self.assertEqual(e.size, 0)
        self.assertEqual(e.user_agent, "")

    def test_garbage_and_empty_files(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.log"
            p.write_text("garbage\n\n" + ev() + "\n\x00\xff broken\n", encoding="utf-8", errors="replace")
            events, st = web.parse_file(p, "EV-0001")
            self.assertEqual(len(events), 1)
            self.assertEqual(st["unparsed"], 2)
            empty = Path(d) / "e.log"
            empty.write_text("")
            events, st = web.parse_file(empty, "EV-0002")
            self.assertEqual((len(events), st["lines"]), (0, 0))

    def test_bad_timestamp_is_skipped(self):
        self.assertIsNone(web.parse_line(ev(ts="99/Foo/2026:10:00:00 +0000"), "E", "f", 1))


if __name__ == "__main__":
    unittest.main()
