import hashlib, os, stat, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_x.core.case import Case, CaseError
from sentinel_x.evidence.collector import EvidenceStore, EvidenceError, sha256_file


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.case = Case.create(self.root / "cases", "T-1")
        self.src = self.root / "a.log"
        self.src.write_bytes(b"hello forensic world\n")

    def tearDown(self):
        for p in self.root.rglob("*"):
            if p.is_file():
                os.chmod(p, 0o644)
        self.tmp.cleanup()

    def test_sha256_known_value(self):
        self.assertEqual(sha256_file(self.src), hashlib.sha256(b"hello forensic world\n").hexdigest())

    def test_add_creates_readonly_copy_and_leaves_original_untouched(self):
        before = (self.src.read_bytes(), self.src.stat().st_mtime)
        e = EvidenceStore(self.case.dir).add_file(self.src)
        self.assertEqual(e["evidence_id"], "EV-0001")
        self.assertEqual(before, (self.src.read_bytes(), self.src.stat().st_mtime))
        wc = self.case.dir / e["working_copy"]
        self.assertFalse(wc.stat().st_mode & stat.S_IWUSR)
        self.assertEqual(e["custody"][0]["action"], "collected")

    def test_duplicate_is_skipped_by_hash(self):
        st = EvidenceStore(self.case.dir)
        st.add_file(self.src)
        dup = self.root / "copy.log"
        dup.write_bytes(self.src.read_bytes())
        self.assertIsNone(st.add_file(dup))
        self.assertEqual(len(st.entries()), 1)

    def test_tamper_detection(self):
        st = EvidenceStore(self.case.dir)
        e = st.add_file(self.src)
        wc = self.case.dir / e["working_copy"]
        os.chmod(wc, 0o644)
        wc.write_bytes(b"tampered")
        res = st.verify()
        self.assertFalse(res[0]["ok"])
        self.assertIn("MISMATCH", res[0]["detail"])

    def test_open_rejects_invalid_case_names(self):
        for name in ("../outside", "/tmp/outside", "nested/child", "bad\\nname"):
            with self.subTest(name=name):
                with self.assertRaises(CaseError):
                    Case.open(self.root / "cases", name)

    def test_manifest_working_copy_cannot_escape_case_directory(self):
        store = EvidenceStore(self.case.dir)
        entry = store.add_file(self.src)
        manifest = store.load()
        manifest["evidence"][0]["working_copy"] = "../outside.log"
        store._save(manifest)
        result = store.verify()[0]
        self.assertFalse(result["ok"])
        self.assertIn("relative path", result["detail"])
        with self.assertRaises(EvidenceError):
            store.path_of(manifest["evidence"][0])

    def test_manifest_symlink_cannot_escape_case_directory(self):
        store = EvidenceStore(self.case.dir)
        entry = store.add_file(self.src)
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "secret.log").write_text("not case evidence", encoding="utf-8")
        (self.case.dir / "escape").symlink_to(outside, target_is_directory=True)
        entry["working_copy"] = "escape/secret.log"
        with self.assertRaises(EvidenceError):
            store.path_of(entry)
        manifest = store.load()
        manifest["evidence"][0]["working_copy"] = "escape/secret.log"
        store._save(manifest)
        self.assertFalse(store.verify()[0]["ok"])

    def test_missing_file_and_bad_case_name(self):
        with self.assertRaises(EvidenceError):
            EvidenceStore(self.case.dir).add_file(self.root / "nope.log")
        with self.assertRaises(CaseError):
            Case.create(self.root / "cases", "../evil")
        with self.assertRaises(CaseError):
            Case.create(self.root / "cases", "T-1")


if __name__ == "__main__":
    unittest.main()
