"""Investigation case management (file based; SQLite planned for Phase 4)."""
from __future__ import annotations

import getpass
import json
import os
import re
from pathlib import Path

from sentinel_x import __version__
from sentinel_x.evidence.collector import utcnow

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class CaseError(Exception):
    pass


def default_home() -> Path:
    return Path(os.environ.get("SENTINEL_X_HOME", Path.home() / ".sentinel-x" / "cases"))


class Case:
    def __init__(self, home: str | Path, name: str):
        self.name = name
        self.dir = Path(home) / name
        self.case_file = self.dir / "case.json"
        self.custody_log = self.dir / "custody.log"
        self.analysis_file = self.dir / "analysis.json"
        self.ai_file = self.dir / "ai_investigation.json"
        self.reports_dir = self.dir / "reports"

    @classmethod
    def create(cls, home: str | Path, name: str, author: str = "THEEVVEN") -> "Case":
        if not NAME_RE.match(name):
            raise CaseError("Case name must match [A-Za-z0-9._-] (max 64 chars, no leading symbol)")
        case = cls(home, name)
        if case.dir.exists():
            raise CaseError(f"Case already exists: {case.dir}")
        case.dir.mkdir(parents=True)
        case.reports_dir.mkdir()
        meta = {"name": name, "created_at": utcnow(), "created_by": getpass.getuser(),
                "author": author, "tool_version": __version__}
        case.case_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        case.log("case_created", f"Case {name} created")
        return case

    @classmethod
    def open(cls, home: str | Path, name: str) -> "Case":
        case = cls(home, name)
        if not case.case_file.exists():
            raise CaseError(f"Case not found: {name} (looked in {case.dir})")
        return case

    @classmethod
    def list_cases(cls, home: str | Path) -> list[str]:
        home = Path(home)
        if not home.exists():
            return []
        return sorted(p.name for p in home.iterdir() if (p / "case.json").exists())

    def meta(self) -> dict:
        return json.loads(self.case_file.read_text(encoding="utf-8"))

    def log(self, action: str, note: str = "") -> None:
        """Append-only action log (chain of custody / investigation history)."""
        rec = {"ts": utcnow(), "user": getpass.getuser(), "action": action, "note": note}
        with open(self.custody_log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
