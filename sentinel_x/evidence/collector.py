"""Evidence collection: working copies, SHA-256, manifest, chain of custody.

Originals are only ever READ. Analysis runs on a read-only working copy.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: str | Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


class EvidenceError(Exception):
    pass


class EvidenceStore:
    def __init__(self, case_dir: str | Path):
        self.case_dir = Path(case_dir)
        self.evidence_dir = self.case_dir / "evidence"
        self.manifest_path = self.case_dir / "manifest.json"

    def load(self) -> dict:
        if not self.manifest_path.exists():
            return {"evidence": []}
        with open(self.manifest_path, encoding="utf-8") as fh:
            return json.load(fh)

    def _save(self, manifest: dict) -> None:
        tmp = self.manifest_path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
        os.replace(tmp, self.manifest_path)

    def entries(self) -> list[dict]:
        return self.load()["evidence"]

    def add_file(self, src: str | Path, collector: str | None = None) -> dict | None:
        """Add one file. Returns the manifest entry, or None if it is an exact duplicate."""
        src = Path(src)
        if not src.is_file():
            raise EvidenceError(f"Not a regular file: {src}")
        manifest = self.load()
        src_hash = sha256_file(src)
        for e in manifest["evidence"]:
            if e["sha256"] == src_hash:
                return None

        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        ev_id = f"EV-{len(manifest['evidence']) + 1:04d}"
        dest = self.evidence_dir / f"{ev_id}_{src.name}"
        shutil.copy2(src, dest)
        if sha256_file(dest) != src_hash:
            dest.unlink(missing_ok=True)
            raise EvidenceError(f"Hash mismatch after copying {src}")
        os.chmod(dest, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

        who = collector or getpass.getuser()
        entry = {
            "evidence_id": ev_id,
            "filename": src.name,
            "original_path": str(src.resolve()),
            "working_copy": f"evidence/{dest.name}",
            "size_bytes": src.stat().st_size,
            "sha256": src_hash,
            "collected_at": utcnow(),
            "collected_by": who,
            "custody": [{"ts": utcnow(), "action": "collected", "by": who,
                         "note": "Read-only working copy created; SHA-256 verified"}],
        }
        manifest["evidence"].append(entry)
        self._save(manifest)
        return entry

    def add_path(self, path: str | Path, collector: str | None = None) -> tuple[list[dict], list[str]]:
        path = Path(path)
        if path.is_dir():
            files = sorted(p for p in path.rglob("*") if p.is_file())
        elif path.is_file():
            files = [path]
        else:
            raise EvidenceError(f"Path not found: {path}")
        added: list[dict] = []
        skipped: list[str] = []
        for f in files:
            entry = self.add_file(f, collector)
            if entry:
                added.append(entry)
            else:
                skipped.append(str(f))
        return added, skipped

    def _working_copy_path(self, entry: dict) -> Path:
        """Resolve a manifest path and ensure it remains inside this case directory."""
        value = entry.get("working_copy") if isinstance(entry, dict) else None
        if not isinstance(value, str) or not value:
            raise EvidenceError("Invalid manifest working_copy path")

        relative = Path(value)
        windows_path = PureWindowsPath(value)
        if (relative.is_absolute() or windows_path.is_absolute()
                or ".." in relative.parts or ".." in windows_path.parts):
            raise EvidenceError("Manifest working_copy must be a relative path inside the case directory")

        root = self.case_dir.resolve()
        try:
            resolved = (root / relative).resolve()
            resolved.relative_to(root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise EvidenceError("Manifest working_copy escapes the case directory") from exc
        return resolved

    def verify(self) -> list[dict]:
        results = []
        for e in self.entries():
            try:
                wc = self._working_copy_path(e)
            except EvidenceError as exc:
                results.append({"evidence_id": e.get("evidence_id", "unknown"),
                                "ok": False, "detail": str(exc)})
                continue
            if not wc.exists():
                results.append({"evidence_id": e["evidence_id"], "ok": False, "detail": "working copy missing"})
                continue
            actual = sha256_file(wc)
            ok = actual == e["sha256"]
            results.append({"evidence_id": e["evidence_id"], "ok": ok,
                            "detail": "SHA-256 matches manifest" if ok else f"SHA-256 MISMATCH (now {actual})"})
        return results

    def path_of(self, entry: dict) -> Path:
        """Return a validated working-copy path confined to the case directory."""
        return self._working_copy_path(entry)
