import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def synthetic_lines():
    spec = importlib.util.spec_from_file_location("gen", ROOT / "samples" / "generate_synthetic_logs.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.generate()


def ev(ip="203.0.113.5", ts="03/Nov/2026:10:00:00 +0000", method="GET", path="/", status=200,
       ua="Mozilla/5.0", size=100):
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
