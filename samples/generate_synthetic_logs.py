#!/usr/bin/env python3
"""Write synthetic demo logs (access.log + auth.log). Usage: generate_synthetic_logs.py [DIR]"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sentinel_x.demo import synthetic  # noqa: E402


def generate():
    """Web log lines (kept for tests/back-compat)."""
    return synthetic.generate_web()


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parent / "synthetic_logs")
    for p in synthetic.write(out):
        print("written", p)
