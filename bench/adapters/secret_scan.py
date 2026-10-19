"""The secret-scan adapter (harshahemanth/secret-scan, MIT). It runs in a new process of the Python that
BENCH_SECRET_SCAN_PYTHON names (an environment with secret-scan installed from the pinned commit).

Each case is written to a file at its path (else input.txt); `secret_scanner.scan_directory` scans
the folder with its defaults (its named patterns, entropy off, as the CLI without --entropy), and with redact=False so
the match keeps its offsets. A finding is a match: line and column give the offset. Its patterns find secrets, so its
scope is `secret.`."""
from __future__ import annotations

import os
import sys

from bench.adapters import _proc

NAME = "secret-scan"
SCOPE = ("secret.",)
COMMIT = "7d8b5c1874501c1e2edc99c8b6ec2949decc4fc9"

_WORKER = r'''
import json, os, sys, time
from pathlib import Path
t0 = time.perf_counter()
from secret_scanner import scan_directory
from importlib.metadata import version
first, times = None, []
work = Path(os.getcwd()) / "cases"
with open(sys.argv[1], encoding="utf-8") as fin, open(sys.argv[2], "w", encoding="utf-8") as fout:
    for n, line in enumerate(fin):
        case = json.loads(line)
        text = case["text"]
        d = work / str(n)
        f = d / (case.get("path") or "input.txt")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
        t = time.perf_counter()
        matches = scan_directory(d, output_path=None, redact=False)
        times.append(time.perf_counter() - t)
        if first is None:
            first = time.perf_counter() - t0
        starts = [0]
        for ln in text.split("\n"):
            starts.append(starts[-1] + len(ln) + 1)
        out = []
        for m in matches:
            i = m["line"] - 1
            if "column" in m and 0 <= i < len(starts) - 1:
                out.append([starts[i] + m["column"], starts[i] + m["end_column"], "secret", m.get("rule_id")])
        fout.write(json.dumps(out) + "\n")
json.dump({"api": "scan_directory", "version": version("secret-scan"), "cold_start_s": first, "times_s": times},
          sys.stdout)
'''


def _python() -> str:
    return os.environ.get("BENCH_SECRET_SCAN_PYTHON") or sys.executable


def describe() -> dict:
    ident = _proc.identity(_python(), "secret-scan", version="", commit=COMMIT)
    return {"scanner": NAME, "version": ident["version"], "commit": ident["commit"],
            "configuration": "scan_directory defaults: named patterns, entropy off, redact off (for the offsets)",
            "detectors": "all named patterns of the release", "network": False, "dependencies": "none (stdlib)",
            "region": "none", "scope": list(SCOPE), "python": _python(),
            "python_version": ident["python_version"], "installed": _proc.installed(_python())}


def scan(cases):
    return _proc.run_worker("secret-scan", _python(), _WORKER, cases, fields=("text", "path"))
