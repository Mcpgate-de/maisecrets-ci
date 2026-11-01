#!/usr/bin/env python3
"""Run the unit suite one test file per process, side by side, and print one log of all their -v output.

    python scripts/run_tests_parallel.py [-j N] [--log unit.log]

Each tests/test_*.py runs as `python -m unittest discover -s tests -p <file> -v` in its own process (the command of a
serial run, cut to one file: the same import path and the same test names), N at once (default: one per CPU), the
slowest files first. It runs in the current folder, as `unittest discover` does. The log holds every file's -v
output (its test lines, failures and its own Ran/OK lines) in file order, then one summary for all, so
scripts/no_unexpected_skips.py and the annotations of scripts/github_matrix.py read it as before. The exit is 1 when
a file failed or a file found no test.

A file's tests still share one process, as in a serial run; two files never do. A test that needs another file's
state in the same process was never safe: unittest runs the files in name order, and -k or a single file breaks
that order too."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# the files that took longest on the reference host (2026-11-01, 25 s and more), slowest first: started first, so the
# run ends with short ones
SLOW_FIRST = ("test_cli_matrix", "test_vault_refs", "test_label_languages", "test_rules_from_the_catalogs",
              "test_word_values_not_hunted", "test_invariant_model_output", "test_rules_from_other_detectors",
              "test_skill")


UNIT_FILE = Path(__file__).resolve().parent / "_unit_file.py"


def run(name: str) -> tuple:
    """(name, exit, console text, seconds, tests run). The count comes from the file's own result, not from its text:
    a test that runs unittest in a child prints a second "Ran ..." line, before or after the file's own."""
    t0 = time.monotonic()
    with tempfile.TemporaryDirectory() as d:
        result = Path(d, "result.json")
        # UTF-8 both ways: a Windows console code page cannot hold every test name and value
        p = subprocess.run([sys.executable, str(UNIT_FILE), f"{name}.py", str(result)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8", errors="replace",
                           env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        try:
            ran = int(json.loads(result.read_text(encoding="utf-8"))["ran"])
        except (OSError, ValueError, KeyError, TypeError):
            ran = 0                     # the file did not get as far as its result: a crash or a kill
    return name, p.returncode, p.stdout, time.monotonic() - t0, ran


def main(argv: list) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-j", type=int, default=0)
    ap.add_argument("--log", default="")
    a = ap.parse_args(argv)
    names = sorted(p.stem for p in Path("tests").glob("test_*.py"))
    order = sorted(names, key=lambda n: (SLOW_FIRST.index(n) if n in SLOW_FIRST else len(SLOW_FIRST), n))
    n = a.j if a.j > 0 else (os.cpu_count() or 1)
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=n) as pool:
        done = {name: (rc, out, sec, ran) for name, rc, out, sec, ran in pool.map(run, order)}
    total, bad, lines = 0, [], []
    for name in names:
        rc, out, sec, ran = done[name]
        lines.append(out)
        total += ran
        if rc != 0 or ran == 0:
            bad.append(f"{name} (exit {rc}, {ran} tests)")
    slowest = sorted(names, key=lambda x: -done[x][2])[:8]
    print("slowest files: " + ", ".join(f"{x} {done[x][2]:.0f} s" for x in slowest), file=sys.stderr)
    summary = (f"\n{len(names)} files, {n} at once, {time.monotonic() - t0:.0f} s\nRan {total} tests\n"
               + ("OK\n" if not bad else "FAILED: " + ", ".join(bad) + "\n"))
    text = "".join(lines) + summary
    if a.log:
        Path(a.log).write_text(text, encoding="utf-8")
    sys.stdout.buffer.write(text.replace("\r\n", "\n").encode("utf-8", "replace"))
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
