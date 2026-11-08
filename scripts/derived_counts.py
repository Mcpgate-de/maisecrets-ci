#!/usr/bin/env python3
"""Re-derive the numbers the docs state, so a stale count fails CI instead of a reader.

The first public review found the test count wrong in two files and the scenario count wrong
in one; each had been true once. A number in prose inherits the reference point of whoever
typed it. This script measures each declared number again and refuses a mismatch.

The docs no longer state the number of tests (2026-11-08): nearly every merge request changed it, so two merge
requests in parallel collided on that line and each rebase ran the whole pipeline again. `unittest` prints the count;
a test module that no longer imports fails the run, a shadowed test is ruff's F811, and a skip is no_unexpected_skips.

    python3 scripts/derived_counts.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def count_scenarios(path: str, marker: str) -> int:
    """Top-level entries of the SCENARIOS dict: four spaces, a name, an opening brace."""
    text = (ROOT / path).read_text(encoding="utf-8")
    return len(re.findall(marker, text, re.M))


def declared(path: str, pattern: str) -> int | None:
    m = re.search(pattern, (ROOT / path).read_text(encoding="utf-8"), re.M)
    return int(m.group(1)) if m else None


def main() -> int:
    checks = [
        ("README Claude scenarios", declared("README.md", r"harness/run.py\s+# (\d+) scenarios"),
         count_scenarios("harness/run.py", r'^    "[a-z_]+": \{$')),
        ("README Codex scenarios", declared("README.md", r"harness/codex.py \[--real\]\s+# (\d+) scenarios"),
         count_scenarios("harness/codex.py", r'^    "[a-z_]+": \{$')),
        ("README beliefs", declared("README.md", r"replay_can_fail.py\s+# (\d+) proofs"),
         len(list((ROOT / "beliefs").glob("*.toml")))),
    ]
    rc = 0
    for name, stated, measured in checks:
        ok = stated == measured
        rc |= not ok
        print(f"[{'ok ' if ok else 'BAD'}] {name}: stated {stated}, measured {measured}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
