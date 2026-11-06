#!/usr/bin/env python3
"""The guard of a baseline merge request (.gitlab-ci.yml, job baseline_only): every changed path is a measurement
result of a release gate. Such a merge request skips the long test jobs, so a branch named chore/baseline-X that
changed anything else would carry it past the tests; the guard fails it instead.

    python3 scripts/baseline_only.py BASE_SHA     # exit 0: only results changed; exit 1: names the other paths
"""
from __future__ import annotations

import re
import subprocess
import sys

# what scripts/release_gate.py --keep writes, and nothing else: the run's folder, the holdout log line, the coverage
ALLOWED = re.compile(r"bench/results/[^/]+-v3-[^/]+/.+|bench/HOLDOUT-LOG\.md|docs/coverage\.json")


def changed(base: str) -> list[str]:
    out = subprocess.run(["git", "diff", "--name-only", "--no-renames", f"{base}...HEAD"], capture_output=True,
                         text=True, check=True).stdout
    return [line for line in out.splitlines() if line]


def outside(paths: list[str]) -> list[str]:
    return [p for p in paths if not ALLOWED.fullmatch(p)]


def main(argv: list[str]) -> int:
    if len(argv) != 1 or not argv[0]:
        print("usage: baseline_only.py BASE_SHA (the merge request's diff base)")
        return 1
    paths = changed(argv[0])
    if not paths:
        print("baseline_only: the merge request changes nothing")
        return 1
    bad = outside(paths)
    if bad:
        print("baseline_only: a baseline merge request may change measurement results only. Other paths:")
        for p in bad:
            print(f"  {p}")
        print("Rename the branch (not chore/baseline-*) so every test job runs.")
        return 1
    print(f"baseline_only: {len(paths)} changed paths, all measurement results")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
