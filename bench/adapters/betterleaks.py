"""The betterleaks adapter (betterleaks/betterleaks, MIT, a successor of gitleaks): the release binary that
BENCH_BETTERLEAKS names, pinned by version. The same run and report format as bench/adapters/gitleaks.py: `dir` over
the folder of case files with the default configuration, offline."""
from __future__ import annotations

from bench.adapters import gitleaks

NAME = "betterleaks"
SCOPE = ("secret.",)
VERSION = "1.9.0"
ENV = "BENCH_BETTERLEAKS"


def describe() -> dict:
    return gitleaks.describe_leaks(NAME, ENV, VERSION)


def scan(cases):
    return gitleaks.scan_leaks(NAME, ENV, cases)
