"""Kingfisher 1.x (mongodb/kingfisher, Apache-2.0), the last release with its own rule catalog (the catalog of
bench/sources.py, CATALOGS, is that of 1.113.0): the release binary that BENCH_KINGFISHER1 names, pinned by version.
Kingfisher 2.x ships the rules of betterleaks and Veles instead (bench/adapters/kingfisher.py). The same run and report
format."""
from __future__ import annotations

from bench.adapters import kingfisher

NAME = "kingfisher1"
SCOPE = ("secret.",)
VERSION = "1.113.0"
ENV = "BENCH_KINGFISHER1"


def describe() -> dict:
    d = kingfisher.describe_kf(NAME, ENV, VERSION, "1.x: its own rule catalog")
    return {**d, "scanner": "kingfisher", "variant": NAME}


def scan(cases):
    return kingfisher.scan_kf(NAME, ENV, cases)
