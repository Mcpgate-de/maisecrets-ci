"""The kingfisher adapter (mongodb/kingfisher, Apache-2.0): the release binary that BENCH_KINGFISHER names, pinned by
version.

`kingfisher scan` runs once over the folder of case files with its built-in rules and its default confidence
(medium), `--no-validate` (no rule calls its service), `--no-update-check` and `--no-dedup` (every place, not one per
value), offline (bench/adapters/_filescan.py). A finding is the `snippet` of a finding at its line. Its rules find
secrets, so its scope is `secret.`."""
from __future__ import annotations

import json
import os

from bench.adapters import _filescan

NAME = "kingfisher"
SCOPE = ("secret.",)
VERSION = "2.11.1"
ENV = "BENCH_KINGFISHER"


def describe_kf(name: str, env: str, version: str, rules: str) -> dict:
    path = _filescan.binary(env, name)
    got = _filescan.version_of(path, ["--version"], name)
    _filescan.check_version(got, version, name)
    return {"scanner": name, "version": version, "rules": rules, "commit": None, "binary": path,
            "binary_sha256": _filescan.sha256_file(path),
            "configuration": "scan over the folder of case files, built-in rules, default confidence, "
                             "--no-validate --no-update-check --no-dedup",
            "detectors": "all built-in rules of the release", "network": False,
            "network_guard": _filescan.network_guard(), "region": "none", "scope": list(SCOPE)}


def describe() -> dict:
    return describe_kf(NAME, ENV, VERSION, "2.x: the rules of betterleaks and Veles that it ships")


def scan(cases):
    return scan_kf(NAME, ENV, cases)


def scan_kf(name: str, env: str, cases):
    path = _filescan.binary(env, name)
    r = _filescan.Run(name, cases)
    try:
        report = os.path.join(r.tmp, "report.json")
        r.run([path, "scan", _filescan.CASE_DIR, "--format", "json", "--no-validate", "--no-update-check",
               "--no-dedup", "-o", report], ok_codes=(0, 200, 205))
        with open(report, encoding="utf-8") as fh:
            d = json.load(fh)
        for x in d.get("findings") or []:
            f = x.get("finding") or {}
            r.add(f.get("path", ""), f.get("snippet") or "", f.get("line"), (x.get("rule") or {}).get("id", ""))
        return r.finish("kingfisher scan, one run over all cases")
    finally:
        r.close()
