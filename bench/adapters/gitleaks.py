"""The gitleaks adapter (gitleaks/gitleaks, MIT): the release binary that BENCH_GITLEAKS names, pinned by version.

`gitleaks dir` scans the folder of case files once with the default configuration (all rules of the release, its
allowlists and entropy limits), no git history, offline (bench/adapters/_filescan.py). A finding is the `Secret` of a
report entry at its line. Its rules find secrets, so its scope is `secret.`."""
from __future__ import annotations

import json
import os

from bench.adapters import _filescan

NAME = "gitleaks"
SCOPE = ("secret.",)
VERSION = "8.30.1"
ENV = "BENCH_GITLEAKS"


def describe_leaks(name: str, env: str, version: str) -> dict:
    path = _filescan.binary(env, name)
    got = _filescan.version_of(path, ["version"], name)
    _filescan.check_version(got, version, name)
    return {"scanner": name, "version": version, "commit": None, "binary": path,
            "binary_sha256": _filescan.sha256_file(path),
            "configuration": "`dir` over the folder of case files, the default configuration, --exit-code 0",
            "detectors": "all rules of the release", "network": False, "network_guard": _filescan.network_guard(),
            "region": "none", "scope": list(SCOPE)}


def scan_leaks(name: str, env: str, cases):
    path = _filescan.binary(env, name)
    r = _filescan.Run(name, cases)
    try:
        report = os.path.join(r.tmp, "report.json")
        r.run([path, "dir", _filescan.CASE_DIR, "--report-format", "json", "--report-path", report,
               "--no-banner", "--exit-code", "0", "--log-level", "error"])
        with open(report, encoding="utf-8") as fh:
            entries = json.load(fh) or []
        for x in entries:
            r.add(x["File"], x.get("Secret") or "", x.get("StartLine"), x.get("RuleID", ""))
        return r.finish(f"{name} dir, one run over all cases")
    finally:
        r.close()


def describe() -> dict:
    return describe_leaks(NAME, ENV, VERSION)


def scan(cases):
    return scan_leaks(NAME, ENV, cases)
