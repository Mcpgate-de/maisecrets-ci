"""The Nosey Parker adapter (praetorian-inc/noseyparker, Apache-2.0): the release binary that BENCH_NOSEYPARKER names,
pinned by version.

`noseyparker scan` runs once over the folder of case files into a temp datastore with its default rules, then
`report --format jsonl` lists the matches, offline (bench/adapters/_filescan.py). A finding is each capture group of a
match (what the rule reports as the secret), placed inside the match's byte span; a match without a group that can be
placed is its whole span. Identical files are one blob with one provenance per file. Its rules find secrets, so its
scope is `secret.`."""
from __future__ import annotations

import base64
import json
import os

from bench.adapters import _filescan

NAME = "noseyparker"
SCOPE = ("secret.",)
VERSION = "0.24.0"
ENV = "BENCH_NOSEYPARKER"


def describe() -> dict:
    path = _filescan.binary(ENV, NAME)
    got = _filescan.version_of(path, ["--version"], NAME)
    _filescan.check_version(got, VERSION, NAME)
    return {"scanner": NAME, "version": VERSION, "commit": None, "binary": path,
            "binary_sha256": _filescan.sha256_file(path),
            "configuration": "scan over the folder of case files into a temp datastore, default rules; "
                             "report --format jsonl; a finding per capture group",
            "detectors": "the default rules of the release", "network": False,
            "network_guard": _filescan.network_guard(), "region": "none", "scope": list(SCOPE)}


def _chars(text: str, byte_offset: int) -> int:
    return len(text.encode("utf-8")[:byte_offset].decode("utf-8", errors="ignore"))


def scan(cases):
    path = _filescan.binary(ENV, NAME)
    r = _filescan.Run(NAME, cases)
    try:
        ds, report = os.path.join(r.tmp, "datastore"), os.path.join(r.tmp, "report.jsonl")
        r.run([path, "scan", "-d", ds, _filescan.CASE_DIR, "-q"])
        r.run([path, "report", "-d", ds, "--format", "jsonl", "-o", report])
        with open(report, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                x = json.loads(line)
                for m in x.get("matches") or []:
                    span = (m.get("location") or {}).get("offset_span") or {}
                    groups = [base64.b64decode(g).decode("utf-8", errors="replace") for g in m.get("groups") or []
                              if g]
                    for prov in m.get("provenance") or []:
                        if prov.get("kind") != "file":
                            continue
                        n = _filescan.case_of(r.files, r.tmp, prov.get("path", ""))
                        if n is None:
                            r.add(prov.get("path", ""), "", None, m.get("rule_text_id", ""))
                            continue
                        text = r.cases[n]["text"]
                        a, b = _chars(text, span.get("start", 0)), _chars(text, span.get("end", 0))
                        placed = False
                        for g in groups:
                            at = text.find(g, a, b) if g else -1
                            if at >= 0:
                                r.add(prov["path"], g, None, m.get("rule_text_id", ""), span=(at, at + len(g)))
                                placed = True
                        if not placed and b > a:
                            r.add(prov["path"], "", None, m.get("rule_text_id", ""), span=(a, b))
        return r.finish("noseyparker scan + report, one run over all cases")
    finally:
        r.close()
