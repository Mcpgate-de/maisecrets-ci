#!/usr/bin/env python3
"""Compare two benchmark result directories and list what a reviewer must explain (docs/REGRESSION-POLICY.md).

    python3 scripts/compare_bench.py BASE_DIR NEW_DIR [--strict]

Each directory holds `bench/run.py` results named `<source>-<split>-maisecrets.json` and may hold the false-alarm
bank's `fpbank-7trees.json` (`scripts/measure_fp_bank.py measure --json`). The script compares the same file names
only. It prints one line per finding and exits 0, or 1 with --strict when there is a finding. It changes nothing.

The counts are deterministic: the same code on the same cases gives the same numbers, so any difference is real. The
time per case is not: on one machine it moved 26 to 233 % between runs of the same code (2026-10-20), so time is
reported, never judged; a performance claim needs alternating runs of both commits."""
from __future__ import annotations

import json
import sys
from pathlib import Path

# the proposals of docs/REGRESSION-POLICY.md, from the changes of 2026-10-19/20
WHOLE_DROP_SPANS = 5          # a class losing more whole spans than this on val
WHOLE_DROP_SHARE = 0.005      # or more than this share of its spans
FP_RISE_SHARE = 0.01          # false positives of a source and split rising by more than 1 %


def _load(d: Path) -> dict:
    out = {}
    for f in sorted(d.glob("*-maisecrets.json")):
        try:
            out[f.name] = json.loads(f.read_text(encoding="utf-8"))["metrics"]
        except (OSError, ValueError, KeyError):
            continue
    return out


def _fpbank(d: Path) -> dict:
    f = d / "fpbank-7trees.json"
    if not f.is_file():
        return {}
    trees = json.loads(f.read_text(encoding="utf-8"))["trees"]
    out: dict = {}
    for tree in trees.values():
        for key, (_hits, acted) in tree["rules"].items():
            rule = key.split("|")[-1]
            out[rule] = out.get(rule, 0) + acted
    return out


def compare(base: Path, new: Path) -> list[str]:
    findings = []
    a, b = _load(base), _load(new)
    for name in sorted(set(a) & set(b)):
        split = name.rsplit("-", 2)[-2]
        ma, mb = a[name], b[name]
        fa, fb = ma.get("all", {}).get("fp") or 0, mb.get("all", {}).get("fp") or 0
        if fb > fa and (fb - fa) > FP_RISE_SHARE * max(fa, 1):
            findings.append(f"{name}: false positives {fa} -> {fb}")
        for cls in sorted(k for k in set(ma) | set(mb) if k.count(".") == 1):
            x, y = ma.get(cls, {}), mb.get(cls, {})
            spans = y.get("spans") or x.get("spans") or 0
            wa, wb = x.get("full") or 0, y.get("full") or 0
            pa, pb = x.get("partial") or 0, y.get("partial") or 0
            if split == "val" and wb < wa and (wa - wb > WHOLE_DROP_SPANS or wa - wb > WHOLE_DROP_SHARE * spans):
                findings.append(f"{name}: {cls} whole spans {wa} -> {wb}")
            if pb > pa:
                findings.append(f"{name}: {cls} partial spans {pa} -> {pb}")
    ra, rb = _fpbank(base), _fpbank(new)
    if not ra or not rb:
        return findings + (["false-alarm bank: measured on one side only, not compared"] if ra or rb else [])
    for rule in sorted(set(ra) | set(rb)):
        if rb.get(rule, 0) > ra.get(rule, 0):
            findings.append(f"false-alarm bank: {rule} acted hits {ra.get(rule, 0)} -> {rb.get(rule, 0)}")
    return findings


def main(argv) -> int:
    strict = "--strict" in argv
    argv = [x for x in argv if x != "--strict"]
    if len(argv) != 2:
        sys.stderr.write(__doc__)
        return 2
    findings = compare(Path(argv[0]), Path(argv[1]))
    for f in findings:
        print(f)
    print(f"{len(findings)} finding(s)")
    return 1 if strict and findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
