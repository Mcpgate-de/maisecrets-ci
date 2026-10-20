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

# the lines of docs/REGRESSION-POLICY.md, set from the releases 0.6.41 to 0.7.0 (2026-10-20): no release lost a whole
# span on val, and no release made a single span worse
WHOLE_DROP_SPANS = 0          # a class losing any whole span on val
FP_RISE_SHARE = 0.01          # false positives of a source and split rising by more than 1 %
# per span, from the outcomes of each case: a span that got worse is always a finding; missed -> partial is a gain
RANK = {"missed": 0, "partial": 1, "full": 2}


def _load(d: Path, hashes: dict | None = None, per_case: dict | None = None) -> dict:
    out = {}
    for f in sorted(d.glob("*-maisecrets.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            out[f.name] = data["metrics"]
        except (OSError, ValueError, KeyError):
            continue
        if hashes is not None:
            hashes[f.name] = data.get("cases_sha256")
        if per_case is not None:
            per_case[f.name] = data.get("per_case")
    return out


def worse_spans(a: dict | None, b: dict | None) -> int:
    """The spans whose outcome got worse from a to b (whole -> partial or missed, partial -> missed), case by case.
    The outcomes of a case are in span order, the false positives after them; two runs on the same cases align."""
    if not a or not b:
        return 0
    n = 0
    for case, ob in b.items():
        oa = [x for x in a.get(case, []) if x != "fp"]
        ob = [x for x in ob if x != "fp"]
        n += sum(1 for x, y in zip(oa, ob) if RANK.get(y, 0) < RANK.get(x, 0))
    return n


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
    ha: dict = {}
    hb: dict = {}
    pa_: dict = {}
    pb_: dict = {}
    a, b = _load(base, ha, pa_), _load(new, hb, pb_)
    for name in sorted(set(a) & set(b)):
        # two runs on different cases (another generator, another dataset revision, another sample) are not compared:
        # each difference would be the cases, not the change
        if ha.get(name) != hb.get(name):
            findings.append(f"{name}: the cases differ (sha256 {str(ha.get(name))[:12]} vs {str(hb.get(name))[:12]}),"
                            " not compared")
            continue
        split = name.rsplit("-", 2)[-2]
        ma, mb = a[name], b[name]
        worse = worse_spans(pa_.get(name), pb_.get(name))
        if worse:
            findings.append(f"{name}: {worse} spans got worse (whole to partial or missed, partial to missed)")
        fa, fb = ma.get("all", {}).get("fp") or 0, mb.get("all", {}).get("fp") or 0
        if fb > fa and (fb - fa) > FP_RISE_SHARE * max(fa, 1):
            findings.append(f"{name}: false positives {fa} -> {fb}")
        for cls in sorted(k for k in set(ma) | set(mb) if k.count(".") == 1):
            x, y = ma.get(cls, {}), mb.get(cls, {})
            wa, wb = x.get("full") or 0, y.get("full") or 0
            pa, pb = x.get("partial") or 0, y.get("partial") or 0
            if split == "val" and wa - wb > WHOLE_DROP_SPANS:
                findings.append(f"{name}: {cls} whole spans {wa} -> {wb}")
            # without the outcomes per case a rise of partial counts is all there is to judge
            if pb > pa and (pa_.get(name) is None or pb_.get(name) is None):
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
