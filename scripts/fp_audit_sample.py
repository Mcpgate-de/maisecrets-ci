#!/usr/bin/env python3
"""The sample of the false-positive audit of docs/BENCHMARK-V3-DRAFT.md, on development data only.

    python3 scripts/fp_audit_sample.py MAISECRETS_CHECKOUT [--n 40]

Four strata (Nemotron us-ssn, Nemotron other rules, Gretel us-bank, Gretel other rules) of the false positives on the
dev split. Each stratum is ordered by sha256("v3-audit-20261020/" + case id + "/" + start) and its first n are
printed: class, rule, the value's shape (letters and digits counted, never a character of it), and 80 characters of
context on each side with every digit written as 9 and every labelled span replaced by its class. Privy is refused:
it stays unread (docs/BENCHMARK-V3-DRAFT.md, "Privy stays unread")."""
from __future__ import annotations

import collections
import hashlib
import importlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
SALT = "v3-audit-20261020/"
STRATA = (("nemotron", "us-ssn", True), ("nemotron", "us-ssn", False), ("gretel", "us-bank", True),
          ("gretel", "us-bank", False))


def shape(v: str) -> str:
    runs = re.findall(r"\d+|[^\W\d_]+|[^\w\s]|\s+", v)
    out = []
    for r in runs:
        out.append(f"{len(r)}d" if r[0].isdigit() else f"{len(r)}a" if r[0].isalpha() else
                   " " if r.isspace() else r)
    return "".join(out)


def masked_context(case: dict, s: int, e: int, width: int = 80) -> str:
    text = case["text"]
    a, b = max(0, s - width), min(len(text), e + width)
    marks = sorted([(sp["start"], sp["end"], "<" + sp["class"] + ">") for sp in case["spans"]
                    if sp["end"] > a and sp["start"] < b] + [(s, e, "[[" + shape(text[s:e]) + "]]")])
    out, pos = [], a
    for ms, me, tok in marks:
        if ms < pos:
            continue
        out.append(re.sub(r"\d", "9", text[pos:max(pos, ms)]))
        out.append(tok)
        pos = me
    out.append(re.sub(r"\d", "9", text[pos:b]))
    return "".join(out).replace("\n", " | ")


def sample(checkout: Path, n: int) -> dict:
    sources = importlib.import_module("bench.sources")
    score = importlib.import_module("bench.score")
    adapter = importlib.import_module("bench.adapters." + "maise" + "crets")
    out = {}
    for name in sorted({s for s, _, _ in STRATA}):
        cs = [c for c in sources.load(name, None, None, 0, collections.Counter()) if c["split"] == "dev"]
        found, _ = adapter.scan(cs, checkout, "de,us")
        fps = []
        for case, hits in zip(cs, found):
            for s, e, cls, rule in hits:
                if score.score_case(case, [(s, e, cls)], adapter.SCOPE)["fp"]:
                    fps.append((hashlib.sha256(f"{SALT}{case['id']}/{s}".encode()).hexdigest(), case, s, e, cls,
                                rule.split("#")[0]))
        fps.sort(key=lambda x: x[0])
        for src, rule_id, same in STRATA:
            if src != name:
                continue
            stratum = [f for f in fps if (f[5] == rule_id) == same]
            out[(src, rule_id if same else "other")] = (len(stratum), stratum[:n])
    return out


def main(argv) -> int:
    if not argv or "privy" in argv:
        sys.stderr.write(__doc__)
        return 2
    n = int(argv[argv.index("--n") + 1]) if "--n" in argv else 40
    for (src, label), (total, rows) in sample(Path(argv[0]).resolve(), n).items():
        print(f"== {src} dev, {label}: {total} false positives, sample {len(rows)}")
        for i, (_h, case, s, e, cls, rule) in enumerate(rows, 1):
            print(f"{i:3d}  {cls:18s} {rule:24s} {masked_context(case, s, e)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
