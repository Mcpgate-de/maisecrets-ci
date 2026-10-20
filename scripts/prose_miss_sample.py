#!/usr/bin/env python3
"""The sample of the prose miss report of docs/BENCHMARK-V3-DRAFT.md, on development data only.

    python3 scripts/prose_miss_sample.py MAISECRETS_CHECKOUT [--n 50]

The missed name and address spans of Gretel and Nemotron `dev` in prose cases, 50 per dataset and class, ordered by
sha256("prose-misses-20261020/" + case id + "/" + start). Each row: class, the length of the case text, and 150
characters of context on each side with the value replaced by its shape and every digit written as 9 (the labelled
spans around it as their class). Privy is refused: it stays unread."""
from __future__ import annotations

import collections
import hashlib
import importlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import fp_audit_sample as fa  # noqa: E402

SALT = "prose-misses-20261020/"


def is_prose(t: str) -> bool:
    """No JSON, XML, HTML, SQL, CSV, Markdown table or key-value list: running text."""
    s = t.lstrip()
    if s.startswith(("{", "[", "<")) or re.search(r"(?i)\binsert\s+into\b|<t[hdr]\b|\|\s*-{3}", s):
        return False
    first = s.split("\n", 1)[0]
    if first.count(",") >= 2 and " " not in first.strip() and "\n" in s:
        return False
    lines = [ln for ln in s.split("\n") if ln.strip()]
    kv = sum(1 for ln in lines if re.match(r"\s*[-*]?\s*\**[\w ./-]{1,40}\**\s*:\s*\S", ln))
    return not (len(lines) >= 3 and kv / len(lines) > 0.5)


def length_bucket(n: int) -> str:
    return "<500" if n < 500 else "500-2000" if n < 2000 else "2000-8000" if n < 8000 else ">8000"


def sample(checkout: Path, n: int) -> dict:
    sources = importlib.import_module("bench.sources")
    score = importlib.import_module("bench.score")
    adapter = importlib.import_module("bench.adapters." + "maise" + "crets")
    out = {}
    for name in ("gretel", "nemotron"):
        cs = [c for c in sources.load(name, None, None, 0, collections.Counter())
              if c["split"] == "dev" and is_prose(c["text"])]
        found, _ = adapter.scan(cs, checkout, "de,us")
        misses = collections.defaultdict(list)
        for case, hits in zip(cs, found):
            res = score.score_case(case, [(s, e, c) for s, e, c, _ in hits], adapter.SCOPE)
            spans = [s for s in case["spans"] if not s.get("neutral")]
            for sp, o in zip(spans, res["spans"]):
                if o["outcome"] == "missed" and sp["class"] in ("pii.name", "pii.address"):
                    key = hashlib.sha256(f"{SALT}{case['id']}/{sp['start']}".encode()).hexdigest()
                    misses[sp["class"]].append((key, case, sp))
        for cls, rows in misses.items():
            out[(name, cls)] = (len(rows), sorted(rows, key=lambda r: r[0])[:n])
    return out


def main(argv) -> int:
    if not argv or "privy" in argv:
        sys.stderr.write(__doc__)
        return 2
    n = int(argv[argv.index("--n") + 1]) if "--n" in argv else 50
    for (src, cls), (total, rows) in sorted(sample(Path(argv[0]).resolve(), n).items()):
        print(f"== {src} dev, {cls}: {total} missed in prose, sample {len(rows)}")
        for i, (_k, case, sp) in enumerate(rows, 1):
            others = {**case, "spans": [s for s in case["spans"] if s is not sp]}
            print(f"{i:3d}  len {length_bucket(len(case['text'])):9s} "
                  f"{fa.masked_context(others, sp['start'], sp['end'], 150)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
