#!/usr/bin/env python3
"""The provenance of every detection rule as one JSON file: where it comes from, what it finds, how it decides, what
is known about its limits, and, with --coverage, what it did on the development data.

    python3 scripts/rule_provenance.py --out FILE [--coverage]

One row per rule of the rule list and per rule of the passes (the personal-data step, the export), every region on:
key, id, source, origin (vendored, patched, own, fallback), the upstream version and licence of a vendored rule,
region, channel, type, class, form, matcher, filters, label languages, what a pass rule needs (a label or a form),
the validator, the context words and whether a weak shape needs them, and the limits that docs/rule-limits.json names
for the rule or its family. Ids, names and words only: never a regex and never a value.

--coverage scans the `dev` split of Nemotron, Gretel, Mendeley and PIILO (Benchmark V2, development data) and adds per
rule the hits, the hits on a labelled span and the false positives. Privy is never read here."""
from __future__ import annotations

import collections
import importlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
LIMITS = ROOT / "docs" / "rule-limits.json"
ALL_REGIONS = ("generic", "de", "us", "uk", "fr", "es", "it", "nl", "se", "in", "au", "ca", "pt", "jp")
LICENCE = {"betterleaks": "MIT (rules/LICENSE-betterleaks)",
           "detect-secrets": "Apache-2.0 (rules/LICENSE-detect-secrets)", "presidio": "MIT (rules/LICENSE-presidio)"}


def specs() -> list:
    from maisecrets import detect, regions
    active = regions.Active(regions=ALL_REGIONS, languages=("en", "de"), source="provenance")
    with detect.Detector(regions=active).activate():
        return [(s, r) for s, r in detect.rule_specs(active)] + [(s, None) for s in detect.pass_specs()]


def limits() -> dict:
    data = json.loads(LIMITS.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def row(spec, rule, known: dict) -> dict:
    up = spec.upstream
    family = spec.rule_class
    return {
        "key": spec.key, "id": spec.id, "source": spec.source, "origin": spec.origin,
        "upstream": f"{up.source} {up.version}" if up else None,
        "licence": LICENCE.get(spec.source, "Apache-2.0 (this repository)"),
        "patches": [f"{p.field} {p.op}" for p in spec.patches],
        "region": spec.region, "channel": spec.channel, "type": spec.type, "class": family, "form": spec.form,
        "matcher": spec.matcher, "filters": sorted(spec.filters), "languages": spec.language or None,
        "needs": spec.needs or None,
        "validator": getattr(rule, "validator", None),
        "context": list(getattr(rule, "context", ()) or ()),
        "requires_context": bool(getattr(rule, "require_context", False)),
        # a Presidio rule has one id per pattern (us-ssn#0, us-ssn#1); its limits are those of the recognizer
        "limits": known.get(spec.id.split("#")[0], []) + known.get("class:" + family, []),
    }


def coverage() -> dict:
    """Per rule id on the dev splits: hits, hits on a labelled span, false positives."""
    sources = importlib.import_module("bench.sources")
    score = importlib.import_module("bench.score")
    adapter = importlib.import_module("bench.adapters." + "maise" + "crets")
    out: dict = collections.defaultdict(lambda: {"hits": 0, "on_label": 0, "fp": 0})
    for name in ("nemotron", "gretel", "mendeley", "piilo"):
        cs = [c for c in sources.load(name, None, None, 0, collections.Counter()) if c["split"] == "dev"]
        found, _ = adapter.scan(cs, ROOT, "de,us")
        for case, hits in zip(cs, found):
            for s, e, cls, rule in hits:
                r = out[rule.split("#")[0]]
                r["hits"] += 1
                one = score.score_case(case, [(s, e, cls)], adapter.SCOPE)
                r["fp"] += one["fp"]
                r["on_label"] += sum(one["on_target"].values())
    return dict(out)


def main(argv) -> int:
    if "--out" not in argv:
        sys.stderr.write(__doc__)
        return 2
    known = limits()
    rows = [row(s, r, known) for s, r in sorted(specs(), key=lambda x: x[0].priority)]
    if "--coverage" in argv:
        cov = coverage()
        for r in rows:
            r["dev_coverage"] = cov.get(r["id"], {"hits": 0, "on_label": 0, "fp": 0})
    out = Path(argv[argv.index("--out") + 1])
    out.write_text(json.dumps({"rules": rows, "count": len(rows)}, indent=1, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    print(f"{len(rows)} rules: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
