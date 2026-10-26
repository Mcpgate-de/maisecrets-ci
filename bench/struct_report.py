#!/usr/bin/env python3
"""The report of the structured corpus (docs/BENCHMARK-STRUCTURED.md, "The report"): maisecrets on template set A,
split by class, format, field-name language, spelling style and diacritics, with the false positives named by the
kind of look-alike they fall on and the rule that made them.

    python3 bench/struct_report.py [--maisecrets DIR] [--split dev] [--regions de,us] [--languages LIST]
                                   [--json OUT] [--markdown OUT]

It prints counts, rule ids and field names only, never a value or a case text. The scoring is bench/score.py; a
span counts when its core is masked whole (strict), in part (partial) or not at all."""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import score, structgen  # noqa: E402
from bench.adapters import maisecrets as adapter  # noqa: E402

ALL_REGIONS = "de,us,fr,es,it,nl,se,pl,pt"
ALL_LANGUAGES = "en,de,fr,es,it,nl,sv,pl,pt"


def _tag(case, key):
    return next((t.split(":", 1)[1] for t in case["tags"] if t.startswith(key + ":")), "-")


def measure(cs, found):
    """One row per span in scope (its attributes and its outcome), the false positives with what they fall on,
    and the coverage of the policy-neutral e-mail spans."""
    spans, fps, mail = [], [], collections.Counter()
    for c, fs in zip(cs, found):
        sc = score.score_case(c, [f[:3] for f in fs], adapter.SCOPE)
        scored = [s for s in c["spans"] if not s.get("neutral")]
        rules = [(s, e, k) for s, e, _, k in fs]
        for sp, out in zip(scored, sc["spans"]):
            near = sorted({k for s, e, k in rules if s < sp["end"] and e > sp["start"]})
            spans.append({"class": sp["class"], "outcome": out["outcome"], "format": _tag(c, "format"),
                          "lang": c["lang"], "style": sp.get("style", "-"), "diacritics": sp.get("diacritics", "-"),
                          "concept": sp.get("concept", "-"), "field": sp.get("field", "-"),
                          "keypath": sp.get("keypath", "-"), "channel": c["channel"],
                          "labels": _tag(c, "labels"), "variant": _tag(c, "variant"), "rules": near,
                          "negative_case": False})
        for sp in c["spans"]:
            if sp.get("policy") == "reserved-mail-domain":
                cov = score._covered([(s, e) for s, e, _, _ in fs], sp["start"], sp["end"])
                mail["spans"] += 1
                mail["masked_whole" if cov == sp["end"] - sp["start"] else "masked_part" if cov else "text"] += 1
        for s, e, cls in sc["fp_found"]:
            rule = next((k for fs_, fe, _, k in fs if fs_ == s and fe == e), "?")
            look = next((lk for lk in c.get("lookalikes", ()) if s < lk["end"] and e > lk["start"]), None)
            fps.append({"format": _tag(c, "format"), "lang": c["lang"], "class": cls, "rule": rule,
                        "negative_case": not c["spans"] or all(x.get("neutral") for x in c["spans"]),
                        "kind": look["kind"] if look else "structure", "concept": look["concept"] if look else "-",
                        "field": look["field"] if look else "-"})
    return spans, fps, dict(mail)


def table(spans, key, classes=None):
    rows = collections.defaultdict(collections.Counter)
    for s in spans:
        if classes and s["class"] not in classes:
            continue
        k = key(s)
        rows[k]["spans"] += 1
        rows[k][s["outcome"]] += 1
    return {k: {**v, "recall": round(v["full"] / v["spans"], 3)} for k, v in sorted(rows.items())}


def report(cs, found) -> dict:
    spans, fps, mail = measure(cs, found)
    neg_cases = [c for c in cs if not any(not s.get("neutral") for s in c["spans"])]
    neg_ids = {id(c) for c in neg_cases}
    misses = collections.Counter((s["class"], s["concept"], s["format"]) for s in spans if s["outcome"] != "full")
    miss_fields = collections.Counter((s["class"], s["field"]) for s in spans if s["outcome"] != "full")
    hit_fields = collections.Counter((s["class"], s["field"]) for s in spans if s["outcome"] == "full")
    return {
        "cases": len(cs), "negative_cases": len(neg_cases), "spans": len(spans), "mail_policy_neutral": mail,
        "by_class": table(spans, lambda s: s["class"]),
        "by_format": table(spans, lambda s: s["format"]),
        "by_format_family": table(spans, lambda s: f"{s['format']}/{s['class'].split('.')[0]}"),
        "by_lang": table(spans, lambda s: s["lang"]),
        "by_lang_class": table(spans, lambda s: f"{s['lang']}/{s['class']}"),
        "by_style": table(spans, lambda s: s["style"]),
        "by_style_class": table(spans, lambda s: f"{s['style']}/{s['class']}"),
        "by_diacritics": table(spans, lambda s: s["diacritics"]),
        "by_keypath": table(spans, lambda s: s["keypath"], {"pii.phone", "pii.birth_date"}),
        "by_channel": table(spans, lambda s: s["channel"]),
        "by_variant": table(spans, lambda s: f"{s['format']}/{s['variant']}"),
        "by_format_class": table(spans, lambda s: f"{s['format']}/{s['class']}"),
        "by_concept": table(spans, lambda s: s["concept"]),
        "misses_by_class_concept_format": [[*k, n] for k, n in misses.most_common(60)],
        "miss_fields": [[c, f, n, hit_fields.get((c, f), 0)] for (c, f), n in miss_fields.most_common(120)],
        "partial_rules": collections.Counter(r for s in spans if s["outcome"] == "partial" for r in s["rules"]),
        "fp": len(fps),
        "fp_negative_cases": sum(f["negative_case"] for f in fps),
        "fp_per_1000_negative_cases": round(1000 * sum(f["negative_case"] for f in fps) / max(1, len(neg_cases)), 1),
        "negative_cases_with_fp": len({id(c) for c, fs in zip(cs, found) if id(c) in neg_ids and fs}),
        "fp_by_kind": dict(collections.Counter(f["kind"] for f in fps).most_common()),
        "fp_by_kind_rule": [[*k, n] for k, n in collections.Counter((f["kind"], f["rule"], f["class"])
                                                                     for f in fps).most_common(40)],
        "fp_by_kind_field": [[*k, n] for k, n in collections.Counter((f["kind"], f["concept"], f["field"])
                                                                      for f in fps).most_common(40)],
        "fp_by_format": dict(collections.Counter(f["format"] for f in fps).most_common()),
    }


def _md_table(title, rows, first="group"):
    out = [f"### {title}", "", f"| {first} | support | full | partial | missed | recall |", "|---|---|---|---|---|---|"]
    for k, v in rows.items():
        out.append(f"| {k} | {v['spans']} | {v.get('full', 0)} | {v.get('partial', 0)} | {v.get('missed', 0)} | "
                   f"{v['recall']} |")
    return "\n".join(out) + "\n"


def markdown(rep: dict, head: str) -> str:
    parts = [head, "",
             f"Cases {rep['cases']} (negative {rep['negative_cases']}), scored spans {rep['spans']}, false positives "
             f"{rep['fp']} (on negative cases {rep['fp_negative_cases']}, "
             f"{rep['fp_per_1000_negative_cases']} per 1000 negative cases). E-mail spans (policy-neutral): "
             f"{rep['mail_policy_neutral']}.", ""]
    for key, title in (("by_class", "Per class"), ("by_format", "Per format"), ("by_lang", "Per field-name language"),
                       ("by_style", "Per spelling style"), ("by_diacritics", "Per diacritics of the field name"),
                       ("by_keypath", "Phone and birth date: label in the parent key"),
                       ("by_channel", "Per channel")):
        parts.append(_md_table(title, rep[key]))
    parts.append("### False positives by look-alike kind\n\n| kind | FP |\n|---|---|")
    parts += [f"| {k} | {n} |" for k, n in rep["fp_by_kind"].items()]
    parts.append("\n### False positives by kind, rule and class\n\n| kind | rule | class | FP |\n|---|---|---|---|")
    parts += [f"| {a} | {b} | {c} | {n} |" for a, b, c, n in rep["fp_by_kind_rule"]]
    return "\n".join(parts) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--maisecrets", type=Path, default=ROOT)
    ap.add_argument("--split", default="dev", choices=("dev", "val", "all"))
    ap.add_argument("--regions", default="de,us", help=f"or 'all' ({ALL_REGIONS})")
    ap.add_argument("--languages", default="", help=f"label languages, or 'all' ({ALL_LANGUAGES})")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--markdown", type=Path)
    a = ap.parse_args(argv)
    regions = ALL_REGIONS if a.regions == "all" else a.regions
    languages = ALL_LANGUAGES if a.languages == "all" else a.languages
    cs = [c for c in structgen.generate() if a.split == "all" or c["split"] == a.split]
    found, _ = adapter.scan(cs, a.maisecrets.resolve(), regions, languages=languages)
    desc = adapter.describe(a.maisecrets.resolve(), regions)
    rep = {"scanner": {k: desc[k] for k in ("version", "commit", "dirty")}, "regions": regions,
           "languages": languages or "worker default", "split": a.split, **report(cs, found)}
    if a.json:
        a.json.write_text(json.dumps(rep, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    md = markdown(rep, f"## maisecrets {desc['version']} {(desc['commit'] or '')[:8]} on structured/{a.split}, "
                       f"regions {regions}, languages {languages or 'worker default'}")
    if a.markdown:
        a.markdown.write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
