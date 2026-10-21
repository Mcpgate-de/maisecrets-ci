"""The Markdown tables of docs/NER-EXPERIMENT.md from the analysis files (bench/ner/analyze.py --json), counts only.

    python3 bench/ner/tables.py ANALYSIS_DIR > tables.md"""
import json
import sys
from pathlib import Path

S = Path(sys.argv[1])
VARIANTS = [("A", "spaCy sm"), ("B", "spaCy lg"), ("C", "GLiNER 0.5"), ("Chigh", "GLiNER 0.3"), ("D", "DistilBERT"),
            ("D2", "DistilBERT, whole words"), ("D3", "multilingual DistilBERT, whole words")]
SRC = ["nemotron", "gretel", "mendeley", "piilo"]


def load(v):
    return json.loads((S / f"{v}.json").read_text())


def pct(n, d):
    return f"{100 * n / d:.1f} %" if d else "-"


def names_table(suffix, title):
    print(f"\n### {title}\n")
    print("| Variant | " + " | ".join(f"{s}: names whole / added FP / PII precision" for s in SRC) + " |")
    print("|---|" + "---|" * len(SRC))
    base = load("A")
    cells = []
    for s in SRC:
        r = base.get(f"{s}-all{suffix}-maisecrets.json")
        whole, spans = (r["name"]["full"][0], r["name"]["spans"][0]) if r else (0, 0)
        cells.append(f"{whole} of {spans} ({pct(whole, spans)}) / – / {r['pii']['precision'][0]}" if r else "–")
    print("| maisecrets 0.7.3 | " + " | ".join(cells) + " |")
    for v, label in VARIANTS:
        R = load(v)
        cells = []
        for s in SRC:
            r = R.get(f"{s}-all{suffix}-maisecrets.json")
            if not r:
                cells.append("not run")
                continue
            fp = r["added"].get("false positive", 0)
            cells.append(f"{r['name']['full'][1]} ({pct(r['name']['full'][1], r['name']['spans'][1])}) / {fp} / "
                         f"{r['pii']['precision'][1]}")
        print(f"| + {label} | " + " | ".join(cells) + " |")


names_table("-every50", "Samples of 1 in 50 (all `dev`)")
names_table("", "Full datasets (all splits)")

print("\n### Spans made worse, and PERSON spans dropped on a deterministic finding\n")
print("| Variant | spans made worse (all files) | dropped on a finding (all files), by its type |")
print("|---|---:|---|")
for v, label in VARIANTS:
    R = load(v)
    worse = sum(r["worse"] for r in R.values())
    conf = {}
    for r in R.values():
        for k, n in r["conflicts"].items():
            conf[k] = conf.get(k, 0) + n
    top = ", ".join(f"{k} {n}" for k, n in sorted(conf.items(), key=lambda kv: -kv[1])[:5])
    print(f"| {label} | {worse} | {sum(conf.values())}: {top} |")

print("\n### Names in running text and in record fields (samples)\n")
print("| Variant | " + " | ".join(f"{b}: whole before → after (of spans)" for b in ("prose", "person-cue", "label-same",
                                                                                   "record-field")) + " |")
print("|---|---|---|---|---|")
for v, label in VARIANTS:
    R = load(v)
    agg = {}
    for f, r in R.items():
        if "-every50-" not in f:
            continue
        for k, n in r["names_by_bucket"].items():
            agg[k] = agg.get(k, 0) + n
    cells = [f"{agg.get(b + '/base', 0)} → {agg.get(b + '/variant', 0)} ({agg.get(b + '/spans', 0)})"
             for b in ("prose", "person-cue", "label-same", "record-field")]
    print(f"| {label} | " + " | ".join(cells) + " |")

print("\n### Gretel by language (samples): whole names before → after (of spans), added false positives\n")
langs = ["us", "de", "es", "fr", "it", "nl", "se"]
print("| Variant | " + " | ".join(langs) + " |")
print("|---|" + "---|" * len(langs))
for v, label in VARIANTS:
    r = load(v).get("gretel-all-every50-maisecrets.json")
    n = r["names_by_region"]
    cells = [f"{n.get(lg + '/base', 0)} → {n.get(lg + '/variant', 0)} ({n.get(lg + '/spans', 0)}), "
             f"FP {r['added'].get('false positive, region ' + lg, 0)}" for lg in langs]
    print(f"| {label} | " + " | ".join(cells) + " |")

print("\n### Full datasets by split (A and B): whole names before → after (of spans)\n")
for v in ("A", "B"):
    R = load(v)
    agg = {}
    for f, r in R.items():
        if "-every50-" in f:
            continue
        for k, n in r["names_by_split"].items():
            agg[k] = agg.get(k, 0) + n
    print(f"- {dict(VARIANTS)[v]}: " + "; ".join(f"{sp} {agg.get(sp + '/base')} → {agg.get(sp + '/variant')} of "
                                                f"{agg.get(sp + '/spans')}" for sp in ("dev", "val", "holdout")))

print("\n### False positives the layer adds, by family (samples, `dev`)\n")
fams = ["record field", "technical identifier", "company word", "one word at a sentence start", "role or title words",
        "rest"]
print("| Variant | " + " | ".join(fams) + " | on a gold span of another class (not a false positive) |")
print("|---|" + "---|" * (len(fams) + 1))
for v, label in VARIANTS:
    R = load(v)
    agg, other = {}, 0
    for f, r in R.items():
        if "-every50-" not in f:
            continue
        for k, n in r["fp_families"].items():
            agg[k] = agg.get(k, 0) + n
        other += r["added"].get("on a gold span of another class", 0)
    print(f"| {label} | " + " | ".join(str(agg.get(k, 0)) for k in fams) + f" | {other} |")
