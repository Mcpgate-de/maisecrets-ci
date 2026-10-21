"""The `dev` false positives of the family "rest" of a variant, text around the span and the span, into a JSONL file
for bench/ner/rest_label.py (docs/NER-EXPERIMENT.md). Nothing is printed but counts.

    python3 bench/ner/rest_dump.py BASE_DIR VARIANT_DIR OUT.jsonl CHECKOUT FILE..."""
import collections
import importlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
an = importlib.import_module("analyze")
run = importlib.import_module("bench.run")
sources = importlib.import_module("bench.sources")
score = importlib.import_module("bench.score")
funnel = importlib.import_module("bench.funnel")
for m in [m for m in sys.modules if m == "maisecrets" or m.startswith("maisecrets.")]:
    del sys.modules[m]
checkout = Path(sys.argv[4]).resolve()
sys.path.insert(0, str(checkout))
p = importlib.import_module("maisecrets.detection.personal")
assert Path(p.__file__).resolve().is_relative_to(checkout), p.__file__
base, var, out = Path(sys.argv[1]), Path(sys.argv[2]), open(sys.argv[3], "w", encoding="utf-8")
n = collections.Counter()
for fname in sys.argv[5:]:
    rv = json.loads((var / fname).read_text())
    cases = {c["id"]: c for c in sources.load(rv["source"], None, None, 0, collections.Counter())
             if run.in_sample(c["id"], rv["every"])}
    for line in open(var / fname.replace("-maisecrets.json", "-ner.jsonl")):
        row = json.loads(line)
        c = cases[row["id"]]
        if c["split"] != "dev":
            continue
        spans = [s for s in c["spans"] if not s.get("neutral")]
        removed = [s for s in c["spans"] if s.get("neutral")]
        for s, e, _ in row["add"]:
            if any(s < sp["end"] and e > sp["start"] for sp in spans):
                continue
            allowed = [(score._label_start(c["text"], sp["start"]), sp["end"]) for sp in c["spans"]]
            extra = (e - s) - score._covered(allowed, s, e)
            if any(s < r["end"] and e > r["start"] for r in removed) and extra <= score.SLACK:
                continue
            if an.family(funnel, p, c["text"], s, e) != "rest":
                continue
            a, b = max(0, s - 300), min(len(c["text"]), e + 300)
            out.write(json.dumps({"source": rv["source"], "text": c["text"][a:b], "s": s - a, "e": e - a}) + "\n")
            n[rv["source"]] += 1
print(dict(n))
