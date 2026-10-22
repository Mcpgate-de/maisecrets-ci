"""The analysis of the NER experiment (docs/NER-EXPERIMENT.md): a variant's results against the baseline of the same
cases, per result file. Counts only, never a value.

    python3 bench/ner/analyze.py BASE_DIR VARIANT_DIR --maisecrets CHECKOUT [--json OUT] [FILE ...]

BASE_DIR holds the deterministic results, VARIANT_DIR the results of bench/adapters/maisecrets_ner.py and their
sidecars (`<file>-ner.jsonl` next to `<file>-maisecrets.json`). CHECKOUT is the maisecrets of both runs: the buckets of
bench/funnel.py read its record fields. The cases are loaded again and must have the sha256 of both result files.

Per file: the `pii.name` class and the PII family before and after; spans made worse (the layer may make none worse);
the spans the layer added, sorted into on a gold name, on a gold span of another class, and false positive (the
scoring of bench/score.py); the PERSON spans dropped on a deterministic finding, by its type; whole names by funnel
bucket and by region (language), and by split; the false positives of the `dev` split by the families fixed in
docs/NER-EXPERIMENT.md before any was read (`val` decides and the holdout split of V1 is never read, so neither is
sorted)."""
from __future__ import annotations

import argparse
import collections
import importlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent.parent
COMPANY = re.compile(r"(?i)\b(?:inc|llc|ltd|corp|corporation|gmbh|ag|bank|group|company|partners|holdings|technologies"
                     r"|solutions|services|university|hospital|foundation)\b\.?")
ROLE = {"customer", "manager", "director", "patient", "client", "user", "admin", "administrator", "doctor", "officer",
        "agent", "team", "support", "sir", "madam", "mr", "mrs", "ms", "dr", "dear", "employee", "applicant", "owner",
        "holder", "account", "representative", "member", "staff", "analyst", "engineer", "president", "ceo", "cfo",
        "cto", "coordinator", "specialist", "consultant", "advisor", "nurse", "teacher", "student", "professor", "prof"}
RANK = {"missed": 0, "partial": 1, "full": 2}


def family(funnel, p, text: str, s: int, e: int) -> str:
    v = text[s:e]
    if funnel.bucket(p, text, {"start": s, "end": e, "class": "pii.name"}) == "record-field":
        return "record field"
    if re.search(r"[\d@_/]", v):
        return "technical identifier"
    if COMPANY.search(v):
        return "company word"
    words = re.findall(r"[\w'-]+", v)
    before = text[max(0, s - 3):s]
    if len(words) == 1 and (s == 0 or text[s - 1] == "\n" or re.search(r"[.!?:]\s+$", before)):
        return "one word at a sentence start"
    if words and all(w.lower().strip(".") in ROLE for w in words):
        return "role or title words"
    return "rest"


def main(argv: list) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base", type=Path)
    ap.add_argument("variant", type=Path)
    ap.add_argument("files", nargs="*")
    ap.add_argument("--maisecrets", type=Path, required=True)
    ap.add_argument("--json", type=Path)
    a = ap.parse_args(argv)
    sys.path.insert(0, str(HERE))
    run = importlib.import_module("bench.run")
    sources = importlib.import_module("bench.sources")
    score = importlib.import_module("bench.score")
    funnel = importlib.import_module("bench.funnel")
    for name in [m for m in sys.modules if m == "maisecrets" or m.startswith("maisecrets.")]:
        del sys.modules[name]
    sys.path.insert(0, str(a.maisecrets.resolve()))
    p = importlib.import_module("maisecrets.detection.personal")
    assert Path(p.__file__).resolve().is_relative_to(a.maisecrets.resolve()), p.__file__
    files = a.files or sorted(f.name for f in a.variant.glob("*-maisecrets.json") if (a.base / f.name).exists())
    report = {}
    loaded: dict = {}
    for fname in files:
        rb = json.loads((a.base / fname).read_text(encoding="utf-8"))
        rv = json.loads((a.variant / fname).read_text(encoding="utf-8"))
        if rb["cases_sha256"] != rv["cases_sha256"]:
            raise SystemExit(f"{fname}: the two runs saw different cases")
        # a V3 result names its split and its sample salt (bench/run.py); a V1 result has neither
        split, salt = rv.get("split", "all"), rv.get("sample_salt") or ""
        key = (rv["source"], rv["every"], split, salt)
        if key not in loaded:
            loaded.clear()
            loaded[key] = [c for c in sources.load(rv["source"], None, None, 0, collections.Counter())
                           if (split == "all" or c["split"] == split) and run.in_sample(c["id"], rv["every"], salt)]
        cases = loaded[key]
        if run.cases_hash(cases) != rv["cases_sha256"]:
            raise SystemExit(f"{fname}: the cases differ from the result file")
        side = {}
        with open(a.variant / fname.replace("-maisecrets.json", "-ner.jsonl"), encoding="utf-8") as f:
            for line in f:
                row = json.loads(line)
                side[row["id"]] = row
        c_ = collections.Counter
        worse, added, conflicts, families = 0, c_(), c_(), c_()
        bucket_names, region_names, split_names = c_(), c_(), c_()
        for c in cases:
            ob = [o for o in rb["per_case"][c["id"]] if o != "fp"]
            ov = [o for o in rv["per_case"][c["id"]] if o != "fp"]
            spans = [s for s in c["spans"] if score.in_scope(s["class"], ("pii.", "secret.")) and not s.get("neutral")]
            removed = [s for s in c["spans"] if s.get("neutral")]
            worse += sum(1 for x, y in zip(ob, ov) if RANK[y] < RANK[x])
            for sp, x, y in zip(spans, ob, ov):
                if sp["class"] != "pii.name":
                    continue
                b = funnel.bucket(p, c["text"], sp)
                for counter, k in ((bucket_names, b), (region_names, c.get("region", "-")),
                                   (split_names, c["split"])):
                    counter[(k, "spans")] += 1
                    counter[(k, "base")] += x == "full"
                    counter[(k, "variant")] += y == "full"
            row = side.get(c["id"], {"add": [], "conflicts": []})
            conflicts.update(row["conflicts"])
            for s, e, _score in row["add"]:
                hits = [sp for sp in spans if s < sp["end"] and e > sp["start"]]
                if any(h["class"] == "pii.name" for h in hits):
                    added["on a gold name"] += 1
                elif hits:
                    added["on a gold span of another class"] += 1
                    added["other: " + hits[0]["class"]] += 1
                else:
                    allowed = [(score._label_start(c["text"], sp["start"]), sp["end"]) for sp in c["spans"]]
                    extra = (e - s) - score._covered(allowed, s, e)
                    if any(s < r["end"] and e > r["start"] for r in removed) and extra <= score.SLACK:
                        added["on a neutral span"] += 1
                        continue
                    added["false positive"] += 1
                    added["false positive, " + c["split"]] += 1
                    added["false positive, region " + c.get("region", "-")] += 1
                    # the families are read on dev only: val decides, and V1's holdout split is never read
                    if c["split"] == "dev":
                        families[family(funnel, p, c["text"], s, e)] += 1
        mb, mv = rb["metrics"], rv["metrics"]
        report[fname] = {
            "source": rv["source"], "every": rv["every"], "cases": rv["cases"],
            "name": {k: [mb.get("pii.name", {}).get(k), mv.get("pii.name", {}).get(k)]
                     for k in ("spans", "full", "partial", "missed", "recall_strict", "recall_lenient")},
            "pii": {k: [mb.get("pii", {}).get(k), mv.get("pii", {}).get(k)]
                    for k in ("spans", "full", "fp", "precision", "recall_strict", "f1")},
            "worse": worse, "added": dict(added), "conflicts": dict(conflicts), "fp_families": dict(families),
            "names_by_bucket": {f"{k}/{w}": v for (k, w), v in sorted(bucket_names.items())},
            "names_by_region": {f"{k}/{w}": v for (k, w), v in sorted(region_names.items())},
            "names_by_split": {f"{k}/{w}": v for (k, w), v in sorted(split_names.items())},
            "ner_timing": rv.get("timing", {}).get("ner"),
        }
        r = report[fname]
        print(f"{fname}: names whole {r['name']['full'][0]} -> {r['name']['full'][1]} of {r['name']['spans'][1]}, "
              f"PII FP {r['pii']['fp'][0]} -> {r['pii']['fp'][1]}, precision {r['pii']['precision'][0]} -> "
              f"{r['pii']['precision'][1]}, worse {worse}, added {dict(added)}")
    if a.json:
        a.json.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
