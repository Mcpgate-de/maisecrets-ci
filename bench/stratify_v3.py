"""Post-hoc diagnostic of Benchmark V3: the strict PII recall of each scanner split into names (`pii.name`) and the
other PII classes, and per class with its support. Not a new benchmark: it reads the stored result files, runs no
scanner and changes no number. Only the recall denominator is split; the false positives (V3 and V2) are copied as
they are, because a result file keeps no class and no position of a false positive.

    python3 -m bench.stratify_v3 [RUN_DIR] [OUT_DIR]

RUN_DIR defaults to bench/results/2026-10-21-v3/run, OUT_DIR to bench/results/2026-10-21-v3/stratified. The output
holds counts only, never a case text."""
from __future__ import annotations

import csv
import gzip
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SETS = [("Nemotron-PII", "nemotron-val-every25"), ("Mendeley financial", "mendeley-val-every25"),
        ("Gretel finance", "gretel-val-every25"), ("Privy", "privy-all-every10")]
TOOLS = ["maisecrets", "presidio", "preserve", "pii_anon"]
SMALL = 30      # a class with less support is marked small_sample


def _ratio(a: int, b: int):
    return round(a / b, 4) if b else None


def split(d: dict) -> tuple:
    """(summary row without the names of dataset and scanner, per-class rows) of one result file."""
    m, v3 = d["metrics"], d["v3"]["pii"]
    tot = m["pii"]
    cls = {k: x for k, x in m.items() if k.startswith("pii.") and isinstance(x, dict) and x.get("spans")}
    # the classes are a partition of the PII spans: anything else would split a number the report does not have
    assert sum(x["spans"] for x in cls.values()) == tot["spans"]
    assert sum(x.get("full") or 0 for x in cls.values()) == (tot.get("full") or 0)
    full = tot.get("full") or 0
    name = cls.get("pii.name", {"spans": 0, "full": 0, "partial": 0})
    name_full = name.get("full") or 0
    nn_spans, nn_full = tot["spans"] - name["spans"], full - name_full
    row = {
        "scanner_version": (d.get("scanner") or {}).get("version"), "sample": f"1/{d['every']}", "cases": d["cases"],
        "overall_support": tot["spans"], "overall_tp": full, "overall_fn": tot["spans"] - full,
        "overall_recall": _ratio(full, tot["spans"]),
        "name_support": name["spans"], "name_tp": name_full, "name_fn": name["spans"] - name_full,
        "name_partial": name.get("partial") or 0, "name_recall": _ratio(name_full, name["spans"]),
        "nonname_support": nn_spans, "nonname_tp": nn_full, "nonname_fn": nn_spans - nn_full,
        "nonname_partial": sum(x.get("partial") or 0 for k, x in cls.items() if k != "pii.name"),
        "nonname_recall": _ratio(nn_full, nn_spans),
        "fp_v3": v3["fp"], "precision_v3": v3["precision"], "fp_v2": tot["fp"], "precision_v2": tot["precision"],
        "out_of_scope_findings_v3": sum(v3["out_of_scope"].values()),
        "lower_bound_classes": ",".join(d["v3"].get("lower_bound") or []),
    }
    rows = [{"class": k[len("pii."):], "support": x["spans"], "tp": x.get("full") or 0,
             "fn": x["spans"] - (x.get("full") or 0), "partial": x.get("partial") or 0,
             "recall": _ratio(x.get("full") or 0, x["spans"]), "small_sample": x["spans"] < SMALL}
            for k, x in sorted(cls.items())]
    return row, rows


def main(argv: list) -> int:
    run = Path(argv[0]) if argv else HERE / "results/2026-10-21-v3/run"
    out = Path(argv[1]) if len(argv) > 1 else HERE / "results/2026-10-21-v3/stratified"
    summary, per_class = [], []
    for ds, pattern in SETS:
        for tool in TOOLS:
            with gzip.open(run / f"{pattern}-{tool}.json.gz") as f:
                row, rows = split(json.load(f))
            summary.append({"dataset": ds, "scanner": tool, **row})
            per_class += [{"dataset": ds, "scanner": tool, **r} for r in rows]
    out.mkdir(parents=True, exist_ok=True)
    for name, data in (("summary", summary), ("per_class", per_class)):
        with open(out / f"{name}.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(data[0]))
            w.writeheader()
            w.writerows(data)
    for r in summary:
        print(f"{r['dataset'][:9]:9} {r['scanner']:10} all {r['overall_tp']:4}/{r['overall_support']:4}  "
              f"names {r['name_tp']:4}/{r['name_support']:4}  non-name {r['nonname_tp']:4}/{r['nonname_support']:4}  "
              f"FP(V3) {r['fp_v3']} FP(V2) {r['fp_v2']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
