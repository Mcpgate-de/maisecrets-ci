"""The report of Benchmark V3 (docs/BENCHMARK-V3.md) from the result files of one run: per source, split and
family, each scanner's strict recall (as in V1 and V2), the precision as V2 counts it, the precision of V3 and the
false positives V3 sets apart because the source labels no value of their class. Counts only, never a value.

    python3 bench/report_v3.py RESULT_DIR > report-v3.md

Every result file must carry a `v3` block (bench/run.py from Benchmark V3 on); one without it is named and left out,
so an old run is never scored twice under different rules."""
from __future__ import annotations

import collections
import json
import sys
from pathlib import Path


def load(d: Path) -> list:
    out = []
    for f in sorted(d.glob("*.json")):
        if f.name == "environment.json" or f.name.startswith("fpbank"):
            continue
        r = json.loads(f.read_text(encoding="utf-8"))
        if "metrics" in r:
            out.append((f.name, r))
    return out


def _fmt(x) -> str:
    return "-" if x is None else f"{x:.3f}" if isinstance(x, float) else str(x)


def main(argv: list) -> int:
    results = load(Path(argv[0]))
    groups = collections.defaultdict(list)
    skipped = []
    for name, r in results:
        if "v3" not in r or (r.get("every", 1) > 1 and not r.get("sample_salt")):
            skipped.append(name)
            continue
        sample = f", sample 1 in {r['every']} (salt `{r['sample_salt']}`)" if r.get("every", 1) > 1 else ""
        groups[(r["source"], r["split"], sample, r["cases_sha256"])].append(r)
    print("# Benchmark V3 report\n")
    print("Recall as in V1 and V2 (strict: the span masked whole). P(V2): a finding on no labelled span is wrong. "
          "P(V3): only a finding of a class the source labels counts (`bench/v3_scope.json`); the rest is listed as "
          "out of scope. A class in `lower bound` has labels a read sample showed not exhaustive: its precision is a "
          "lower bound. Privy is never read: its precision is observed under incomplete annotation.\n")
    if skipped:
        print("Left out, no V3 block or a sample without a salt (an older run): " + ", ".join(skipped) + "\n")
    for (source, split, sample, sha), runs in sorted(groups.items()):
        first = runs[0]
        print(f"## {source}, split {split}{sample} ({first['cases']} cases)\n")
        print(f"Cases sha256 `{sha[:12]}`, benchmark commit `{first['bench_commit'][:8]}`. Lower bound: "
              f"{', '.join(first['v3'].get('lower_bound') or []) or 'none'}.\n")
        for fam in ("secret", "pii"):
            rows = [r for r in runs if fam in r["metrics"] and any(s.startswith(fam) or s.startswith(fam + ".")
                                                                   for s in r["scanner"].get("scope", [fam]))]
            if not rows:
                continue
            print(f"### {fam}\n")
            print("| Scanner | Version | Spans | Recall strict | FP (V2) | P (V2) | FP (V3) | P (V3) | Out of scope "
                  "(V3) |")
            print("|---|---|---:|---:|---:|---:|---:|---:|---|")
            for r in sorted(rows, key=lambda r: r["scanner"].get("scanner", "")):
                m, v = r["metrics"][fam], r["v3"][fam]
                oos = ", ".join(f"{k} {n}" for k, n in sorted(v["out_of_scope"].items(), key=lambda kv: -kv[1])[:4])
                version = r["scanner"].get("version") or ""
                commit = (r["scanner"].get("commit") or "")[:8]
                print(f"| {r['scanner'].get('scanner')} | {version}{f' ({commit})' if commit else ''} | "
                      f"{m.get('spans', 0)} | {_fmt(m.get('recall_strict'))} | {m.get('fp', 0)} | "
                      f"{_fmt(m.get('precision'))} | {v['fp']} | {_fmt(v['precision'])} | {oos or '-'} |")
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
