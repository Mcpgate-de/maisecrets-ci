#!/usr/bin/env python3
"""Write the Markdown tables of Benchmark V1 from result files of bench/run.py.

    python3 bench/report.py [--allow-dirty] RESULT.json [RESULT.json ...] > report.md

One table per source and split and per family: a scanner gets a row in a family table only when its scope claims
that family, so a PII scanner is not listed under secrets and a secret scanner not under personal data. A rate is "-"
where a group has fewer than 30 spans (bench/score.py, MIN_RATE)."""
from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path


def _f(x, digits=3):
    return "-" if x is None else f"{x:.{digits}f}" if isinstance(x, float) else str(x)


def claims(scope, family: str) -> bool:
    return any(s == family + "." or s.startswith(family + ".") or s == family for s in scope)


def _scanner_dirty(r: dict):
    """A maisecrets result must name the state of its checkout (a missing field is unknown, not clean); the other
    scanners are installed packages whose identity the adapter checked."""
    s = r["scanner"]
    return s.get("dirty") if s.get("scanner") == "maisecrets" else s.get("dirty", False)


def main(argv) -> int:
    allow_dirty = "--allow-dirty" in argv
    argv = [a for a in argv if a != "--allow-dirty"]
    runs = [json.loads(Path(p).read_text(encoding="utf-8")) for p in argv]
    # a result without a benchmark commit or a known state is never compared, not even in a draft
    unknown = [p for p, r in zip(argv, runs)
               if not re.fullmatch(r"[0-9a-f]{40}", str(r.get("bench_commit", "")))
               or not isinstance(r.get("bench_dirty"), bool) or not isinstance(_scanner_dirty(r), bool)]
    if unknown:
        sys.stderr.write("results without a benchmark commit or a known tree state: " + ", ".join(unknown) + "\n")
        return 2
    dirty = [p for p, r in zip(argv, runs) if r["bench_dirty"] or _scanner_dirty(r)]
    if dirty and not allow_dirty:
        # a modified benchmark or maisecrets tree is not the commit the result names: no comparison from it
        sys.stderr.write("results from a modified tree or without a benchmark commit (--allow-dirty for a draft): "
                         + ", ".join(dirty) + "\n")
        return 2
    groups = collections.defaultdict(list)
    for r in runs:
        # only runs on the same cases with the same benchmark share a table
        groups[(r["source"], r["split"], r.get("every", 1), r.get("cases_sha256", "?"), r.get("bench_commit", "?"))
               ].append(r)
    out = []
    for (source, split, every, chash, commit), rs in sorted(groups.items()):
        n = rs[0]["cases"]
        sample = f", sample 1 in {every}" if every > 1 else ""
        dirty = " (benchmark tree modified)" if any(r.get("bench_dirty") for r in rs) else ""
        out.append(f"## {source}, split {split}{sample} ({n} cases)\n")
        out.append(f"Cases sha256 `{chash[:12]}`, benchmark commit `{commit[:8]}`{dirty}.\n")
        for fam in ("secret", "pii"):
            rows = [r for r in rs if claims(r["scanner"].get("scope", []), fam) and r["metrics"].get(fam)]
            if not rows:
                continue
            out.append(f"### {fam}\n")
            out.append("| Scanner | Version | Spans | Full | Partial | Missed | Recall strict | Recall lenient | "
                       "Char recall | Family right | FP | Precision | F1 | Too wide (all) | FP / 1000 negative (all) | "
                       "Median ms |")
            out.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
            for r in sorted(rows, key=lambda r: r["scanner"]["scanner"]):
                m, a, s = r["metrics"][fam], r["metrics"]["all"], r["scanner"]
                ver = s.get("version") or ""
                if s.get("commit"):
                    ver += f" ({s['commit'][:8]})"
                out.append(f"| {s['scanner']} | {ver} | {m.get('spans', 0)} | {m.get('full', 0)} | "
                           f"{m.get('partial', 0)} | {m.get('missed', 0)} | {_f(m.get('recall_strict'))} | "
                           f"{_f(m.get('recall_lenient'))} | {_f(m.get('char_recall'))} | "
                           f"{_f(m.get('family_right_rate'))} | {m.get('fp', 0)} | {_f(m.get('precision'))} | "
                           f"{_f(m.get('f1'))} | {a.get('too_wide', 0)} | "
                           f"{_f(a.get('fp_per_1000_negative'), 1)} | {_f(r['timing'].get('median_ms'), 2)} |")
            out.append("")
            classes = sorted({k for r in rows for k in r["metrics"] if k.startswith(fam + ".")})
            if classes:
                out.append("| Class | " + " | ".join(r["scanner"]["scanner"] for r in rows) + " |")
                out.append("|---|" + "---|" * len(rows))
                for c in classes:
                    cells = []
                    for r in rows:
                        m = r["metrics"].get(c, {})
                        cells.append(f"{m.get('full', 0)} / {m.get('partial', 0)} / {m.get('missed', 0)}"
                                     if m else "-")
                    out.append(f"| {c} | " + " | ".join(cells) + " |")
                out.append("\nCells: full / partial / missed spans.\n")
    sys.stdout.write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
