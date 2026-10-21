"""Two runs of maisecrets on the same cases, side by side: per result file, family and class, and per group.

    python3 bench/history.py OLD_DIR NEW_DIR > history.md

Each directory holds `*-maisecrets.json` from bench/run.py (bench/run_all.sh). A file is compared only when both runs
saw the same cases (cases sha256); otherwise the table names it and leaves it out. Counts only, never a value.

The groups (docs/BENCHMARKS.md): names are pii.name, addresses pii.address, structured PII every other pii class (a
value with a shape: email, phone, card, account, id, date of birth, ip, user name), secrets every secret class."""
from __future__ import annotations

import json
import sys
from pathlib import Path


def group(cls: str) -> str:
    if cls.startswith("secret"):
        return "secrets"
    return {"pii.name": "names", "pii.address": "addresses"}.get(cls, "structured PII")


def load(d: Path) -> dict:
    return {f.name: json.loads(f.read_text(encoding="utf-8")) for f in sorted(d.glob("*-maisecrets.json"))}


def _ratio(n: int, d: int) -> str:
    return f"{n / d:.3f}" if d else "-"


def row(name: str, a: dict, b: dict, fp: bool = True) -> str:
    sp = b.get("spans") or a.get("spans") or 0
    cells = [name, str(sp)]
    for k in ("full", "partial", "missed"):
        x, y = a.get(k) or 0, b.get(k) or 0
        cells.append(f"{x} → {y}" + (f" ({y - x:+d})" if y != x else ""))
    cells.append(f"{_ratio(a.get('full') or 0, sp)} → {_ratio(b.get('full') or 0, sp)}")
    if fp:
        cells.append(f"{a.get('fp') or 0} → {b.get('fp') or 0}")
        cells.append(f"{a.get('precision', '-')} → {b.get('precision', '-')}")
    else:
        cells += ["", ""]
    return "| " + " | ".join(cells) + " |"


HEAD = ("| | Spans | Whole | Partial | Missed | Recall strict | FP | Precision |\n"
        "|---|---:|---:|---:|---:|---:|---:|---:|")


def main(argv: list) -> int:
    old, new = load(Path(argv[0])), load(Path(argv[1]))
    va = next(iter(old.values()))["scanner"]["version"]
    vb = next(iter(new.values()))["scanner"]["version"]
    print(f"maisecrets {va} → {vb}. Cells: {va} → {vb} (change). The false positives and the precision are counted "
          "per family; a class row has none.\n")
    totals: dict = {}
    for name in sorted(set(old) & set(new)):
        a, b = old[name], new[name]
        if a["cases_sha256"] != b["cases_sha256"]:
            print(f"## {name}\n\nThe cases differ (sha256 {a['cases_sha256'][:12]} vs {b['cases_sha256'][:12]}): "
                  "not compared.\n")
            continue
        sample = f", sample 1 in {b['every']}" if b.get("every", 1) > 1 else ""
        print(f"## {b['source']}, split {b['split']}{sample} ({b['cases']} cases)\n\n"
              f"Cases sha256 `{b['cases_sha256'][:12]}`.\n\n{HEAD}")
        ma, mb = a["metrics"], b["metrics"]
        for fam in ("secret", "pii"):
            if fam not in mb:
                continue
            print(row(f"**{fam}**", ma.get(fam, {}), mb[fam]))
            for cls in sorted(k for k in mb if k.startswith(fam + ".")):
                print(row(cls, ma.get(cls, {}), mb[cls], fp=False))
                if b.get("every", 1) == 1 and b["source"] != "bank":
                    t = totals.setdefault(group(cls), [{}, {}])
                    for side, m in ((0, ma.get(cls, {})), (1, mb[cls])):
                        for k in ("spans", "full", "partial", "missed"):
                            t[side][k] = t[side].get(k, 0) + (m.get(k) or 0)
        print()
    if totals:
        print("## By group, the four PII datasets and the catalogs in full\n\n" + HEAD)
        for g in ("names", "addresses", "structured PII", "secrets"):
            if g in totals:
                print(row(g, *totals[g], fp=False))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
