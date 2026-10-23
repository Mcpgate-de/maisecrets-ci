#!/usr/bin/env python3
"""The weekly drift of the catalog coverage: catalog rules that are new since docs/coverage-rules.txt.

    python3 scripts/coverage_drift.py CATALOGS [--fetch] [--out FILE]

--fetch clones or updates each catalog of CATALOGS (shallow, the newest commit; kingfisher at its last commit with
own rules, as it now imports betterleaks and Veles). The script measures this checkout on them
(scripts/measure_catalog_coverage.py) and compares rule by rule with docs/coverage-rules.txt, the per-rule result of
the last release:

- a new catalog rule whose examples maisecrets misses even after a label is a gap: exit 1, and the scheduled job
  turns red;
- a new rule that maisecrets finds only after a label is a candidate for a prefix or signature rule
  (docs/DETECTION-COVERAGE.md, loop 2): listed, exit 0.

Rule ids and counts only, never an example.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "docs" / "coverage-rules.txt"
CATALOGS = {
    "noseyparker": ("https://github.com/praetorian-inc/noseyparker.git", None),
    "kingfisher": ("https://github.com/mongodb/kingfisher.git", "82d050530cdef9af070b8f9a75701c9c27a948c3"),
    "gitleaks": ("https://github.com/gitleaks/gitleaks.git", None),
    "betterleaks": ("https://github.com/betterleaks/betterleaks.git", None),
    "trufflehog": ("https://github.com/trufflesecurity/trufflehog.git", None),
    "gitlab": ("https://gitlab.com/gitlab-org/security-products/secret-detection/secret-detection-rules.git", None),
}


def fetch(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for name, (url, pin) in CATALOGS.items():
        d = root / name
        if not (d / ".git").is_dir():
            subprocess.run(["git", "init", "-q", str(d)], check=True)
            subprocess.run(["git", "-C", str(d), "remote", "add", "origin", url], check=True)
        subprocess.run(["git", "-C", str(d), "fetch", "-q", "--depth", "1", "origin", pin or "HEAD"], check=True)
        subprocess.run(["git", "-C", str(d), "checkout", "-q", "--detach", "FETCH_HEAD"], check=True)


def load_rules(text: str) -> dict:
    """catalog TAB rule TAB bare(0/1) TAB label(0/1) per line -> {(catalog, rule): (bare, label)}"""
    out = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            cat, rule, bare, label = line.split("\t")
            out[(cat, rule)] = (bare == "1", label == "1")
    return out


def dump_rules(rows: list) -> str:
    head = "# catalog\trule\tfound bare\tfound after a label (scripts/measure_catalog_coverage.py; never an example)\n"
    return head + "".join(f"{c}\t{r}\t{int(b)}\t{int(lab)}\n" for c, r, b, lab in sorted(rows))


def drift(before: dict, rows: list) -> tuple:
    """(new rules missed even after a label, new rules found only after a label)."""
    new = [(c, r, b, lab) for c, r, b, lab in rows if (c, r) not in before]
    return ([(c, r) for c, r, _b, lab in new if not lab], [(c, r) for c, r, b, lab in new if lab and not b])


def main(argv: list) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("catalogs", type=Path)
    ap.add_argument("--fetch", action="store_true")
    ap.add_argument("--out", type=Path, default=Path("coverage-drift.json"))
    a = ap.parse_args(argv)
    if a.fetch:
        fetch(a.catalogs)
    subprocess.run([sys.executable, str(ROOT / "scripts" / "measure_catalog_coverage.py"), str(a.catalogs),
                    "--maisecrets", str(ROOT), "--out", str(a.out)], check=True)
    rows = json.loads(a.out.read_text(encoding="utf-8"))["rules"]["maisecrets"]
    gaps, candidates = drift(load_rules(RULES.read_text(encoding="utf-8")), rows)
    print(f"new catalog rules: {len(gaps) + len(candidates)} not found bare; "
          f"{len(gaps)} not found even after a label")
    for c, r in gaps:
        print(f"GAP        {c}\t{r}")
    for c, r in candidates:
        print(f"CANDIDATE  {c}\t{r}")
    return 1 if gaps else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
