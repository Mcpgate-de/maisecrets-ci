#!/usr/bin/env python3
"""Compare a release with the one before it, per dataset, split and class (docs/REGRESSION-POLICY.md).

    python3 scripts/release_compare.py PREV NEW OUT_DIR [--reuse-prev DIR] [--reuse-new DIR] [--sources a,b]

PREV and NEW are tags or commits of this repository. For each, a detached worktree is measured with bench/run.py on the
`dev` and `val` splits of the development sources (default nemotron, gretel, mendeley, piilo, bank, traces) and the
false-alarm bank when its cache is given (MAISECRETS_FPBANK_CACHE); `--reuse-*` takes an existing result directory
instead of a run. Privy is measured as totals only (`privy-all`), as Benchmark V2 allows; the holdout never.

OUT_DIR/release-compare.md holds, per source and split: whole, partial and missed spans, false positives, precision,
recall and F1 of both, the change, and the median time per case (reported, never judged: it moves 26 to 233 % between
runs of the same code); then the five largest gains and the five largest regressions by class, and the findings of
scripts/compare_bench.py. The counts are deterministic, so every change in them is real."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import compare_bench  # noqa: E402

SOURCES = ("nemotron", "gretel", "mendeley", "piilo", "bank", "traces")
FIELDS = ("full", "partial", "missed", "fp", "precision", "recall_strict", "f1")


def measure(ref: str, out: Path, sources) -> Path:
    """bench/run.py of this checkout against a detached worktree of `ref`."""
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="relcmp-") as tmp:
        wt = Path(tmp) / "wt"
        subprocess.run(["git", "-C", str(ROOT), "worktree", "add", "-q", "--detach", str(wt), ref], check=True)
        try:
            runs = [(s, sp) for s in sources for sp in ("dev", "val")] + [("privy", "all")]
            for src, split in runs:
                subprocess.run([sys.executable, str(ROOT / "bench" / "run.py"), "--scanner", "maisecrets",
                                "--maisecrets", str(wt), "--source", src, "--split", split,
                                "--out", str(out / f"{src}-{split}-maisecrets.json")],
                               check=False, capture_output=True, cwd=ROOT)
            cache = os.environ.get("MAISECRETS_FPBANK_CACHE")
            if cache:
                subprocess.run([sys.executable, "scripts/measure_fp_bank.py", "measure", cache, "--json",
                                str(out / "fpbank-7trees.json")], check=False, capture_output=True, cwd=wt)
        finally:
            subprocess.run(["git", "-C", str(ROOT), "worktree", "remove", "--force", str(wt)], check=False)
    return out


def _load(d: Path) -> dict:
    out = {}
    for f in sorted(Path(d).glob("*-maisecrets.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        out[f.name[:-len("-maisecrets.json")]] = data
    return out


def _fmt(v) -> str:
    if v is None:
        return "-"
    return f"{v:,}" if isinstance(v, int) else f"{v:.4f}"


def _delta(a, b) -> str:
    if a is None or b is None:
        return ""
    d = b - a
    if d == 0:
        return "±0"
    return f"{d:+,}" if isinstance(d, int) else f"{d:+.4f}"


def report(prev: Path, new: Path, prev_name: str, new_name: str) -> str:
    a, b = _load(prev), _load(new)
    lines = [f"# Release comparison: {prev_name} → {new_name}", "",
             "Counts are deterministic; the median time per case is reported, never judged.", ""]
    changes = []
    for name in sorted(set(a) & set(b)):
        ma, mb = a[name]["metrics"], b[name]["metrics"]
        lines += [f"## {name}", "", "| Measure | " + prev_name + " | " + new_name + " | change |", "|---|---|---|---|"]
        for f in FIELDS:
            x, y = ma.get("all", {}).get(f), mb.get("all", {}).get(f)
            lines.append(f"| {f} | {_fmt(x)} | {_fmt(y)} | {_delta(x, y)} |")
        ta, tb = a[name].get("timing", {}).get("median_ms"), b[name].get("timing", {}).get("median_ms")
        lines += [f"| median ms per case (not judged) | {_fmt(ta)} | {_fmt(tb)} | |", ""]
        for cls in sorted(k for k in set(ma) | set(mb) if k.count(".") == 1):
            x, y = ma.get(cls, {}), mb.get(cls, {})
            for f, sign in (("full", 1), ("partial", -1), ("fp", -1)):
                d = (y.get(f) or 0) - (x.get(f) or 0)
                if d:
                    changes.append((sign * d, f"{name}: {cls} {f} {x.get(f) or 0:,} → {y.get(f) or 0:,}"))
    changes.sort(key=lambda c: c[0])
    gains = [c for c in reversed(changes) if c[0] > 0][:5]
    losses = [c for c in changes if c[0] < 0][:5]
    lines += ["## Largest gains", ""] + [f"- {t}" for _, t in gains] + ([] if gains else ["- none"]) + [""]
    lines += ["## Largest regressions", ""] + [f"- {t}" for _, t in losses] + ([] if losses else ["- none"]) + [""]
    findings = compare_bench.compare(prev, new)
    lines += ["## Findings of scripts/compare_bench.py", ""] + [f"- {f}" for f in findings] + \
        ([] if findings else ["- none"]) + [""]
    return "\n".join(lines)


def main(argv) -> int:
    pos = [x for i, x in enumerate(argv) if not x.startswith("--") and (i == 0 or not argv[i - 1].startswith("--"))]
    if len(pos) != 3:
        sys.stderr.write(__doc__)
        return 2
    prev, new, out = pos[0], pos[1], Path(pos[2])
    opt = {argv[i]: argv[i + 1] for i in range(len(argv) - 1) if argv[i].startswith("--")}
    sources = tuple(opt.get("--sources", ",".join(SOURCES)).split(","))
    out.mkdir(parents=True, exist_ok=True)
    pdir = Path(opt["--reuse-prev"]) if "--reuse-prev" in opt else measure(prev, out / prev, sources)
    ndir = Path(opt["--reuse-new"]) if "--reuse-new" in opt else measure(new, out / new, sources)
    (out / "release-compare.md").write_text(report(pdir, ndir, prev, new), encoding="utf-8")
    print(f"report: {out / 'release-compare.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
