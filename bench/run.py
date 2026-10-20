#!/usr/bin/env python3
"""Run one scanner on one source of Benchmark V1 and write a result file (docs/BENCHMARK-V1.md).

    python3 bench/run.py --scanner maisecrets --maisecrets DIR [--regions de,us] --source NAME
        [--split dev|val|holdout|all] [--data DIR] [--catalogs DIR] [--holdout DIR] [--limit N] [--out FILE]

The result file holds the description of the scanner, the source and its split, the metrics per class, family,
region and context, the timing, and the outcome per case id. It holds no text and no value. For the holdout split it
holds totals only, and the run adds one line to bench/HOLDOUT-LOG.md."""
from __future__ import annotations

import argparse
import collections
import datetime
import hashlib
import importlib
import json
import os
import re
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import cases as casefmt  # noqa: E402
from bench import score, sources  # noqa: E402

ADAPTERS = ("maisecrets", "detect_secrets", "secret_scan", "pii_anon", "preserve", "presidio")
HOLDOUT_LOG = ROOT / "bench" / "HOLDOUT-LOG.md"
MANIFEST = ROOT / "bench" / "holdout.manifest"


def holdout_cases(directory: Path) -> list:
    """The private bank: its files must match bench/holdout.manifest (sha256 per file), so it cannot change unseen."""
    want = {}
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            digest, name = line.split(None, 1)
            want[name] = digest
    have = {p.relative_to(directory).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(Path(directory).rglob("*.jsonl"))}
    if have != want:
        raise SystemExit("the holdout directory does not match bench/holdout.manifest")
    out = casefmt.load_bank(Path(directory))
    if any(c["split"] != "holdout" for c in out):
        raise SystemExit("a case of the holdout directory is not in the holdout split")
    return out


def in_sample(case_id: str, every: int) -> bool:
    return every <= 1 or int(hashlib.sha256(case_id.encode()).hexdigest()[:8], 16) % every == 0


def _git(*args) -> str:
    """git in this checkout, without the GIT_* of a caller (GIT_DIR would point it elsewhere); a failure ends the run,
    so a result never names a commit or a clean tree it could not read."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    try:
        p = subprocess.run(["git", "-C", str(ROOT), "-c", "core.fsmonitor=false", *args], capture_output=True,
                           text=True, timeout=30, env=env)
    except (OSError, subprocess.SubprocessError) as e:
        raise SystemExit(f"git failed: {type(e).__name__}") from None
    if p.returncode:
        raise SystemExit(f"git {args[0]} failed with exit code {p.returncode}")
    return p.stdout.strip()


def _commit() -> str:
    c = _git("rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", c):
        raise SystemExit("the benchmark checkout has no commit")
    return c


def _dirty() -> bool:
    """Whether the benchmark itself (bench/, the scripts it imports) differs from the commit it names."""
    # bench/HOLDOUT-LOG.md is written by the runner itself: a new row is no change of the benchmark
    return bool(_git("status", "--porcelain", "--", "bench", "scripts/measure_datasets.py",
                     "scripts/measure_catalog_coverage.py", ":(exclude)bench/HOLDOUT-LOG.md"))


def source_meta(selected: list) -> dict:
    """The provenance the cases carry (name, url, commit or revision, licence), the same for every case of a source."""
    metas = {json.dumps({k: v for k, v in c["source"].items() if k != "record"}, sort_keys=True) for c in selected}
    return {"provenance": [json.loads(m) for m in sorted(metas)], "provenances": len(metas)}


def cases_hash(selected: list) -> str:
    """The sha256 of what every scanner sees and is scored on: id, text, channel, context, path and spans, in order."""
    h = hashlib.sha256()
    for c in selected:
        h.update(json.dumps([c["id"], c["text"], c["channel"], c["context"], c.get("path"), c["spans"]],
                            sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n")
    return h.hexdigest()


def timing_summary(timing: dict, n_bytes: int) -> dict:
    t = sorted(timing.get("times_s") or [0.0])
    total = sum(t)
    return {"api": timing.get("api"), "cold_start_ms": round(1000 * (timing.get("cold_start_s") or 0), 1),
            "median_ms": round(1000 * statistics.median(t), 3), "p95_ms": round(1000 * t[int(0.95 * (len(t) - 1))], 3),
            "total_s": round(total, 2), "kb_per_s": round(n_bytes / 1024 / total, 1) if total else None}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scanner", choices=ADAPTERS, default="maisecrets")
    ap.add_argument("--maisecrets", type=Path, default=ROOT, help="the checkout the maisecrets adapter scans with")
    ap.add_argument("--regions", default="de,us")
    ap.add_argument("--source", required=True, choices=sources.SOURCES + ("holdout",))
    ap.add_argument("--split", choices=casefmt.SPLITS + ("all",), default="dev")
    ap.add_argument("--data", type=Path)
    ap.add_argument("--catalogs", type=Path)
    ap.add_argument("--holdout", type=Path, help="the private bank (source holdout)")
    ap.add_argument("--limit", type=int, default=0, help="read at most N records of a dataset (a quick run)")
    ap.add_argument("--every", type=int, default=1, help="a fixed sample: keep a case when sha256 of its id is a "
                    "multiple of N (the same cases for every scanner)")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)

    stats = collections.Counter()
    if a.source == "holdout":
        if not a.holdout:
            raise SystemExit("--source holdout needs --holdout DIR")
        selected, a.split = holdout_cases(a.holdout), "holdout"
    else:
        selected = [c for c in sources.load(a.source, a.data, a.catalogs, a.limit, stats)
                    if (a.split == "all" or c["split"] == a.split) and in_sample(c["id"], a.every)]
    adapter = importlib.import_module(f"bench.adapters.{a.scanner}")
    if a.scanner == "maisecrets":
        desc = adapter.describe(a.maisecrets.resolve(), a.regions)
        found, timing = adapter.scan(selected, a.maisecrets.resolve(), a.regions)
    else:
        desc = adapter.describe()
        found, timing = adapter.scan(selected)
    results = [(c, score.score_case(c, [f[:3] for f in fs], adapter.SCOPE)) for c, fs in zip(selected, found)]
    holdout = a.split == "holdout"
    out = {
        "date": datetime.date.today().isoformat(), "bench_commit": _commit(), "bench_dirty": _dirty(),
        "scanner": desc, "source_meta": source_meta(selected), "cases_sha256": cases_hash(selected),
        "source": a.source, "split": a.split, "limit": a.limit, "every": a.every, "cases": len(selected),
        "dataset_stats": dict(stats),
        "metrics": score.aggregate(results),
        "by_region": score.aggregate(results, lambda c, s: f"{c.get('region', '-')}/{s['class']}"),
        "by_context": score.aggregate(results, lambda c, s: f"{c['context']}/{s['class']}"),
        "timing": timing_summary(timing, sum(sc["bytes"] for _, sc in results)),
    }
    if holdout:
        out.pop("by_region")
        out.pop("by_context")
        with open(HOLDOUT_LOG, "a", encoding="utf-8") as f:
            m = out["metrics"].get("all", {})
            f.write(f"| {out['date']} | {desc.get('scanner')} {desc.get('version')} {desc.get('commit') or ''} | "
                    f"{a.source} | {len(selected)} | {m.get('recall_strict')} | {m.get('precision')} | "
                    f"{m.get('fp')} |\n")
    else:
        out["per_case"] = {c["id"]: [s["outcome"] for s in sc["spans"]] + (["fp"] * sc["fp"])
                           for c, sc in results}
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    m = out["metrics"].get("all", {})
    print(f"{desc.get('scanner')} {desc.get('version') or ''} on {a.source}/{a.split}: {len(selected)} cases, "
          f"spans {m.get('spans', 0)}, full {m.get('full', 0)}, partial {m.get('partial', 0)}, "
          f"missed {m.get('missed', 0)}, FP {m.get('fp')}, recall {m.get('recall_strict')}, "
          f"precision {m.get('precision')}, F1 {m.get('f1')}, too wide {m.get('too_wide')}")
    for key, r in out["metrics"].items():
        if key != "all":
            print(f"  {key:28} spans {r.get('spans', 0):6}  full {r.get('full', 0):6}  partial {r.get('partial', 0):5}"
                  f"  missed {r.get('missed', 0):6}  FP {r.get('fp', 0):5}  R {r.get('recall_strict', '-')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
