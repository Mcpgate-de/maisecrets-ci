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

ADAPTERS = ("maisecrets", "detect_secrets", "secret_scan", "pii_anon", "preserve", "presidio", "maisecrets_ner",
            "ai_gateway")
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


def release_candidate(checkout: Path) -> str:
    """The commit of a maisecrets checkout when it may meet Holdout V2: a clean tree whose HEAD is the tip of `next`
    (the head of a release merge request) or of `main`, or carries a release tag. A feature branch never does."""
    def git(*args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        r = subprocess.run(["git", "-C", str(checkout), *args], capture_output=True, text=True, timeout=30, env=env)
        return r.stdout.strip() if r.returncode == 0 else ""
    head = git("rev-parse", "HEAD")
    if not head or git("status", "--porcelain"):
        raise SystemExit("refused: Holdout V2 runs on a clean maisecrets checkout only")
    tips = {git("rev-parse", "origin/next"), git("rev-parse", "origin/main")} - {""}
    tagged = [t for t in git("tag", "--points-at", head).split() if re.fullmatch(r"v\d+\.\d+\.\d+", t)]
    if head not in tips and not tagged:
        raise SystemExit("refused: Holdout V2 runs only on a release candidate (the tip of next or main, or a v tag)")
    return head


def in_sample(case_id: str, every: int, salt: str = "") -> bool:
    """The fixed sample: sha256 of the id modulo `every`. Without a salt it is the hash of the split rule
    (bench/cases.py, split_of) taken modulo a multiple of 10, so every sample of V1 and V2 lies in `dev` alone; the
    salt of Benchmark V3 makes the sample independent of the split (2026-10-21)."""
    return every <= 1 or int(hashlib.sha256((salt + case_id).encode()).hexdigest()[:8], 16) % every == 0


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
    out = {"api": timing.get("api"), "cold_start_ms": round(1000 * (timing.get("cold_start_s") or 0), 1),
           "median_ms": round(1000 * statistics.median(t), 3), "p95_ms": round(1000 * t[int(0.95 * (len(t) - 1))], 3),
           "total_s": round(total, 2), "kb_per_s": round(n_bytes / 1024 / total, 1) if total else None}
    if "ner" in timing:     # the NER experiment's layer alone (bench/adapters/maisecrets_ner.py)
        out["ner"] = {**timing["ner"], **timing_summary({"times_s": timing["ner_times_s"],
                                                         "cold_start_s": timing["ner"].get("cold_start_s")}, n_bytes)}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scanner", choices=ADAPTERS, default="maisecrets")
    ap.add_argument("--maisecrets", type=Path, default=ROOT, help="the checkout the maisecrets adapter scans with")
    ap.add_argument("--regions", default="de,us")
    ap.add_argument("--source", required=True, choices=sources.SOURCES + ("holdout", "holdout-v2"))
    ap.add_argument("--split", choices=casefmt.SPLITS + ("all",), default="dev")
    ap.add_argument("--data", type=Path)
    ap.add_argument("--catalogs", type=Path)
    ap.add_argument("--holdout", type=Path, help="the private bank (source holdout) or the sealed cases (holdout-v2)")
    ap.add_argument("--release-candidate", action="store_true",
                    help="holdout-v2 only: this run measures a release candidate (bench/holdout_v2.py)")
    ap.add_argument("--limit", type=int, default=0, help="read at most N records of a dataset (a quick run)")
    ap.add_argument("--every", type=int, default=1, help="a fixed sample: keep a case when sha256 of its id is a "
                    "multiple of N (the same cases for every scanner)")
    ap.add_argument("--sample-salt", default="", help="Benchmark V3: a salt for --every, so the sample does not "
                    "follow the split (V3 uses v3/)")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)

    stats = collections.Counter()
    if a.source == "holdout":
        if not a.holdout:
            raise SystemExit("--source holdout needs --holdout DIR")
        selected, a.split = holdout_cases(a.holdout), "holdout"
    elif a.source == "holdout-v2":
        if not a.holdout or not a.release_candidate:
            raise SystemExit("--source holdout-v2 needs --holdout DIR and --release-candidate")
        if a.scanner == "maisecrets":
            release_candidate(a.maisecrets.resolve())
        from bench import holdout_v2
        try:
            selected, a.split = holdout_v2.verify(a.holdout), "holdout"
        except holdout_v2.HoldoutError as e:
            raise SystemExit(f"refused: {e}") from None
    else:
        selected = [c for c in sources.load(a.source, a.data, a.catalogs, a.limit, stats)
                    if (a.split == "all" or c["split"] == a.split) and in_sample(c["id"], a.every, a.sample_salt)]
    adapter = importlib.import_module(f"bench.adapters.{a.scanner}")
    if a.scanner in ("maisecrets", "maisecrets_ner"):
        desc = adapter.describe(a.maisecrets.resolve(), a.regions)
        found, timing = adapter.scan(selected, a.maisecrets.resolve(), a.regions)
    else:
        desc = adapter.describe()
        found, timing = adapter.scan(selected)
    results = [(c, score.score_case(c, [f[:3] for f in fs], adapter.SCOPE)) for c, fs in zip(selected, found)]
    # the private holdout (its source), never the public holdout split of a dataset: `--split holdout` on a dataset
    # wrote rows to bench/HOLDOUT-LOG.md and left out the outcomes per case (found by Benchmark V3, 2026-10-21)
    holdout = a.source in ("holdout", "holdout-v2")
    out = {
        "date": datetime.date.today().isoformat(), "bench_commit": _commit(), "bench_dirty": _dirty(),
        "scanner": desc, "source_meta": source_meta(selected), "cases_sha256": cases_hash(selected),
        "source": a.source, "split": a.split, "limit": a.limit, "every": a.every, "cases": len(selected),
        **({"sample_salt": a.sample_salt} if a.sample_salt else {}),
        "dataset_stats": dict(stats),
        "metrics": score.aggregate(results),
        "by_region": score.aggregate(results, lambda c, s: f"{c.get('region', '-')}/{s['class']}"),
        "by_context": score.aggregate(results, lambda c, s: f"{c['context']}/{s['class']}"),
        "timing": timing_summary(timing, sum(sc["bytes"] for _, sc in results)),
    }
    # Benchmark V3: precision only where the source labels it; a sample counts only with a salt (without one a sample
    # of 1 in 10 or a multiple of it lies in `dev` alone, the fault of V1 and V2)
    if not holdout and (a.every <= 1 or a.sample_salt):
        from bench import v3
        out["v3"] = v3.metrics(a.source, results)
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
