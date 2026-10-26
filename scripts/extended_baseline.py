#!/usr/bin/env python3
"""The extended baseline of a release: Benchmark V3 plus the newer sets, for maisecrets and the other scanners.

    python3 scripts/extended_baseline.py CANDIDATE OUT [--v3 DIR] [--ghissues DIR] [--nym DIR] [--dialogpii DIR]
        [--structured-b FILE] [--catalogs DIR] [--reuse DIR] [--only GLOB ...] [--plan] [--keep]

CANDIDATE is a clean checkout of the release candidate; OUT a new directory for the run. Three sections, each apart:

1. **Benchmark V3** (docs/BENCHMARK-V3.md). maisecrets: the results of the release gate (--v3 OUT of
   scripts/release_gate.py), else bench/run_all_v3.sh runs for maisecrets alone. The other scanners: the results of
   the published V3 run (--reuse, default bench/results/2026-10-21-v3/run) are reused only where the dataset and split
   (cases_sha256), the scoring (bench/score.py and the V3 scope of the source), the configuration (the adapter and its
   pinned requirements) and the scanner version are unchanged (`reuse_check`); otherwise the scanner runs again.
2. **New sets**, never mixed into the V3 tables or their denominators: nym and DialogPII (PII), the GitHub-issues
   secret set and the catalog examples (secrets), the structured corpus set A (dev, val) and set B (holdout). PII
   scanners (Presidio, Preserve, pii-anon) run on the PII sets and the structured corpus; the secret scanners on the
   GitHub issues and the catalogs; maisecrets on all.
3. **Comparisons**: the candidate against the last release (bench/results/*-v3-<last version>) and against the
   published 0.7.3 baseline (bench/results/2026-10-21-v3), V3 only.

Scoring is that of V3 (bench/score.py, strict span level). The GitHub-issues set has labelled candidates, so its
result also carries the snippet level (`ghissues` block, a finding on a candidate), labelled as such. The structured
corpus is a targeted regression benchmark, not independent evidence of competitive superiority: every row of it says
so. A holdout split runs for totals only (bench/run.py) and adds one row to bench/HOLDOUT-LOG.md: run the holdouts once,
on the final candidate. Nobody tunes a rule on a holdout total.

OUT gets one result file per run, `index.json` (section, label, level, reuse decision of each file), `report.md`,
`environment.json` (bench/manifest.py) and `tools.json`; with --resources also `resources.json` and `resources.md`
(scripts/measure_resources.py: cold start, warm latency, peak RSS and install footprint of each scanner, run after the
result runs, one scanner at a time). With --keep, OUT goes to
bench/results/<date>-v3-<next version>/extended/ as scripts/release_gate.py keeps its baseline: JSON as gzip,
measured.json (commit, runtime trees, tool versions, environment) and SHA256SUMS. Counts only, never a value.

A scanner whose environment variable is not set is listed as not run. --plan prints the runs and the reuse decisions
and runs nothing; --only keeps the runs whose file name matches a glob (a dry run on one small set)."""
from __future__ import annotations

import argparse
import collections
import datetime
import fnmatch
import gzip
import importlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import release_gate  # noqa: E402

PUBLISHED_073 = ROOT / "bench" / "results" / "2026-10-21-v3"
REUSE_DEFAULT = PUBLISHED_073 / "run"
PII_SCANNERS = ("presidio", "preserve", "pii_anon")
SECRET_SCANNERS = ("detect_secrets", "gitleaks", "betterleaks", "trufflehog", "kingfisher", "kingfisher1",
                   "noseyparker")
# the environment a scanner needs: a Python (bench/run_all.sh) or a release binary (bench/adapters/_filescan.py)
SCANNER_ENV = {"detect_secrets": "BENCH_DETECT_SECRETS_PYTHON", "secret_scan": "BENCH_SECRET_SCAN_PYTHON",
               "pii_anon": "BENCH_PII_ANON_PYTHON", "preserve": "BENCH_PRESERVE_PYTHON",
               "presidio": "BENCH_PRESIDIO_PYTHON", "ai_gateway": "BENCH_GATEWAY_PYTHON",
               "gitleaks": "BENCH_GITLEAKS", "betterleaks": "BENCH_BETTERLEAKS", "trufflehog": "BENCH_TRUFFLEHOG",
               "kingfisher": "BENCH_KINGFISHER", "kingfisher1": "BENCH_KINGFISHER1", "noseyparker": "BENCH_NOSEYPARKER"}
REGRESSION = ("targeted regression benchmark: written for the known gaps of maisecrets, not independent evidence of "
              "competitive superiority (docs/BENCHMARK-STRUCTURED.md)")
SPAN = "span level, strict (bench/score.py)"
SNIPPET = "span level, strict; and snippet level: a finding on a labelled candidate (bench/ghissues.py)"
SALT = "v3/"


# ---------------------------------------------------------------------------------------------------------- the runs

def job(section: str, source: str, split: str, scanner: str, every: int = 1, salt: str = "", label: str = "",
        level: str = SPAN) -> dict:
    sample = f"every{every}" if every > 1 else "full"
    return {"section": section, "source": source, "split": split, "scanner": scanner, "every": every,
            "salt": salt if every > 1 else "", "label": label, "level": level,
            "name": f"{source}-{split}-{sample}-{scanner}.json"}


# Preserve scans about 2 KB/s (Benchmark V3, 2026-10-21): on the two large PII sets it reads a smaller salted sample,
# and maisecrets runs on the same sample, so each comparison is paired
SLOW = {"preserve": {"nym": 125, "dialogpii": 5}}


def new_jobs() -> list:
    """The runs of section 2. nym is large: maisecrets on 1 in 5 (salted, as its holdout row), the PII scanners on
    the same 1 in 25; the other sets in full; a slow scanner on its smaller sample (SLOW), and last."""
    jobs = []
    pii_fast = tuple(s for s in PII_SCANNERS if s not in SLOW)
    for split in ("dev", "val", "holdout"):
        jobs.append(job("new-pii", "nym", split, "maisecrets", 5, SALT))
        for s in ("maisecrets",) + pii_fast:
            jobs.append(job("new-pii", "nym", split, s, 25, SALT))
        for s in ("maisecrets",) + pii_fast:
            jobs.append(job("new-pii", "dialogpii", split, s))
    for split in ("dev", "val"):
        for s in ("maisecrets",) + PII_SCANNERS:
            jobs.append(job("new-structured", "structured", split, s, label=REGRESSION))
    for s in ("maisecrets",) + PII_SCANNERS:
        jobs.append(job("new-structured", "structured-b", "holdout", s, label=REGRESSION))
    for split in ("dev", "holdout"):
        for s in ("maisecrets",) + SECRET_SCANNERS:
            jobs.append(job("new-secret", "ghissues", split, s, level=SNIPPET))
    for source in ("catalogs", "catalogs-example"):
        for s in ("maisecrets",) + SECRET_SCANNERS:
            jobs.append(job("new-secret", source, "all", s))
    for s, samples in SLOW.items():
        for source, every in samples.items():
            for split in ("dev", "val", "holdout"):
                for scanner in ("maisecrets", s):
                    jobs.append(job("new-pii", source, split, scanner, every, SALT))
    return jobs


def run_args(j: dict, cand: Path, data: dict, out: Path) -> list | None:
    """The bench/run.py arguments of one run, or None when its data is not given."""
    args = ["bench/run.py", "--scanner", j["scanner"], "--maisecrets", str(cand), "--source", j["source"],
            "--split", j["split"], "--out", str(out)]
    if j["every"] > 1:
        args += ["--every", str(j["every"])] + (["--sample-salt", j["salt"]] if j["salt"] else [])
    if j.get("limit"):
        args += ["--limit", str(j["limit"])]
    need = {"ghissues": "ghissues", "nym": "nym", "dialogpii": "dialogpii"}.get(j["source"])
    if need:
        if not data.get(need):
            return None
        args += ["--data", str(data[need])]
    if j["source"] in ("catalogs", "catalogs-example"):
        if not data.get("catalogs"):
            return None
        args += ["--catalogs", str(data["catalogs"])]
    if j["source"] == "structured-b":
        if not data.get("structured_b"):
            return None
        args += ["--holdout", str(data["structured_b"]), "--release-candidate"]
    return args


def missing_env(scanner: str, env: dict) -> str | None:
    var = SCANNER_ENV.get(scanner)
    return var if var and not env.get(var) else None


# ---------------------------------------------------------------------------------------------------------- reuse

def _load(path: Path) -> dict:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        return json.load(f)


def scanner_of(name: str) -> str:
    """The adapter module of a result file name: the last part, `bank-dev-pii_anon.json.gz` → pii_anon."""
    return name.split(".json")[0].rsplit("-", 1)[1]


def requirement_pins(scanner: str, root: Path = ROOT) -> dict:
    f = root / "bench" / "adapters" / "requirements" / (scanner.replace("_", "-") + ".txt")
    if not f.is_file():
        return {}
    pins = {}
    for line in f.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if "==" in line:
            name, version = line.split("==", 1)
            pins[name.strip().lower().replace("_", "-")] = version.strip()
    return pins


def _installed(desc: dict) -> dict:
    out = {}
    for item in desc.get("installed") or []:
        if isinstance(item, str) and "==" in item:
            name, version = item.split("==", 1)
            out[name.strip().lower().replace("_", "-")] = version.strip()
    return out


def _unchanged(commit: str, paths: list, root: Path = ROOT) -> bool | None:
    """True when none of the paths changed from `commit` to HEAD; None when the commit is unknown here."""
    if not commit or subprocess.run(["git", "cat-file", "-e", commit + "^{commit}"], cwd=root,
                                    capture_output=True).returncode:
        return None
    return subprocess.run(["git", "diff", "--quiet", commit, "HEAD", "--", *paths], cwd=root,
                          capture_output=True).returncode == 0


IDENTITY_KEYS = ("scanner", "version", "configuration", "detectors", "dependencies", "scope", "rules", "variant",
                 "binary_sha256", "installed")


def reuse_check(stored: dict, scanner: str, now_cases_sha256: str | None, now_scope, describe_now: dict | None,
                code_unchanged: bool | None, score_unchanged: bool | None) -> list:
    """Why a stored result of another scanner cannot be reused (empty: reuse it). Each condition must hold:
    the same cases (dataset and split), the same scoring, the same configuration and the same scanner version."""
    why = []
    if now_cases_sha256 is None:
        why.append("dataset: the cases could not be loaded to compare")
    elif stored.get("cases_sha256") != now_cases_sha256:
        why.append("dataset: other cases (cases_sha256 differs)")
    if score_unchanged is not True:
        why.append("scoring: bench/score.py changed since the stored run" if score_unchanged is False
                   else "scoring: the commit of the stored run is unknown")
    stored_scope = (stored.get("v3") or {}).get("scope")
    if stored_scope != now_scope:
        why.append("scoring: the V3 scope of the source changed")
    if code_unchanged is not True:
        why.append("configuration: the adapter or its pinned requirements changed" if code_unchanged is False
                   else "configuration: the commit of the stored run is unknown")
    desc = stored.get("scanner") or {}
    try:
        module = importlib.import_module(f"bench.adapters.{scanner}")
    except ImportError:
        module = None
    pinned_version = getattr(module, "VERSION", None)
    if pinned_version and desc.get("version") != pinned_version:
        why.append(f"version: {desc.get('version')} stored, {pinned_version} pinned")
    pins, have = requirement_pins(scanner), _installed(desc)
    if pins and have and any(have.get(k) != v for k, v in pins.items()):
        why.append("version: the stored distributions differ from bench/adapters/requirements")
    if describe_now is not None:
        diff = [k for k in IDENTITY_KEYS if k in desc or k in describe_now if desc.get(k) != describe_now.get(k)]
        if diff:
            why.append("configuration or version differs from the scanner now: " + ", ".join(diff))
    elif not pinned_version and not pins:
        why.append("version: no pin to compare and no environment to describe the scanner now")
    return why


class CaseCache:
    """The cases_sha256 of a source, split and sample as bench/run.py would select them now; each source loads once."""

    def __init__(self, data: dict):
        self.data, self.loaded = data, {}

    def sha(self, stored: dict) -> str | None:
        from bench import run as brun
        from bench import sources
        src = stored.get("source")
        if src not in sources.SOURCES or src in sources.HOLDOUT_SETS:
            return None
        if src not in self.loaded:
            try:
                d = self.data.get(src) if src in ("nym", "dialogpii", "ghissues") else None
                self.loaded[src] = list(sources.load(src, d, self.data.get("catalogs"), 0, collections.Counter()))
            except (SystemExit, OSError, ValueError):
                self.loaded[src] = None
        cs = self.loaded[src]
        if cs is None or stored.get("limit"):
            return None
        split, every, salt = stored.get("split"), stored.get("every", 1), stored.get("sample_salt", "")
        return brun.cases_hash([c for c in cs if (split == "all" or c["split"] == split)
                                and brun.in_sample(c["id"], every, salt)])


def describe_now(scanner: str, env: dict) -> dict | None:
    """The description the scanner gives now (its version, configuration and distributions), or None without its
    environment. It runs in this process with the environment of the run."""
    if missing_env(scanner, env) or scanner not in SCANNER_ENV:
        return None
    saved = dict(os.environ)
    try:
        os.environ.update({k: v for k, v in env.items() if k.startswith("BENCH_")})
        return importlib.import_module(f"bench.adapters.{scanner}").describe()
    except Exception:   # an adapter that cannot describe itself here: its stored result is not reused
        return {"error": "describe failed"}
    finally:
        os.environ.clear()
        os.environ.update(saved)


LOADERS = {"ghissues": ["bench/ghissues.py"], "nym": ["bench/nym.py", "bench/sealed.py"],
           "dialogpii": ["bench/dialogpii.py", "bench/sealed.py"], "structured-b": ["bench/structured_b.py"],
           "structured": ["bench/structgen.py", "bench/structvocab.py", "bench/structvalues.py"],
           "catalogs": ["bench/sources.py", "scripts/measure_catalog_coverage.py"],
           "catalogs-example": ["bench/sources.py", "scripts/measure_catalog_coverage.py"]}


def staged_plan(jobs: list, staged: Path, env: dict) -> None:
    """Mark each run of another scanner whose result a staging run of this command already wrote (--reuse-from):
    reused when the scoring, the configuration and the version are unchanged and the loader of its sealed or generated
    cases is the same code (the seals pin the data). A maisecrets result is never taken: it belongs to the candidate."""
    from bench import v3
    scope, described = v3.inventory(), {}
    for j in jobs:
        f = staged / "results" / j["name"]
        if j["scanner"].startswith("maisecrets") or (j.get("reuse") or {}).get("ok") or not f.is_file():
            continue
        stored, scanner = _load(f), j["scanner"]
        if scanner not in described:
            described[scanner] = describe_now(scanner, env)
        commit = stored.get("bench_commit")
        loader_same = _unchanged(commit, LOADERS.get(j["source"], ["bench/sources.py", "bench/cases.py", "bench/bank",
                                                                   "scripts/measure_datasets.py"]))
        src = stored.get("source")
        now_scope = scope.get(src, "every class (written by this project)" if src in v3.OWN_SOURCES else None)
        if "v3" not in stored:   # a holdout result has no V3 block: its scope is that of the loader
            now_scope = None
        adapter_paths = [f"bench/adapters/{scanner}.py", f"bench/adapters/requirements/{scanner.replace('_', '-')}.txt",
                         "bench/adapters/_filescan.py", "bench/adapters/_proc.py"]
        why = reuse_check(stored, scanner, stored.get("cases_sha256") if loader_same else None, now_scope,
                          described[scanner], _unchanged(commit, adapter_paths),
                          _unchanged(commit, ["bench/score.py", "bench/v3.py", "bench/v3_scope.json"]))
        if stored.get("bench_dirty") is not False:
            why.append("the staging run measured a modified benchmark tree")
        j["reuse"] = {"from": str(f), "ok": not why, "why_not": why}
        j["stored"] = f


def v3_competitor_plan(reuse_dir: Path, data: dict, env: dict) -> list:
    """Each stored result of another scanner in the published V3 run: reuse it, or run it again."""
    from bench import v3
    scope, cache, described, plan = v3.inventory(), CaseCache(data), {}, []
    for f in sorted(reuse_dir.glob("*.json*")):
        if f.name.startswith("environment") or "-maisecrets" in f.name:   # maisecrets: section 1, the gate's run
            continue
        stored, scanner = _load(f), scanner_of(f.name)
        if scanner not in described:
            described[scanner] = describe_now(scanner, env)
        src = stored.get("source")
        now_scope = scope.get(src, "every class (written by this project)" if src in v3.OWN_SOURCES else None)
        adapter_paths = [f"bench/adapters/{scanner}.py", f"bench/adapters/requirements/{scanner.replace('_', '-')}.txt"]
        why = reuse_check(stored, scanner, cache.sha(stored), now_scope, described[scanner],
                          _unchanged(stored.get("bench_commit"), adapter_paths),
                          _unchanged(stored.get("bench_commit"), ["bench/score.py"]))
        j = job("v3-competitors", src, stored.get("split"), scanner, stored.get("every", 1),
                stored.get("sample_salt", ""))
        j["name"] = f.name.replace(".gz", "")
        j["limit"] = stored.get("limit", 0)
        j["reuse"] = {"from": str(f.relative_to(ROOT)) if f.is_relative_to(ROOT) else f.name, "ok": not why,
                      "why_not": why}
        j["stored"] = f
        plan.append(j)
    return plan


# ---------------------------------------------------------------------------------------------------------- report

def summary(result: dict) -> dict:
    m = result.get("metrics", {}).get("all", {})
    v3 = (result.get("v3") or {}).get("all") or {}
    desc = result.get("scanner") or {}
    out = {"scanner": desc.get("scanner"), "version": desc.get("version"), "cases": result.get("cases"),
           "spans": m.get("spans"), "recall_strict": m.get("recall_strict"),
           "precision": v3.get("precision", m.get("precision")), "fp": v3.get("fp", m.get("fp")),
           "seconds": (result.get("timing") or {}).get("total_s")}
    g = result.get("ghissues")
    if g:
        out["snippet"] = {k: g.get(k) for k in ("candidate_precision", "candidate_recall", "precision",
                                                "precision_secret_findings") if k in g}
    return out


def _fmt(x) -> str:
    return "–" if x is None else str(x)


def compare_table(title: str, base_dir: Path, run_dir: Path) -> list:
    """maisecrets V3 files of the run against the baseline files of the same name: recall and precision, and the
    spans made worse where the cases are the same (scripts/release_gate.py, compare)."""
    shown = base_dir.relative_to(ROOT) if base_dir.is_relative_to(ROOT) else base_dir.name
    lines = ["", f"### {title}", "", f"Baseline: `{shown}`.",
             "", "| Result | Recall strict | Precision | FP | Spans worse |", "|---|---|---|---|---:|"]
    n = 0
    for f in sorted(run_dir.glob("*-maisecrets*.json")):
        b = base_dir / (f.name + ".gz")
        b = b if b.exists() else base_dir / f.name
        if not b.exists():
            continue
        before, after = _load(b), _load(f)
        sb, sa = summary(before), summary(after)
        cmp = release_gate.compare(before, after) if "per_case" in before and "per_case" in after else {}
        worse = cmp.get("worse") if cmp.get("comparable") else "not comparable"
        lines.append(f"| {f.stem} | {_fmt(sb['recall_strict'])} → {_fmt(sa['recall_strict'])} | "
                     f"{_fmt(sb['precision'])} → {_fmt(sa['precision'])} | {_fmt(sb['fp'])} → {_fmt(sa['fp'])} | "
                     f"{worse} |")
        n += 1
    if not n:
        lines.append("| no result of the same name in both | | | | |")
    return lines


def report(index: list, out: Path, v3_dir: Path | None, base_081: Path | None) -> str:
    lines = ["# Extended baseline", "", "Counts only. Holdout rows are totals. Each section stands alone: the new sets "
             "are not in the V3 tables or their denominators."]
    if v3_dir is not None and v3_dir.is_dir():
        lines += ["", "## Benchmark V3: maisecrets against earlier releases"]
        if base_081 is not None:
            lines += compare_table(f"Against the last release ({base_081.name})", base_081, v3_dir)
        lines += compare_table("Against the published 0.7.3 baseline (2026-10-21-v3)", REUSE_DEFAULT, v3_dir)
    sections = [("v3-competitors", "Benchmark V3: the other scanners (reused only when unchanged)"),
                ("new-pii", "New PII sets: nym and DialogPII"),
                ("new-structured", "Structured corpus (" + REGRESSION + ")"),
                ("new-secret", "New secret sets: GitHub issues and the catalog examples")]
    for key, title in sections:
        rows = [r for r in index if r["section"] == key]
        if not rows:
            continue
        lines += ["", f"## {title}", "", "| Result | Scanner | Status | Level | Cases | Spans | Recall strict | "
                  "Precision | FP | Snippet level |", "|---|---|---|---|---:|---:|---|---|---:|---|"]
        for r in rows:
            s = r.get("summary") or {}
            snip = ", ".join(f"{k} {v}" for k, v in (s.get("snippet") or {}).items()) or "–"
            lines.append(f"| {r['name']} | {_fmt(s.get('scanner') or r['scanner'])} {_fmt(s.get('version'))} | "
                         f"{r['status']} | {'snippet + span' if r['level'] == SNIPPET else 'span'} | "
                         f"{_fmt(s.get('cases'))} | {_fmt(s.get('spans'))} | {_fmt(s.get('recall_strict'))} | "
                         f"{_fmt(s.get('precision'))} | {_fmt(s.get('fp'))} | {snip} |")
        if key == "new-structured":
            lines += ["", "Label: " + REGRESSION + "."]
    return "\n".join(lines) + "\n"


def merge_resources(path: Path, staged_path: Path) -> dict:
    """The candidate's maisecrets rows and the other scanners' rows of the staging run in one table. A staged row keeps
    the load average of its run; a staging run on another machine is not merged."""
    import measure_resources
    res, staged = json.loads(path.read_text(encoding="utf-8")), json.loads(staged_path.read_text(encoding="utf-8"))
    if staged.get("machine") != res.get("machine"):
        res["staged_not_merged"] = "the staging run measured another machine"
    else:
        for name, row in staged.get("scanners", {}).items():
            if not name.startswith("maisecrets"):
                res["scanners"][name] = {**row, "staged": True}
        res["staged_load_average"] = staged.get("load_average")
        res["staged_date"] = staged.get("date")
    path.write_text(json.dumps(res, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    text = measure_resources.markdown(res)
    if res.get("staged_load_average"):
        sl = res["staged_load_average"]
        text += (f"\nThe rows of the other scanners come from the staging run of {res.get('staged_date')} on the same "
                 f"machine (load average {sl.get('start')} at its start, {sl.get('end')} at its end).\n")
    path.with_name("resources.md").write_text(text, encoding="utf-8")
    return res


# ---------------------------------------------------------------------------------------------------------- main

def tool_versions(index: list) -> dict:
    tools = {}
    for r in index:
        s = r.get("desc") or {}
        if s.get("scanner"):
            key = s.get("variant") or s["scanner"]
            tools[key] = {k: s.get(k) for k in ("version", "commit", "binary_sha256", "python_version") if s.get(k)}
    return tools


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("candidate", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--v3", type=Path, help="the OUT of scripts/release_gate.py on this candidate (its V3 results)")
    ap.add_argument("--ghissues", type=Path)
    ap.add_argument("--nym", type=Path)
    ap.add_argument("--dialogpii", type=Path)
    ap.add_argument("--structured-b", type=Path, help="the sealed cases file of set B")
    ap.add_argument("--catalogs", type=Path, default=os.environ.get("BENCH_CATALOGS") or None)
    ap.add_argument("--reuse", type=Path, default=REUSE_DEFAULT, help="the published V3 run of the other scanners")
    ap.add_argument("--only", action="append", default=[], help="keep the runs whose file name matches (a glob)")
    ap.add_argument("--exclude", action="append", default=[], help="leave out the runs whose file name matches")
    ap.add_argument("--competitors-only", action="store_true", help="a staging run: every scanner but maisecrets, no "
                    "V3 run of maisecrets and no comparison; the final run takes it in with --reuse-from")
    ap.add_argument("--reuse-from", type=Path, help="the OUT of a staging run: its results of the other scanners are "
                    "reused when unchanged (staged_plan)")
    ap.add_argument("--plan", action="store_true", help="print the runs and the reuse decisions, run nothing")
    ap.add_argument("--resources", action="store_true", help="also speed and resources of each scanner "
                    "(scripts/measure_resources.py), after the runs")
    ap.add_argument("--resources-quick", action="store_true", help="the same with few repeats (a check)")
    ap.add_argument("--keep", action="store_true", help="write OUT to bench/results/<date>-v3-<next version>/extended")
    a = ap.parse_args(argv)
    cand = a.candidate.resolve()
    if release_gate._git("status", "--porcelain", "--untracked-files=all", cwd=cand):
        raise SystemExit("the candidate checkout has changes: measure a commit")
    env = dict(os.environ)
    py = env.get("BENCH_PYTHON", sys.executable)
    data = {"ghissues": a.ghissues, "nym": a.nym, "dialogpii": a.dialogpii, "structured_b": a.structured_b,
            "catalogs": a.catalogs}
    if a.structured_b:   # verify the seal before anything runs
        from bench import structured_b
        try:
            structured_b.verify(a.structured_b)
        except structured_b.SealError as e:
            raise SystemExit(f"set B refused: {e}") from None

    jobs = new_jobs()
    keep_job = (lambda j: any(fnmatch.fnmatch(j["name"], g) for g in a.only)) if a.only else (lambda j: True)
    if not a.only or any("v3" in g or "every25" in g or "bank" in g or "privy" in g for g in a.only):
        jobs = v3_competitor_plan(a.reuse, data, env) + jobs
    jobs = [j for j in jobs if keep_job(j) and not any(fnmatch.fnmatch(j["name"], g) for g in a.exclude)]
    if a.competitors_only:
        jobs = [j for j in jobs if not j["scanner"].startswith("maisecrets")]
    if a.reuse_from:
        staged_plan(jobs, a.reuse_from, env)
    want_v3 = not a.only and not a.competitors_only

    if a.plan:
        for j in jobs:
            r = j.get("reuse")
            state = ("reuse" if r["ok"] else "run again: " + "; ".join(r["why_not"])) if r else "run"
            gone = missing_env(j["scanner"], env)
            print(f"{j['section']:15} {j['name']:55} {state}" + (f" (needs {gone})" if gone and not (r and r["ok"])
                                                                  else ""))
        return 0

    a.out.mkdir(parents=True, exist_ok=True)
    v3_dir = None
    if want_v3:
        v3_dir = a.v3.resolve() if a.v3 else a.out / "v3"
        if not a.v3:   # maisecrets alone: the other scanners come from section 1's reuse or runs
            v3_env = {k: v for k, v in env.items() if k not in SCANNER_ENV.values()}
            subprocess.run(["bash", str(ROOT / "bench" / "run_all_v3.sh"), str(v3_dir), str(cand)], cwd=ROOT,
                           env=v3_env, check=True)
    results = a.out / "results"
    results.mkdir(exist_ok=True)
    index, t_all = [], time.monotonic()
    for j in jobs:
        dest = results / j["name"]
        row = {k: j[k] for k in ("section", "name", "source", "split", "scanner", "every", "salt", "label", "level")}
        r = j.get("reuse")
        if r:
            row["reuse"] = r
        if r and r["ok"]:
            dest.write_text(json.dumps(_load(j["stored"]), indent=1, sort_keys=True) + "\n", encoding="utf-8")
            row["status"] = "reused from " + r["from"]
        elif dest.exists() and dest.stat().st_size:
            row["status"] = "measured (kept from an earlier pass of this OUT)"
        else:
            gone = missing_env(j["scanner"], env)
            args = run_args(j, cand, data, dest)
            if gone or args is None:
                row["status"] = f"not run: {gone} is not set" if gone else "not run: its data was not given"
                index.append(row)
                print(f"{j['name']}: {row['status']}")
                continue
            t0 = time.monotonic()
            p = subprocess.run([py, *args], cwd=ROOT, env=env)
            row["seconds_wall"] = round(time.monotonic() - t0, 1)
            if p.returncode:
                row["status"] = f"failed: exit code {p.returncode}"
                index.append(row)
                continue
            row["status"] = "measured"
        res = _load(dest)
        row["summary"], row["desc"] = summary(res), res.get("scanner")
        index.append(row)
    from bench import manifest as bench_manifest
    environment = bench_manifest.manifest(cand, env)
    # the release binaries: their pinned version and whether this run had them (tools.json has each binary's sha256)
    environment["binaries"] = {s: {"version": importlib.import_module(f"bench.adapters.{s}").VERSION,
                                   "set": bool(env.get(SCANNER_ENV[s]))} for s in SECRET_SCANNERS[1:]}
    tools = tool_versions(index)
    base_081 = release_gate.default_baseline(release_gate.last_release(cand))
    index_out = [{k: v for k, v in r.items() if k != "desc"} for r in index]
    (a.out / "index.json").write_text(json.dumps(index_out, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    (a.out / "environment.json").write_text(json.dumps(environment, indent=1, sort_keys=True) + "\n",
                                            encoding="utf-8")
    (a.out / "tools.json").write_text(json.dumps(tools, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    text = report(index, a.out, v3_dir, base_081)
    if a.resources or a.resources_quick:   # after the runs, alone: the times need a machine without our own load
        import measure_resources
        staged = a.reuse_from / "resources.json" if a.reuse_from else None
        mine = ["--scanners", "maisecrets,maisecrets_ner"] if staged and staged.is_file() else []
        measure_resources.main([str(cand), str(a.out)] + (["--quick"] if a.resources_quick else []) + mine)
        if mine:   # the other scanners from the staging run: same machine, their own load average
            merge_resources(a.out / "resources.json", staged)
        text += "\n" + (a.out / "resources.md").read_text(encoding="utf-8")
    (a.out / "report.md").write_text(text, encoding="utf-8")
    print(text)
    print(f"{len(index)} runs, {round(time.monotonic() - t_all)} s; report: {a.out / 'report.md'}")
    if a.keep:
        version = release_gate.next_version(release_gate.last_release(cand))
        dest = ROOT / "bench" / "results" / f"{datetime.date.today().isoformat()}-v3-{version}" / "extended"
        flat = a.out / "keep"
        flat.mkdir(exist_ok=True)
        extra = [a.out / n for n in ("index.json", "environment.json", "tools.json", "report.md", "resources.json",
                                     "resources.md") if (a.out / n).exists()]
        for f in list(results.glob("*.json")) + extra:
            (flat / f.name).write_bytes(f.read_bytes())
        release_gate.keep(flat, dest, cand, version, env.get("BENCH_PYTHON", ""))
        m = json.loads((dest / "measured.json").read_text(encoding="utf-8"))
        m["tools"] = tools
        m["environment"] = "environment.json.gz"
        (dest / "measured.json").write_text(json.dumps(m, indent=2) + "\n", encoding="utf-8")
        release_gate._sums(dest)
        print(f"kept: {dest.relative_to(ROOT)}")
    return 1 if any(r["status"].startswith("failed") for r in index) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
