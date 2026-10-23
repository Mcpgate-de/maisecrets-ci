#!/usr/bin/env python3
"""The release gate: before a release, answer whether the candidate needs to be measured again, and measure it.

    python3 scripts/release_gate.py CANDIDATE OUT [--baseline DIR] [--holdout CASES] [--dry-run]

CANDIDATE is a clean checkout of the commit to release (the head of `next`); OUT a new directory for the run. The gate
compares the candidate with the last release tag:

- **detection changed** (maisecrets/detection/**): Benchmark V3 for maisecrets on the candidate (bench/run_all_v3.sh,
  about 40 minutes), compared span by span with the last release's results in bench/results/ (--baseline, default
  the newest `*-v3-<last version>`). Any span the candidate masks worse than the release stops the gate; the change
  of false positives per source goes into the report. With --holdout, Holdout V2 runs on the candidate too and its
  recall may not fall below the last row of bench/HOLDOUT-LOG.md.
- **hooks changed** (the hooks, the mod, the settings and the rest of the runtime): the gate names the checks that only
  a client shows: the harness (python3 harness/run.py) and a live test between two sessions with --plugin-dir.
- **nothing at run time** (docs, bench, CI, tests): no measurement is needed.

The gate exits 1 when the candidate masks any span worse, 0 otherwise, and prints a report for the release merge
request. Counts only, never a value. It runs locally: the datasets are too large for CI (docs/REPO-STANDARDS.md).

The measurement of the gate is also the baseline of the next release: the release commit changes only the version,
so a second run on the tag measures the same code. With --keep the gate writes its results to
bench/results/<date>-v3-<next version> of this checkout, with measured.json (the commit and the git tree of each
runtime directory), and that directory goes to next before the release. After the release,

    python3 scripts/release_gate.py --verify-tag v<version>

checks that the runtime directories of the tag are the trees that were measured (exit 1 if one differs: then the
results are no baseline, and the gate runs again on the tag)."""
from __future__ import annotations

import collections
import datetime
import gzip
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DETECTION = ("maisecrets/detection/",)
RUNTIME = ("maisecrets/", "hooks/", "claude-mod/", "commands/", "skills/", ".claude-plugin/")
RANK = {"missed": 0, "partial": 1, "full": 2}
# the directories whose code runs in the client; .claude-plugin is left out, as the release changes its version
RUNTIME_DIRS = ("maisecrets", "hooks", "claude-mod", "commands", "skills")


def classify(changed: list) -> dict:
    """What the changed paths since the last release ask for: detection, hooks (the rest of the run time), or none."""
    detection = sorted(p for p in changed if p.startswith(DETECTION))
    hooks = sorted(p for p in changed if p.startswith(RUNTIME) and not p.startswith(DETECTION)
                   and not p.endswith(("plugin.json", "marketplace.json")))
    return {"detection": detection, "hooks": hooks, "retest": bool(detection), "live": bool(hooks)}


def _load(path: Path) -> dict:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        return json.load(f)


def compare(base: dict, cand: dict) -> dict:
    """Span by span, two result files of bench/run.py on the same cases: the changes of outcome, the spans made worse,
    and the false positives before and after."""
    if base.get("cases_sha256") != cand.get("cases_sha256"):
        return {"comparable": False}
    moves, worse, fp_base, fp_cand = collections.Counter(), 0, 0, 0
    for cid, oc in cand["per_case"].items():
        ob = base["per_case"].get(cid, [])
        fp_base += ob.count("fp")
        fp_cand += oc.count("fp")
        for x, y in zip([o for o in ob if o != "fp"], [o for o in oc if o != "fp"]):
            if x != y:
                moves[f"{x}->{y}"] += 1
                worse += RANK[y] < RANK[x]
    return {"comparable": True, "moves": dict(moves), "worse": worse, "fp": [fp_base, fp_cand]}


def compare_dirs(baseline: Path, run: Path) -> dict:
    """Each maisecrets result of the run against the file of the same name in the baseline (plain or gzip)."""
    out = {}
    for f in sorted(run.glob("*-maisecrets*.json")):
        b = baseline / (f.name + ".gz")
        b = b if b.exists() else baseline / f.name
        out[f.name.replace(".json", "")] = compare(_load(b), _load(f)) if b.exists() else {"comparable": False}
    return out


def _git(*args: str, cwd: Path = ROOT) -> str:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


def last_release(candidate: Path) -> str:
    """The highest release tag: a release tag sits on main, so `git describe` from next would find an older one."""
    return _git("tag", "--list", "v[0-9]*", "--sort=-v:refname", cwd=candidate).splitlines()[0]


def default_baseline(version: str) -> Path | None:
    hits = sorted(ROOT.glob(f"bench/results/*-v3-{version.lstrip('v')}"))
    return hits[-1] if hits else None


def last_holdout_recall() -> float | None:
    rows = [r for r in (ROOT / "bench" / "HOLDOUT-LOG.md").read_text(encoding="utf-8").splitlines()
            if "holdout-v2" in r and r.startswith("|")]
    return float(rows[-1].split("|")[5]) if rows else None


def report(kind: dict, results: dict, holdout: tuple | None) -> tuple:
    lines = ["## Release gate", ""]
    if not kind["retest"] and not kind["live"]:
        lines.append("Nothing at run time changed since the last release: no measurement needed.")
    if kind["live"]:
        lines.append("Hooks or other runtime files changed (" + ", ".join(kind["hooks"][:8]) + "): run the harness "
                     "and a live test between two sessions with --plugin-dir before the release.")
    failed = False
    if kind["retest"]:
        lines += ["", "Detection changed (" + ", ".join(kind["detection"][:8]) + "): Benchmark V3 against the last "
                  "release, span by span:", "", "| Result | Spans worse | Changes | False positives |",
                  "|---|---:|---|---|"]
        for name, r in results.items():
            if not r.get("comparable"):
                lines.append(f"| {name} | – | not comparable (other cases or no baseline) | – |")
                continue
            failed |= r["worse"] > 0
            lines.append(f"| {name} | {r['worse']} | {r['moves'] or 'none'} | {r['fp'][0]} → {r['fp'][1]} |")
    if holdout:
        before, after = holdout
        failed |= before is not None and after is not None and after < before
        lines += ["", f"Holdout V2 recall: {before} → {after}"]
    lines += ["", "**Gate: " + ("stopped, a span got worse" if failed else "passed") + "**"]
    return "\n".join(lines), failed


def next_version(tag: str) -> str:
    """The version the release gives: the last number of the tag plus one (scripts/release.py)."""
    parts = tag.lstrip("v").split(".")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


def runtime_trees(rev: str, cwd: Path = ROOT) -> dict:
    """The git tree of each runtime directory at `rev`: equal trees hold equal files."""
    out = {}
    for d in RUNTIME_DIRS:
        r = subprocess.run(["git", "rev-parse", f"{rev}:{d}"], cwd=cwd, capture_output=True, text=True)
        if r.returncode == 0:
            out[d] = r.stdout.strip()
    return out


def _write_gz(path: Path, text: str) -> None:
    """gzip with no time stamp and no name, so the same result gives the same bytes."""
    with open(path, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as gz:
        gz.write(text.encode("utf-8"))


def _sums(d: Path) -> None:
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}" for p in sorted(d.iterdir())
             if p.is_file() and p.name != "SHA256SUMS"]
    (d / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def keep(out: Path, dest: Path, cand: Path, version: str, python: str = "") -> None:
    """The results of the run as the baseline of the release in the repository: JSON as gzip, the reports as text,
    Holdout V2 in holdout-v2/, measured.json, and SHA256SUMS. The local paths become <candidate>, <repo>, <python>,
    <tmp> and <home>; a path of this computer that is left stops the copy."""
    home = str(Path.home())
    names = [(str(cand), "<candidate>"), (str(ROOT), "<repo>"), (os.path.realpath(tempfile.gettempdir()), "<tmp>"),
             (home, "<home>")]
    if python:
        names.append((str(Path(python).parent.parent), "<python>"))
    names.sort(key=lambda pair: -len(pair[0]))

    def escaped(path: str) -> str:
        return json.dumps(path)[1:-1]   # a path inside JSON text: C:\\Users\\… on Windows

    def clean(text: str) -> str:
        for local, name in names:
            text = text.replace(escaped(local), name).replace(local, name)
        if home in text or escaped(home) in text:
            raise SystemExit("a local path is left in the results: not kept")
        return text

    dest.mkdir(parents=True, exist_ok=True)
    for f in sorted(out.iterdir()):
        if not f.is_file():
            continue
        text = clean(f.read_text(encoding="utf-8"))
        if f.name == "holdout-v2.json":
            (dest / "holdout-v2").mkdir(exist_ok=True)
            _write_gz(dest / "holdout-v2" / f"holdout-v2-v{version}.json.gz", text)
        elif f.suffix == ".json":
            _write_gz(dest / (f.name + ".gz"), text)
        else:
            (dest / f.name).write_text(text, encoding="utf-8")
    commit = _git("rev-parse", "HEAD", cwd=cand)
    # a list of {"dir", "tree"}: as `"maisecrets": "<tree>"` the label names a secret, and the tree scan takes the hash
    trees = [{"dir": d, "tree": t} for d, t in runtime_trees(commit, cand).items()]
    (dest / "measured.json").write_text(json.dumps({"version": version, "commit": commit, "trees": trees},
                                                   indent=2) + "\n", encoding="utf-8")
    if (dest / "holdout-v2").is_dir():
        _sums(dest / "holdout-v2")
    _sums(dest)


def verify_tag(tag: str, root: Path = ROOT) -> list:
    """The runtime directories of the tag whose tree differs from the measured commit's (empty: the results of
    bench/results/*-v3-<version> are the tag's)."""
    hits = sorted(root.glob(f"bench/results/*-v3-{tag.lstrip('v')}/measured.json"))
    if not hits:
        raise SystemExit(f"no measured.json for {tag} in bench/results/")
    measured = {t["dir"]: t["tree"] for t in json.loads(hits[-1].read_text(encoding="utf-8"))["trees"]}
    now = runtime_trees(tag, root)
    return sorted(d for d in set(measured) | set(now) if measured.get(d) != now.get(d))


COVERAGE = ROOT / "docs" / "coverage.json"
TIME_LIMIT = 1.2   # the candidate may take at most this much of the base's CPU time, unless the difference is too
# small to feel: a short prompt went from 0.43 to 0.55 ms with 205 more rules (+27 %), which no hook notices
TIME_MIN_DELTA = {"tool_1mb": 0.5, "prompt": 1.0}   # seconds for 1 MB, milliseconds for a prompt


def coverage_check(cand: Path, catalogs: Path, out: Path, python: str) -> tuple:
    """The catalog coverage of the candidate (scripts/measure_catalog_coverage.py) against docs/coverage.json: per
    catalog, the rules found bare and after a label may not fall. A catalog at another commit than the pinned one is
    not compared (its rules differ), and the report says so."""
    pinned = json.loads(COVERAGE.read_text(encoding="utf-8"))
    run = out / "coverage.json"
    subprocess.run([python, str(ROOT / "scripts" / "measure_catalog_coverage.py"), str(catalogs),
                    "--maisecrets", str(cand), "--out", str(run)], cwd=ROOT, check=True, capture_output=True)
    got = json.loads(run.read_text(encoding="utf-8"))
    lines, failed = ["", "Catalog coverage (rules whose examples are found whole), against docs/coverage.json:", "",
                     "| Catalog | Bare | After a label |", "|---|---|---|"], False
    for cat, before in pinned["counts"].items():
        if got["commits"].get(cat) != pinned["commits"].get(cat):
            lines.append(f"| {cat} | not compared: catalog at another commit | |")
            continue
        after = got["counts"]["maisecrets"][cat]
        cells = []
        for field in ("bare", "label"):
            fell = after[field] < before[field]
            failed |= fell
            cells.append(f"{before[field]} → {after[field]}" + (" **fell**" if fell else ""))
        lines.append(f"| {cat} | {cells[0]} | {cells[1]} |")
    return lines, failed


def _time_text(cand: Path, dest: Path) -> Path:
    """1 MB of the candidate's own source and docs: the same characters for base and candidate."""
    parts = []
    for folder, ext in (("maisecrets", ".py"), ("docs", ".md")):
        for f in sorted((cand / folder).rglob("*" + ext)):
            parts.append(f.read_text(encoding="utf-8", errors="replace"))
    dest.write_text("\n".join(parts)[:1_000_000], encoding="utf-8")
    return dest


def time_check(cand: Path, tag: str, out: Path, rounds: int = 3) -> tuple:
    """CPU time of the base (the last release tag) and the candidate on the same text, measured in turns so that a
    change of load meets both; the median of each. The candidate may take at most TIME_LIMIT times the base."""
    text = _time_text(cand, out / "time-text.txt")
    base = out / "base-checkout"
    _git("worktree", "add", "--detach", str(base), tag, cwd=cand)
    load_before = os.getloadavg()[0]
    runs = {"base": [], "candidate": []}
    try:
        for _ in range(rounds):
            for name, checkout in (("base", base), ("candidate", cand)):
                r = subprocess.run([sys.executable, "-I", str(cand / "scripts" / "time_detector.py"), str(checkout),
                                    str(text)], capture_output=True, text=True, check=True)
                runs[name].append(json.loads(r.stdout))
    finally:
        _git("worktree", "remove", "--force", str(base), cwd=cand)
    load_after = os.getloadavg()[0]
    med = {name: {k: sorted(x[k] for x in rs)[len(rs) // 2] for k in ("tool_1mb", "prompt")}
           for name, rs in runs.items()}
    return time_report(med, tag, rounds, (load_before, load_after), os.cpu_count() or 1)


def time_report(med: dict, tag: str, rounds: int, loads: tuple, cpus: int) -> tuple:
    """The lines of the time table and whether the candidate is too slow: above TIME_LIMIT of the base and slower by
    more than TIME_MIN_DELTA."""
    lines, failed = ["", f"CPU time, base {tag} and candidate in turns ({rounds} rounds, median; load average "
                         f"{loads[0]:.1f} before, {loads[1]:.1f} after, {cpus} CPUs):", "",
                     "| Text | Base | Candidate | Ratio |", "|---|---:|---:|---:|"], False
    for key, label, unit in (("tool_1mb", "1 MB tool text", "s"), ("prompt", "short prompt", "ms")):
        b, c = med["base"][key], med["candidate"][key]
        ratio = c / b if b else 1.0
        slow = ratio > TIME_LIMIT and c - b > TIME_MIN_DELTA[key]
        failed |= slow
        lines.append(f"| {label} | {b} {unit} | {c} {unit} | {ratio:.2f}" + (" **slower**" if slow else "") + " |")
    if max(loads) > cpus:
        lines += ["", "The load was above the number of CPUs: the times say little. Measure again on a quiet machine."]
    return lines, failed


def main(argv: list) -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("candidate", type=Path, nargs="?")
    ap.add_argument("out", type=Path, nargs="?")
    ap.add_argument("--baseline", type=Path)
    ap.add_argument("--holdout", type=Path)
    ap.add_argument("--dry-run", action="store_true", help="classify the changes only")
    ap.add_argument("--keep", action="store_true", help="write the results to bench/results/ as the next baseline")
    ap.add_argument("--verify-tag", help="check that a release tag holds the measured runtime trees")
    ap.add_argument("--catalogs", type=Path, help="the catalog clones of docs/coverage.json: coverage may not fall")
    ap.add_argument("--time", action="store_true", help="CPU time against the last release: at most 20 %% more")
    a = ap.parse_args(argv)
    if a.verify_tag:
        differ = verify_tag(a.verify_tag)
        print(f"{a.verify_tag}: " + ("the runtime trees are the measured ones" if not differ
                                     else "differs from the measured commit in " + ", ".join(differ)))
        return 1 if differ else 0
    if a.candidate is None or a.out is None:
        ap.error("CANDIDATE and OUT are needed, except with --verify-tag")
    cand = a.candidate.resolve()
    if _git("status", "--porcelain", "--untracked-files=all", cwd=cand):
        raise SystemExit("the candidate checkout has changes: measure a commit")
    tag = last_release(cand)
    kind = classify(_git("diff", "--name-only", f"{tag}..HEAD", cwd=cand).splitlines())
    head = _git("rev-parse", "--short=8", "HEAD", cwd=cand)
    print(f"last release {tag}, candidate {head}: retest {'needed' if kind['retest'] else 'not needed'}, "
          f"live test {'needed' if kind['live'] else 'not needed'}")
    if a.dry_run or not kind["retest"]:
        text, failed = report(kind, {}, None)
        print(text)
        return 0
    baseline = a.baseline or default_baseline(tag)
    if baseline is None:
        raise SystemExit(f"no results of {tag} in bench/results/: run Benchmark V3 on the release first")
    a.out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    subprocess.run(["bash", str(ROOT / "bench" / "run_all_v3.sh"), str(a.out), str(cand)], cwd=ROOT, env=env,
                   check=True)
    results = compare_dirs(baseline, a.out)
    holdout = None
    if a.holdout:
        out = a.out / "holdout-v2.json"
        subprocess.run([env.get("BENCH_PYTHON", sys.executable), "bench/run.py", "--scanner", "maisecrets",
                        "--maisecrets", str(cand), "--source", "holdout-v2", "--holdout", str(a.holdout),
                        "--release-candidate", "--out", str(out)], cwd=ROOT, check=True)
        m = json.loads(out.read_text(encoding="utf-8"))["metrics"].get("all", {})
        holdout = (last_holdout_recall(), m.get("recall_strict"))
    text, failed = report(kind, results, holdout)
    extra = []
    if a.catalogs:
        lines, fell = coverage_check(cand, a.catalogs, a.out, env.get("BENCH_PYTHON", sys.executable))
        extra += lines
        failed |= fell
    if a.time:
        lines, slow = time_check(cand, tag, a.out)
        extra += lines
        failed |= slow
    if extra:
        text = text.rsplit("\n\n**Gate:", 1)[0] + "\n" + "\n".join(extra) + "\n\n**Gate: " + (
            "stopped" if failed else "passed") + "**"
    (a.out / "release-gate.md").write_text(text + "\n", encoding="utf-8")
    print(text)
    if a.keep and not failed:
        dest = ROOT / "bench" / "results" / f"{datetime.date.today().isoformat()}-v3-{next_version(tag)}"
        keep(a.out, dest, cand, next_version(tag), env.get("BENCH_PYTHON", ""))
        if (a.out / "coverage.json").exists():   # the coverage of this release is the next one's floor
            run = json.loads((a.out / "coverage.json").read_text(encoding="utf-8"))
            COVERAGE.write_text(json.dumps({"version": next_version(tag), "commits": run["commits"],
                                            "counts": run["counts"]["maisecrets"]}, indent=1) + "\n",
                                encoding="utf-8")
            sys.path.insert(0, str(ROOT / "scripts"))
            import coverage_drift   # the per-rule result: the weekly drift job compares with it
            coverage_drift.RULES.write_text(coverage_drift.dump_rules(run["rules"]["maisecrets"]), encoding="utf-8")
        print(f"kept as the baseline of {next_version(tag)}: {dest.relative_to(ROOT)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
