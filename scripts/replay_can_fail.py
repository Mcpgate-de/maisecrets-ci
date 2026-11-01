#!/usr/bin/env python3
"""Replay every belief's proof: mutate the guarded code, run the owning tests, demand RED.

`beliefs/*.toml` names, per documented control, the tests that own it and one mutation
(file, find, replace) that removes the control. A test that stays green under that mutation
proves nothing about the control (docs/TESTING.md said "every control has a test that goes
red without it"; before this script that sentence was prose). Borrowed from the ai-gateway's
beliefs layer, cut to what a repository this size needs: no provenance vocabulary, no shards.

    python3 scripts/replay_can_fail.py             # every belief
    python3 scripts/replay_can_fail.py --belief X  # one
    python3 scripts/replay_can_fail.py --list

Each belief: the owning tests run once unmutated and must pass (a red baseline is not
evidence about the mutation), then the file is mutated, the tests run again and must fail,
and the file is restored on every exit, signals included. With --jobs 1 the replay owns this
working tree for its length; with more (the default: one per CPU, up to 8, or
MAISECRETS_REPLAY_JOBS) each worker replays in a private copy and this tree is never mutated.
Never run it inside the test suite.
"""
from __future__ import annotations

import argparse
import shutil
import signal
import subprocess
import sys
import tomllib
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BELIEFS = ROOT / "beliefs"


def load() -> list[dict]:
    out = []
    for path in sorted(BELIEFS.glob("*.toml")):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        data["_path"] = path
        out.append(data)
    return out


def unittest_id(test_id: str) -> str:
    """tests/test_gates.py::Class::method -> tests.test_gates.Class.method"""
    file, _, rest = test_id.partition("::")
    module = file[:-3].replace("/", ".") if file.endswith(".py") else file.replace("/", ".")
    return module + ("." + rest.replace("::", ".") if rest else "")


def run_tests(ids: list[str], root: Path = ROOT) -> tuple[int, dict[str, str]]:
    """Run the owning tests once; return the exit code and each test's outcome.

    Each run gets a fresh bytecode cache. A mutation of the same length written in the same
    second as the green run's compile left a .pyc that Python took for current (size and mtime
    match), so the tests ran the unmutated code and stayed green (2026-09-27)."""
    import json
    import os
    import tempfile
    with tempfile.TemporaryDirectory(prefix="maisecrets-pyc-") as cache:
        report = os.path.join(cache, "outcomes.json")
        cmd = [sys.executable, str(root / "scripts" / "_run_tests_json.py"), report] + [unittest_id(t) for t in ids]
        env = dict(os.environ, PYTHONPYCACHEPREFIX=cache)
        r = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=600, env=env)
        try:
            with open(report, encoding="utf-8") as fh:
                outcomes = json.load(fh)
        except (OSError, ValueError):
            # the runner itself died (the mutation broke an import); every test counts as red
            outcomes = {unittest_id(t): "broken" for t in ids}
    # a skipped owning test is no evidence either way: without git in the CI image the skill's
    # tests were skipped, the replay read the skip as green and failed C17 for the wrong reason,
    # and read it as "green before the mutation" too (2026-09-27)
    if "skip" in outcomes.values():
        return SKIPPED, outcomes
    if "broken" in outcomes.values():
        return BROKEN, outcomes
    return (1 if "fail" in outcomes.values() or r.returncode else 0), outcomes


SKIPPED = -1
BROKEN = -2


@contextmanager
def restored_on_any_exit(target: Path, original: str):
    """Put the file back on every exit: a SIGTERM from a cancelled CI job would otherwise
    leave the mutation in the tree, indistinguishable from an edit."""
    previous = {}

    def restore_and_die(signum, _frame):
        target.write_text(original, encoding="utf-8")
        signal.signal(signum, previous.get(signum, signal.SIG_DFL))
        raise SystemExit(128 + signum)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            previous[sig] = signal.signal(sig, restore_and_die)
        except (ValueError, OSError):
            pass
    try:
        yield
    finally:
        target.write_text(original, encoding="utf-8")
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def proofs_of(belief: dict) -> list[dict]:
    """`[proof]` (a mechanism belief: one guard, one mutation) or `[[proof]]` (an invariant
    belief: one goal, a mutation per path to it)."""
    proof = belief["proof"]
    return proof if isinstance(proof, list) else [proof]


def is_invariant(belief: dict) -> bool:
    return belief.get("kind") == "invariant"


def _check_mutation(target: Path, mutated: str) -> str | None:
    # a mutation that breaks the syntax turns every test red for the wrong reason
    if target.suffix == ".py":
        try:
            compile(mutated, str(target), "exec")
        except SyntaxError as exc:
            return f"the mutation does not compile ({exc.msg}, line {exc.lineno}); a red proves nothing"
    if target.suffix == ".json":
        import json
        try:
            json.loads(mutated)
        except ValueError as exc:
            return f"the mutation is not valid JSON ({exc}); a red proves nothing"
    return None


def _replay_one(belief: dict, proof: dict, root: Path = ROOT) -> tuple[bool, str, set[str]]:
    """Apply one mutation, run the owning tests, restore. Returns (red, why, the red test ids)."""
    target = root / proof["file"]
    original = target.read_text(encoding="utf-8")
    n = original.count(proof["find"])
    if n != 1:
        return False, f"anchor occurs {n} times in {proof['file']} (must be exactly once)", set()
    with restored_on_any_exit(target, original):
        mutated = original.replace(proof["find"], proof["replace"], 1)
        target.write_text(mutated, encoding="utf-8")
        bad = _check_mutation(target, mutated)
        if bad:
            return False, bad, set()
        rc, outcomes = run_tests(belief["runner"], root)
    if target.read_text(encoding="utf-8") != original:
        return False, "the file was not restored", set()
    if rc == SKIPPED:
        return False, "an owning test was skipped under the mutation; a skip is no evidence", set()
    if rc == BROKEN:
        return False, ("the mutation broke an import or a class set-up, so the owning tests did not run; "
                       "a red there proves nothing"), set()
    red = {tid for tid, o in outcomes.items() if o == "fail"}
    if rc == 0:
        return False, "the owning tests stayed GREEN under the mutation: they do not carry this belief", red
    return True, "red", red


def replay(belief: dict, root: Path = ROOT) -> tuple[bool, str]:
    proofs = proofs_of(belief)
    for proof in proofs:
        target = root / proof["file"]
        n = target.read_text(encoding="utf-8").count(proof["find"])
        if n != 1:
            return False, f"anchor occurs {n} times in {proof['file']} (must be exactly once)"
    first, _ = run_tests(belief["runner"], root)
    if first == SKIPPED:
        return False, "an owning test was skipped here (a missing tool?); a skip is no evidence"
    if first == BROKEN:
        return False, "an owning test cannot run here (an import or a class set-up fails); no evidence"
    if first != 0:
        return False, "the owning tests are red before the mutation; no evidence"
    killed: set[str] = set()
    for i, proof in enumerate(proofs, 1):
        ok, why, red = _replay_one(belief, proof, root)
        killed |= red
        if not ok:
            label = proof.get("path", f"mutation {i}")
            return False, (f"{label} ({proof['file']}): {why}" if len(proofs) > 1 else why)
    if is_invariant(belief):
        # a test that no mutation turns red proves nothing about the goal; it is ballast that
        # reads like coverage
        idle = [t for t in belief["runner"]
                if not any(k == unittest_id(t) or k.startswith(unittest_id(t) + ".") for k in killed)]
        if idle:
            return False, "no mutation turns these owning tests red: " + ", ".join(idle)
        return True, f"red under each of {len(proofs)} mutations, every owning test killed, green restored"
    return True, "red under the mutation, green restored"


_COPY_IGNORE = (".git", "__pycache__", ".ruff_cache", ".pytest_cache", "*.pyc", ".coverage*")


def _tree_copy(tmp: str, n: int) -> Path:
    """A private copy of the tree for one worker: a replay mutates files, so two replays in one
    tree would see each other's mutations. The copy has no .git; a belief whose tests need the
    repository history goes red at its baseline and says so."""
    dest = Path(tmp) / f"tree-{n}"
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(*_COPY_IGNORE), symlinks=True)
    return dest


def _baseline(belief: dict, root: Path) -> str | None:
    """The checks of replay() before the first mutation; None when the mutations may run."""
    for proof in proofs_of(belief):
        n = (root / proof["file"]).read_text(encoding="utf-8").count(proof["find"])
        if n != 1:
            return f"anchor occurs {n} times in {proof['file']} (must be exactly once)"
    first, _ = run_tests(belief["runner"], root)
    if first == SKIPPED:
        return "an owning test was skipped here (a missing tool?); a skip is no evidence"
    if first == BROKEN:
        return "an owning test cannot run here (an import or a class set-up fails); no evidence"
    if first != 0:
        return "the owning tests are red before the mutation; no evidence"
    return None


def _verdict(belief: dict, results: list[tuple[bool, str, set[str]]]) -> tuple[bool, str]:
    """replay()'s answer from the results of each mutation, in proof order: the first that failed decides."""
    proofs = proofs_of(belief)
    killed: set[str] = set()
    for i, (proof, (ok, why, red)) in enumerate(zip(proofs, results), 1):
        killed |= red
        if not ok:
            label = proof.get("path", f"mutation {i}")
            return False, (f"{label} ({proof['file']}): {why}" if len(proofs) > 1 else why)
    if is_invariant(belief):
        idle = [t for t in belief["runner"]
                if not any(k == unittest_id(t) or k.startswith(unittest_id(t) + ".") for k in killed)]
        if idle:
            return False, "no mutation turns these owning tests red: " + ", ".join(idle)
        return True, f"red under each of {len(proofs)} mutations, every owning test killed, green restored"
    return True, "red under the mutation, green restored"


def replay_all(beliefs: list[dict], jobs: int) -> list[tuple[dict, bool, str]]:
    """Each belief in a worker of its own. With one job the replay runs in this tree, as it did
    before; with more, every worker owns a copy, and this tree is never mutated at all.

    With more than one job the work is split finer than a belief: first every belief's green run, then every
    mutation on its own, the costliest first (by the time of its green run). One belief with 17 mutations held a
    worker for 612 s while the others waited (2026-11-01). The answer is replay()'s: the same checks, and the first
    mutation in proof order that failed decides."""
    if jobs <= 1 or len(beliefs) <= 1:
        return [(b, *replay(b)) for b in beliefs]
    import queue
    import tempfile
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor
    jobs = min(jobs, sum(len(proofs_of(b)) for b in beliefs))
    with tempfile.TemporaryDirectory(prefix="maisecrets-replay-") as tmp:
        roots: queue.Queue = queue.Queue()
        for n in range(jobs):
            roots.put(_tree_copy(tmp, n))
        lock = threading.Lock()

        def in_a_tree(fn, *args):
            root = roots.get()
            try:
                return fn(*args, root)
            finally:
                roots.put(root)

        def baseline(b: dict) -> tuple[str | None, float]:
            t0 = time.monotonic()
            return in_a_tree(_baseline, b), time.monotonic() - t0

        def mutation(task: tuple) -> tuple[bool, str, set[str]]:
            b, proof = task
            return in_a_tree(_replay_one, b, proof)

        order = sorted(beliefs, key=lambda b: -len(proofs_of(b)) * len(b["runner"]))
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            base = dict(zip((b["belief"] for b in order), pool.map(baseline, order)))
            tasks = [(b, p) for b in beliefs if base[b["belief"]][0] is None for p in proofs_of(b)]
            tasks.sort(key=lambda t: -base[t[0]["belief"]][1])
            done = dict(zip((id(t[1]) for t in tasks), pool.map(mutation, tasks)))
        out = []
        for b in beliefs:
            why = base[b["belief"]][0]
            ok, why = (False, why) if why is not None else _verdict(b, [done[id(p)] for p in proofs_of(b)])
            with lock:
                print(f"[{'OK ' if ok else 'FAIL'}] {b['belief']}: {why}", flush=True)
            out.append((b, ok, why))
        return out


def default_jobs() -> int:
    """MAISECRETS_REPLAY_JOBS, else one per CPU up to 8. Each job is one test process at a time."""
    import os
    env = os.environ.get("MAISECRETS_REPLAY_JOBS", "")
    if env.isdigit() and int(env) > 0:
        return int(env)
    return max(1, min(8, os.cpu_count() or 1))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--belief")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--jobs", type=int, default=None, help="parallel workers (default: one per CPU, up to 8)")
    args = ap.parse_args(argv)
    beliefs = load()
    if args.belief:
        beliefs = [b for b in beliefs if b["belief"] == args.belief]
        if not beliefs:
            print(f"no belief named {args.belief}")
            return 2
    if args.list:
        for b in beliefs:
            files = ", ".join(sorted({p["file"] for p in proofs_of(b)}))
            print(f"{b['belief']:<55} {b['control']:<12} {files}")
        return 0
    if not beliefs:
        print("no beliefs found; nothing was proven")
        return 1
    jobs = args.jobs if args.jobs is not None else default_jobs()
    results = replay_all(beliefs, jobs)
    failures = sum(not ok for _b, ok, _why in results)
    if jobs <= 1 or len(beliefs) <= 1:
        for b, ok, why in results:
            print(f"[{'OK ' if ok else 'FAIL'}] {b['belief']}: {why}")
    else:
        for b, ok, why in results:
            if not ok:
                print(f"failed: {b['belief']}: {why}")
    print(f"{len(beliefs) - failures} of {len(beliefs)} beliefs proven; failures: {failures} ({jobs} job(s))")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
