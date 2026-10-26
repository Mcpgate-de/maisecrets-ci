"""Run a secret scanner binary once over a folder of case files, offline, and map its findings back to the cases.

Each case is written to `cases/<n>/<path or input.txt>` in a temp directory that is always removed. The binary runs
once over the folder in a minimal environment (bench/adapters/_proc.py). On macOS it runs under `sandbox-exec` with a
profile that denies every network access, so no finding can be verified against a service even when a flag is
missing; elsewhere only the tool's own offline flags hold. A finding is the value the tool reports as the secret,
placed at its line (the first place on or after the reported line that no finding of the same value took yet). A
reported value that is not in the text (a decoded or normalised value) is left out and counted on stderr; no value is
printed."""
from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import time

from bench.adapters import _proc

SANDBOX = "(version 1)(allow default)(deny network*)"
CASE_DIR = "cases"


def binary(env_var: str, name: str) -> str:
    path = os.environ.get(env_var) or shutil.which(name)
    if not path or not os.path.isfile(path):
        raise _proc.AdapterError(f"{name}: no binary (set {env_var})")
    return os.path.realpath(path)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def offline(cmd: list) -> list:
    if sys.platform == "darwin" and shutil.which("sandbox-exec"):
        return ["sandbox-exec", "-p", SANDBOX, *cmd]
    return list(cmd)


def network_guard() -> str:
    return "sandbox-exec, network denied" if sys.platform == "darwin" and shutil.which("sandbox-exec") \
        else "the tool's offline flags only"


def version_of(path: str, args: list, name: str) -> str:
    tmp = tempfile.mkdtemp(prefix="bench-ver-")
    try:
        p = _proc.run(offline([path, *args]), name, env=_proc.minimal_env(tmp), cwd=tmp, timeout=60)
        return (p.stdout or p.stderr).strip().splitlines()[0] if (p.stdout or p.stderr).strip() else ""
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_version(got: str, want: str, name: str) -> None:
    if want not in got.split() and not got.endswith(want):
        raise _proc.AdapterError(f"{name}: version {got!r} installed, {want} pinned")


def write_cases(cases: list, root: str) -> dict:
    """{path relative to root: case index}."""
    files = {}
    for n, c in enumerate(cases):
        rel = c.get("path") or "input.txt"
        if not _proc.safe_path(rel):
            raise _proc.AdapterError("a case path is absolute or leaves its folder")
        f = os.path.join(root, CASE_DIR, str(n), rel)
        os.makedirs(os.path.dirname(f), exist_ok=True)
        with open(f, "w", encoding="utf-8", newline="") as fh:
            fh.write(c["text"])
        files[os.path.relpath(f, root).replace(os.sep, "/")] = n
    return files


def case_of(files: dict, root: str, reported: str):
    """The case index of a path as the tool reports it (relative to its working directory, or absolute)."""
    p = reported if os.path.isabs(reported) else os.path.join(root, reported)
    rel = os.path.relpath(os.path.realpath(p), os.path.realpath(root)).replace(os.sep, "/")
    return files.get(rel)


def line_starts(text: str) -> list:
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def locate(text: str, value: str, line, used: set):
    """(start, end) of a reported value: from the start of its line (1-based) on, the first place not used yet."""
    if not value:
        return None
    starts = line_starts(text)
    begin = starts[line - 1] if isinstance(line, int) and 1 <= line <= len(starts) else 0
    for origin in (begin, 0):
        at = text.find(value, origin)
        while at >= 0 and (at, at + len(value)) in used:
            at = text.find(value, at + 1)
        if at >= 0:
            used.add((at, at + len(value)))
            return at, at + len(value)
    return None


class Run:
    """A temp directory with the cases written, the binary run, and the findings collected per case."""

    def __init__(self, name: str, cases: list):
        self.name, self.cases = name, cases
        self.tmp = tempfile.mkdtemp(prefix=f"bench-{name}-")
        self.home = os.path.join(self.tmp, "home")
        os.mkdir(self.home)
        self.files = write_cases(cases, self.tmp)
        self.found = [[] for _ in cases]
        self.used = [set() for _ in cases]
        self.unlocated = self.unknown_file = self.total = 0
        self.seconds = 0.0

    def run(self, cmd: list, ok_codes=(0,), extra_env: dict | None = None):
        t = time.perf_counter()
        p = _proc.run(offline(cmd), self.name, env=_proc.minimal_env(self.home, extra_env), cwd=self.tmp)
        self.seconds += time.perf_counter() - t
        if p.returncode not in ok_codes:
            raise _proc.AdapterError(f"{self.name}: exit code {p.returncode} (its output is not shown: it can hold a "
                                     f"case value)")
        return p

    def add(self, reported_path: str, value: str, line, rule: str, span=None):
        """One finding: a value at a line, or a (start, end) span in characters that the tool gave."""
        self.total += 1
        n = case_of(self.files, self.tmp, reported_path)
        if n is None:
            self.unknown_file += 1
            return
        loc = span if span else locate(self.cases[n]["text"], value, line, self.used[n])
        if not loc:
            self.unlocated += 1
            return
        self.found[n].append([int(loc[0]), int(loc[1]), "secret", str(rule)])

    def finish(self, api: str):
        n = max(1, len(self.cases))
        sys.stderr.write(f"{self.name}: {self.total} findings, {self.unlocated} not placed in the text, "
                         f"{self.unknown_file} in no case file\n")
        timing = {"api": api, "cold_start_s": self.seconds, "times_s": [self.seconds / n] * n,
                  "findings": self.total, "unlocated": self.unlocated}
        return _proc.check(self.name, self.cases, self.found), timing

    def close(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
