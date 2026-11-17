"""What a test must leave as it found it: the module globals of maisecrets.hooks, the temp dir and
the client environment of the process, and no child that still serves a value.

The Codex review of the suite (2026-09-27) found `hooks._clipboard` replaced by a lambda and never
put back in seven places, `tempfile.tempdir` changed at the import of one module, and allowed-command
tests that left 120-second FIFO children running, which printed ResourceWarnings about running
subprocesses. A test module calls `assert_pristine` in its tearDownModule, so a leak fails the module
in any test order, and `watch_children(self)` in the setUp of a class that rewrites commands.

Import this after maisecrets.hooks can be imported (after the config.json of the temp home exists).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import _isolate
from maisecrets import hooks

# the functions as maisecrets.hooks defines them; every module is imported before any test runs
_ORIGINAL = {"_clipboard": hooks._clipboard, "_clipboard_read": hooks._clipboard_read}
# the source line only the value-serving child runs (hooks._serve_value_later)
SERVING_MARKER = "os.mkfifo(spec['fifo']"


def state_problems() -> list[str]:
    """How the process differs from the state _isolate set up: empty when it is pristine."""
    problems = [f"hooks.{name} is {getattr(hooks, name)!r}, not the function hooks.py defines"
                for name, fn in _ORIGINAL.items() if getattr(hooks, name) is not fn]
    if tempfile.tempdir != _isolate.TMP:
        problems.append(f"tempfile.tempdir is {tempfile.tempdir!r}, not {_isolate.TMP!r}")
    if os.environ.get("TMPDIR") != _isolate.TMP:
        problems.append(f"TMPDIR is {os.environ.get('TMPDIR')!r}, not {_isolate.TMP!r}")
    if os.environ.get("MAISECRETS_HOME") != _isolate.HOME:
        problems.append(f"MAISECRETS_HOME is {os.environ.get('MAISECRETS_HOME')!r}, not {_isolate.HOME!r}")
    leaked = _isolate.client_variables()
    if leaked:
        problems.append(f"client variables are set: {', '.join(leaked)}")
    try:
        with open(_isolate.TRIPWIRE, encoding="utf-8") as f:
            calls = f.read().split("\n")
        os.unlink(_isolate.TRIPWIRE)     # reported once, by the first check after the call
        problems.append(f"a test ran a real tool: {'; '.join(c for c in calls if c)}")
    except FileNotFoundError:
        pass
    return problems


def assert_pristine() -> None:
    problems = state_problems()
    if problems:
        raise AssertionError("a test changed the process state and did not restore it: " + "; ".join(problems))


def _cwd_of(pids: list[int]) -> dict[int, str]:
    if not pids:
        return {}
    if os.path.isdir("/proc"):
        out = {}
        for pid in pids:
            try:
                out[pid] = os.readlink(f"/proc/{pid}/cwd")
            except OSError:
                pass
        return out
    r = subprocess.run(["lsof", "-a", "-d", "cwd", "-Fn", "-p", ",".join(map(str, pids))],
                       capture_output=True, text=True, timeout=10)
    out, pid = {}, None
    for line in r.stdout.splitlines():
        if line.startswith("p"):
            pid = int(line[1:])
        elif line.startswith("n") and pid is not None:
            out[pid] = line[1:]
    return out


def serving_children(cwd_root: str | None = None) -> list[int]:
    """The live value-serving children of this process, and, with ``cwd_root``, every serving
    process whose working directory lies under it (the children a hook subprocess left behind:
    they belong to no parent any more, and the real plugin on this machine runs the same code)."""
    if sys.platform == "win32":
        return []
    r = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,stat=,command="], capture_output=True, text=True, timeout=10)
    mine, others = [], []
    for line in r.stdout.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 4 or SERVING_MARKER not in parts[3] or parts[2].startswith("Z"):
            continue
        (mine if int(parts[1]) == os.getpid() else others).append(int(parts[0]))
    if cwd_root:
        root = os.path.realpath(cwd_root)
        for pid, cwd in _cwd_of(others).items():
            if os.path.realpath(cwd) == root or os.path.realpath(cwd).startswith(root + os.sep):
                mine.append(pid)
    return sorted(mine)


def wait_for_no_serving_child(cwd_root: str | None = None, seconds: float = 3.0) -> list[int]:
    deadline = time.monotonic() + seconds
    while True:
        alive = serving_children(cwd_root)
        if not alive or time.monotonic() > deadline:
            return alive
        time.sleep(0.05)


def _fifos() -> set[str]:
    try:
        d = hooks._run_dir()
    except (OSError, RuntimeError):
        return set()
    return {os.path.join(d, n) for n in os.listdir(d) if n.startswith("v-")}


_KEPT: list[subprocess.Popen] = []


def watch_children(case: unittest.TestCase) -> None:
    """For one test: keep every child it starts, and take back every value it left waiting
    (hooks._unserve on each FIFO it created). A kept child is never collected while it runs (the
    ResourceWarning); `assert_children_ended` in the tearDownClass of the class waits for them."""
    real = subprocess.Popen

    class Kept(real):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            _KEPT.append(self)

    before = _fifos()
    patcher = mock.patch.object(subprocess, "Popen", Kept)
    patcher.start()

    def check() -> None:
        patcher.stop()
        hooks._unserve(sorted(_fifos() - before))
        case.assertEqual(state_problems(), [])

    case.addCleanup(check)


def assert_children_ended(seconds: float = 3.0) -> None:
    """Every child the tests of a class started has ended, the value-serving ones included; one
    that still runs is killed and named. All wait at once: a serving child polls every 50 ms."""
    deadline = time.monotonic() + seconds
    alive = []
    for p in _KEPT:
        try:
            p.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            alive.append(p.pid)
            p.kill()
            p.wait()
    _KEPT.clear()
    if alive:
        raise AssertionError(f"children still ran after their FIFOs were taken back: {alive}")


# the client marker every payload of a test carries: Claude Code sends `prompt_id` on every event,
# Codex `turn_id` on turn-scoped ones (hooks.client_of). A payload without either takes the client
# from the environment, so a helper that omits it tests the machine it runs on.
CLAUDE = {"prompt_id": "p"}
CODEX = {"turn_id": "t"}


def codex_rollout(source="cli") -> dict:
    """The transcript_path of a Codex payload whose rollout starts with session_meta and this source (cli: the
    terminal UI, vscode: the app server, exec: `codex exec`); the shape of codex-rs protocol SessionMetaLine."""
    fd, path = tempfile.mkstemp(prefix="rollout-", suffix=".jsonl")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps({"timestamp": "2026-11-17T00:00:00Z", "type": "session_meta",
                            "payload": {"id": "t", "cwd": "/tmp", "originator": "x", "source": source}}) + "\n")
        f.write(json.dumps({"type": "response_item", "payload": {}}) + "\n")
    return {"transcript_path": path}


def patch(case: unittest.TestCase, target: object, attribute: str, value: object) -> None:
    """Replace ``target.attribute`` for one test; the cleanup puts the original back."""
    p = mock.patch.object(target, attribute, value)
    p.start()
    case.addCleanup(p.stop)


def without_client_env():
    """For a test whose input carries no payload to mark (a broken stdin): no client variable,
    whatever the process has; the context restores the environment."""
    env = {k: v for k, v in os.environ.items() if k not in _isolate.client_variables()}
    return mock.patch.dict(os.environ, env, clear=True)
