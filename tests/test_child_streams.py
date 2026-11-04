"""No child process of a hook gets the hook's own stdout or stderr. The client reads the hook's answer from them and
waits for them to close; a child that keeps one open (xclip stays in the background to serve the selection) held the
client after the hook ended (Gate A of 0.6.15).

Run: python3 -m unittest tests.test_child_streams -v
"""
from __future__ import annotations

import ast
import os
import platform
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import hooks, vault  # noqa: E402

CALLS = {"run", "Popen", "call", "check_call", "check_output"}


def unpiped_calls(path: Path) -> list[str]:
    """subprocess calls that set neither capture_output nor both stdout and stderr. check_output pipes stdout itself,
    so it needs stderr; _run_store sets the pipes for its callers."""
    out = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"
                and node.func.attr in CALLS):
            continue
        kws = {k.arg for k in node.keywords}
        if None in kws or "capture_output" in kws:
            continue                       # **kw: the wrapper decides (vault._run_store); capture_output: both piped
        need = {"stderr"} if node.func.attr == "check_output" else {"stdout", "stderr"}
        if not need <= kws:
            out.append(f"{path.name}:{node.lineno}")
    return out


class ChildStreamTests(unittest.TestCase):
    def test_every_subprocess_call_of_the_package_sets_its_streams(self):
        files = sorted((ROOT / "maisecrets").glob("*.py")) + sorted((ROOT / "hooks").glob("*.py"))
        self.assertEqual([c for f in files for c in unpiped_calls(f)], [])

    def test_the_clipboard_child_gets_no_stream_of_the_hook(self):
        platform.system()   # on Windows the first call runs a child of its own; cache it before the mock
        with mock.patch.object(hooks.subprocess, "run") as run:
            hooks._clipboard("text")
        if run.called:
            kw = run.call_args.kwargs
            self.assertEqual((kw.get("stdout"), kw.get("stderr")), (subprocess.DEVNULL, subprocess.DEVNULL))

    def test_a_store_call_without_capture_still_pipes_both_streams(self):
        with mock.patch.object(vault.subprocess, "run") as run:
            vault._run_store("openssl", ["true"], input=b"", timeout=5)
        kw = run.call_args.kwargs
        self.assertEqual((kw.get("stdout"), kw.get("stderr")), (subprocess.PIPE, subprocess.PIPE))


if __name__ == "__main__":
    unittest.main()
