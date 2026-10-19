"""A scan carries its channel and its path itself; the detector keeps no process-shared scan context.

scan() used to put its channel and path into two module globals (_CHANNEL, _PATH) and read them deep inside the
rules. Two scans at the same time in two threads then read each other's channel and path: a tool result scanned next
to a typed prompt lost its tool-only hits, or a prompt took them. These tests run both at once and compare each result
with the result of the same scan alone, and they hold the module state that the functions of a scan write to a known
list: the scan context is no longer in it. They prove neither that a Sources object of a caller is thread-safe nor
that the timing of the rules of your own is.

Run: python3 -m unittest tests.test_scan_context -v
"""
from __future__ import annotations

import ast
import os
import random
import string
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402
from test_tool_channel import LETTERS  # noqa: E402  letters after a password label: a hit in a tool result only

RNG = random.Random(91)
PASSWORD = "".join(RNG.choice(string.ascii_letters + string.digits + "!#%") for _ in range(14))
EXPORT = f"password,comment\n{PASSWORD},old router\n"     # an export only by its file name
EXPORT_PATH = "/tmp/passwords.csv"

# (text, channel, path): each decides by its channel or its path
CASES = [(LETTERS, "tool", ""), (LETTERS, "prompt", ""), (EXPORT, "tool", EXPORT_PATH), (EXPORT, "tool", "")]


def kinds(text: str, channel: str, path: str) -> list:
    return sorted(m.kind for m in detect.scan(text, channel=channel, path=path))


class ScanContextTests(unittest.TestCase):
    def test_the_cases_decide_by_channel_and_path(self):
        alone = {case: kinds(*case) for case in CASES}
        self.assertNotEqual(alone[CASES[0]], alone[CASES[1]], "the premise: the channel decides LETTERS")
        self.assertNotEqual(alone[CASES[2]], alone[CASES[3]], "the premise: the path decides EXPORT")

    def test_the_text_index_of_one_thread_is_not_the_index_of_another(self):
        # the order of the race, made fixed: thread A indexes its text, thread B indexes another one, then A asks
        # again. With one index for the process, B's text replaced A's index object between A's two questions; in a
        # scan, A then read line breaks and literal hits that another thread had just put there
        a_text, b_text = "a\nb\nc\n", "only one line"
        a_ready, b_done = threading.Event(), threading.Event()
        seen: dict = {}
        errors: list = []

        def thread_a():
            try:
                first = detect._text_index(a_text)
                a_ready.set()
                seen["b done"] = b_done.wait(timeout=60)
                seen["a"] = (detect._text_index(a_text) is first, detect._newlines(a_text))
            except BaseException as exc:  # noqa: BLE001 - a worker's exception must fail the test
                errors.append(repr(exc))

        def thread_b():
            try:
                seen["a ready"] = a_ready.wait(timeout=60)
                detect._text_index(b_text)
                b_done.set()
            except BaseException as exc:  # noqa: BLE001
                errors.append(repr(exc))
        threads = [threading.Thread(target=thread_a, daemon=True), threading.Thread(target=thread_b, daemon=True)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        self.assertFalse([t for t in threads if t.is_alive()], "a thread did not end")
        self.assertEqual(errors, [])
        self.assertEqual((seen.get("a ready"), seen.get("b done")), (True, True), "the fixed order did not happen")
        self.assertEqual(seen.get("a"), (True, [1, 3, 5]), "B's text replaced the index of A")

    def test_two_scans_at_once_keep_their_own_channel_and_path(self):
        # the cases hold two texts and both channels: a scan must read neither the channel, nor the path, nor the
        # per-text index of a scan in another thread
        alone = {case: kinds(*case) for case in CASES}
        wrong: list = []
        errors: list = []
        start = threading.Barrier(len(CASES))

        def run(case):
            try:
                start.wait(timeout=60)
                for _ in range(300):
                    got = kinds(*case)
                    if got != alone[case]:
                        wrong.append((case[1], case[2], got, alone[case]))
                        return
            except BaseException as exc:  # noqa: BLE001 - a worker's exception must fail the test, not vanish
                errors.append(repr(exc))
        threads = [threading.Thread(target=run, args=(case,), daemon=True) for case in CASES]
        interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)    # switch threads as often as possible: the race showed within a few rounds
        try:
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=300)
        finally:
            sys.setswitchinterval(interval)
        self.assertFalse([t for t in threads if t.is_alive()], "a scan thread did not end")
        self.assertEqual(errors, [])
        self.assertEqual(wrong, [], "a scan read the channel, the path or the text index of another scan")


# the module-level names that the functions of a scan still write: caches of the process whose content depends on
# no configuration (the word list, the public test values, the regexes of context words and of curl rules, the word
# cover of a run). A new name here is new scan state; remove a name when no function of a scan writes it any more.
# _CHANNEL, _PATH and _INDEX left this list (2026-10-18); the per-text index is now one per thread
# (THREAD_LOCAL_STATE). The caches that follow from the configuration (_RULES, _ALLOW, _REGIONS, _ORDER,
# _LABEL_CLASS, _PW_LAST_ON, _REGEX_*, _RUNNING) left it for the Detector, which owns them (tests/test_detector.py).
KNOWN_SCAN_STATE = frozenset({"_COVER_CACHE", "_CTX_CACHE", "_CURL_PARTS", "_PUBLIC_TEST_VALUES", "_WORDS",
                              "_WORDS_OK"})
# module-level objects a scan writes that are one per thread (threading.local): no thread reads another's
THREAD_LOCAL_STATE = frozenset({"_TEXT_INDEX"})


def _module_names(tree: ast.Module) -> set:
    names = set()
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else [getattr(node, "target", None)]
        names |= {t.id for t in targets if isinstance(t, ast.Name)}
    return names


def _base(e):
    while isinstance(e, (ast.Subscript, ast.Attribute, ast.Call)):
        e = e.func if isinstance(e, ast.Call) else e.value
    return e


def module_writes(func: ast.AST, names: set) -> set:
    """The module-level names a function writes: a global statement, an assignment, augmented assignment or del of an
    item or attribute of the name (also deeper: S[0].x = 1), a mutating method call on the name or on a part of it
    (S.append, S[0].clear), and setattr on it; also through a local name bound to it (t = S; t.x = 1, also chained).
    A name bound through a call or a return value is out of its reach."""
    alias = {n: n for n in names}
    for _ in range(3):
        for node in ast.walk(func):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name) and node.value.id in alias:
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id not in names:
                        alias[t.id] = alias[node.value.id]
    out = set()
    mutators = {"append", "extend", "insert", "pop", "popitem", "clear", "update", "setdefault", "add", "remove",
                "discard", "sort", "reverse", "__setitem__", "__delitem__"}
    for node in ast.walk(func):
        if isinstance(node, ast.Global):
            out |= set(node.names)
        targets = []
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        elif isinstance(node, ast.Delete):
            targets = node.targets
        for t in targets:
            for e in (t.elts if isinstance(t, (ast.Tuple, ast.List)) else [t]):
                base = _base(e)
                if isinstance(base, ast.Name) and base.id in alias and base is not e:
                    out.add(alias[base.id])
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in mutators:
            base = _base(node.func.value)
            if isinstance(base, ast.Name) and base.id in alias:
                out.add(alias[base.id])
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "setattr" and node.args:
            base = _base(node.args[0])
            if isinstance(base, ast.Name) and base.id in alias:
                out.add(alias[base.id])
    return out


def reachable(tree: ast.Module, root: str) -> dict:
    """The module-level functions a call from `root` reaches by name, `root` included."""
    funcs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    seen, todo = {}, [root]
    while todo:
        name = todo.pop()
        if name in seen or name not in funcs:
            continue
        seen[name] = funcs[name]
        for node in ast.walk(funcs[name]):
            if isinstance(node, ast.Name) and node.id in funcs:   # a call, or a function handed on as a value
                todo.append(node.id)
    return seen


class NoModuleScanStateTests(unittest.TestCase):
    def setUp(self):
        self.tree = ast.parse((ROOT / "maisecrets" / "detection" / "core.py").read_text(encoding="utf-8"))
        self.names = _module_names(self.tree)

    def test_the_checker_sees_each_form_of_a_module_write(self):
        src = ("S = [1]\nD = {}\nT = [[]]\nU = []\nV = {}\nW = []\nX = 0\nY = []\nZ = object()\n"
               "def f(c):\n    global X\n    S[0] = c\n    D['k'] = c\n    T[0].append(c)\n    del U[0]\n"
               "    setattr(V, 'a', c)\n    W[0] += 1\n    a, Y[0] = 1, c\n    local = [c]\n    local[0] = 2\n"
               "    local.append(S[0])\n    t = Z\n    u = t\n    u.x = c\n")
        tree = ast.parse(src)
        func = [n for n in tree.body if isinstance(n, ast.FunctionDef)][0]
        self.assertEqual(module_writes(func, _module_names(tree)), {"S", "D", "T", "U", "V", "W", "X", "Y", "Z"})

    def test_the_call_graph_reaches_the_helpers_of_a_scan(self):
        graph = reachable(self.tree, "scan")
        for name in ("_scan", "_literal_hits", "_pw_literal_ok", "_export_hits", "_personal_hits", "_text_index",
                     "_scan_cleaned_copy", "_matches", "rules"):
            self.assertIn(name, graph, "the premise: the walk reaches the inside of a scan")

    def test_a_scan_writes_no_new_module_state(self):
        graph = reachable(self.tree, "scan")
        written = set().union(*(module_writes(f, self.names) for f in graph.values()))
        self.assertFalse(written & {"_CHANNEL", "_PATH", "_INDEX"}, "the scan context is back in module state")
        self.assertEqual(written - KNOWN_SCAN_STATE - THREAD_LOCAL_STATE, set(),
                         "a scan writes new module state: pass it as an argument")
        self.assertEqual((KNOWN_SCAN_STATE | THREAD_LOCAL_STATE) - written, set(),
                         "no longer written: remove it from KNOWN_SCAN_STATE")

    def test_the_thread_local_state_is_a_threading_local(self):
        made = {n.targets[0].id: ast.unparse(n.value) for n in self.tree.body
                if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)}
        for name in THREAD_LOCAL_STATE:
            self.assertEqual(made.get(name), "threading.local()", name)


if __name__ == "__main__":
    unittest.main()
