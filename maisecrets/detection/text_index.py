"""The index of a text (its line breaks and the positions of a few patterns, one per thread) and the check whether a
hit stands in test code.

maisecrets/detection/core.py imports each name of this module, so `core.<name>` (and `detect.<name>`) is the same
object. A patch of one of these names on the core does not reach the functions of this module: patch this module."""
from __future__ import annotations

import bisect
import re
import threading

from . import registry as _registry
from .lazy_regex import LazyRx as _LazyRx


_NL_RE = _LazyRx("\n")
# the last text and its index (line breaks, lines, positions, literal hits), one per thread: scan() and is_fixture()
# ask about one text, and two scans in two threads must not read the index of each other's text
_TEXT_INDEX = threading.local()


def _text_index(text: str) -> dict:
    """The index of `text` in this thread, made at the first question about it."""
    t = _TEXT_INDEX
    if getattr(t, "text", None) is not text:
        t.text, t.cache = text, {"nl": [m.start() for m in _NL_RE.finditer(text)]}
    return t.cache


def _newlines(text: str) -> list:
    """The offsets of the line breaks of `text`, computed once per text. A search for the start or the end of a line
    at each keyword hit was one pass over the line, and a one-line text of 2 MB took 14.5 s (review of 3e5d53e,
    2026-09-30)."""
    return _text_index(text)["nl"]


def _line_start(text: str, pos: int) -> int:
    nl = _newlines(text)
    i = bisect.bisect_left(nl, pos)
    return nl[i - 1] + 1 if i else 0


def _line_end(text: str, pos: int) -> int:
    nl = _newlines(text)
    i = bisect.bisect_left(nl, pos)
    return nl[i] if i < len(nl) else len(text)


def _positions(text: str, name: str, rx: re.Pattern) -> list:
    """The start offsets of the matches of `rx` in `text`, computed once per text (see _newlines)."""
    cache = _text_index(text)
    if name not in cache:
        cache[name] = [m.start() for m in rx.finditer(text)]
    return cache[name]


# ------------------------------------------------------------- test fixtures --
# A label rule finds a value by its label alone, so a test password looks like a real one: `PASSWD = '<word>'` in the
# tests of the Python standard library (2026-09-29). In test code the value is a fixture, and a
# block or a placeholder there only stops the work. A token shape (glpat-, AKIA, a PEM key) and personal data stay
# hits in test code too: a real token or a copy of customer data in a test is a leak.
# The id prefixes of the label rules and of the keyword rules (the detect-secrets ones and maisecrets' own label rules
# with no `=` or `:`) live in maisecrets/detection/registry.py; a rule carries its form (Rule.form), a stored kind is
# read with
# registry.is_label. The names stay for the scripts and tests that read them.
LABEL_RULES = _registry.LABEL_PREFIXES
KEYWORD_RULES = _registry.KEYWORD_PREFIXES
_TEST_PATH_RE = _LazyRx(r"(?:^|[/\\])(?i:tests?|__tests__|spec|testdata|test_data|e2e)[/\\]"
                           r"|(?:^|[/\\]|[a-z])Tests?\.\w+$"
                           r"|(?:^|[/\\])[^/\\]*[._-]e2e[._-][^/\\]*$"
                           r"|(?:^|[/\\])(?:test_[^/\\]*|[^/\\]*_test\.\w+|[^/\\]*\.(?:test|spec)\.\w+|conftest\.py)$")
# a file of real values even under tests/: an .env, a recorded HTTP cassette (review, 2026-09-29)
_REAL_VALUE_FILE_RE = _LazyRx(r"(?i)(?:^|[/\\])(?:\.env[^/\\]*|[^/\\]*\.env(?:\.[^/\\]*)?|[^/\\]*\.har"
                                 r"|[^/\\]*\.har\.\w+|(?:cassettes?|(?:__)?recordings?(?:__)?|recorded|tapes|vcr"
                                 r"|__nock-fixtures__)[/\\].*)$")
_TEST_MARKER_RE = _LazyRx(
    r"(?m)^(?:(?:async[ \t]+)?def[ \t]+test_?\w*[ \t]*\(|[ \t]*class[ \t]+Tests?(?:[A-Z_(:]|$)|[ \t]*@pytest\."
    r"|[ \t]*@Test\b|[ \t]*#\[test\]"
    r"|[ \t]*(?:import|from)[ \t]+(?:pytest|unittest)\b|[ \t]*func[ \t]+Test\w*\("
    r"|[ \t]*(?:describe|it|test|beforeEach)[ \t]*\()")
_TEST_METHOD_RE = _LazyRx(r"(?m)^[ \t+-]+(?:async[ \t]+)?def[ \t]+test_?\w*[ \t]*\([ \t]*self\b")
_CLASS_LINE_RE = _LazyRx(r"(?m)^[ \t+-]*class[ \t]+\w|^@@[^\n]*\bclass[ \t]+\w")
_TEST_CLASS_LINE_RE = _LazyRx(r"[ \t+-]*class[ \t]+Tests?(?:[A-Z_(:]|$)|@@[^\n]*\bclass[ \t]+Tests?(?:[A-Z_(:]|\b)")
# `assert` alone is no marker: production code asserts too (review, 2026-09-29). A diff starts a new file here
_DIFF_FILE_RE = _LazyRx(r"(?m)^(?:diff --git |\+\+\+ |--- a/)")
_GREP_PATH_RE = _LazyRx(r"((?:[A-Za-z]:)?[^\s:]+):\d+[:-]")
_TEST_LOOKBACK_LINES = 40


def is_test_path(path: str) -> bool:
    return bool(path) and bool(_TEST_PATH_RE.search(path)) and not _REAL_VALUE_FILE_RE.search(path)


def in_test_code(text: str, start: int, path: str = "") -> bool:
    """Whether the hit at `start` sits in test code: the file is a test file, a grep line names one, or a test
    marker (`def test_`, `assert`, `describe(` …) stands in its line or in the 40 lines before it."""
    if is_test_path(path):
        return True
    line_start = _line_start(text, start)
    m = _GREP_PATH_RE.match(text, line_start)
    if m and is_test_path(m.group(1)):
        return True
    nl = _newlines(text)
    i = bisect.bisect_left(nl, line_start)       # the line of the hit is line i
    begin = nl[i - _TEST_LOOKBACK_LINES - 1] + 1 if i > _TEST_LOOKBACK_LINES else 0
    diffs = _positions(text, "diff", _DIFF_FILE_RE)
    j = bisect.bisect_left(diffs, line_start)
    if j and diffs[j - 1] >= begin:
        begin = diffs[j - 1]      # a marker of another file in the same diff does not count
    end = _line_end(text, start)
    markers = _positions(text, "marker", _TEST_MARKER_RE)
    k = bisect.bisect_left(markers, begin)
    if k < len(markers) and markers[k] < end:
        return True
    # an indented `def test_…(self` counts when no class other than a test class stands nearer above it: a test
    # method in a diff hunk or a paste, but not `def test_connection(self)` in class Db (reviews, 2026-09-30)
    defs = _positions(text, "defs", _TEST_METHOD_RE)
    k = bisect.bisect_left(defs, end) - 1
    if k < 0 or defs[k] < begin:
        return False
    classes = _positions(text, "classes", _CLASS_LINE_RE)
    c = bisect.bisect_left(classes, end) - 1   # the class nearest above the hit, also one after the method
    if c < 0 or classes[c] < begin:
        return True
    return bool(_TEST_CLASS_LINE_RE.match(text, classes[c]))
