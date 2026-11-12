"""How far a rescan of a long line must read (core._label_scan_near, core._changed_windows_scan).

Two rescans of the core read a text a second time: the scan of a field value with its label before it
(fields.added) and the scan of the cleaned copy of a tool result (core._scan_cleaned_copy). Both rescanned whole lines,
so on a text of one long line (a JSON document dumped on one line) each read the whole text again. Here are the
helpers that let them read only the part that can change, on a long line or a long value. A short one is scanned as
before.

A rule reads at most core._WINDOW_BEFORE (2,048) characters before a value and _WINDOW_AFTER (512) after it, with
these exceptions, measured in the code of 0.9.6 (each has its guard in core):

- the gates of a rule (a keyword, a leading literal, a required literal, a context word) are searched in the whole
  text: a rescan of a part takes the gates of the whole text;
- the record and table readers of personal.py (JSON, XML, key-value lines, CSV, Markdown and HTML tables, SQL, vCard)
  judge a value by its whole record or table (personal.record_hits);
- a seed phrase reads its context word back to the start of its line (core._matches, matcher "seed");
- a quoted list after a label (matcher "list") runs on to its closing bracket, and a curl part reads back to the
  nearest `curl` on its line or the 5 lines above it (matcher "curl");
- a FHIR identifier array is read up to 4,000 characters back (personal._in_identifier_array);
- the checks that read a whole line (core._in_table_cell, _command_start, value_checks._a_version, the time budget of a
  rule of your own) only take a hit away, so a part of a line gives a hit more, never one less; a rescan that finds a
  hit the whole line might drop falls back to the whole line.
"""
from __future__ import annotations

import re

from .lazy_regex import LazyRx

# a line or a value longer than this is rescanned in windows; a shorter one as before
LONG = 16_384
# the part of a long labelled value that is scanned: the reach of the label (2,048, or 4,000 for a FHIR identifier
# array) and room for a hit that starts there and is long (a PEM block, a list of names)
LABEL_REACH = 6_144
# the characters before and after a changed run of the cleaned copy that its window holds: a hit that the change can
# alter starts at most 4,000 characters after it or ends at most 512 before it, and needs its own context around it
COPY_MARGIN = 6_144
# how far a cut looks for whitespace, so that no value is cut in half
SNAP = 1_024
# a run of the cleaned copy is compared character by character below this length
_LEAF = 32

_SPACE_RE = LazyRx(r"\s")
# the characters of a field label that read as text only: no bracket, quote, pipe, comma or slash that a record,
# a table, a list or a path reader could take for its own syntax
_PLAIN_LABEL_RE = LazyRx(r"[^\W_]+(?:[ _.-]+[^\W_]+)*")
# words that start a statement or a command whose reader runs past the label's reach (SQL, curl)
_STATEMENT_WORDS = frozenset({"select", "update", "delete", "insert", "create", "curl"})


def cut_at_space(text: str, pos: int, hi: int) -> int | None:
    """The first whitespace at or after `pos` and before `hi`, at most SNAP characters on: a window ends there, so no
    value runs across its end. None when there is none."""
    m = _SPACE_RE.search(text, pos, min(hi, pos + SNAP))
    return m.start() if m else None


def start_after_space(text: str, pos: int, lo: int) -> int | None:
    """The character after the last whitespace at or before `pos` and after `lo`, at most SNAP characters back: a
    window starts there. None when there is none."""
    a = max(lo, pos - SNAP)
    for i in range(pos, a - 1, -1):
        if text[i].isspace():
            return i + 1
    return None


def plain_label(label: str) -> bool:
    """The label is words of letters and digits with spaces, `_`, `.` or `-` between them, and none of them starts a
    statement or a command."""
    if not _PLAIN_LABEL_RE.fullmatch(label):
        return False
    return not any(w in _STATEMENT_WORDS for w in re.split(r"[ _.-]+", label.lower()))


def changed_runs(raw: str, copy: str, starts, ends, a: int, b: int) -> list:
    """The runs [x, y) of copy[a:b] that are not the raw text, merged when they touch. A part whose characters are the
    raw text at one offset and as many characters long is left out; the rest is halved down to _LEAF characters and
    compared there one by one. A character deleted between two kept ones marks both."""
    marks: list = []
    todo = [(a, b)]
    while todo:
        lo, hi = todo.pop()
        if hi <= lo:
            continue
        s = starts[lo]
        if ends[hi - 1] - s == hi - lo and copy[lo:hi] == raw[s:s + hi - lo]:
            continue
        if hi - lo <= _LEAF:
            for i in range(lo, hi):
                if ends[i] - starts[i] != 1 or raw[starts[i]] != copy[i]:
                    marks.append((i, i + 1))
                if i > lo and starts[i] != ends[i - 1]:
                    marks.append((i - 1, i + 1))
            continue
        mid = (lo + hi) // 2
        if starts[mid] != ends[mid - 1]:
            marks.append((mid - 1, mid + 1))
        todo.append((mid, hi))
        todo.append((lo, mid))
    marks.sort()
    runs: list = []
    for x, y in marks:
        if runs and x <= runs[-1][1]:
            runs[-1][1] = max(runs[-1][1], y)
        else:
            runs.append([x, y])
    return runs
