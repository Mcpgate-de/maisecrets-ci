"""The findings of a JSON-shaped object in few scans, each finding placed in its string leaf.

A caller that holds a parsed response (a dict from an API) and wants the findings of each string in it can scan each
string apart after its key, or scan fewer texts. A call has a fixed cost of about 0.6 ms and a gateway response has
69 strings on average, so the calls are most of the time. This module scans one text per record (layout "lines": each
string on a line after its last key, as written) or one JSON text (layout "json", with the limits that docs/
DETECTION.md names), and gives each finding in the coordinates of its string:

    from maisecrets.detection.leaves import findings_by_leaf
    for leaf, m in findings_by_leaf(detector, response):
        leaf.path, m.start, m.end, m.type   # the path of the string (keys and list indices), the span in the string

In layout "json" the text is the one `json.dumps(obj, ensure_ascii=False)` writes, and a string that needs an escape
is mapped back character by character, so a span is always one of the string as the caller holds it. A finding that
starts in a key, a label or the structure belongs to no leaf (`leaf` is None); one that starts in a string and
runs past its end is cut at the end of the string.
"""
from __future__ import annotations

import dataclasses
import json

_SHORT = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\b": "\\b", "\f": "\\f"}


@dataclasses.dataclass(frozen=True)
class Leaf:
    """A string of the object: its path (dict keys and list indices, outermost first), the string, and where it sits
    in the JSON text."""
    path: tuple
    value: str
    start: int
    end: int
    places: tuple   # the JSON offset of each character of value, and of its end, relative to start


def _escape(s: str) -> tuple:
    out, places, n = [], [], 0
    for ch in s:
        places.append(n)
        e = _SHORT.get(ch) or (f"\\u{ord(ch):04x}" if ord(ch) < 0x20 else ch)
        out.append(e)
        n += len(e)
    places.append(n)
    return "".join(out), tuple(places)


def json_text(obj) -> tuple:
    """`(text, leaves)`: the object as JSON text, as json.dumps(obj, ensure_ascii=False) writes it, and its strings.
    Raises TypeError for a value JSON cannot hold and ValueError for a cycle, as json.dumps does. The walk keeps its
    own stack, so a depth json.dumps writes does not end in a RecursionError here."""
    parts, leaves, n, seen = [], [], 0, set()
    # a stack of work: ("v", value, path) writes a value, ("s", text) writes text, ("x", id) leaves a container
    todo = [("v", obj, ())]
    while todo:
        job = todo.pop()
        if job[0] == "s":
            parts.append(job[1])
            n += len(job[1])
            continue
        if job[0] == "x":
            seen.discard(job[1])
            continue
        _, x, path = job
        if isinstance(x, str):
            value = str.__str__(x)   # the characters json.dumps writes, whatever a subclass does in __iter__
            written, places = _escape(value)
            leaves.append(Leaf(path, value, n + 1, n + 1 + len(written), places))
            parts.append('"' + written + '"')
            n += len(written) + 2
        elif x is None or isinstance(x, (bool, int, float)):
            w = json.dumps(x)
            parts.append(w)
            n += len(w)
        elif isinstance(x, (dict, list, tuple)):
            if id(x) in seen:
                raise ValueError("Circular reference detected")
            seen.add(id(x))
            items = []
            if isinstance(x, dict):
                for i, (k, v) in enumerate(x.items()):
                    if not isinstance(k, (str, int, float, bool)) and k is not None:
                        raise TypeError(f"keys must be str, int, float, bool or None, not {type(k).__name__}")
                    key = str.__str__(k) if isinstance(k, str) else json.dumps(k)
                    items.append(("s", (", " if i else "") + '"' + _escape(key)[0] + '": '))
                    items.append(("v", v, path + (key,)))
                opening, closing = "{", "}"
            else:
                for i, v in enumerate(x):
                    if i:
                        items.append(("s", ", "))
                    items.append(("v", v, path + (i,)))
                opening, closing = "[", "]"
            parts.append(opening)
            n += 1
            todo.append(("x", id(x)))
            todo.append(("s", closing))
            todo.extend(reversed(items))
        else:
            raise TypeError(f"Object of type {type(x).__name__} is not JSON serializable")
    return "".join(parts), leaves


def _back(places: tuple, offset: int, end: bool) -> int:
    """The character of the string at a JSON offset inside it: the last one that starts at or before it, or for an
    end the first one that starts at or after it."""
    lo, hi = 0, len(places) - 1
    while lo < hi:
        mid = (lo + hi + (0 if end else 1)) // 2
        if (places[mid] < offset) if end else (places[mid] <= offset):
            lo = mid + (1 if end else 0)
        else:
            hi = mid - (0 if end else 1)
    return lo


def records(leaves: list) -> list:
    """The strings grouped by record: each item of the outermost list on a string's path is a record of its own, and
    the strings that sit in no list are the record of the object itself. The order of the strings is kept."""
    groups: dict = {}
    for leaf in leaves:
        cut = next((i for i, part in enumerate(leaf.path) if isinstance(part, int)), None)
        groups.setdefault(() if cut is None else leaf.path[:cut + 1], []).append(leaf)
    return list(groups.values())


# a key with one of these is no label: it would end the label line or read as an assignment, a quote or a table cell
_NOT_IN_LABEL = frozenset(':=|"\'')
_LABEL_MAX = 64


def _label(path: tuple) -> str:
    """The last key of the path as the label of its string, or "" when it can be none: a key that is empty, longer
    than 64 characters, holds a line boundary of str.splitlines() (\\r, U+2028 …) or a control character, holds
    one of `: = | " '`, or names the cursor of a paged list (nextPageToken: the gateway gives no label there either)."""
    last = next((part for part in reversed(path) if isinstance(part, str)), "")
    if not last or len(last) > _LABEL_MAX or any(c in _NOT_IN_LABEL for c in last):
        return ""
    if last.splitlines() != [last] or any(ord(c) < 0x20 or 0x7f <= ord(c) < 0xa0 for c in last):
        return ""
    from .fields import is_cursor, label_words
    return "" if is_cursor(label_words(last), field=True) else last


def _segments(group: list) -> list:
    """A record cut before each string that has no label: on its own line after another string, the last line of that
    string (`password:`) would read as its label, which neither string gives alone (codex review, 2026-11-02)."""
    out = []
    for leaf in group:
        if not out or not _label(leaf.path):
            out.append([])
        out[-1].append(leaf)
    return out


def _lines(detector, obj, channel: str, **kwargs) -> list:
    out = []
    for group in (seg for rec in records(json_text(obj)[1]) for seg in _segments(rec)):
        parts, placed, n = [], [], 0
        for leaf in group:
            label = _label(leaf.path)
            lead = f"{label}: " if label else ""
            placed.append((leaf, n + len(lead)))
            parts.append(lead + leaf.value)
            n += len(lead) + len(leaf.value) + 1
        text = "\n".join(parts)
        k = 0   # the findings come sorted by start and the strings in text order: one pass over both
        for m in sorted(detector.findings(text, channel=channel, **kwargs), key=lambda m: m.start):
            while k < len(placed) and placed[k][1] + len(placed[k][0].value) < m.start:
                k += 1
            hit = None
            for leaf, at in placed[k:k + 2]:
                end = at + len(leaf.value)
                # a span starts in a string; a point may also sit at its end, and an empty string owns its one point
                if at <= m.start < end or (m.end <= m.start and m.start == end):
                    hit = (leaf, at)
                    break
            if hit is None:
                out.append((None, m))
                continue
            leaf, at = hit
            s, e = m.start - at, min(m.end, at + len(leaf.value)) - at
            out.append((leaf, dataclasses.replace(m, start=s, end=max(s, e), value=leaf.value[s:max(s, e)])))
    return out


def findings_by_leaf(detector, obj, channel: str = "tool", layout: str = "lines", **kwargs) -> list:
    """The findings of the object's strings, as `(leaf, match)`: `match.start`, `match.end` and `match.value` are
    those of the string `leaf.value`. Further keyword arguments go to `detector.findings`.

    layout "lines" (the default since 0.8.11): one scan per record (`records`), each string on a line of its own after
    its last key, as written (no JSON escape). layout "json": one scan of the JSON text; a string with a line break or
    a quote is read with its escapes there, so a value can run over a line end or lose its label (gateway check of
    0.8.10, 2026-11-02)."""
    if layout == "lines":
        return _lines(detector, obj, channel, **kwargs)
    if layout != "json":
        raise ValueError("layout must be lines or json")
    text, leaves = json_text(obj)
    out, k = [], 0
    for m in sorted(detector.findings(text, channel=channel, **kwargs), key=lambda m: m.start):
        while k < len(leaves) and leaves[k].end < m.start:
            k += 1
        leaf = leaves[k] if k < len(leaves) and leaves[k].start <= m.start < max(leaves[k].end, leaves[k].start + 1) \
            else None
        if leaf is None or leaf.start == leaf.end:
            out.append((None, m))
            continue
        s = _back(leaf.places, m.start - leaf.start, end=False)
        e = s if m.end <= m.start else _back(leaf.places, min(m.end, leaf.end) - leaf.start, end=True)
        out.append((leaf, dataclasses.replace(m, start=s, end=e, value=leaf.value[s:e])))
    return out
