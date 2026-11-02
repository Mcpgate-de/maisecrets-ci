"""The findings of a JSON-shaped object, one scan for the whole object, each finding placed in its string leaf.

A caller that holds a parsed response (a dict from an API) and wants the findings of each string in it can scan each
string apart, or write the object as JSON once and scan that. The core reads JSON keys as labels, so the second sees
each string after its key as the first does with a field name before it; it also sees the strings around it, so a
record can add a finding that a string alone does not give (last_name next to first_name). On the gateway corpus both
found the same, and the second took a third of the time:
a call has a fixed cost of about 0.6 ms, and a response has about 170 strings (bench/gateway_report.py, 2026-11-02).
What the caller then needs is each finding in the coordinates of its string, not of the JSON text, and that is what
this module gives:

    from maisecrets.detection.leaves import findings_by_leaf
    for leaf, m in findings_by_leaf(detector, response):
        leaf.path, m.start, m.end, m.type   # the path of the string (keys and list indices), the span in the string

The JSON text is the one `json.dumps(obj, ensure_ascii=False)` writes. A string that needs an escape (a quote, a
backslash, a control character) is mapped back character by character, so a span is always one of the string as
the caller holds it. A finding that starts in a key or in the structure belongs to no leaf (`leaf` is None); one
that starts in a string and runs past its end is cut at the end of the string.
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


def findings_by_leaf(detector, obj, channel: str = "tool", **kwargs) -> list:
    """The findings of one scan of the object's JSON text, as `(leaf, match)`: `match.start`, `match.end` and
    `match.value` are those of the string `leaf.value`. Further keyword arguments go to `detector.findings`."""
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
