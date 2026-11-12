"""How far one match of a regex can run past a whitespace inside it: the mechanical check of the window cuts of
rescan.py.

A bounded rescan (rescan.py) reads a window of a long line that starts after a whitespace and ends before one. A
match of the whole line that crosses an edge of the window holds that whitespace. A hit that the change of the window
can alter starts at most reach.CONTEXT characters after the change (the context a filter reads before a value) and
ends at most reach.AFTER characters before it. So a match that crosses the end of a window, COPY_MARGIN after the
change, runs at least COPY_MARGIN - CONTEXT characters from its start to a whitespace in it; one that crosses the start
runs at least COPY_MARGIN - AFTER characters from a whitespace in it to its end.

`spread(pattern, flags)` gives (before, after): the most characters a match can hold before a whitespace in it,
counted from the start of the match, and after one, counted to its end, with what a lookaround reads included. A
repeat of whitespace alone counts as at most WS_RUN characters and a repeat of non-whitespace alone as at most TOKEN:
rescan.py does not cut a line that holds a longer run of either. A regex the parser cannot read, or whose parts this
module does not know, is unbounded (FAR) on both sides.
"""
from __future__ import annotations

import functools

try:
    import re._constants as _C
    import re._parser as _P
except ImportError:          # Python before 3.11
    import sre_constants as _C
    import sre_parse as _P

FAR = 1 << 30
WS_RUN = 64                  # the longest run of whitespace in a line that rescan.py cuts
TOKEN = 1024                 # the longest run of non-whitespace in a line that rescan.py cuts
_WS = " \t\n\r\x0b\x0c\x85\xa0              " \
      "  　"
_REPEATS = tuple(getattr(_C, n) for n in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT") if hasattr(_C, n))


def _cap(n: int) -> int:
    return FAR if n >= FAR else n


def _class_matches(items, ch: str, flags: int) -> bool:
    """Whether a character class (the items of IN) can match `ch`."""
    negate = False
    hit = False
    for op, av in items:
        if op is _C.NEGATE:
            negate = True
        elif op is _C.LITERAL:
            hit = hit or chr(av) == ch
        elif op is _C.RANGE:
            hit = hit or av[0] <= ord(ch) <= av[1]
        elif op is _C.CATEGORY:
            name = str(av).lower()
            space = ch.isspace()
            if "not_space" in name:
                hit = hit or not space
            elif "space" in name:
                hit = hit or space
            elif "not_word" in name or "not_digit" in name:
                hit = hit or not ch.isalnum()
            else:
                hit = hit or ch.isalnum() or ch == "_"
        else:
            return True      # a part this module does not know: it may match
    return hit != negate


def _item_ws(op, av, flags: int) -> bool:
    """Whether a single-character item can match whitespace."""
    if op is _C.LITERAL:
        return chr(av).isspace()
    if op is _C.NOT_LITERAL:
        return True
    if op is _C.ANY:
        return True          # without DOTALL it still matches a space
    if op is _C.IN:
        return any(_class_matches(av, ch, flags) for ch in _WS)
    return True


class _W:
    """width: the most characters; ws: whether it can hold whitespace; only_ws: whether it holds only whitespace;
    before/after: the spread of a whitespace in it to its start and to its end (0 when it holds none)."""
    __slots__ = ("width", "ws", "only_ws", "before", "after")

    def __init__(self, width, ws, only_ws, before, after):
        self.width, self.ws, self.only_ws, self.before, self.after = _cap(width), ws, only_ws, _cap(before), \
            _cap(after)


_UNKNOWN = _W(FAR, True, False, FAR, FAR)


def _seq(items, flags: int) -> _W:
    parts = [_node(op, av, flags) for op, av in items]
    width = 0
    before = after = 0
    ws = False
    for i, p in enumerate(parts):
        if p.ws:
            before = max(before, width + p.before)
            ws = True
        width = _cap(width + p.width)
    tail = 0
    for p in reversed(parts):
        if p.ws:
            after = max(after, tail + p.after)
        tail = _cap(tail + p.width)
    only = all(p.only_ws or p.width == 0 for p in parts) and ws
    return _W(width, ws, only, before, after)


def _alt(branches) -> _W:
    if not branches:
        return _W(0, False, False, 0, 0)
    return _W(max(b.width for b in branches), any(b.ws for b in branches), all(b.only_ws for b in branches),
              max(b.before for b in branches), max(b.after for b in branches))


def _node(op, av, flags: int) -> _W:
    if op in (_C.LITERAL, _C.NOT_LITERAL, _C.ANY, _C.IN):
        ws = _item_ws(op, av, flags)
        only = ws and op is _C.IN and not any(_class_matches(av, ch, flags) for ch in "aZ09_-.:/")
        if op is _C.LITERAL:
            only = ws
        return _W(1, ws, only, 1 if ws else 0, 1 if ws else 0)
    if op is _C.AT:
        return _W(0, False, False, 0, 0)
    if op is _C.SUBPATTERN:
        return _seq(av[-1], flags | (av[1] or 0))
    if op is _C.BRANCH:
        return _alt([_seq(b, flags) for b in av[1]])
    if op in _REPEATS:
        lo, hi, body = av
        b = _seq(body, flags)
        if b.only_ws:
            hi = min(hi, WS_RUN)
        elif not b.ws and b.width:
            hi = min(hi, -(-TOKEN // b.width))
        n = FAR if hi >= _C.MAXREPEAT else hi
        if n == 0 or b.width == 0:
            return _W(0, False, False, 0, 0)
        width = _cap(b.width * n) if n < FAR else (FAR if b.width else 0)
        if not b.ws:
            return _W(width, False, False, 0, 0)
        # the whitespace of the last copy has every earlier copy before it, and of the first every later one after it
        before = _cap(b.width * (n - 1) + b.before) if n < FAR else FAR
        after = _cap(b.width * (n - 1) + b.after) if n < FAR else FAR
        return _W(width, True, b.only_ws, before, after)
    if op is getattr(_C, "ATOMIC_GROUP", object()):
        return _seq(av, flags)
    if op in (_C.ASSERT, _C.ASSERT_NOT):
        # a lookaround reads its text: a lookahead after the match, a lookbehind before it. Its width counts on its
        # side, and a whitespace it reads counts as a whitespace of the match
        direction, body = av
        b = _seq(body, flags)
        if not b.ws:
            return _W(0, False, False, 0, 0)
        if direction > 0:     # lookahead: reads b.width characters on from here
            return _W(0, True, False, b.before, b.width)
        return _W(0, True, False, b.width, b.after)
    if op in (_C.GROUPREF, getattr(_C, "GROUPREF_EXISTS", None)):
        return _UNKNOWN
    return _UNKNOWN


@functools.lru_cache(maxsize=4096)
def spread(pattern: str, flags: int = 0) -> tuple:
    """(before, after) of a regex: see the module text. (FAR, FAR) for a regex the parser cannot read."""
    try:
        w = _seq(list(_P.parse(pattern, flags)), flags)
    except Exception:  # noqa: BLE001 - a pattern the parser cannot read is unbounded
        return FAR, FAR
    return w.before, w.after
