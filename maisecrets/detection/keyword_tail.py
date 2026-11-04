"""The vendored keyword rules of detect-secrets, matched in linear time (core.py builds them)."""
from __future__ import annotations

import itertools
import re

from .lazy_regex import LazyRx as _LazyRx


# the label tail of the vendored keyword rules: `<keyword>\w*` and then a separator. On `password=` and a long run of
# letters with no space, each keyword inside the run (pwd, key) took the rest of the run and gave it back one character
# at a time (the rule with a quote and a semicolon tried 50 more characters each time): quadratic, 320 KB took 10 s,
# also in 0.6.15. What follows `\w*` in these rules never starts with a word character (a quote, ], a space, a colon,
# =, or `[^\s]{0,50}?` that a shorter run can only reach less far with), so the regex matches only where `\w*` takes
# the whole run. _KeywordTail finds each keyword, jumps to the end of its word run with an index of the runs, and runs
# the rest of the regex once per run end: the same matches, in linear time. tests/test_scan_bounds.py compares it
# with the vendored regex on runs of 0 to 5000 characters
class _KeywordTail:
    r"""A vendored keyword regex `(<alternatives>)\w*<tail>` matched without backtracking into the word run."""
    __slots__ = ("pattern", "flags", "_prefix", "_alts", "_any", "_tail", "_heads", "_alone", "_cross", "_rx")

    def __init__(self, pattern: str, keywords_prefix: str, alts: list, flags: int) -> None:
        self.pattern, self.flags, self._prefix, self._alts = pattern, flags, keywords_prefix, alts
        self._any = self._tail = None
        self._heads: list = []
        self._alone: list = []

    def _compile(self) -> None:
        if self._any is not None:
            return
        tail = self.pattern[len(self._prefix) + len("\\w*"):]
        any_ = re.compile(self._prefix, self.flags)
        groups = any_.groups
        # the alternatives that can match a character outside a word (mot de passe): only they can start inside a
        # word run and end past it. Every other one ends inside the run, at the run's end once \w* has run
        cross = [a for a in self._alts if _CROSS_CHARS_RE.search(_LOOKAROUND_RE.sub("", a))]
        self._rx = re.compile(self.pattern, self.flags)
        # a head per alternative (the others never match, keep the group numbers), compiled where the alternative
        # alone matches (a head holds all alternatives: 18 ms each, 3 s of a hook's first long text)
        self._alone = [re.compile("(?<!mai)(?:" + a + ")", self.flags) for a in self._alts]
        self._heads = [None] * len(self._alts)
        self._tail = re.compile("()" * groups + tail, self.flags)   # empty groups keep the numbers of backreferences
        self._cross = re.compile("(?<!mai)(?:" + "|".join(cross) + ")", self.flags) if cross else None
        self._any = any_   # last: another thread takes a set _any for a complete rule

    def finditer(self, text: str):
        self._compile()
        if _LONG_WORD_RUN_RE.search(text) is None:
            # no word run of 200 characters: the vendored regex backtracks at most that far per keyword, and its C
            # loop is faster than this one on ordinary lines
            yield from self._rx.finditer(text)
            return
        tails: dict = {}
        word = _WORD_RUN_ANY_RE
        pos, n = 0, len(text)
        while pos <= n:
            m = self._any.search(text, pos)
            if m is None:
                return
            p = m.start()
            w = word.match(text, m.end())
            if w is None or w.end() - m.end() < 200:
                # a short word run after the keyword: the vendored regex at p backtracks at most that far, and it is
                # the same regex. Only a keyword before a long run takes the loop below (codex verification of 0.6.16:
                # one long word made the whole text slow)
                r = self._rx.match(text, p)
                if r is not None:
                    yield r
                    pos = r.end() if r.end() > p else p + 1
                else:
                    pos = p + 1
                continue
            hit = None
            e = -1
            # the first alternative to match at p is the one the regex tries first: the search found it
            for h in itertools.chain((m,), (self._head(i).match(text, p) for i, alone in enumerate(self._alone)
                                            if alone.match(text, p) is not None)):
                if h is None:
                    continue
                q = h.end()
                w = word.match(text, q)
                e = w.end() if w is not None else q     # \w* takes the whole run after the keyword
                if e not in tails:
                    tails[e] = self._tail.match(text, e)
                t = tails[e]
                if t is not None:
                    hit = _HeadTail(text, h, t)
                    break
            if hit is None:
                pos = p + 1
                run = word.match(text, p)
                if run is not None and run.end() == e and e > pos:
                    # p starts a word run whose rest failed: a keyword later in the run that stays in it fails too.
                    # Only an alternative that leaves the run can start a match before its end
                    c = self._cross.search(text, pos, e + 256) if self._cross is not None else None
                    pos = c.start() if c is not None and c.start() < e else e
                continue
            yield hit
            pos = hit.end() if hit.end() > p else p + 1

    def _head(self, i: int):
        head = self._heads[i]
        if head is None:
            head = self._heads[i] = re.compile("(?<!mai)(" + "|".join(a if j == i else "(?!)" + a
                                                                      for j, a in enumerate(self._alts)) + ")",
                                               self.flags)
        return head

    def search(self, text: str):
        return next(self.finditer(text), None)

    @property
    def groups(self) -> int:
        self._compile()
        return self._tail.groups


class _HeadTail:
    """A match of _KeywordTail: the groups of the keyword from the head, the rest from the tail."""
    __slots__ = ("_text", "_h", "_t", "_n")

    def __init__(self, text: str, h, t) -> None:
        self._text, self._h, self._t, self._n = text, h, t, h.re.groups

    def group(self, i: int = 0):
        if i == 0:
            return self._text[self._h.start():self._t.end()]
        return self._h.group(i) if i <= self._n else self._t.group(i)

    def start(self, i: int = 0) -> int:
        if i == 0:
            return self._h.start()
        return self._h.start(i) if i <= self._n else self._t.start(i)

    def end(self, i: int = 0) -> int:
        if i == 0:
            return self._t.end()
        return self._h.end(i) if i <= self._n else self._t.end(i)

    def span(self, i: int = 0) -> tuple:
        return self.start(i), self.end(i)


_WORD_RUN_ANY_RE = _LazyRx(r"\w+")
_LONG_WORD_RUN_RE = _LazyRx(r"\w{200}")
_LOOKAROUND_RE = _LazyRx(r"\(\?<?[=!][^()]*\)")
_CROSS_CHARS_RE = _LazyRx(r"[ .\[-]|\\[sWdbBSD]")   # a space, a dot, a class, a hyphen or a non-word escape
