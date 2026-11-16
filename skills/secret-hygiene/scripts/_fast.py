"""The fast tier of the session audit (#59): the full detector runs only near a line that can hold a match.

Tier 1 searches each text once for the anchors of the enabled rules: a rule's leading literal (every match starts
with it), else its required literals (every match holds one), else its keywords. Tier 2 runs the detector on each
line that holds an anchor, with LINES_BEFORE lines before it and LINES_AFTER after it (a label on the line above, the
secret line after an AWS key id); a PEM header takes the lines up to its END line. Windows that touch are merged.
The rules without any anchor (a bare token shape, such as a Telegram bot token) run over the whole text.

What it can miss, and the full scan (--full) finds: a match whose keyword stands more than LINES_BEFORE lines before
it or LINES_AFTER after it, and a match that needs a word farther away than the window (a context word of a weak
shape). A value with no label and no prefix is found by neither tier, as before.
"""
from __future__ import annotations

import re

LINES_BEFORE = 3
LINES_AFTER = 3
PEM_LINES = 200
_STATE: dict = {}


def _trie_regex(words) -> str:
    """One regex for many literals, as a trie: the regex engine tests the first character once per position."""
    trie: dict = {}
    for w in words:
        node = trie
        for ch in w:
            node = node.setdefault(ch, {})
        node[""] = {}

    def emit(node) -> str:
        alts, end = [], "" in node
        for ch in sorted(k for k in node if k):
            alts.append(re.escape(ch) + emit(node[ch]))
        if not alts:
            return ""
        body = alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")"
        return "(?:" + body + ")?" if end else body
    return emit(trie)


TOKEN = r"[a-z0-9_\-+/=.~]"
# after a keyword: the rest of its name (password_hash, apiKey, api key, clé d'accès), quotes, brackets or a line
# break, then an assignment, a colon (not one before digits alone: a file:line), an arrow, a call, a pipe, or a
# comma and a quote: `token: x`, `"api_key": "x"`, `<password>x`, `getToken("x")`, `nkey = "x"`,
# `Password    = "x"`; or a quoted value (`--token "x"`); or a token with a digit after a space (`Basic dXNl…`)
AFTER_KEYWORD = (r"[\w.\-'’ \t]{0,24}[\s\"'`\])]{0,4}[ \t]{0,8}(?::(?!\d+(?:[:\s,;)]|$))|[=>(|]|,[ \t]*[\"'`])"
                 r"|[ \t]+[\"'`]|[ \t]+(?=" + TOKEN + r"{8,})(?=\S*\d)")


def build(detect, enabled) -> tuple:
    """(anchors over the lower case, regex over the text as it is, ids of the rules without an anchor). A leading or
    required literal of four characters or more counts wherever it stands; a shorter one only where a token starts
    with it; a keyword, and a leading literal that is a plain word, only where a value can follow it on its line
    (AFTER_KEYWORD). A required literal never needs a value after it: the value may stand before it."""
    case, strong, short, words, shortword, bare = set(), set(), set(), set(), set(), set()
    before: set = set()
    for r in detect.rules():
        if enabled is not None and r.id not in enabled and getattr(r, "key", None) not in enabled:
            continue
        lit, ic = r.prefix if r.prefix else ("", False)
        if lit and not ic and len(lit) >= 3:
            case.add(lit)
        elif lit or r.need or r.keywords:
            lits = (lit,) if lit else r.need or r.keywords
            after = _after_value(r, lits) if not lit else set()
            for x in lits:
                x = x.lower()
                if x in after:
                    # the value can stand before this literal: "use <value> as the password" (a required literal:
                    # an anchor wherever it stands), `"<value>" == password` (a keyword: after a comparison). The
                    # regex may name it on both sides, so it keeps its own shape below too
                    (strong if r.need else before).add(x)
                x = x.lower()
                # a word (client, token) is a label: it counts where a value can follow; another literal (hvs., ghp_)
                # starts or is a part of the value
                (words if x.isalpha() and len(x) >= 4 else shortword if x.isalpha() else strong if len(x) >= 4
                 else short).add(x)
        else:
            bare.add(r.id)
    rx_c = re.compile(_trie_regex(sorted(case))) if case else None
    anchors = (_Anchors(strong, short, words, shortword, before)
               if strong or short or words or shortword or before else None)
    return anchors, rx_c, frozenset(bare)


_ALNUM = frozenset("abcdefghijklmnopqrstuvwxyz0123456789")
_TOKEN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-+/=.~")
_COMPARED = re.compile(r"[!=]==?[ \t]*[\"'`]?[ \t]*\Z|[!=]==?[ \t]*[\"'`]?[ \t]*$")
LONG_TOKEN = 20


def _in_long_token(low: str, a: int, b: int) -> bool:
    """A literal inside a token of LONG_TOKEN characters or more: a key word that is a part of the value
    (azure ...AzFu..., new relic ...FFFFNRAL)."""
    i, j = a, b
    while i > 0 and low[i - 1] in _TOKEN_CHARS and b - i < LONG_TOKEN:
        i -= 1
    while j < len(low) and low[j] in _TOKEN_CHARS and j - i < LONG_TOKEN:
        j += 1
    return j - i >= LONG_TOKEN


def _group_span(pattern: str, group: int) -> tuple:
    """(start, end) in the pattern of capture group `group`, or (-1, -1)."""
    n, i, stack = 0, 0, []
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            j = i + 1
            if pattern[j:j + 1] == "]":
                j += 1
            while j < len(pattern) and pattern[j] != "]":
                j += 2 if pattern[j] == "\\" else 1
            i = j + 1
            continue
        if c == "(":
            cap = not pattern.startswith("(?", i) or pattern.startswith("(?P<", i)
            n += cap
            stack.append((i, cap and n == group))
        elif c == ")" and stack:
            start, mine = stack.pop()
            if mine:
                return start, i
        i += 1
    return -1, -1


def _after_value(rule, lits) -> set:
    """The literals of a rule that its regex places after the value group: the value stands before them."""
    pattern = getattr(rule.regex, "pattern", None)
    if not isinstance(pattern, str):
        return set()
    a, b = _group_span(pattern, rule.secret_group or 1)
    low = pattern.lower()
    return {x.lower() for x in lits if a >= 0 and low.find(x.lower()) > b}


class _Anchors:
    """One search for every lower-case literal (a trie, searched again from the next position after each hit), then
    the check of its kind at that position only. Five alternations over the whole text cost 29 % of the fast scan."""
    STRONG, SHORT, WORD, BEFORE = 1, 2, 4, 8

    def __init__(self, strong, short, words, shortword, before=frozenset()):
        self.kind: dict = {}
        for bit, group in ((self.STRONG, strong), (self.SHORT, short), (self.WORD, words | shortword),
                           (self.BEFORE, before)):
            for x in group:
                self.kind[x] = self.kind.get(x, 0) | bit
        self.lengths = sorted({len(x) for x in self.kind})
        self.rx = re.compile(_trie_regex(sorted(self.kind)))
        self.after = re.compile(AFTER_KEYWORD)
        self.token = re.compile(TOKEN + "{8,}")
        self.flag = re.compile(r"[\w\-]{0,16}[ \t=]+[^\s\-]")   # --password x, -token=x

    def hits(self, low: str) -> list:
        """(position, literal) of each anchor in the lower-case text."""
        out = []
        kind, token, after, flag = self.kind, self.token, self.after, self.flag
        search = self.rx.search
        m = search(low)
        while m:
            pos, longest = m.start(), m.group()
            m = search(low, pos + 1)    # the next literal may start inside this one
            head = pos == 0 or low[pos - 1] not in _ALNUM
            for k in self.lengths:      # the longest literal here and each literal that is a prefix of it
                if k > len(longest):
                    break
                x = longest[:k]
                c = kind.get(x)
                if c is None:
                    continue
                end = pos + k
                if (c & self.STRONG or (head and c & (self.SHORT | self.WORD) and token.match(low, end))
                        or (c & self.BEFORE and _COMPARED.search(low, max(0, pos - 32), pos))
                        or (c & self.WORD and not head and _in_long_token(low, pos, end))
                        or (c & self.WORD and (after.match(low, end)
                                               or (pos and low[pos - 1] == "-" and flag.match(low, end))))):
                    out.append((pos, x))
                    break
        return out


def _state(detect, enabled) -> tuple:
    key = (id(detect), None if enabled is None else frozenset(enabled))
    if _STATE.get("key") != key:
        _STATE.clear()
        _STATE["key"], _STATE["built"] = key, build(detect, enabled)
    return _STATE["built"]


def windows(text: str, rx_i, rx_c) -> list:
    """The [start, end) ranges of the text that tier 2 scans, merged."""
    hits = []
    if rx_i is not None:
        low = text.lower()
        if len(low) != len(text):   # a letter whose lower case is longer moves the offsets: the whole text
            return [[0, len(text)]]
        hits += rx_i.hits(low)
    if rx_c is not None:
        hits += [(m.start(), m.group()) for m in rx_c.finditer(text) if m.group()]
    if not hits:
        return []

    def back(pos: int, lines: int) -> int:   # the start of the line `lines` lines above the line of pos
        a = text.rfind("\n", 0, pos) + 1
        while lines and a:
            a = text.rfind("\n", 0, a - 1) + 1
            lines -= 1
        return a

    def ahead(pos: int, lines: int) -> int:  # the end of the line `lines` lines below the line of pos
        b = text.find("\n", pos)
        while lines and b >= 0:
            b = text.find("\n", b + 1)
            lines -= 1
        return len(text) if b < 0 else b
    spans: list = []
    for pos, lit in sorted(hits):
        pem = "begin" in lit.lower()
        if spans and pos < spans[-1][2] and not pem:
            continue    # on the anchor line of the window before: it adds nothing
        a = back(pos, LINES_BEFORE)
        b = ahead(pos, LINES_AFTER)
        if pem:   # a key block: up to its END line
            end = text.find("-----END", pos, ahead(pos, PEM_LINES))
            if end >= 0:
                b = max(b, ahead(end, 0))
        if spans and a <= spans[-1][1] + 1:
            spans[-1][1] = max(spans[-1][1], b)
        else:
            spans.append([a, b, 0])
        spans[-1][2] = ahead(pos, 0)
    return [[a, b] for a, b, _ in spans]


def scan(detect, text: str, enabled, channel: str, scan_text) -> list:
    """The matches of the fast tier, each with its offsets in `text`."""
    import dataclasses
    rx_i, rx_c, bare = _state(detect, enabled)
    out, taken = [], []
    for a, b in windows(text, rx_i, rx_c):
        for m in scan_text(detect, text[a:b], enabled, channel):
            out.append(dataclasses.replace(m, start=m.start + a, end=m.end + a))
            taken.append((m.start + a, m.end + a))
    if bare:
        for m in scan_text(detect, text, bare, channel):
            if not any(s < m.end and m.start < e for s, e in taken):
                out.append(m)
    return out
