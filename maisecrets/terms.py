"""Terms: names, case numbers and customer names, which have no shape (README "Terms", C26).

Based on the personal-terms design by @danszymkowiak (github.com/danszymkowiak/maisecrets, docs/TERMS.md): his file
form, his four match modes and his rule that no message shows a term. What is different here, and why, is in the
README section "Terms".

The sources, read once per hook process:

- `~/.maisecrets/terms.txt`, the person's own list. The agent cannot read or write it (C8). A line the loader cannot
  read stops every hook (fail closed): only the person writes the file, the message names the line, and the
  alternative is a silent leak of exactly the names the person listed.
- `*.terms` in each folder of `rule_dirs` (a team list). An agent can write a shared checkout, so a team entry has a
  floor (3 characters, not a word of rules/term_stoplist.txt), and a line that fails is QUARANTINED: left out and
  named in /maisecrets:rules, never fatal.
- the names the person marked in a typed prompt as `{{Jan Kowalski}}`: in `terms.marked.json` until the lifetime of a
  NAME value ends.

A hit is a detect.Match of kind `term:<id>`: the id is a hash of the source and the label, never the term. hooks.py
stores no term in the store: the vault keeps one entry per entity, whose value is the text `maisecrets-term:<id>`,
so every spelling of an entity gets the same placeholder, and the placeholder is never resolved back (mask only).
"""
from __future__ import annotations

import errno
import hashlib
import json
import marshal
import math
import os
import re
import stat
import sys
import time
import unicodedata
import zlib
from bisect import bisect_left
from array import array
from dataclasses import dataclass, field
from pathlib import Path

from . import term_files
from .home import HOME, ConfigError

WORD = "word"        # Jan: the whole word
STARTS = "starts"    # Kowalsk*: word start, any ending
ENDS = "ends"        # *kowalski: any start, word end
INSIDE = "inside"    # *kowalski*: anywhere inside a word

PERSONAL = term_files.PERSONAL
MARKED = term_files.MARKED
STATE_FILE = term_files.STATE_FILE
SUGGESTED = HOME / "terms.suggested.txt"    # the proposal of `maisecrets terms suggest`: names, so in the store
SUFFIX = term_files.SUFFIX
STORE_PREFIX = term_files.STORE_PREFIX

MIN_INSIDE = 4        # *x*: a shorter x would mask half of every text
MIN_AFFIX = 3         # the stem of Kowalsk* or *kowalski
MIN_TEAM = 3          # a team entry, without its stars
MIN_TEAM_AFFIX = 5    # the stem of a team `stem*`, `*stem` or `*stem*`: `ret*`, `*ing` masked half of every text
MAX_COMMON = 3        # a team stem that this many stop-list words share is refused (`*tion*`, `contr*`)
MAX_INSIDE = 50       # *x* variants in all: each one is a search over the whole text
MAX_WORDS = 8
MAX_BUCKET = 16       # team variants that share one index record (a stem, or the words of a whole-word variant)
MAX_TEAM_ENTITIES = 150_000
MAX_TEAM_BYTES = 4 * 1024 * 1024   # about 100,000 entries; a build takes 1.4 s (3.14) to 2.2 s (3.9)
LABEL_RE = re.compile(r"[A-Z][A-Z0-9_]{0,31}")
TYPES = ("SECRET", "NAME", "EMAIL", "PHONE", "IBAN", "CARD", "IP")
# a word: letters, digits and the underscore, so Kowalski_report.pdf holds the word kowalski_report, not kowalski
_WORD_RE = re.compile(r"\w+")
_SPACE_RE = re.compile(r"\s+")
_JOINTS = ("-", ".")      # with `_`, the joints of a joined name: jan.kowalski, Jan-Kowalski, jan_kowalski


class TermsError(ConfigError):
    """A ConfigError: every hook fails closed on it, as on a broken config. The message names the file and a line
    number, never the text of a line."""

    def __init__(self, message: str, line: int | None = None):
        super().__init__(message)
        self.line = line


@dataclass(frozen=True)
class Variant:
    text: str
    mode: str


@dataclass(frozen=True)
class Entity:
    label: str
    variants: tuple
    line: int
    source: str = "own"     # own | marked | <folder>/<file>
    ident: str = field(default="", compare=False)    # the id, when the variants are not at hand (Matcher.entity)

    @property
    def id(self) -> str:
        """A hash of the source, the label and the variants: a label that a removal freed and an add took again for
        another name gets another placeholder (gate review of block 2, M3)."""
        if self.ident:
            return self.ident
        forms = "\0".join(sorted(f"{v.mode}:{_lower(v.text)}" for v in self.variants))
        return hashlib.sha256(f"{self.source}\0{self.label}\0{forms}".encode("utf-8")).hexdigest()[:12]

    @property
    def type(self) -> str:
        """The placeholder type: the label when it is a type (EMAIL, or EMAIL_BOSS), else NAME."""
        return next((t for t in TYPES if self.label == t or self.label.startswith(t + "_")), "NAME")


@dataclass(frozen=True)
class Refused:
    source: str
    line: int
    reason: str      # fixed text, never a term


# ---------------------------------------------------------------- parsing --
def _variant(raw: str, n: int, floor: frozenset | None) -> Variant:
    """One variant; raises TermsError with a reason that names the line only. `floor` is the stop list of a team
    list (None for the person's own list)."""
    text = _norm(raw).strip()
    starts, ends = text.startswith("*"), text.endswith("*") and len(text) > 1
    text = text[1 if starts else 0:len(text) - 1 if ends else len(text)].strip()
    if not text:
        raise TermsError(f"line {n}: an empty variant", n)
    if "*" in text:
        raise TermsError(f"line {n}: a * may stand only at the start or the end of a variant", n)
    text = " ".join(text.split())
    if any(ord(ch) < 32 for ch in text):
        raise TermsError(f"line {n}: a control character in a variant", n)
    words = _WORD_RE.findall(_lower(text))
    if not words:
        raise TermsError(f"line {n}: a variant needs a letter or a digit", n)
    if len(words) > MAX_WORDS:
        raise TermsError(f"line {n}: a variant of more than {MAX_WORDS} words", n)
    mode = INSIDE if starts and ends else STARTS if ends else ENDS if starts else WORD
    if mode == INSIDE and len(text) < MIN_INSIDE:
        raise TermsError(f"line {n}: a *…* variant needs at least {MIN_INSIDE} characters", n)
    if mode == STARTS and (len(words[-1]) < MIN_AFFIX or not _WORD_RE.fullmatch(text[-1])):
        raise TermsError(f"line {n}: the word before a * needs at least {MIN_AFFIX} letters or digits", n)
    if mode == ENDS and (len(words[0]) < MIN_AFFIX or not _WORD_RE.fullmatch(text[0])):
        raise TermsError(f"line {n}: the word after a * needs at least {MIN_AFFIX} letters or digits", n)
    if floor is not None:
        if len(text) < MIN_TEAM:
            raise TermsError(f"line {n}: a team entry needs at least {MIN_TEAM} characters", n)
        if all(w in floor for w in words):
            raise TermsError(f"line {n}: {'a common word' if len(words) == 1 else 'only common words'} "
                             "(rules/term_stoplist.txt) in a team list", n)
        stem = words[-1] if mode == STARTS else words[0] if mode == ENDS else _lower(text) if mode == INSIDE else ""
        if mode != WORD and len(stem) < MIN_TEAM_AFFIX:
            raise TermsError(f"line {n}: a * in a team list needs a stem of at least {MIN_TEAM_AFFIX} letters", n)
        if mode != WORD and _common_stem(stem, mode) >= MAX_COMMON:
            raise TermsError(f"line {n}: a * stem that common words (rules/term_stoplist.txt) share, in a team "
                             "list", n)
    return Variant(text, mode)


def _common_stem(stem: str, mode: str) -> int:
    """How many words of the stop list the stem of a team entry matches: words that start with it (stem*), end with
    it (*stem) or hold it (*stem*). A bisect in the sorted list, so a team list of 100,000 entries stays fast."""
    words, rev = _stop_sorted()
    if mode == STARTS:
        return bisect_left(words, stem + "\uffff") - bisect_left(words, stem)
    if mode == ENDS:
        r = stem[::-1]
        return bisect_left(rev, r + "\uffff") - bisect_left(rev, r)
    return _stop_inside().get(stem, 0)


_INSIDE: list = []


def _stop_inside() -> dict:
    """{substring: how many stop words hold it} for every substring of MIN_TEAM_AFFIX characters or more: a *stem*
    entry is one lookup. A walk over the stop list for each entry made a 4 MB team list of *…* entries cost 5 s of CPU
    before the cap of MAX_INSIDE left all but 50 of them out (Gate A, review of the rebase)."""
    if not _INSIDE:
        counts: dict = {}
        for w in stoplist():
            subs = {w[i:j] for i in range(len(w)) for j in range(i + MIN_TEAM_AFFIX, len(w) + 1)}
            for sub in subs:
                counts[sub] = counts.get(sub, 0) + 1
        _INSIDE.append(counts)
    return _INSIDE[0]


def parse(text: str, source: str = "own", strict: bool = True,
          floor: frozenset | None = None) -> tuple[list, list]:
    """(entities, refused) of a term list. One entity per line: `LABEL  variant | variant`, `#` comments. Strict (the
    person's own list): the first bad line raises TermsError. Not strict (a team list): a bad line or variant is
    refused and the rest loads."""
    entities: list = []
    refused: list = []
    seen: set = set()
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parts = line.split(None, 1)
            label, rest = parts[0], parts[1] if len(parts) > 1 else ""
            if not LABEL_RE.fullmatch(label):
                raise TermsError(f"line {n}: the line must start with a label of capital letters, digits and _ "
                                 "(at most 32), then the variants", n)
            if label in seen:
                raise TermsError(f"line {n}: the label appears on an earlier line", n)
            seen.add(label)
            variants = []
            for raw in rest.split("|"):
                try:
                    variants.append(_variant(raw, n, floor))
                except TermsError as exc:
                    if strict or floor is None:
                        raise
                    refused.append(Refused(source, n, str(exc).split(": ", 1)[1]))
            if variants:
                entities.append(Entity(label, tuple(variants), n, source))
        except TermsError as exc:
            if strict:
                raise
            refused.append(Refused(source, n, str(exc).split(": ", 1)[1]))
    return entities, refused


# ---------------------------------------------------------------- matcher --
def _lower(text: str) -> str:
    """Lower case as detect._lower: the Turkish capital İ lowers to i plus a combining dot, which is no letter and
    would split the word; the dot is dropped."""
    return text.lower().replace("i\u0307", "i")


# the format characters (Unicode Cf) a name can hold without a visible change: soft hyphen, zero-width space and
# joiners, word joiner, byte order mark, the bidi marks and the tag characters
_CF = frozenset(chr(c) for r in ((0xAD, 0xAD), (0x600, 0x605), (0x61C, 0x61C), (0x6DD, 0x6DD), (0x70F, 0x70F),
                                 (0x180E, 0x180E), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064),
                                 (0x2066, 0x206F), (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB), (0xE0001, 0xE0001),
                                 (0xE0020, 0xE007F)) for c in range(r[0], r[1] + 1))
_CF_RE = re.compile("[" + "".join(sorted(_CF)) + "]")


def _norm(text: str) -> str:
    """A variant as the index holds it: NFC, without format characters (`Mu\u0308ller` is `Müller`)."""
    return unicodedata.normalize("NFC", _CF_RE.sub("", text))


def _prepare(text: str) -> tuple:
    """(text, None, None) when the text is NFC and has no format character (nearly always: a fast check); else (the
    text in NFC without them, the start and the end in the text of each of its characters). A file name from macOS
    is NFD, and a soft hyphen in a name hid it from the matcher (gate review of block 2, H2)."""
    if text.isascii() or (unicodedata.is_normalized("NFC", text) and not _CF_RE.search(text)):
        return text, None, None
    starts: list = []
    ends: list = []
    parts: list = []
    i, n = 0, len(text)
    while i < n:
        if text[i] in _CF:
            i += 1
            continue
        j = i + 1
        seg = text[i]
        nf = unicodedata.normalize("NFC", seg)
        while j < n:
            c = text[j]
            if c in _CF:
                j += 1
                continue
            # a combining mark, or a character of class 0 that still composes (Hangul jamo, some Indic vowels)
            nxt = unicodedata.normalize("NFC", seg + c)
            if not unicodedata.combining(c) and len(nxt) > len(nf):
                break
            seg, nf, j = seg + c, nxt, j + 1
        starts += [i] * len(nf)
        ends += [j] * len(nf)
        parts.append(nf)
        i = j
    return "".join(parts), starts, ends


def _shape(text: str) -> tuple:
    """(words, gaps, lead, trail) of a variant: its words lower-cased, the text between them with whitespace as one
    space, and what stands before the first word and after the last."""
    low = _lower(text)
    spans = [(m.start(), m.end()) for m in _WORD_RE.finditer(low)]
    words = tuple(low[a:b] for a, b in spans)
    gaps = tuple(_SPACE_RE.sub(" ", low[spans[i][1]:spans[i + 1][0]]) for i in range(len(spans) - 1))
    return words, gaps, low[:spans[0][0]], low[spans[-1][1]:]


class Matcher:
    """Every variant of every entity, in one index: the words of a whole-word variant (its n-gram), the first three
    letters of the stem of `stem*`, the last three of `*stem`. A text costs one pass over its words, one lookup per
    distinct word and kind, plus at most 50 `*inside*` needles searched in the whole text.

    The index is two byte strings and an array, so it loads from the disk cache without building an object per
    entry (100,000 entries as Python dicts took 150 ms to unmarshal; this takes a few): `_blob` holds one record per
    key, `key \\x1f most-words \\x1f candidate \\x1e candidate … \\n`, and `_table` is an open-addressing hash table of
    record offsets (zlib.crc32 of the key). A candidate is `entity \\x1d words \\x1d gaps \\x1d lead \\x1d trail \\x1d
    stem`, the lists joined with \\x1c. `_ents` holds `label \\x1f source \\x1f line \\n` per entity."""

    def __init__(self, entities=(), data: tuple | None = None):
        if data is None:
            data = _index(list(entities))
        table, self._blob, ent_offsets, self._ents, self.inside, self._kinds, pre, suf = data
        self._pre, self._suf = tuple(pre), tuple(suf)     # the stem lengths of `stem*` and of `*stem`
        self._table = array(_ARRAY)
        self._table.frombytes(table)
        self._ent_offsets = array(_ARRAY)
        self._ent_offsets.frombytes(ent_offsets)
        self._mask = len(self._table) - 1
        self._data = data
        self._records: dict = {}
        self._objs: dict = {}

    def data(self) -> tuple:
        return self._data

    def __len__(self) -> int:
        return len(self._ent_offsets)

    def entity(self, ei: int) -> Entity:
        ent = self._objs.get(ei)
        if ent is None:
            off = self._ent_offsets[ei]
            label, source, line, ident = self._ents[off:self._ents.index(b"\n", off)].decode("utf-8").split("\x1f")
            ent = self._objs[ei] = Entity(label, (), int(line), source, ident)
        return ent

    def _get(self, key: str):
        """(most words, [candidate]) of a key, or None."""
        kb = key.encode("utf-8")
        tab, blob, mask = self._table, self._blob, self._mask
        i = zlib.crc32(kb) & mask
        n = len(kb)
        while True:
            off = tab[i]
            if not off:
                return None
            off -= 1
            if blob[off:off + n] == kb and blob[off + n:off + n + 1] == b"\x1f":
                rec = self._records.get(off)
                if rec is None:
                    _k, most, cands = blob[off:blob.index(b"\n", off)].decode("utf-8").split("\x1f", 2)
                    rec = self._records[off] = (int(most), [_cand(c) for c in cands.split("\x1e")] if cands else [])
                return rec
            i = (i + 1) & mask

    @staticmethod
    def _fits(text: str, toks: list, i: int, c: tuple) -> tuple | None:
        """(start, end) when the words from toks[i] on are the variant's, with its gaps, lead and trail."""
        _ei, words, gaps, lead, trail, _stem = c
        n = len(words)
        for j in range(n - 1):
            gap = text[toks[i + j][1]:toks[i + j + 1][0]]
            want = gaps[j]
            # a space of the variant: any whitespace run, or the joint of a joined name (jan.kowalski, Jan-Kowalski)
            if want == " " and (gap.isspace() or gap in _JOINTS):
                continue
            if _SPACE_RE.sub(" ", gap).lower() != want:
                return None
        start, end = toks[i][0], toks[i + n - 1][1]
        if lead:
            if text[max(0, start - len(lead)):start].lower() != lead:
                return None
            start -= len(lead)
        if trail:
            if text[end:end + len(trail)].lower() != trail:
                return None
            end += len(trail)
        return start, end

    def find(self, text: str) -> list:
        """(start, end, entity) of each run, left to right, the longest first where two start alike; no overlap."""
        return _select(self.hits(text))

    def hits(self, text: str) -> list:
        """Every (start, end, entity) any variant finds, overlapping. The text is matched in NFC, without format
        characters (a soft hyphen, a zero-width space), and each span is mapped back to the text as it is."""
        if not len(self) or not text:
            return []
        norm, starts, ends = _prepare(text)
        found = self._hits(norm)
        if starts is None:
            return found
        return [(starts[a], ends[b - 1], ent) for a, b, ent in found]

    def _lookup(self, t: str) -> tuple:
        """(the n-gram record, the `stem*` candidates, the `*stem` candidates) of one word: one lookup per stem length
        the index holds, never a walk over a bucket (a team list of 100,000 `abc…*` entries took 16 s for 1000
        words; gate review of block 2)."""
        get = self._get
        pre: list = []
        suf: list = []
        for n in self._pre:
            if n > len(t):
                break
            rec = get("p:" + t[:n])
            if rec:
                pre += rec[1]
        for n in self._suf:
            if n > len(t):
                break
            rec = get("s:" + t[-n:])
            if rec:
                suf += rec[1]
        return get("g:" + t), pre, suf

    def _hits(self, text: str) -> list:
        low = text.lower()
        aligned = len(low) == len(text)
        src = low if aligned else text
        toks = [(m.start(), m.end(), m.group() if aligned else _lower(m.group())) for m in _WORD_RE.finditer(src)]
        hits: list = []
        get = self._get
        seen: dict = {}
        count = len(toks)
        for i, (s, e, t) in enumerate(toks):
            found = seen.get(t)
            if found is None:
                found = seen[t] = self._lookup(t)
            gram, pre, suf = found
            if gram:
                most, cands = gram
                for c in cands:
                    span = self._fits(text, toks, i, c)
                    if span:
                        hits.append((span[0], span[1], c[0]))
                for n in range(min(most, count - i), 1, -1):
                    rec = get("g:" + " ".join(x[2] for x in toks[i:i + n]))
                    for c in rec[1] if rec else ():
                        span = self._fits(text, toks, i, c)
                        if span:
                            hits.append((span[0], span[1], c[0]))
            for c in pre:
                words, k = c[1], len(c[1]) - 1
                if t.startswith(c[5]) and i >= k and all(toks[i - k + j][2] == words[j] for j in range(k)):
                    span = self._fits(text, toks, i - k, c)
                    if span:
                        hits.append((span[0], e, c[0]))
            for c in suf:
                words, k = c[1], len(c[1]) - 1
                if t.endswith(c[5]) and i + k < count and all(toks[i + 1 + j][2] == words[1 + j] for j in range(k)):
                    span = self._fits(text, toks, i, c)
                    if span:
                        hits.append((s, span[1], c[0]))
        for needle, spaced, ei in self.inside:
            if aligned and not spaced:
                at = low.find(needle)
                while at >= 0:
                    hits.append(self._widen(text, at, at + len(needle), ei))
                    at = low.find(needle, at + len(needle))
            else:
                rx = re.compile(r"\s+".join(re.escape(w) for w in needle.split()), re.IGNORECASE)
                hits.extend(self._widen(text, m.start(), m.end(), ei) for m in rx.finditer(text))
        return [(a, b, self.entity(ei)) for a, b, ei in hits]

    @staticmethod
    def _widen(text: str, a: int, b: int, ei: int) -> tuple:
        """The whole word around an *inside* hit: no part of the word stays."""
        while a > 0 and (text[a - 1].isalnum() or text[a - 1] == "_"):
            a -= 1
        while b < len(text) and (text[b].isalnum() or text[b] == "_"):
            b += 1
        return a, b, ei


_ARRAY = "I" if array("I").itemsize == 4 else "L"


def _cand(c: str) -> tuple:
    ei, words, gaps, lead, trail, stem = c.split("\x1d")
    return int(ei), tuple(words.split("\x1c")), tuple(gaps.split("\x1c")) if gaps else (), lead, trail, stem


def _index(entities: list) -> tuple:
    """The data of a Matcher: (table, blob, entity offsets, entity blob, inside needles, kinds)."""
    records: dict = {}
    inside: list = []
    ents: list = []
    pre: set = set()
    suf: set = set()
    for ei, ent in enumerate(entities):
        ents.append(f"{ent.label}\x1f{_CTRL_RE.sub('?', ent.source)}\x1f{ent.line}\x1f{ent.id}\n")
        for v in ent.variants:
            words, gaps, lead, trail = _shape(v.text)
            stem = words[-1] if v.mode == STARTS else words[0] if v.mode == ENDS else ""
            cand = "\x1d".join((str(ei), "\x1c".join(words), "\x1c".join(gaps), lead if v.mode != ENDS else "",
                                trail if v.mode != STARTS else "", stem))
            if v.mode == WORD and len(words) > 1 and set(gaps) == {" "} and not lead and not trail:
                # jan_kowalski: one word for the matcher (`_` is no word boundary), so it gets a record of its own
                records.setdefault("g:" + "_".join(words), [0, []])[1].append(
                    "\x1d".join((str(ei), "_".join(words), "", "", "", "")))
            if v.mode == WORD:
                records.setdefault("g:" + " ".join(words), [0, []])[1].append(cand)
                first = records.setdefault("g:" + words[0], [0, []])
                first[0] = max(first[0], len(words))
            elif v.mode == STARTS:
                records.setdefault("p:" + stem, [0, []])[1].append(cand)
                pre.add(len(stem))
            elif v.mode == ENDS:
                records.setdefault("s:" + stem, [0, []])[1].append(cand)
                suf.add(len(stem))
            elif len(inside) < MAX_INSIDE:    # load() refuses the 51st with a message; this is the last guard
                low = _lower(v.text)
                inside.append((low, " " in low, ei))
    size = 8
    while size < 2 * len(records):
        size *= 2
    table = array(_ARRAY, bytes(size * array(_ARRAY).itemsize))
    parts: list = []
    pos = 0
    for key, (most, cands) in records.items():
        line = f"{key}\x1f{most}\x1f{chr(0x1e).join(cands)}\n".encode("utf-8")
        i = zlib.crc32(key.encode("utf-8")) & (size - 1)
        while table[i]:
            i = (i + 1) & (size - 1)
        table[i] = pos + 1
        parts.append(line)
        pos += len(line)
    ent_offsets = array(_ARRAY)
    pos = 0
    ent_parts: list = []
    for line in ents:
        b = line.encode("utf-8")
        ent_offsets.append(pos)
        ent_parts.append(b)
        pos += len(b)
    kinds = "".join(sorted({k[0] for k in records}))
    return (table.tobytes(), b"".join(parts), ent_offsets.tobytes(), b"".join(ent_parts), inside, kinds,
            sorted(pre), sorted(suf))


_CTRL_RE = re.compile(r"[\x00-\x1f]")


def _select(hits: list) -> list:
    """Left to right; hits that overlap become one run over all of them, with the entity of the first (Anna Maria and
    Maria Kowalski in `Anna Maria Kowalski`: one placeholder over the three words, no part in clear)."""
    hits.sort(key=lambda h: (h[0], -h[1]))
    out: list = []
    for h in hits:
        if out and h[0] < out[-1][1]:
            if h[1] > out[-1][1]:
                out[-1] = (out[-1][0], h[1], out[-1][2])
        else:
            out.append(h)
    return out


class _Union:
    """The cached index and the small one of the marked names, as one matcher."""

    def __init__(self, parts: list):
        self.parts = parts

    def __len__(self) -> int:
        return sum(len(p) for p in self.parts)

    def find(self, text: str) -> list:
        return _select([h for p in self.parts for h in p.hits(text)])


# ------------------------------------------------------------------ files --
def _read_personal(path: Path | None = None) -> bytes | None:
    """The bytes of the person's terms.txt; None without the file. A file that the group or others can read is set
    to 0600 (it is in the maisecrets folder, which only the person writes); one that cannot be set or read raises
    TermsError: the hooks fail closed."""
    path = Path(path) if path is not None else PERSONAL
    try:
        st = path.stat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise TermsError(f"{path}: cannot read it ({type(exc).__name__})") from None
    if os.name != "nt" and st.st_mode & 0o077:
        try:
            os.chmod(path, 0o600)
        except OSError:
            raise TermsError(f"{path}: mode {stat.S_IMODE(st.st_mode):04o} lets others read it, and maisecrets "
                             f"cannot change it; run chmod 600 {path}") from None
    try:
        return path.read_bytes()
    except OSError as exc:
        raise TermsError(f"{path}: cannot read it ({type(exc).__name__})") from None


def _parse_personal(raw: bytes | None, path: Path | None = None) -> list:
    """The entities of terms.txt; a line the parser refuses raises TermsError with the file and the line."""
    if raw is None:
        return []
    path = Path(path) if path is not None else PERSONAL
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise TermsError(f"{path}: not UTF-8 text") from None
    try:
        return _cap_inside(parse(text, "own")[0], 0, None)[0]
    except TermsError as exc:
        raise TermsError(f"{path}: {exc}", exc.line) from None


def _cap_inside(ents: list, used: int, refused: list | None) -> tuple[list, int]:
    """(the entities, the *…* variants in all): at most MAX_INSIDE *…* variants over every list, as each one is a
    search over the whole text. Past the cap, the person's own list raises (refused is None): its line would be
    left out without a word. A team list loses the variant and names it in refused."""
    out = []
    for e in ents:
        keep = []
        for v in e.variants:
            if v.mode == INSIDE:
                if used >= MAX_INSIDE:
                    reason = f"more than {MAX_INSIDE} *…* variants in all the term lists"
                    if refused is None:
                        raise TermsError(f"line {e.line}: {reason}", e.line)
                    refused.append(Refused(e.source, e.line, reason))
                    continue
                used += 1
            keep.append(v)
        if keep:
            out.append(Entity(e.label, tuple(keep), e.line, e.source))
    return out, used


def _personal(path: Path | None = None) -> list:
    return _parse_personal(_read_personal(path), path)


_STOP: list = []


def stoplist() -> frozenset:
    if not _STOP:
        path = Path(__file__).resolve().parent / "rules" / "term_stoplist.txt"
        _STOP.append(frozenset(line.strip() for line in path.read_text(encoding="utf-8").splitlines()
                               if line.strip() and not line.startswith("#")))
    return _STOP[0]


def _stop_sorted() -> tuple:
    if len(_STOP) < 2:
        words = sorted(stoplist())
        _STOP.append((words, sorted(w[::-1] for w in words)))
    return _STOP[1]


@dataclass
class TeamFile:
    source: str      # <folder as configured>/<file>
    entities: int
    digest: str


@dataclass
class Loaded:
    entities: list = field(default_factory=list)
    refused: list = field(default_factory=list)     # Refused, team lists only
    files: list = field(default_factory=list)       # TeamFile
    personal: int = 0
    marked: int = 0
    error: str = ""                                  # the TermsError of terms.txt, if any


def _team_sources(cfg: dict) -> tuple[list, list]:
    """([(source, bytes)], [Refused]) of the *.terms files in the folders of rule_dirs (the setting and the policy;
    not rules.d, the person's own folder: their list is terms.txt). A folder with a subfolder `rules/` is read there,
    as for the rules of your own (term_files.team_folders)."""
    found, refused = [], []
    for source, path in term_files.team_files(cfg):
        if path.is_symlink():
            refused.append(Refused(source, 0, "a symbolic link (a rule folder is read without links)"))
            continue
        try:
            # one open, without a link, without blocking on a FIFO, read with a bound: a file swapped after the
            # listing (a FIFO, a link, a file that grows) can neither hold the hook nor pass the cap (Gate A, round 2)
            raw = _read_bounded(path, MAX_TEAM_BYTES)
        except OSError as exc:
            refused.append(Refused(source, 0, "a symbolic link (a rule folder is read without links)"
                                   if getattr(exc, "errno", None) == errno.ELOOP else "a file that cannot be read"))
            continue
        if raw is None:
            refused.append(Refused(source, 0, f"a file larger than {MAX_TEAM_BYTES >> 20} MB"))
            continue
        if len(raw) + sum(len(r) for _s, r in found) > MAX_TEAM_BYTES:
            # the cap holds for all the team lists together: each file alone was no bound on the build
            refused.append(Refused(source, 0, f"the team lists together are larger than {MAX_TEAM_BYTES >> 20} MB"))
            continue
        found.append((source, raw))
    return found, refused


def _read_bounded(path: Path, limit: int) -> bytes | None:
    """The bytes of a regular file opened without following a link and without blocking, or None past `limit`.
    Raises OSError for a link (ELOOP), a FIFO or any other file that is not regular."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        chunks, size = [], 0
        while size <= limit:
            chunk = os.read(fd, limit + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return None if size > limit else b"".join(chunks)
    finally:
        os.close(fd)


def _key(v: Variant) -> str:
    """The index record a variant lands in (as in _index): its words, or the stem of `stem*` and `*stem`."""
    words = _WORD_RE.findall(_lower(v.text))
    if v.mode == STARTS:
        return "p:" + words[-1]
    if v.mode == ENDS:
        return "s:" + words[0]
    return ("g:" if v.mode == WORD else "i:") + " ".join(words)


def _bound(ents: list, seen: set, buckets: dict, refused: list, team: int) -> list:
    """A team list's entities within the bounds of a scan (codex review of block 2, HIGH 5): a variant that an
    earlier entry (the person's list first) holds is left out, so 100,000 copies of `abcde*` are one; at most
    MAX_BUCKET variants share one record (a word matching that record walks them all); at most MAX_TEAM_ENTITIES
    entries in all the team lists. Each one left out is named in refused."""
    out = []
    for e in ents:
        if team >= MAX_TEAM_ENTITIES:
            refused.append(Refused(e.source, e.line, f"more than {MAX_TEAM_ENTITIES} entries in all the team lists"))
            continue
        keep = []
        for v in e.variants:
            form = (v.mode, _lower(v.text))
            key = _key(v)
            if form in seen:
                refused.append(Refused(e.source, e.line, "a variant that an earlier entry holds"))
            elif buckets.get(key, 0) >= MAX_BUCKET:
                refused.append(Refused(e.source, e.line, f"more than {MAX_BUCKET} variants that share a stem or a "
                                                         "first word"))
            else:
                seen.add(form)
                buckets[key] = buckets.get(key, 0) + 1
                keep.append(v)
        if keep:
            out.append(Entity(e.label, tuple(keep), e.line, e.source))
            team += 1
    return out


def _parse_team(sources: list, out: Loaded) -> None:
    used = sum(1 for e in out.entities for v in e.variants if v.mode == INSIDE)
    own = len(out.entities)
    seen = {(v.mode, _lower(v.text)) for e in out.entities for v in e.variants}
    buckets: dict = {}
    for source, raw in sources:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            out.refused.append(Refused(source, 0, "a file that cannot be read as UTF-8"))
            continue
        ents, refused = parse(text, source, strict=False, floor=stoplist())
        ents, used = _cap_inside(ents, used, refused)
        ents = _bound(ents, seen, buckets, refused, len(out.entities) - own)
        out.entities += ents
        out.refused += refused
        out.files.append(TeamFile(source, len(ents), hashlib.sha256(raw).hexdigest()[:12]))


def _lock():
    """One lock for every read-modify-write of terms.txt and terms.marked.json: two hooks at once lost an add, a
    removal or a marked name (codex review of block 2). Re-entrant in the process; a lock that stays busy raises,
    and the hook fails closed."""
    from .home import _lock_for
    return _lock_for(HOME / ".terms.lock")


def _expiry_ok(value) -> bool:
    """A finite number, not a bool. An integer too large for a float (10**400) is invalid too: math.isfinite raised
    OverflowError on it (codex verification of block 2)."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _marked_items() -> list:
    """Every record of terms.marked.json, expired ones too. No file: none. A file that cannot be read or parsed
    raises TermsError, so the hooks fail closed: an empty list would let every marked name through (codex review of
    block 2). The file is never overwritten then; the person deletes it to start again."""
    try:
        raw = MARKED.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except (OSError, UnicodeDecodeError) as exc:
        raise TermsError(f"{MARKED}: cannot read it ({type(exc).__name__})") from None
    try:
        data = json.loads(raw)
        items = data["terms"]
        # each record needs its text and a finite number as its expiry: a record without one was taken for expired
        # and purged, so damage erased a marked name instead of stopping the hooks (codex verification of block 2)
        if not isinstance(items, list) or not all(isinstance(x, dict) and isinstance(x.get("text"), str)
                                                  and _expiry_ok(x.get("expires")) for x in items):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise TermsError(f"{MARKED}: damaged, so the names marked with {{{{…}}}} cannot be masked. maisecrets does "
                         "not overwrite it: delete the file in a terminal to start again (those marks are then "
                         "gone).") from None
    return items


def _write_marked(items: list) -> None:
    """terms.marked.json with `items`, or no file when none is left (term_files.present then sees no list)."""
    if items:
        from .home import atomic_write
        atomic_write(MARKED, json.dumps({"terms": items}))
        return
    try:
        MARKED.unlink()
    except FileNotFoundError:
        pass


def _marked(now: float | None = None) -> list:
    """The live marked names. An expired one is deleted from the file here (under the lock), so its clear text
    does not stay on disk after its lifetime (codex review of block 2)."""
    now = time.time() if now is None else now
    items = _marked_items()
    if any(x.get("expires", 0) <= now for x in items):
        # every hook passes here, so a lock that another process holds for 6 s (vault._Lock.LOCK_DEADLINE) makes
        # this hook fail closed with LockTimeout. Accepted: a holder only reads, merges and writes two small files,
        # and a purge that waited without a bound would run into the client's timeout, which fails open
        with _lock():
            items = _marked_items()
            live = [x for x in items if x.get("expires", 0) > now]
            if len(live) != len(items):
                _write_marked(live)
            items = live
    return [_marked_entity(x["text"]) for x in items if x.get("expires", 0) > now and _WORD_RE.search(x["text"])]


def _marked_entity(text: str) -> Entity:
    label = "MARKED_" + hashlib.sha256(text.lower().encode("utf-8")).hexdigest()[:8].upper()
    return Entity(label, (Variant(_norm(text), WORD),), 0, "marked")


def load(cfg: dict | None = None, strict: bool = True) -> Loaded:
    """Every source. Strict (the hooks): a bad terms.txt raises TermsError. Not strict (status, /maisecrets:rules):
    the error is in `error`, and the other sources still load."""
    if cfg is None:
        from .user_rules import _config
        cfg = _config()
    out = Loaded()
    try:
        own = _personal()
    except TermsError as exc:
        if strict:
            raise
        own, out.error = [], str(exc)
    out.entities += own
    out.personal = len(own)
    team, out.refused = _team_sources(cfg)
    _parse_team(team, out)
    try:
        marked = _marked()
    except TermsError as exc:
        if strict:
            raise
        marked, out.error = [], (out.error + " " if out.error else "") + str(exc)
    out.entities += marked
    out.marked = len(marked)
    return out


_CACHE: list = []    # [Matcher] or [TermsError]
CACHE_FILE = HOME / ".terms-cache"
_FORMAT = 2


def _cache_key(personal: bytes | None, team: list) -> str:
    h = hashlib.sha256(f"{_FORMAT} {sys.version_info[0]}.{sys.version_info[1]}".encode())
    if team:    # the floor of a team list is the stop list: a new one must parse the team lists again (Gate B)
        h.update(_stop_digest().encode())
    for source, raw in [("own", personal or b"")] + team:
        h.update(source.encode("utf-8") + b"\0" + str(len(raw)).encode() + b"\0" + raw)
    return h.hexdigest()


def _stop_digest() -> str:
    try:
        return hashlib.sha256((Path(__file__).parent / "rules" / "term_stoplist.txt").read_bytes()).hexdigest()
    except OSError:
        return ""


def _cached(key: str) -> Matcher | None:
    """The index of the last build, when its sources are byte for byte the same. The file is in the maisecrets
    folder (C8) and holds data only: marshal builds no class and runs nothing. Anything unexpected is a miss."""
    try:
        fmt, k, data = marshal.loads(CACHE_FILE.read_bytes())
        if fmt == _FORMAT and k == key and isinstance(data, tuple) and len(data) == 8:
            return Matcher(data=data)
    except (OSError, ValueError, EOFError, TypeError):
        pass
    return None


def _store(key: str, m: Matcher) -> None:
    tmp = CACHE_FILE.with_name(CACHE_FILE.name + f".{os.getpid()}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(marshal.dumps((_FORMAT, key, m.data())))
        os.replace(tmp, CACHE_FILE)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _build() -> Matcher:
    """The person's list and the team lists from the cache or parsed (and then cached), plus the marked names,
    which expire and so are never cached."""
    from .user_rules import _config
    raw = _read_personal()
    team, _refused = _team_sources(_config())
    if raw is None and not team:
        m = Matcher()
    else:
        key = _cache_key(raw, team)
        m = _cached(key)
        if m is None:
            out = Loaded()
            out.entities = _parse_personal(raw)
            _parse_team(team, out)
            m = Matcher(out.entities)
            _store(key, m)
    marked = _marked()
    return _Union([m, Matcher(marked)]) if marked else m


def matcher() -> Matcher:
    """The matcher of every source, built once per process. A bad terms.txt raises at every call."""
    if not _CACHE:
        try:
            _CACHE.append(_build())
        except TermsError as exc:
            _CACHE.append(exc)
    if isinstance(_CACHE[0], TermsError):
        raise _CACHE[0]
    return _CACHE[0]


def reset() -> None:
    _CACHE.clear()
    term_files.forget()     # a list written in this process is there for the next scan


def _cache_loaded(loaded: Loaded) -> None:
    """At session start: cache the index of what load() just parsed, so the start parses the lists once (gate review
    of block 2, L4). The entities are those of _build: the person's list, then the team lists; the marked names are
    last and never cached."""
    if loaded.error:
        return
    from .user_rules import _config
    try:
        raw = _read_personal()
    except TermsError:
        return
    team, _refused = _team_sources(_config())
    if raw is None and not team:
        return
    key = _cache_key(raw, team)
    if _cached(key) is None:
        _store(key, Matcher(loaded.entities[:len(loaded.entities) - loaded.marked]))
    reset()


def prebuild() -> None:
    """Build the index now and cache it: at session start (30 s) and after a typed add or remove, so a tool hook
    (10 s) only loads it. A first build of a 4 MB team list inside a tool hook ran into the watchdog, and every
    next hook built it again (gate review of block 2). A bad terms.txt is said by the caller, and stops the next
    hook."""
    reset()
    try:
        matcher()
    except TermsError:
        pass


def matches(text: str) -> list:
    """The hits of the terms pass (detect._term_hits, registry phase "terms"): a Match of kind term:<id> per run."""
    from .detect import Match
    return [Match("term:" + ent.id, ent.type, text[s:e], s, e) for s, e, ent in matcher().find(text)]


store_value = term_files.store_value      # a hook reads these from term_files without importing this module
is_term_kind = term_files.is_term_kind


# --------------------------------------------------------- inline markers --
def markers(prompt: str) -> list:
    """(start, end, name) of each `{{Jan Kowalski}}` in a prompt: 1 to 5 words of letters (a hyphen or an apostrophe
    inside a word), at least one of them capitalised. `{{ .Values.x }}` and `{{ item }}` stay text, and so do one letter
    and one common word alone (rules/term_stoplist.txt)."""
    return [(a, b, " ".join(words)) for a, b, words in term_files.marker_forms(prompt)
            if not (len(words) == 1 and _lower(words[0]) in stoplist())]


def take_markers(prompt: str, ttl: int) -> tuple[str, int]:
    """(the prompt without the braces of each marker, how many names were marked). Each name goes into
    terms.marked.json for `ttl` seconds, so it is masked from now on: in this prompt, in tool results, in every
    session. Only the prompt hook and the mod call this, for a prompt the person typed."""
    found = markers(prompt)
    if not found:
        return prompt, 0
    now = time.time()
    from .home import atomic_write
    with _lock():
        # read after the lock, and a damaged file raises before anything is written
        items = [x for x in _marked_items() if x.get("expires", 0) > now]
        names = {x["text"].lower(): x for x in items}
        for _a, _b, name in found:
            x = names.setdefault(name.lower(), {"text": name})
            x["expires"] = max(x.get("expires", 0), now + ttl)
        atomic_write(MARKED, json.dumps({"terms": list(names.values())}))
    reset()
    out = prompt
    for a, b, name in reversed(found):
        out = out[:a] + name + out[b:]
    return out, len(found)


# ------------------------------------------------------- typed commands --
_COMMAND_RE = re.compile(r"\A\s*(?:/maisecrets:term|maisecrets:\s*term)(?:\s+(\S.*?))?\s*\Z", re.I | re.S)
# a near miss carries the name too, and the model must not get it: /maisecrets:terms add, maisecrets term add
_NEAR_RE = re.compile(r"\A\s*/?maisecrets(?::\s*|\s+)terms?\s+(?:add|remove)\b(.*)\Z", re.I | re.S)


def parse_command(prompt) -> tuple[str, str] | None:
    """("add"|"remove", words), ("usage", text) for any other text after the command, or None. A bare
    /maisecrets:term or `/maisecrets:term list` is None: the slash command shows the lists."""
    if not isinstance(prompt, str):
        return None
    m = _COMMAND_RE.match(prompt)
    if not m:
        near = _NEAR_RE.match(prompt)
        return ("usage", " ".join(near.group(1).split())) if near else None
    rest = (m.group(1) or "").strip()
    if not rest or rest.lower() == "list":
        return None
    verb, _, words = rest.partition(" ")
    if verb.lower() in ("add", "remove") and words.strip():
        return verb.lower(), " ".join(words.split())
    return "usage", rest      # the text goes to the transcript scrub: it may be a name


USAGE = ("maisecrets: send /maisecrets:term add NAME (for example /maisecrets:term add Jan Kowalski | Kowalsk*) or "
         "/maisecrets:term remove NAME as your own prompt; in Codex: maisecrets: term add NAME. /maisecrets:term "
         "alone shows your lists. This prompt was not sent to the model.")


def _shown_suggested() -> str:
    return "~/.maise" + "crets/terms.suggested.txt" if HOME == Path.home() / ".maisecrets" else str(SUGGESTED)


def _shown_path() -> str:
    return "~/.maisecrets/terms.txt" if HOME == Path.home() / ".maisecrets" else str(PERSONAL)


def add_typed(words: str, floor: bool = False) -> tuple[bool, str, list]:
    with _lock():
        return _add_typed(words, floor)


def _add_typed(words: str, floor: bool = False) -> tuple[bool, str, list]:
    """Add one entity to terms.txt. (changed, message, texts to scrub from the transcript). The message names a
    label and a line, never the term. `floor`: the prompt has no source (Codex, an older client), so it may not come
    from the person, and the entry gets the floor of a team list."""
    try:
        for v in words.split("|"):
            _variant(v, 1, stoplist() if floor else None)
    except TermsError as exc:
        reason = str(exc).split(": ", 1)[1]
        if floor:
            reason = (reason.replace(" in a team list", "") + "; a prompt without a source may not come from you, so "
                      "the rules of a team list hold")
        return False, (f"maisecrets: the term was not added ({reason}). "
                       "This prompt was not sent to the model."), [words]
    try:
        text = PERSONAL.read_text(encoding="utf-8") if PERSONAL.exists() else ""
    except (OSError, UnicodeDecodeError):
        return False, f"maisecrets: {_shown_path()} cannot be read; nothing was changed.", [words]
    ents, _ = parse(text, strict=False)
    wanted = {v.strip().strip("*").strip().lower() for v in words.split("|")}
    for e in ents:
        if wanted & {v.text.lower() for v in e.variants}:
            return False, (f"maisecrets: this term is already on your list ({e.label}, line {e.line} of "
                           f"{_shown_path()}). This prompt was not sent to the model."), [words]
    labels = {line.split(None, 1)[0] for line in text.splitlines() if line.strip()}
    n = 1
    while f"NAME_{n}" in labels:
        n += 1
    label = f"NAME_{n}"
    head = "" if text else ("# maisecrets terms: one name per line, `LABEL  variant | variant`; Kowalsk* = any "
                            "ending, *kowalski* = anywhere in a word. README, section Terms.\n")
    given = [v.strip() for v in words.split("|")]
    surnames = _surnames(given)
    variants = " | ".join(given + surnames)
    new = head + text + ("" if not text or text.endswith("\n") else "\n") + f"{label}  {variants}\n"
    from .home import atomic_write
    try:
        atomic_write(PERSONAL, new, mode=0o600)
    except OSError as exc:
        return False, f"maisecrets: {_shown_path()} cannot be written ({type(exc).__name__}); nothing was changed.", \
            [words]
    prebuild()
    line = new.count("\n")
    note = ""
    common = [v for v in wanted if v in stoplist()]
    if common:
        note = (" Note: the term is a common word (rules/term_stoplist.txt), so it is masked in every text; a longer "
                "variant, such as the full name, masks less.")
    try:
        parse(new)
    except TermsError as exc:
        note += (f" Your list has an error at line {exc.line}: until you fix it, maisecrets withholds every tool "
                "result.")
    if surnames:
        note += (f" Also added: {len(surnames)} variant(s), the last name alone and its genitive, so \"Herr Surname\" "
                 "and \"Surname, First name\" are masked too; /maisecrets:term shows them. Masked as well: the joined "
                 "forms first.last, first-last and first_last. The first name alone stays visible; to mask it, add "
                 "it as a term of its own.")
    return True, (f"maisecrets: the term is on your list now as {label} (line {line} of {_shown_path()}). From the "
                  f"next tool result on it is replaced by a placeholder. This prompt was not sent to the model.{note}"
                  ), [v.strip().strip("*").strip() for v in words.split("|")] + [words]


def _surnames(given: list) -> list:
    """The last word of each full name the person adds (2 or more words, no *), as whole words: the surname and its
    genitive (`Kowalski | Kowalskis`), so `Herr Kowalski`, `Kowalskis Bericht` and `Kowalski, Jan` are masked too
    (gate review of block 2, H3). Never a `*` stem: `Koch*` masked `Kochen`, `Lang*` masked `language` (round 2); a
    stem only when the person types it. Not a word under 4 letters, not a common word, not one the variants hold."""
    have = {_lower(v) for v in given}
    out: list = []
    for v in given:
        if "*" in v:
            continue
        words = v.split()
        last = words[-1] if len(words) > 1 else ""
        if not (len(last) >= 4 and last.isalpha() and _lower(last) not in stoplist()):
            continue
        forms = [last] + ([] if _lower(last)[-1] in "sxzß" else [last + "s"])
        out += [f for f in forms if _lower(f) not in have and f not in out]
    return out


def _old_id(e: Entity) -> str:
    """The id before cache format 2 (source and label only): a placeholder the person copied from a result of an
    older version still removes its entity."""
    return hashlib.sha256(f"{e.source}\0{e.label}".encode("utf-8")).hexdigest()[:12]


def _ids(e: Entity) -> tuple:
    return e.id, _old_id(e)


def term_remove_typed(words: str, entity_id: str | None = None) -> tuple[bool, str, list]:
    with _lock():
        return _term_remove_typed(words, entity_id)


def _term_remove_typed(words: str, entity_id: str | None = None) -> tuple[bool, str, list]:
    """Remove from terms.txt each entity that has the variant `words` (or the id of a placeholder the person
    copied), and the same name from the marked names. Only the prompt hook calls this, for a prompt the person
    typed (settings.IN_A_COMMAND_RE refuses the name in a tool call): a removal makes detection weaker."""
    want = words.strip().strip("*").strip().lower()
    removed = []
    try:
        text = PERSONAL.read_text(encoding="utf-8") if PERSONAL.exists() else ""
    except (OSError, UnicodeDecodeError):
        return False, f"maisecrets: {_shown_path()} cannot be read; nothing was changed.", [words]
    ents, _ = parse(text, strict=False)
    drop = {e.line for e in ents
            if (entity_id and entity_id in _ids(e)) or want in {v.text.lower() for v in e.variants}}
    lines = text.splitlines(keepends=True)
    kept = [x for i, x in enumerate(lines, 1) if i not in drop]
    removed += [f"{e.label} ({len(e.variants)} variant{'s' if len(e.variants) != 1 else ''})"
                for e in ents if e.line in drop]
    from .home import atomic_write
    if drop:
        try:
            atomic_write(PERSONAL, "".join(kept), mode=0o600)
        except OSError as exc:
            return False, (f"maisecrets: {_shown_path()} cannot be written ({type(exc).__name__}); nothing was "
                           "changed."), [words]
    try:
        items = _marked_items()
    except TermsError:
        items = []        # damaged: never overwritten; the hooks say so
    left = [x for x in items if not (x["text"].lower() == want or (
        entity_id and entity_id in _ids(_marked_entity(x["text"]))))]
    if len(left) != len(items):
        _write_marked(left)
        removed.append("a marked name")
    prebuild()
    if not removed:
        return False, ("maisecrets: this term is not on your own list, and it is no name you marked; nothing was "
                       "changed. A team list is changed in its folder. This prompt was not sent to the model."), \
            [words]
    return True, (f"maisecrets: removed {', '.join(removed)} from your terms. This prompt was not sent to the model."
                  ), [words]


# ---------------------------------------------------------- session start --
def session_note() -> str | None:
    """At session start: when the team lists changed since the last start, one sentence with the count and the
    entries left out. Unchanged, it says nothing again. A bad terms.txt is said at every start."""
    loaded = load(strict=False)
    _cache_loaded(loaded)
    digest = hashlib.sha256(json.dumps([[f.source, f.digest] for f in loaded.files]
                                       + [[r.source, r.line, r.reason] for r in loaded.refused]).encode()).hexdigest()
    try:
        before = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        before = {}
    team = sum(f.entities for f in loaded.files)
    parts = []
    if loaded.error:
        parts.append(f"your term list cannot be used ({loaded.error}); maisecrets withholds every tool result until "
                     "you fix it.")
    if isinstance(before, dict) and before.get("digest") != digest[:16] and (loaded.files or before.get("team")):
        was = before.get("team")
        parts.append(f"the team term lists changed: {team} term(s) in {len(loaded.files)} file(s)"
                     + (f" (before: {was})" if isinstance(was, int) else "")
                     + (f", {len(loaded.refused)} line(s) left out" if loaded.refused else "")
                     + "; /maisecrets:rules shows them.")
    try:
        from .home import atomic_write
        atomic_write(STATE_FILE, json.dumps({"digest": digest[:16], "team": team}))
    except OSError:
        return None    # a state that cannot be written would repeat the sentence at every start
    return ("maisecrets: " + " ".join(parts)) if parts else None


def summary(loaded: Loaded | None = None) -> str:
    loaded = load(strict=False) if loaded is None else loaded
    team = sum(f.entities for f in loaded.files)
    if loaded.error:
        own = "unusable (" + loaded.error + ")"
    else:
        own = str(loaded.personal)
    return (f"terms: {own} of your own, {team} from {len(loaded.files)} team file(s)"
            + (f" ({len(loaded.refused)} line(s) left out)" if loaded.refused else "")
            + f", {loaded.marked} marked in prompts")
