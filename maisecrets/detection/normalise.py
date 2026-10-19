"""A cleaned copy of a tool result for the detector, with a map back to the original.

A value the model reads can be split or disguised by what a terminal or a renderer hides: an ANSI colour code or a
zero-width space inside a token, an HTML entity, fullwidth letters, or a base64 or hex run around it. Each stage
removes or decodes one of them. Markdown bold around a label (`**Password:** <value>`) hides the label from
the label rules; the emphasis stage drops its stars.
The copy keeps, per character, the range of the original it came from, so a span
found in the copy redacts the true text, with whatever was hidden inside it. A value found in a decoded run takes the
whole run.

Only the tool channel uses it (detect.scan with channel "tool"): a typed prompt keeps its decisions. Bounded: a text
longer than MAX_TEXT is not cleaned, a run longer than MAX_RUN is not decoded (a whole file, an image), at most
MAX_CANDIDATES runs and MAX_DECODED bytes per text. The bounds count work, not time: a time slice (20 ms until
0.6.24) let a busy machine skip a run, and the key it held reached the model (1 of 503,860 fingerprint lines, under
load). The work is linear in the text: under MAX_TEXT, 1 MB of runs costs about 25 ms of CPU with or without it.

Adapted from a public fork of maisecrets (Apache License 2.0, see NOTICE). Changed: six stages (no carriage return,
gutter, escape or unwrap stage), one module, a budget per call. The standard library only.
"""
from __future__ import annotations

import base64
import binascii
import html
import re
import zlib

# entities first: `&#8203;` and `&#27;[1m` written as entities become a zero-width character and an ANSI code that the
# next stages remove (`&#27;` by _ESCAPE_ENTITIES: html.unescape drops it)
STAGES = ("unfold", "entity", "ansi", "invisible", "fullwidth", "emphasis", "decode")

# RFC 6350 3.2: a line break and one space or tab continue the line before it. Inside a vCard (BEGIN:VCARD to
# END:VCARD) the copy joins the parts, so the vCard rules read the whole property and the mask covers both parts. The
# indent of BEGIN:VCARD (a vCard in YAML or a heredoc) is part of each line. A binary property (PHOTO, LOGO, SOUND,
# KEY, ENCODING=b) stays folded: its base64 holds no field, and joined it is one more run to decode
_VCARD_BEGIN_RE = re.compile(r"(?im)^([ \t]*)BEGIN:VCARD[ \t]*\r?$")
_VCARD_END_RE = re.compile(r"(?im)^([ \t]*)END:VCARD[ \t]*\r?$")
_BINARY_PROP_RE = re.compile(r"(?i)[ \t]*(?:[a-z0-9-]{1,64}\.)?(?:PHOTO|LOGO|SOUND|KEY)[;:]"
                             r"|[^:\n]{0,200};ENCODING=(?:b|base64)[;:]")

_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")
# zero-width and format characters a terminal does not show: soft hyphen, zero-width space and joiners, direction
# marks and embeddings, word joiner and invisible operators, byte order mark. Tag characters and variation selectors
# leave every tool result before the detector (hooks.strip_hidden)
_INVISIBLE_RE = re.compile("[­​-‏‪-‮⁠-⁤⁦-⁩﻿]")
_ENTITY_RE = re.compile(r"&(?:#\d{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")
_FULLWIDTH_RE = re.compile("[！-～]")
# a label in Markdown bold: **Label:** value, **Label**: value, __Label:__ value. The copy keeps the label and its colon
# without the stars, so every label rule reads the value after it. `__` needs a capital first and a colon, never `=`:
# __version__ = "1.2", __all__: list are Python names
_EMPHASIS_RE = re.compile(r"(?<![*\w])\*\*([^\W\d_][^*\n:]{0,48}?)(?:(:)\*\*(?=[ \t])|\*\*(?=[ \t]{0,3}[:=]))"
                          r"|(?<![_\w])__([A-ZÀ-Þ][^_*\n:]{0,48}?)(?:(:)__(?=[ \t])|__(?=[ \t]{0,3}:[ \t]))")

MIN_B64 = 24
MIN_HEX = 32
MAX_RUN = 16_384            # encoded characters
MAX_DECODED = 65_536        # bytes per text, over every run and depth: the copy scan reads at most this much more
MAX_CANDIDATES = 64         # runs per text
MAX_TEXT = 1_000_000        # characters: a larger text is not decoded (its offset map alone would cost more)
MAX_DEPTH = 2
PRINTABLE = 0.9

# a run of the base64 alphabets (standard and URL-safe) with its padding; hex is a subset and is told apart in _bytes.
# The padding counts toward MIN_B64: 16 bytes are 22 characters and "=="
RUN_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{%d,}={0,2}(?![A-Za-z0-9+/=_-])" % (MIN_B64 - 2))
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2})+")


class Normalised:
    """The cleaned text; starts[i] and ends[i] are the original range of its character i (None: unchanged)."""
    __slots__ = ("text", "starts", "ends")

    def __init__(self, text: str, starts=None, ends=None):
        self.text, self.starts, self.ends = text, starts, ends

    def span(self, a: int, b: int) -> tuple:
        """The original range under the cleaned span [a, b), b > a."""
        if self.starts is None:
            return a, b
        return self.starts[a], self.ends[b - 1]


def _sub(text: str, rx, repl, stop=None):
    """text with every match replaced by repl(match), and per output character its range in text; None: no change.
    stop(): no further match is looked at once it returns True."""
    out: list = []
    starts: list = []
    ends: list = []
    pos = 0
    for m in rx.finditer(text):
        if stop is not None and stop():
            break
        a, b = m.span()
        new = repl(m)
        if new == m.group(0):
            continue
        out.append(text[pos:a])
        starts.extend(range(pos, a))
        ends.extend(range(pos + 1, a + 1))
        out.append(new)
        starts.extend([a] * len(new))
        ends.extend([b] * len(new))
        pos = b
    if not out:
        return None
    out.append(text[pos:])
    starts.extend(range(pos, len(text)))
    ends.extend(range(pos + 1, len(text) + 1))
    return "".join(out), starts, ends


def _apply_cuts(text: str, cut: list):
    """text with each (a, b, rep) of cut, in order and apart, replaced by rep; per output character its range in text.
    A one-character rep takes the range of what it replaces."""
    out: list = []
    starts: list = []
    ends: list = []
    pos = 0
    for a, b, rep in cut:
        out.append(text[pos:a])
        starts.extend(range(pos, a))
        ends.extend(range(pos + 1, a + 1))
        if rep:
            out.append(rep)
            starts.append(a)
            ends.append(b)
        pos = b
    out.append(text[pos:])
    starts.extend(range(pos, len(text)))
    ends.extend(range(pos + 1, len(text) + 1))
    return "".join(out), starts, ends


def _drop_stars(text: str):
    """text without the stars of each bold label; the label and the rest keep their own ranges. Inside a line the
    opening stars become one space, so a value before the next bold label ends there (**Full name:** Dana Okafor
    **Role:** reviewer: the name rules join words with one space only)."""
    cut = []
    for m in _EMPHASIS_RE.finditer(text):
        g = 1 if m.group(1) is not None else 3
        a = m.start()
        cut.append((a, m.start(g), " " if a and text[a - 1] != "\n" else ""))
        cut.append((m.end(g) + (1 if m.group(g + 1) else 0), m.end(), ""))
    return _apply_cuts(text, cut) if cut else None


def _unfold(text: str):
    """text with the folded lines of each vCard joined: the line break and the one space or tab after the indent of
    BEGIN:VCARD go, each other character keeps its range. None: no folded line."""
    cut: list = []
    done = 0
    for b in _VCARD_BEGIN_RE.finditer(text):
        if b.start() < done:
            continue
        indent = b.group(1)
        k = len(indent)
        # the END:VCARD at the indent of its BEGIN: a folded line that starts with END:VCARD continues a value
        e = next((x for x in _VCARD_END_RE.finditer(text, b.end()) if x.group(1) == indent), None)
        done = e.start() if e else len(text)
        binary = False
        nl = text.find("\n", b.end(), done)
        while nl >= 0:
            line = nl + 1
            if line + k < done and text[line + k] in " \t" and text.startswith(indent, line):
                if not binary:
                    cut.append((nl - 1 if text[nl - 1] == "\r" else nl, line + k + 1, ""))
            else:
                binary = bool(_BINARY_PROP_RE.match(text, line))
            nl = text.find("\n", line, done)
    return _apply_cuts(text, cut) if cut else None


_ESCAPE_ENTITIES = frozenset({"&#27;", "&#027;", "&#x1b;", "&#x1B;", "&#X1b;", "&#X1B;"})


def _entity(m) -> str:
    if m.group(0) in _ESCAPE_ENTITIES:
        return "\x1b"   # html.unescape drops this control character; the ANSI stage removes the code it starts
    got = html.unescape(m.group(0))
    return got if len(got) == 1 else m.group(0)


class Budget:
    """What one text may still spend on decoding: candidates and decoded bytes. No clock: the copy must be the same
    on a busy machine."""
    __slots__ = ("candidates", "decoded")

    def __init__(self) -> None:
        self.candidates = MAX_CANDIDATES
        self.decoded = MAX_DECODED

    def spent(self) -> bool:
        return self.candidates <= 0 or self.decoded <= 0

    def take(self, n_bytes: int) -> bool:
        if self.candidates <= 0 or n_bytes > self.decoded:
            return False
        self.candidates -= 1
        self.decoded -= n_bytes
        return True


def _bytes(run: str):
    if len(run) >= MIN_HEX and _HEX_RE.fullmatch(run):
        return bytes.fromhex(run)
    if len(run) < MIN_B64:
        return None
    body = run.rstrip("=")
    if ("+" in body or "/" in body) and ("-" in body or "_" in body):
        return None   # two alphabets mixed: an identifier or a path, not an encoding
    if len(body) % 4 == 1:
        return None
    try:
        return base64.b64decode(body.replace("-", "+").replace("_", "/") + "=" * (-len(body) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _text(raw: bytes):
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not s:
        return None
    good = sum(1 for c in s if c.isprintable() or c in "\t\n\r")
    return s if good >= PRINTABLE * len(s) else None


def _gunzip(raw: bytes, budget: Budget):
    if raw[:2] != b"\x1f\x8b":
        return None
    try:
        out = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(raw, max(budget.decoded, 1))
    except zlib.error:
        return None
    return out if budget.take(len(out)) else None


def decode_run(run: str, depth: int = MAX_DEPTH, budget=None):
    """The text a base64 or hex run encodes, with runs inside it decoded too while depth lasts; None: no text."""
    budget = budget or Budget()
    if depth <= 0 or len(run) > MAX_RUN:
        return None
    raw = _bytes(run)
    if raw is None or not budget.take(len(raw)):
        return None
    if depth > 1:
        inner = _gunzip(raw, budget)
        if inner is not None:
            return _text(inner)
    s = _text(raw)
    if s is None or depth <= 1:
        return s
    return _decode_text(s, depth - 1, budget)


def _decode_text(text: str, depth: int, budget: Budget) -> str:
    out: list = []
    pos = 0
    for m in RUN_RE.finditer(text):
        if budget.spent():
            break
        got = decode_run(m.group(0), depth, budget)
        if got is not None:
            out += [text[pos:m.start()], got]
            pos = m.end()
    return "".join(out) + text[pos:] if out else text


def _stage(name: str, text: str):
    """One stage as (text, starts, ends) relative to its input, or None when it changes nothing."""
    if name == "unfold":
        return _unfold(text) if "VCARD" in text.upper() else None
    if name == "ansi":
        return _sub(text, _ANSI_RE, lambda m: "") if "\x1b" in text else None
    if name == "invisible":
        return None if text.isascii() else _sub(text, _INVISIBLE_RE, lambda m: "")
    if name == "entity":
        return _sub(text, _ENTITY_RE, _entity) if "&" in text else None
    if name == "emphasis":
        if "**" not in text and "__" not in text:
            return None
        return _drop_stars(text)
    if name == "fullwidth":
        return None if text.isascii() else _sub(text, _FULLWIDTH_RE, lambda m: chr(ord(m.group(0)) - 0xFEE0))
    if name == "decode":
        budget = Budget()
        return _sub(text, RUN_RE, lambda m: decode_run(m.group(0), MAX_DEPTH, budget) or m.group(0), budget.spent)
    raise ValueError(f"unknown normaliser stage {name!r}")


def normalise(text: str, stages=STAGES) -> Normalised:
    """The text after the named stages, in the order of STAGES, with its map back to text. A text that no stage
    changes comes back as the same object."""
    unknown = set(stages) - set(STAGES)
    if unknown:
        raise ValueError(f"unknown normaliser stage {sorted(unknown)[0]!r}")
    if len(text) > MAX_TEXT:
        return Normalised(text)   # a larger text is scanned as it is: its offset map and a second scan cost too much
    cur = text
    starts = ends = None
    for name in STAGES:
        if name not in stages:
            continue
        step = _stage(name, cur)
        if step is None:
            continue
        new, s, e = step
        if starts is None:
            starts, ends = s, e
        else:
            starts, ends = [starts[i] for i in s], [ends[j - 1] for j in e]
        cur = new
    return Normalised(cur, starts, ends)
