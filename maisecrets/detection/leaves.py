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

import contextlib
import dataclasses
import functools
import json

from .deadline import ScanIncomplete
from .prefilter import rules_for, with_response_rules
from .lazy_regex import LazyRx
from .text_index import record_fields

# The level of the record guarantee: in layout "lines" a record finds every span that a scan of each field alone after
# its label finds. A caller can gate on it; it moves up each time a context window that crossed a field is closed.
# 1: negative contexts, the decode budget and the US address windows (0.8.17). 2: the street after its label (0.8.18).
RECORD_CONTEXT_PER_FIELD = 2

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


# a character json.dumps writes as an escape; a string without one is written as it is (most strings of a response)
_NEEDS_ESCAPE = LazyRx(r'["\\\x00-\x1f]')


def _escape(s: str) -> tuple:
    if not _NEEDS_ESCAPE.search(s):
        return s, tuple(range(len(s) + 1))
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


# a parent whose name field names a person: its string is read after `<parent>_name` (author_name), a person label of
# the core (personal._COMPOUND_PERSON_KEY_RE), not after the weak `name`
_PERSON_PARENTS = frozenset({"author", "reviewer", "reviewers", "assignee", "assignees", "reporter", "creator",
                             "organizer", "attendee", "attendees", "committer", "approver", "requester",
                             "merged_by", "closed_by", "approved_by", "requested_by", "merge_user"})
_NAME_KEYS = {"name": "name", "displayname": "display_name", "display_name": "display_name", "fullname": "full_name",
              "full_name": "full_name"}


def _role_label(path: tuple) -> str:
    keys = [part for part in path if isinstance(part, str)]
    if len(keys) < 2 or keys[-1].lower() not in _NAME_KEYS:
        return ""
    parent = keys[-2].lower()
    if parent not in _PERSON_PARENTS:
        return ""
    return f"{parent.rstrip('s') if parent.endswith('ees') or parent.endswith('ers') else parent}_" \
           f"{_NAME_KEYS[keys[-1].lower()]}"


def _label(path: tuple) -> str:
    """The label of a string: `<role>_name` for the name of a person's role (author.name -> author_name, a person
    label of the core), else the last key of the path, or "" when it can be none: a key that is empty, longer than 64
    characters, holds a line boundary of str.splitlines() (\\r, U+2028 …) or a control character, holds one of
    `: = | " '`, or names the cursor of a paged list (nextPageToken: the gateway gives no label there either)."""
    role = _role_label(path)
    if role:
        return role
    from .fields import named_key
    return _key_label(named_key([part for part in path if isinstance(part, str)]))


# a response repeats its keys in each record: the label of a key is worked out once per process. 65,536 keys: a cache
# that a response with more distinct keys overruns made the large response of the linear test 18 times the small one
@functools.lru_cache(maxsize=65536)
def _key_label(last: str) -> str:
    if not last or len(last) > _LABEL_MAX or any(c in _NOT_IN_LABEL for c in last):
        return ""
    if last.splitlines() != [last] or any(ord(c) < 0x20 or 0x7f <= ord(c) < 0xa0 for c in last):
        return ""
    from .fields import is_cursor, label_words
    return "" if is_cursor(label_words(last), field=True) else last


def label(path: tuple) -> str:
    """The label that findings_by_leaf (layout "lines") writes before the string at `path`, or "" for none. Public
    since 0.8.16 for a caller that reports by label; `_label` stays an alias."""
    return _label(path)


def _segments(group: list) -> list:
    """A record cut before each string that has no label: on its own line after another string, the last line of that
    string (`password:`) would read as its label, which neither string gives alone (codex review, 2026-11-02). A string
    that is empty or white space only is left out: it holds nothing to find, and its label line (`address: `) would take
    the next line as its value (gateway review, 2026-11-03); cutting the record there cost a scan per empty field."""
    out = []
    for leaf in group:
        if not leaf.value.strip():
            continue
        if not out or not _label(leaf.path):
            out.append([])
        out[-1].append(leaf)
    return out


def _response_order(detector, texts: list, kwargs: dict):
    """The rules that can fire somewhere in the texts of this response, in scan order (prefilter.rules_for), or None:
    only for a Detector of this package, without further arguments, and for two texts or more."""
    from . import core
    if kwargs or len(texts) < 2 or not isinstance(detector, core.Detector):
        return None
    joined = "\n".join(texts)
    order = detector._run(lambda: core._in_scan_order(core.rules()))
    return rules_for(order, joined, core._lower(joined))


def _lines(detector, obj, channel: str, **kwargs) -> list:
    out = []
    segments = []
    # a string a record already holds after the same label (Slack writes each message twice, in text and in blocks)
    # is scanned once: the record's findings of the first hold all a scan of that field alone finds
    # (RECORD_CONTEXT_PER_FIELD), and the copy gets them
    copies: list = []
    sentences: list = []
    every = json_text(obj)[1]
    for rec in records(every):
        joined = _inline_sentences(rec)
        sentences += joined
        rec = rec + [leaf for leaf, _nodes in joined]
        first: dict = {}
        for group in _segments(rec):
            parts, placed, starts, n = [], [], [], 0
            for leaf in group:
                label = _label(leaf.path)
                seen = first.setdefault((label, leaf.value), leaf)
                if seen is not leaf:
                    copies.append((leaf, seen))
                    continue
                lead = f"{label}: " if label else ""
                placed.append((leaf, n + len(lead)))
                starts.append(n)
                parts.append(lead + leaf.value)
                n += len(lead) + len(leaf.value) + 1
            if parts:
                segments.append(("\n".join(parts), placed, starts))
    try:
        out += _scan_segments(detector, segments, channel, kwargs)
    except ScanIncomplete as e:
        # the steps below only add findings: run them on the part, so a read string keeps every mask they give it. A
        # copy and a joined sentence are not read: their findings come from those steps, which saw only a part
        cut = _after_scan(e.findings, copies, sentences, every)
        raise ScanIncomplete(cut, e.reason, _read_whole(e.read or [], copies, sentences)) from None
    return _after_scan(out, copies, sentences, every)


def _read_whole(read: list, copies: list, sentences: list) -> list:
    """The leaves of a cut scan whose findings are complete: read in a segment that ran to its end, not a copy (its
    findings come from the leaf it copies, after the scan), and not a joined sentence or one of its nodes unless the
    sentence was read too (the nodes get the sentence's findings after the scan)."""
    done = {id(leaf) for leaf in read}
    out = {id(leaf): leaf for leaf in read}
    for leaf, _seen in copies:
        out.pop(id(leaf), None)
    for sentence, nodes in sentences:
        if id(sentence) not in done:
            for node in nodes:
                out.pop(id(getattr(node, "leaf", node)), None)
        out.pop(id(sentence), None)
    return list(out.values())


def _after_scan(out: list, copies: list, sentences: list, every: list) -> list:
    if copies:
        by_leaf: dict = {}
        for leaf, m in out:
            if leaf is not None:
                by_leaf.setdefault(id(leaf), []).append(m)
        out += [(leaf, m) for leaf, seen in copies for m in by_leaf.get(id(seen), ())]
    if sentences:
        out = _sentence_findings(out, sentences)
    return _spread(out, every)


# a value spreads when it names one thing, the rule of the ai-gateway's propagation: a name or a user name of two
# words or more (one word, Wolf or Sommer, is also a word of other strings); any other value of 8 to 256 characters
# with a letter and a digit and none of the common shapes (a label rule takes any word after `password:`, and the word
# is in the code around it)
_SPREAD_MIN, _SPREAD_MAX = 8, 256
_RUN = LazyRx(r"[^\W_]+")
_WORD_TYPES = frozenset({"NAME", "USERNAME"})


# shapes a label rule takes after `password:` that are no secret and stand in other strings too: a date or a time, a
# host or file with a port or line, a dunder name, a ticket key, a version, a word with a version (gateway, Gate B)
_COMMON_SHAPE = LazyRx(r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?"
                       r"|[\w.-]+:\d+|__\w+__|[A-Z][A-Z0-9]*-\d+|v?\d+(?:\.\d+)+[\w.+-]*|[A-Za-z]+[-_.]v?\d+(?:\.\d+)*")


def _spreads(value: str, kind: str) -> bool:
    if kind in _WORD_TYPES:
        return len(value.split()) >= 2 and len(value) <= _SPREAD_MAX
    return (_SPREAD_MIN <= len(value) <= _SPREAD_MAX and any(c.isalpha() for c in value)
            and any(c.isdigit() for c in value) and not value.startswith("@")
            and not _COMMON_SHAPE.fullmatch(value))


def _keeps(leaf) -> bool:
    """The string's label names no secret, so a value under it is kept where a scan of the field finds it (a cursor, the
    key of a file or a component, an id, the time or state of a secret, a revision, a lone `key`): no spread overrides
    that (fields.py; the gateway's spread put a Figma component key into meta.components.key, 2026-11-04)."""
    from . import fields
    words = fields.label_words(next((part for part in reversed(leaf.path) if isinstance(part, str)), ""))
    return (words == ["key"] or fields.names_no_secret(words) or fields.is_a_revision(words, leaf.value))


def _spread(out: list, every: list) -> list:
    """A value found in one string of the response is masked in the other strings that hold it as a whole word: Slack
    writes a message's value once in text, after its cue, and once in a bold or code element of its blocks, where no
    cue stands before it (gateway review, 2026-11-04)."""
    values: dict = {}
    for leaf, m in out:
        # without the marks of Slack's mrkdwn around it (*bold*, `code`): the blocks hold the value without them
        value = leaf.value[m.start:m.end].strip("*_~`") if leaf is not None else ""
        if _spreads(value, m.type):
            values.setdefault(value, m)
    if not values:
        return out
    taken: dict = {}
    for leaf, m in out:
        if leaf is not None:
            taken.setdefault(id(leaf), []).append((m.start, m.end))
    # a value that stands as a whole word holds its longest run of letters and digits as a whole run of the string
    # ([^\W_] is str.isalnum): each string is searched only for the values whose run it holds, not for all of them
    order = {value: i for i, value in enumerate(values)}
    by_run: dict = {}
    loose = []
    for value in values:
        runs = _RUN.findall(value)
        if runs:
            by_run.setdefault(max(runs, key=len), []).append(value)
        else:
            loose.append(value)
    added = []
    for leaf in every:
        if _keeps(leaf):
            continue
        text = leaf.value
        hits = {v for run in set(_RUN.findall(text)) for v in by_run.get(run, ())}
        if not hits and not loose:
            continue
        for value in sorted(hits.union(loose), key=order.__getitem__):
            m = values[value]
            at = text.find(value)
            while at >= 0:
                end = at + len(value)
                if not (at and text[at - 1].isalnum()) and not (end < len(text) and text[end].isalnum()) \
                        and not any(a < end and at < b for a, b in taken.get(id(leaf), ())):
                    taken.setdefault(id(leaf), []).append((at, end))
                    added.append((leaf, dataclasses.replace(m, start=at, end=end, value=value)))
                at = text.find(value, at + 1)
    return out + added


# the containers whose text nodes form one sentence: the paragraphs of Atlassian's document format
# (`"Das Passwort ist "` | a code node). Slack's rich text needs none: its message's text field holds the whole
# sentence, and a value found there is found in the blocks too (_spread)
_INLINE_LISTS = frozenset({"content"})


def _inline_sentences(rec: list) -> list:
    """(sentence, nodes) for each container of the record with two text nodes or more: the sentence is a Leaf of their
    joined text after the label of the first node, scanned beside the nodes, so a value in a node of its own gets the
    cue of the node before it. Each node is still scanned alone."""
    groups: dict = {}
    for leaf in rec:
        p = leaf.path
        if len(p) >= 3 and p[-1] == "text" and isinstance(p[-2], int) and p[-3] in _INLINE_LISTS:
            groups.setdefault(p[:-2], []).append(leaf)
    out = []
    for nodes in groups.values():
        if len(nodes) >= 2 and sum(1 for n in nodes if n.value.strip()) >= 2:
            out.append((Leaf(nodes[0].path, "".join(n.value for n in nodes), -1, -1, ()), nodes))
    return out


def _sentence_findings(out: list, sentences: list) -> list:
    """The findings of each sentence, cut into the nodes they cover; a node's own finding is not repeated."""
    ids = {id(leaf) for leaf, _nodes in sentences}
    kept = [(leaf, m) for leaf, m in out if leaf is None or id(leaf) not in ids]
    have = {(id(leaf), m.start, m.end, m.type) for leaf, m in kept if leaf is not None}
    by_leaf: dict = {}
    for leaf, m in out:
        if leaf is not None and id(leaf) in ids:
            by_leaf.setdefault(id(leaf), []).append(m)
    for sentence, nodes in sentences:
        for m in by_leaf.get(id(sentence), ()):
            at = 0
            for node in nodes:
                a, b = max(m.start, at), min(m.end, at + len(node.value))
                s, e = a - at, b - at
                if s < e and (id(node), s, e, m.type) not in have:
                    have.add((id(node), s, e, m.type))
                    kept.append((node, dataclasses.replace(m, start=s, end=e, value=node.value[s:e])))
                at += len(node.value)
    return kept


def _scan_segments(detector, segments: list, channel: str, kwargs: dict) -> list:
    out = []
    order = _response_order(detector, [t for t, _p, _s in segments], {k: v for k, v in kwargs.items()
                                                                       if k != "deadline"})
    read: list = []
    for text, placed, starts in segments:
        # a negative context counts only inside its field (text_index.py); the rules of the response (prefilter.py)
        try:
            with record_fields(text, starts), (with_response_rules(text, order) if order else contextlib.nullcontext()):
                found = detector.findings(text, channel=channel, **kwargs)
        except ScanIncomplete as e:
            # past the deadline: the segments before, and this one's findings so far, placed in their strings; the
            # strings of the segments before are read whole
            raise ScanIncomplete(out + _placed(e.findings, placed), e.reason, read) from None
        out += _placed(found, placed)
        read += [leaf for leaf, _at in placed]
    return out


def _placed(found: list, placed: list) -> list:
    """(leaf, match) for the findings of one segment, the match in the offsets of its string."""
    out = []
    k = 0   # the findings come sorted by start and the strings in text order: one pass over both
    for m in sorted(found, key=lambda m: m.start):
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
    try:
        found = detector.findings(text, channel=channel, **kwargs)
    except ScanIncomplete as e:
        raise ScanIncomplete(_json_placed(e.findings, leaves), e.reason, []) from None   # one scan: none read whole
    return _json_placed(found, leaves)


def _json_placed(found: list, leaves: list) -> list:
    """(leaf, match) for the findings of the JSON text, the match in the offsets of its string."""
    out, k = [], 0
    for m in sorted(found, key=lambda m: m.start):
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
