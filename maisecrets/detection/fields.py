"""Field names a caller gives with a text (`scan(..., fields=...)`, `findings(..., fields=...)`).

A caller that has the structure of its data (a JSON response walked with a field path, a key-value record) can name
the field of a value: `fields=[(start, end, ("customer", "telefon"))]`, the span of the value in the text and the field
path, outermost first. The name is evidence as a label before the value is in text, and only that: the last part of
the path that is no list index is put before a copy of the value (`telefon: <value>`) and that line is scanned with
the same rules. A hit inside the value is added when the bare value gives no hit there and the scan of the whole text
has none there either. So a field name

- adds no hit that the same label in text would not give, and none that the bare value gives (the context of the text
  decided that one: a test file, a build number before it);
- takes no hit away: the hits of the text stay as they are, and with no fields the scan is the one of before;
- parses nothing: the core reads JSON, CSV and the other formats of the text itself, as without fields. A field that
  names what the core read itself adds no second hit, since the hit of the text is there already.

A name the label rules give no evidence for (id, value, data, an unknown word) adds nothing, as it would in text. Three
kinds of name add nothing either, though the label rules read a key word in them, because in API data they name
identifiers far more often than credentials (measured: under them a ticket key, a file path, a cache key and a
cursor each became a SECRET):

- `key` alone (a Jira issue key, an object key, a translation key) and `token` alone; a name with more words, such as
  api_key, access_token or secret_key, is a label as in text;
- the cursor of a paged list or a sync (nextPageToken, syncToken, continuationToken, ...): every list response of
  many APIs carries one.
"""
from __future__ import annotations

import dataclasses

from .lazy_regex import LazyRx as _LazyRx

# a word before `token` that makes the field the cursor of a paged list or a sync, not a credential (measured on
# synthetic cursors: under nextPageToken, pageToken, syncToken and continuationToken each one was a SECRET)
_CURSOR_WORDS = frozenset({"page", "next", "prev", "previous", "sync", "continuation", "cursor", "pagination",
                           "resume"})
# a word that is no label alone (`key`, `token`); with another word before it, it is one
_NO_LABEL_ALONE = frozenset({"key", "token"})
_LABEL_MAX = 64
# characters that would end the label line or make the name a label and a value of its own
_NOT_IN_LABEL = _LazyRx(r"[\x00-\x1f\x7f\x85\u2028\u2029:=\"']")
_CAMEL = _LazyRx(r"(?<=[a-z0-9])(?=[A-Z])")
_WORD_SPLIT = _LazyRx(r"[\s._\-]+")


def checked(text: str, fields) -> tuple:
    """The fields as ((start, end, label), ...), or () when they add nothing. Raises TypeError or ValueError for a wrong
    shape; a message names the position of the field and never a part of the text or of a name."""
    if fields is None:
        return ()
    if not isinstance(text, str):   # as scan() says it, before a length is read
        raise TypeError(f"text must be a str, not {type(text).__name__}")
    if isinstance(fields, (str, bytes, bytearray, dict)) or not isinstance(fields, (list, tuple)):
        raise TypeError(f"fields must be a list or tuple of (start, end, name), not {type(fields).__name__}")
    out = []
    for i, f in enumerate(fields):
        if not isinstance(f, (list, tuple)) or len(f) != 3:
            raise TypeError(f"fields[{i}] must be a (start, end, name) tuple, not {type(f).__name__}")
        start, end, name = f
        for what, v in (("start", start), ("end", end)):
            if not isinstance(v, int) or isinstance(v, bool):
                raise TypeError(f"fields[{i}] {what} must be an int, not {type(v).__name__}")
        if not 0 <= start < end <= len(text):
            raise ValueError(f"fields[{i}] must have 0 <= start < end <= len(text), got start={start} end={end} "
                             f"for a text of {len(text)} code points")
        if not isinstance(name, (list, tuple)) or not name:
            raise TypeError(f"fields[{i}] name must be a non-empty tuple of path parts, not {type(name).__name__}")
        for part in name:
            if not isinstance(part, (str, int)) or isinstance(part, bool):
                raise TypeError(f"fields[{i}] name parts must be str or int, not {type(part).__name__}")
        label = _label(name)
        if label:
            out.append((start, end, label))
    return tuple(out)


def _label(name) -> str:
    """The label of a field path: its last part that is no list index, or "" when it can give no evidence."""
    for part in reversed(name):
        if isinstance(part, int) or not part.strip() or part.strip().isdigit():
            continue
        label = part.strip()
        if len(label) > _LABEL_MAX or _NOT_IN_LABEL.search(label):
            return ""
        words = [w for w in _WORD_SPLIT.split(_CAMEL.sub("_", label).lower()) if w]
        if words and words[-1] == "token" and any(w in _CURSOR_WORDS for w in words[:-1]):
            return ""
        if len(words) == 1 and words[0] in _NO_LABEL_ALONE:
            return ""
        return label
    return ""


def added(text: str, hits: list, spans: tuple, scan) -> list:
    """`hits` (the scan of the text) with the hits the field labels add; `scan(text)` scans a text with the rules,
    the channel and the rule list of the call."""
    taken = [(m.start, m.end) for m in hits]
    extra = []
    for start, end, label in spans:
        value = text[start:end]
        if not value.strip():
            continue
        lead = len(label) + 2
        bare = [(m.start, m.end) for m in scan(value)]
        for m in scan(f"{label}: {value}"):
            a, b = m.start - lead, m.end - lead
            if a < 0 or b > len(value) or any(a < y and x < b for x, y in bare):
                continue   # in the label, or the bare value has a hit there: the field gives no evidence for it
            a, b = a + start, b + start
            if text[a:b] != m.value or any(a < y and x < b for x, y in taken):
                continue
            taken.append((a, b))
            extra.append(dataclasses.replace(m, start=a, end=b))
    if not extra:
        return hits
    return sorted(hits + extra, key=lambda m: m.start)
