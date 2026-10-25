"""The verdict of ms:(…) as a person reads it: what maisecrets masks the value as, and how sure that is.

One line per hit = a noun (notices.type_word, by the class of the type) + the placeholder type the AI sees + one
sentence on how it was found. The sentence comes from the form of the rule or from the source of the hit, never from
the rule: a rule id means nothing to the person, except the name of a rule of their own (they wrote it) and the line
of the allow list (they must find it). A label hit also says that this exact value is now stored and for how long
(the check stores what it caught, hooks._take_values_out), or why the store will not find it again (too short, a
common word). No value is ever in the text: the label in front of a value is shown only when it overlaps no hit.
"""
from __future__ import annotations

import re

from .notices import _hours, type_word
from .placeholder import CLOSE, OPEN
from .tool_output import _EXACT_MIN_LEN as _MIN_LEN    # a stored value is found again from this length on

FORMAT_LONG = "maisecrets knows this format, so it masks it wherever it appears, also alone."
FORMAT_SHORT = "maisecrets knows this format and masks it everywhere"
EXPORT_RULE = "label-password-export"

# the label in front of a value: a word with `:` or `=` (`password:`, `api_key=`), else the last one or two words
# (`Bearer`, `password is`)
_SIGNED_RE = re.compile(r"[^\W\d][\w.\-]{0,30}\s?[:=]$")
_WORDS_RE = re.compile(r"(?:[^\W\d_][\w.\-]{0,20}\s+)?[^\W\d_][\w.\-]{0,20}$")


def label_before(text: str, start: int, spans) -> str:
    """The label in front of a hit at `start`, from the person's own text, or "" when there is none or it touches a
    hit (a value is never shown)."""
    head = text[:start].rstrip(" \t\"'`")
    m = _SIGNED_RE.search(head) or _WORDS_RE.search(head)
    if not m:
        return ""
    a, b = m.span()
    if any(s < b and a < e for s, e in spans):
        return ""
    return m.group(0)


def _personal_needs(kind: str) -> str:
    try:
        from .detection import personal
    except ImportError:
        return ""
    return personal.NEEDS.get(kind, "")


def how_found(kind: str) -> str:
    """`label` (a word in front of the value found it), `words` (words near it or a fixed form around it) or `format`
    (the value alone). The keyword and label rules of the rule list, the personal-data rules with a label or a form
    (their spec form, rulespec._form) and the rules that fire only with a context word near them are not found alone."""
    from .detection import registry
    if registry.form_of(kind) != "shape":
        return "label"
    needs = _personal_needs(kind)
    if needs:
        return "label" if needs == "label" else "words"
    from . import detect
    for rule in detect.rules():
        if rule.id == kind:
            return "words" if rule.context and (rule.require_context or rule.score < 0.5) else "format"
    return "format"


def _ttl(entry) -> str:
    seconds = int(round(entry.expires - max(entry.created, entry.last_used)))
    return _hours(seconds) if seconds > 0 else ""


def _found_again(entry, value: str, words: bool) -> tuple:
    """(long, short) of what the store does with this exact value from now on."""
    what = "those words" if words else "the label"
    if entry is None:
        return "", ""
    if getattr(entry, "weak", False):
        return (f" It is a common word, so it is found again only with {what}.",
                f"; a common word, found again only with {what}")
    if len(value.strip()) < _MIN_LEN:
        return (f" It is too short to be found again without {what}.", f"; too short to be found again without {what}")
    ttl = _ttl(entry)
    if not ttl:
        return "", ""
    return (f" This value is now stored, so it is masked wherever it appears for {ttl} (each use extends it).",
            f"; this value is now masked everywhere for {ttl}")


def hit_sentences(text: str, m, entry, spans) -> tuple:
    """(long, short) of one hit `m` of `text`: the long one stands alone, the short one is a line of a list."""
    kind = m.kind
    if kind.startswith("term:"):
        return ("It is on your term list, so it is masked. The AI sees a placeholder that is never put back.",
                "on your term list, never put back")
    if kind.startswith("import:"):
        ref = "import:" + kind.split(":")[1]
        return (f"It is in your imported values ({ref}). It is masked and never put back into a command.",
                f"in your imported values ({ref}), never put back into a command")
    if kind.startswith("user:"):
        name = kind[len("user:"):]
        return f"Your own rule {name} found it.", f"found by your own rule {name}"
    if kind == EXPORT_RULE:
        return ("It is in the password column of a password export, so the whole cell is masked.",
                "in the password column of a password export")
    how = how_found(kind)
    if how == "format":
        return FORMAT_LONG, FORMAT_SHORT
    stored_long, stored_short = _found_again(entry, m.value, how == "words")
    if how == "words":
        return ("maisecrets found it by the words around it. A value like this without such words is not found."
                + stored_long, "found by the words around it" + stored_short)
    label = label_before(text, m.start, spans)
    quoted = f" (`{label}`)" if label else ""
    return (f"maisecrets found it by the label in front of it{quoted}. A value like this without such a label is not "
            "found." + stored_long, f"found by the label in front of it{quoted}" + stored_short)


def stored_sentences(entry) -> tuple:
    """(long, short) of a value the store already held (the exact match of hooks._exact_redact)."""
    return (f"This value is already stored as {entry.ref}. maisecrets masks it wherever it appears exactly.",
            f"already stored as {entry.ref}, masked wherever it appears exactly")


def _head(type_: str) -> str:
    return f"{type_word(type_)} ({OPEN}{type_}_…{CLOSE})"


def caught(text: str, matches: list, entries: list) -> str:
    """The verdict of a value that maisecrets masks: one sentence for one hit, a list for several, in text order (the
    values the store held come last: the exact match names no place). The same line twice is said once with `2 ×`."""
    ordered = sorted(matches, key=lambda x: x.start)
    own = entries[:len(ordered)] if len(entries) >= len(ordered) else [None] * len(ordered)
    spans = [(x.start, x.end) for x in ordered]
    items = [(_head(m.type),) + hit_sentences(text, m, e, spans) for m, e in zip(ordered, own)]
    items += [(_head(e.type),) + stored_sentences(e) for e in entries[len(ordered):]]
    if len(items) == 1:
        head, long, _short = items[0]
        return f"✓ maisecrets masks this as {head}. {long}"
    counts: dict = {}
    for head, _long, short in items:
        counts[(head, short)] = counts.get((head, short), 0) + 1
    lines = [f"✓ maisecrets masks {len(items)} parts of this:"]
    for (head, short), n in counts.items():
        lines.append(f"  · {f'{n} × ' if n > 1 else ''}{head}, {short}")
    return "\n".join(lines)
