"""The checks that let the scan skip a rule before its regex runs: a keyword of the rule in the text, or the literal
that every match of the rule starts with. They never change a finding; they only spare regexes that cannot match.

The literal of a rule is worked out once, when the rules load (core._ranked writes it into Rule.prefix): a scan only
reads it. 448 of 923 rules have no keyword, and 367 of those start with a literal of 3 characters or more (ghp_, xox,
sk-); a text without it cannot hold a match (2026-11-02: no finding changed in 2,553 texts, a short text took 16 %
less time). Only the built-in rules that run as one regex over the text take part, never a rule of your own."""
from __future__ import annotations

import contextlib
import functools
import contextvars
import hashlib
import json
import re
from pathlib import Path

MIN = 3
NONE = ("", False)


def any_keyword(keywords: tuple, low: str, known: dict) -> bool:
    """Whether the lower-case text holds one of the keywords. Each keyword is searched once per text: a search runs
    over the whole text, and the same keyword gates several rules."""
    for k in keywords:
        hit = known.get(k)
        if hit is None:
            hit = known[k] = k in low
        if hit:
            return True
    return False


# the literal of each built-in pattern, worked out ahead (scripts/gen_leading_literals.py): parsing 920 patterns took
# ~20 ms of each hook process (netcup, 2026-11-03). The key is a hash of the flags and the pattern, so a changed pattern
# misses and is parsed as before; tests/test_leading_literals.py recomputes every entry
LITERALS_FILE = Path(__file__).parent / "rules" / "leading_literals.json"


def literal_key(pattern: str, flags: int) -> str:
    return hashlib.sha256(f"{int(flags)}\n{pattern}".encode("utf-8", "surrogatepass")).hexdigest()[:24]


def _read_literals() -> dict:
    try:
        return json.loads(LITERALS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


# read once at import (26 KB, under 1 ms): a scan then writes no module state (tests/test_scan_context.py)
_LITERALS = _read_literals()


def _known() -> dict:
    return _LITERALS


def leading_literal(regex, matcher: str, keywords: tuple, source: str) -> tuple:
    """(literal, ignore_case) that every match of the regex starts with, or NONE: the leading literal characters of
    the pattern, at least MIN. NONE for a rule with keywords (they gate it already), a rule of your own, a rule that
    does not run as one regex, and a pattern the parser cannot read (never a lost hit)."""
    pattern = getattr(regex, "pattern", None)
    if keywords or source == "user" or matcher not in ("", "regex") or not isinstance(pattern, str):
        return NONE
    hit = _known().get(literal_key(pattern, regex.flags))
    if isinstance(hit, list) and len(hit) in (2, 3) and isinstance(hit[0], str):
        return (hit[0], bool(hit[1])) if hit[0] else NONE
    return parsed_literal(regex)


def parsed_literal(regex) -> tuple:
    """leading_literal by parsing the pattern: the reference of the file and the way for a pattern it lacks."""
    pattern = regex.pattern
    try:
        try:
            import re._parser as parser
        except ImportError:            # Python before 3.11
            import sre_parse as parser
        lit = []
        for op, av in parser.parse(pattern, regex.flags):
            if op is not parser.LITERAL:
                break
            lit.append(chr(av))
    except Exception:  # noqa: BLE001
        return NONE
    return ("".join(lit), bool(regex.flags & re.IGNORECASE)) if len(lit) >= MIN else NONE


# --------------------------------------------------------------------------- required literals --
# A rule with no keyword, no leading literal and no context gate ran its regex over every text: 58 rules, a third of the
# time of a Slack-shaped response on the reference host (2026-11-03). Most of them still need one of a few literals
# somewhere in each match (%40, the password label words, x-amz-security-token). In an ASCII text str.lower() folds as
# re.IGNORECASE does, so a text whose lower case holds none of them cannot hold a match; any other text runs the rule
# (dotless i and long s fold to i and s only under the regex)
_MAX_ALTS, _MAX_CLASS, _MIN_LEN = 64, 4, 3


def _parser():
    try:
        import re._constants as constants
        import re._parser as parser
    except ImportError:            # Python before 3.11
        import sre_constants as constants
        import sre_parse as parser
    return parser, constants


def _alternatives(items, C, repeats) -> set | None:
    """Every string an all-literal piece can be, or None when it is not all-literal (a class of at most _MAX_CLASS
    literals counts)."""
    cur = {""}
    for op, av in items:
        if op is C.LITERAL:
            cur = {c + chr(av) for c in cur}
        elif op is C.IN:
            if len(av) > _MAX_CLASS or any(o is not C.LITERAL for o, _ in av):
                return None
            cur = {c + chr(v) for c in cur for _, v in av}
        elif op is C.AT:
            continue
        elif op is C.SUBPATTERN:
            sub = _alternatives(av[3], C, repeats)
            if sub is None:
                return None
            cur = {c + x for c in cur for x in sub}
        elif op is C.BRANCH:
            alts: set = set()
            for b in av[1]:
                sub = _alternatives(b, C, repeats)
                if sub is None:
                    return None
                alts |= sub
            cur = {c + x for c in cur for x in alts}
        elif op in repeats and av[0] == av[1] and av[0] >= 1:
            sub = _alternatives(av[2], C, repeats)
            if sub is None:
                return None
            for _ in range(av[0]):
                cur = {c + x for c in cur for x in sub}
        else:
            return None
        if len(cur) > _MAX_ALTS:
            return None
    return cur


def _strong(x: str) -> bool:
    """A literal rare enough to gate on: 3 characters, or 2 that are not ASCII (密码, 암호)."""
    return len(x) >= _MIN_LEN or (len(x) >= 2 and not x.isascii())


def _required(items, C, repeats) -> set | None:
    """A set of strings one of which every match contains, or None. A zero-width item continues a literal run; the
    content of a positive lookaround stands in the text too."""
    cands: list = []
    run = {""}

    def flush():
        nonlocal run
        if run != {""}:
            cands.append(set(run))
        run = {""}

    for op, av in items:
        alts = _alternatives([(op, av)], C, repeats)
        if alts is not None:
            new = {c + x for c in run for x in alts}
            if len(new) <= _MAX_ALTS:
                run = new
                continue
        if op is C.AT or op is C.ASSERT_NOT:
            continue
        if op is C.ASSERT:
            s = _required(av[1], C, repeats)
            if s:
                cands.append(s)
            continue
        flush()
        s = None
        if op is C.SUBPATTERN:
            s = _required(av[3], C, repeats)
        elif op is C.BRANCH:
            parts = [_required(b, C, repeats) for b in av[1]]
            s = set().union(*parts) if all(parts) else None
        elif op in repeats:
            s = _required(av[2], C, repeats) if av[0] >= 1 else None
        elif op is getattr(C, "ATOMIC_GROUP", object()):
            s = _required(av, C, repeats)
        if s:
            cands.append(s)
    flush()
    usable = [s for s in cands if s and len(s) <= _MAX_ALTS and all(_strong(x) for x in s)]
    return max(usable, key=lambda s: (min(len(x) for x in s), -len(s))) if usable else None


def _folds_to_ascii(ch: str) -> bool:
    """Whether re.IGNORECASE matches this non-ASCII character against an ASCII one (long s and s, Kelvin and k)."""
    return any(re.fullmatch(re.escape(ch), a, re.IGNORECASE) for a in "abcdefghijklmnopqrstuvwxyz")


def parsed_required(regex) -> tuple:
    """required_literals by parsing the pattern: the reference of the file and the way for a pattern it lacks."""
    parser, C = _parser()
    repeats = tuple(getattr(C, n) for n in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT") if hasattr(C, n))
    try:
        found = _required(parser.parse(regex.pattern, regex.flags), C, repeats)
    except Exception:  # noqa: BLE001 - a pattern the parser cannot read gets no gate
        return ()
    if not found or any(_folds_to_ascii(ch) for x in found for ch in x if not ch.isascii()):
        return ()
    return tuple(sorted({x.lower() for x in found}))


def required_literals(rule, source: str) -> tuple:
    """The literals one of which every match of the rule holds, lower case, or (): only for a built-in rule that runs as
    one regex and has no other gate (a keyword, a leading literal or a context word that it needs)."""
    regex, pattern = rule.regex, getattr(rule.regex, "pattern", None)
    gated = rule.keywords or rule.prefix[0] or (rule.context and (rule.require_context or rule.score < 0.5))
    if gated or source == "user" or rule.matcher not in ("", "regex") or not isinstance(pattern, str):
        return ()
    hit = _known().get(literal_key(pattern, regex.flags))
    if isinstance(hit, list) and len(hit) == 3 and isinstance(hit[2], list):
        return tuple(hit[2])
    return parsed_required(regex)


def lacks_required(need: tuple, text: str, low: str) -> bool:
    """The text cannot hold a match of a rule that needs one of `need`: it is ASCII and its lower case holds none."""
    return bool(need) and text.isascii() and not any(x in low for x in need)


def lacks_prefix(prefix: tuple, text: str, low: str) -> bool:
    """The rule's literal is not in the text, so its regex cannot match."""
    need, icase = prefix
    return bool(need) and (need.lower() not in low if icase else need not in text)


# ------------------------------------------------------------------------------- the rules of a response --
# findings_by_leaf scans each record of a response apart, and each scan walked all 920 rules with their keyword and
# literal checks. A rule whose keyword, literal and required literals occur nowhere in the whole response cannot fire in
# any of its records (each check is a substring test, so it holds for the joined text): the response decides once, and
# each record scan walks only the rules left (a fifth of the time of a Slack-shaped response on the reference host,
# 2026-11-03). Only for that exact text object: the cleaned copy and a nested scan take every rule
_RESPONSE: contextvars.ContextVar = contextvars.ContextVar("maisecrets_response_rules", default=None)


def response_rules(text: str):
    """The rules in scan order for this text of a response scan, or None (then every rule)."""
    got = _RESPONSE.get()
    return got[1] if got is not None and got[0] is text else None


@contextlib.contextmanager
def with_response_rules(text: str, order: tuple):
    token = _RESPONSE.set((text, order))
    try:
        yield
    finally:
        _RESPONSE.reset(token)


@functools.lru_cache(maxsize=8192)
def _trigrams(word: str) -> frozenset:
    return frozenset(word[i:i + 3] for i in range(len(word) - 2))


class _Grams(dict):
    """A dict of `word in low`, answered first by the three-letter pieces of `low`: a word with a piece the text lacks
    cannot be in it. A response holds a few of the 553 keywords, and a search of the whole text for each of them was
    most of the time of rules_for."""

    def __init__(self, low: str) -> None:
        super().__init__()
        self.low = low
        self.grams = {low[i:i + 3] for i in range(len(low) - 2)}

    def __missing__(self, word: str) -> bool:
        hit = self[word] = (len(word) < 3 or _trigrams(word) <= self.grams) and word in self.low
        return hit


DIGITS = frozenset("0123456789")


def alphabet_of(text: str, low: str) -> frozenset:
    """The characters of a text and of its lower case, with all ten digits when it holds one: the numbers of a series
    share one alphabet."""
    chars = set(text)
    chars.update(low)
    if not chars.isdisjoint(DIGITS):
        chars.update(DIGITS)
    return frozenset(chars)


# the rules that fire without a context word in the tool channel (core.CARD_ALONE_IN_TOOL is this set)
CARD_ALONE_IN_TOOL = frozenset({"credit-card"})


def rules_for_alphabet(order: tuple, alphabet: frozenset, alone: frozenset = frozenset()) -> tuple:
    """The rules of `order` that can fire in some text of this alphabet: the checks of the scan (core._scan) asked of
    the characters instead of a text. A keyword, a literal, a required literal or a context word with a character
    outside the alphabet is in no such text, so a rule that needs one cannot fire there; the scan still checks the
    rest. A gateway scans each number of a metric series apart ("values: 1794412212320"): 2,680 points walked all
    rules each (ai-gateway, 2026-11-11)."""
    def can(word: str) -> bool:
        return alphabet.issuperset(word)
    out = []
    for rule in order:
        if not hasattr(rule, "keywords"):
            out.append(rule)
            continue
        if rule.keywords and not any(can(k) for k in rule.keywords):
            continue
        need, icase = rule.prefix or NONE
        if need and not can(need.lower() if icase else need):
            continue
        if rule.need and not any(can(x) for x in rule.need):
            continue
        # a rule that cannot fire without a context word (core._scan), unless it may fire alone in some channel
        if (rule.context and (rule.require_context or rule.score < 0.5) and rule.id not in alone
                and not any(can(c) for c in rule.context)):
            continue
        out.append(rule)
    return tuple(out)


# a short text walks only the rules its alphabet allows. The list of an alphabet is built the second time the alphabet
# comes, so a response of short texts that all differ pays one set per text
ALPHABET_TEXT_MAX = 512
_ALPHABET_ORDERS_MAX = 256


def alphabet_order(det, order: tuple, text: str, low: str) -> tuple:
    """The rules of a scan order for this text: for a short one, rules_for_alphabet of its alphabet, kept on the
    detector `det` per order and alphabet."""
    if len(text) > ALPHABET_TEXT_MAX:
        return order
    if det._alphabet_orders[0] is not order:
        det._alphabet_orders = (order, {})
    known = det._alphabet_orders[1]
    key = alphabet_of(text, low)
    got = known.get(key)
    if got is None:                     # the first time: note the alphabet, scan with every rule
        if len(known) >= _ALPHABET_ORDERS_MAX:
            known.clear()
        known[key] = False
        return order
    if got is False:
        got = known[key] = rules_for_alphabet(order, key, CARD_ALONE_IN_TOOL)
    return got


def rules_for(order: tuple, joined: str, low: str) -> tuple:
    """The rules of `order` that can fire somewhere in `joined` (its lower case is `low`); the steps that are no rule
    (the personal data, the terms, the imported values) stay in their place."""
    known = _Grams(low)
    out = []
    for rule in order:
        if not hasattr(rule, "keywords"):
            out.append(rule)
            continue
        if rule.keywords and not any(known[k] for k in rule.keywords):
            continue
        need, icase = rule.prefix or NONE
        if need and (not known[need.lower()] if icase else need not in joined):
            continue
        if rule.need and joined.isascii() and not any(known[x] for x in rule.need):
            continue
        out.append(rule)
    return tuple(out)


# ------------------------------------------------------------------------------- the lines of prefixes.txt --
_PREFIX_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:/-")


def prefix_line(line: str) -> tuple[str, str] | None:
    """(id, regex) of one line of rules/prefixes.txt, or None for a comment or an empty line. The short form
    `id  PREFIX  REST` names the literal prefix apart (4 characters or more, no regex syntax): the token starts at
    the prefix only when no token character stands before it (or an escaped \\n, \\r, \\t of a JSON string), and it
    ends where no token character follows. The long form `id  regex` writes all of that itself."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split(None, 2)
    if len(parts) == 3 and len(parts[1]) >= 4 and _PREFIX_CHARS.issuperset(parts[1]):
        p = re.escape(parts[1])
        return parts[0], f"{p}(?:(?<![A-Za-z0-9_-]{p})|(?<=\\\\[nrt]{p})){parts[2]}(?![A-Za-z0-9_-])"
    rule_id, regex = line.split(None, 1)
    return rule_id, regex.strip()
