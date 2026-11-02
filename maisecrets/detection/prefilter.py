"""The checks that let the scan skip a rule before its regex runs: a keyword of the rule in the text, or the literal
that every match of the rule starts with. They never change a finding; they only spare regexes that cannot match.

The literal of a rule is worked out once, when the rules load (core._ranked writes it into Rule.prefix): a scan only
reads it. 448 of 923 rules have no keyword, and 367 of those start with a literal of 3 characters or more (ghp_, xox,
sk-); a text without it cannot hold a match (2026-11-02: no finding changed in 2,553 texts, a short text took 16 %
less time). Only the built-in rules that run as one regex over the text take part, never a rule of your own."""
from __future__ import annotations

import re

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


def leading_literal(regex, matcher: str, keywords: tuple, source: str) -> tuple:
    """(literal, ignore_case) that every match of the regex starts with, or NONE: the leading literal characters of
    the pattern, at least MIN. NONE for a rule with keywords (they gate it already), a rule of your own, a rule that
    does not run as one regex, and a pattern the parser cannot read (never a lost hit)."""
    pattern = getattr(regex, "pattern", None)
    if keywords or source == "user" or matcher not in ("", "regex") or not isinstance(pattern, str):
        return NONE
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


def lacks_prefix(prefix: tuple, text: str, low: str) -> bool:
    """The rule's literal is not in the text, so its regex cannot match."""
    need, icase = prefix
    return bool(need) and (need.lower() not in low if icase else need not in text)
