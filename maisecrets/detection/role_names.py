"""One-word person names after the role key of API data (#40), apart from personal.py, which the plugin directory
reads only up to 200,000 bytes per file. personal.hits calls one_word_names for the name-after-label check."""
from __future__ import annotations

import re


# one word in a role field of an API that is a state or a team, not a person (assignee: Unassigned, assignee: DevOps)
_ROLE_FIELD_WORDS = frozenset({"unassigned", "nobody", "none", "devops", "devsecops", "sre", "qa", "ops", "infra",
                               "frontend", "backend", "fullstack", "it", "hr", "helpdesk", "servicedesk"})
_KEY = r"(?<![\w.-])[\"']?([A-Za-z][A-Za-z0-9]{0,30}(?:[_-]{1,3}[A-Za-z0-9]{1,30}){0,4})[\"']?[ \t]{0,3}[:=][ \t]{0,3}"
_ONE_WORD_KEY_RX: list = []


def _one_word_key_re():
    """A key as personal._COMPOUND_NAME_KEY_RE reads it, then one capitalised word that is the whole value of its line
    or field."""
    if not _ONE_WORD_KEY_RX:
        from .personal import _NAME_STEM
        _ONE_WORD_KEY_RX.append(re.compile(_KEY + r"[\"']?[ \t]{0,3}(" + _NAME_STEM + r")[\"']?[ \t]*(?=$|[\n,}\]])",
                                           re.M))
    return _ONE_WORD_KEY_RX[0]


def one_word_name(v: str) -> bool:
    """One capitalised word after a role key that is a person: no word of the word list (a given name that is a word
    counts as a name), no word of an account, a team, an organisation or a state, no product word of the name
    service, no first word of a value that is no name, no bot."""
    from .personal import _ACCOUNT_WORDS, _NOT_A_NAME_START, _NOT_A_NAME_WORD, _reads_as_words
    from .remote import PRODUCT_WORDS
    low = v.lower()
    return not (_reads_as_words(v, every=True) or low in _ACCOUNT_WORDS or low in _NOT_A_NAME_START
                or low in _NOT_A_NAME_WORD or low in _ROLE_FIELD_WORDS or low in PRODUCT_WORDS
                or low.endswith("bot") or "-" in v)


def one_word_names(text: str) -> list:
    """The spans of one-word names after the role key of API data or after full_name (assignee_display_name: Dana):
    Jira and Slack show many people by a first name or one display word (#40). Not after a weak key (name, owner) or
    a key whose role may be a company (customer_name): there one word is a product, a team or a firm as often."""
    from .personal import _ROLE_KEY_RE
    out = []
    for m in _one_word_key_re().finditer(text):
        key = re.sub(r"[_\s.-]+", "_", re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", m.group(1)).lower()).strip("_")
        if (_ROLE_KEY_RE.search(key) or key.endswith("full_name")) and one_word_name(m.group(2)):
            out.append((m.start(2), m.end(2)))
    return out
