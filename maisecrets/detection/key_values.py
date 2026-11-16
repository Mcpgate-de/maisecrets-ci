"""A value after a key in structured data (#43, #45): a JSON or YAML field, key=value, an HTML table row, an XML
element and an SQL comparison. The names of #43 (role_names.key_names), the passwords and the id numbers of #45 share
these forms. Kept out of core.py and personal.py, which are at the size limit of a release file."""
from __future__ import annotations

import re
from .wordlists import words as _words, word_tuple as _word_tuple

from .lazy_regex import LazyRx as _LazyRx

# the end of a field: a closing quote (also before a space: `last name`='…' LIMIT 3), or the end of the line or a
# separator of the format
_END = r"(?=[\"'`](?:[ \t]|$)|[\"'`]?[ \t]*(?:$|[\n,;&)}\]<]|#))"
_FORMS: dict = {}


def forms(value: str, key: str = r"[A-Za-z0-9 _-]", ops: str = r"(?:=>|[:=])") -> list:
    """The three forms for one value pattern; group 2 or 3 is the key, group 4 the value."""
    got = _FORMS.get((value, key, ops))
    if got is None:
        k = r"[A-Za-z]" + key + r"{2,40}"
        got = _FORMS[(value, key, ops)] = [
            re.compile(r"(?:([\"'`])(" + k + r")\1|(?<![\w.-])([A-Za-z][A-Za-z0-9_-]{2,40}))"
                       r"[ \t]{0,3}" + ops + r"[ \t]{0,3}[\"'`]?" + value + _END, re.M),
            re.compile(r"<th(?:\s[^<>]{0,80})?>\s{0,32}()(" + k + r")()\s{0,32}</th>\s{0,64}"
                       r"<td(?:\s[^<>]{0,80})?>\s{0,32}" + value + r"\s{0,32}</td>"),
            re.compile(r"<()([A-Za-z_][\w.:-]{2,64})()(?:\s[^<>]{0,200})?>[ \t]*" + value + r"[ \t]*</\2>"),
        ]
    return got


def fold(key: str) -> str:
    """A key without case, separators, apostrophes and their entities: driver&#x27;s-license -> driverslicense."""
    k = re.sub(r"&(?:apos|#x27|#39);", "", key.split(":")[-1].lower())
    return re.sub(r"[\s_'’-]+", "", k).replace("licence", "license")


# a key whose value is a password (key_store_password, current-password, keypassword, db_pwd); a key that names a rule
# or a state of one ends in another word (password_policy, password_length) and is no password key
_PASSWORD_ENDS = _word_tuple("passwords/password-key-ends")
# a key whose value is an id number of a person (Privy, the Benchmark V3 sample, 2026-11-14)
_ID_KEYS = _words("id-numbers/id-keys")
# a key that an invoice, an order or a journal uses too (DocumentNumber INV-2024-0042, idNumber ORD-1234): an id of a
# person only in a person's element or next to the type of a person's document. A word near it is no evidence: an
# invoice has a customerName and an address too (Gate A, round 2)
_GENERIC_ID_KEYS = frozenset({"documentnumber", "idnumber", "identitydocument"})
_PERSON_PARENTS = _words("tables/person-parents-of-an-id")
_DOCUMENT_TYPE_RE = re.compile(r"(?i)[\"'`<]?document[_ -]?type[\"'`>]?\s{0,3}[:=>]?\s{0,3}[\"'`]?"
                               r"(?:passport|id[ _-]?card|identity[ _-]?card|national[ _-]?id|driv(?:er|ing))")
_NEAR = 200
# the words one of the keys of a family holds: a text without any of them is not scanned for that family
_PASSWORD_WORDS = ("pass", "pwd")
_ID_WORDS = _word_tuple("id-numbers/id-key-words")
_ID_KEY_CHARS = r"[A-Za-z0-9 _'’&#;-]"            # driver's-license, driver&#x27;s-license in a table head
_COMPARE = r"(?:=>|<>|!=|[:=])"                   # WHEN "keypassword"<>'…' in SQL
_PASSWORD_VALUE = r"([^\s\"'`<>,;|&]{3,64})"
# a key that holds a user name (#51): userID, login_name
_USER_ID_WORDS = _word_tuple("usernames/user-name-key-words")
_USER_VALUE = r"([A-Za-z][A-Za-z0-9._-]{1,30}[A-Za-z0-9])"
_ID_VALUE = r"([A-Za-z0-9](?:[A-Za-z0-9]|[ -](?=[A-Za-z0-9])){3,24})"
# a key that holds the street line of a postal address (Cloakroom 1.4.0 rules.py:134-138): street, address_line1,
# addressLine1, billing_street. The value must be a street line (personal._STREET_LINE_RE)
_STREET_WORDS = _word_tuple("addresses/street-key-words")
_STREET_KEYS = _words("addresses/street-keys")
_STREET_VALUE = r"([0-9A-Za-zÀ-ÿ][^\"'`<>\n,;|]{4,60})"
# a literal that an expression joins with more: password = "…" + os.environ["PW_SUFFIX"] is a part of the value
_JOINED_RE = re.compile(r"[\"'`][ \t]*(?:\+|\|\||\.[ \t]|~)")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}|\d{1,2}[./-]\d{1,2}[./-]\d{2,4}")


def password_key(key: str) -> bool:
    k = fold(key)
    return k.endswith(_PASSWORD_ENDS)


def _password_ok(v: str) -> bool:
    """A value under a password key: the checks of a password literal (core._pw_literal_ok: 4 to 64 characters, no
    fixture word, placeholder, path, URL, reference, version or word)."""
    from .core import _pw_literal_ok
    return _pw_literal_ok(v, "tool")


def _id_ok(v: str) -> bool:
    from .personal import _placeholder_digits
    digits = sum(c.isdigit() for c in v)
    # four digits alone are a year (personal.py, id-number-after-label)
    return (digits >= 5 or digits == 4 and v[0].isalpha()) and not _DATE_RE.fullmatch(v) \
        and not _placeholder_digits(v) and len(v) <= 24


def _a_persons_id(text: str, m, key: str, things, parent) -> bool:
    """Whether an id after a key is a person's: not the element of a thing (a product's passport, a project's
    document number), and a generic key only in a person's element or next to the type of a person's document. A
    password stays a password in any element (Gate A: <profile><key_store_password> was dropped)."""
    element = text.startswith("<", m.start())
    if element and parent(text, m.start()) in things:
        return False
    if fold(key) in _GENERIC_ID_KEYS:
        if element and parent(text, m.start()) in _PERSON_PARENTS:
            return True
        return bool(_DOCUMENT_TYPE_RE.search(text, max(0, m.start() - _NEAR), m.end() + _NEAR))
    return True


def _street_ok(v: str) -> bool:
    from .personal import _STREET_LINE_RE
    return bool(_STREET_LINE_RE.fullmatch(v.strip()))


# a test or placeholder record (Musterstraße, Anytown, a fixture) and a well-known public address are no person's
_PLACEHOLDER_RE = _LazyRx(
    r"(?i)(?<![a-z])(?:muster\w*|anytown|springfield|test\w*|sample|example|fake|fixture|dummy|lorem|placeholder"
    r"|1600 amphitheatre|1 infinite loop|one apple park|1 microsoft way|1 hacker way|410 terry ave|10 downing street"
    r"|1600 pennsylvania|742 evergreen|suite|ste\.?(?= ?\d)|floor)(?![a-z])")
# a place as the parent of the street: a venue, a store, a location of a business
_PLACE_PARENT_RE = _LazyRx(r"(?i)[\"']?(?:venue|store|location|place|merchant|branch|site|facility)[\"']?\s*[:=]")


def _a_business_near(text: str, a: int, b: int) -> bool:
    """A company, an office or a public place in the record around a street key, a test or placeholder record, or a
    well-known public address: its street stays text, as the address rules leave it (the setting business_addresses
    mask turns the business regexes off; a placeholder stays text either way)."""
    from .personal import _BUSINESS_RE, _NOT_A_HOME_RE
    lo, hi = max(0, a - 300), min(len(text), b + 300)
    if _PLACEHOLDER_RE.search(text, lo, hi):
        return True
    return bool(_NOT_A_HOME_RE.search(text, lo, hi) or _BUSINESS_RE.search(text, lo, hi)
                or _PLACE_PARENT_RE.search(text, lo, a))


# the kinds hits() reports: core._personal_steps runs it only when `enabled` holds one (#59)
KINDS = ("name-after-label", "username-after-label", "password-after-key", "id-number-after-label",
         "address-after-key")


def hits(text: str) -> list:
    """(start, end, kind, type) of a name (#43), a password and an id number (#45) after a key, and a user name after
    a user-id key or a cue in prose (#51)."""
    from .personal import ADDRESS, ID_NUMBER, NAME, USERNAME, _THING_PARENTS, _xml_parent
    from .core import _references
    from .role_names import key_names
    from .user_forms import USER_ID_KEYS, user_id_matches, user_id_ok, user_names
    refs = _references()
    low = text.lower()
    out = [(s, e, "name-after-label", NAME) for s, e in key_names(text)] if "name" in low else []
    out += [(s, e, "username-after-label", USERNAME) for s, e in user_names(text)]
    for words, value, is_key, ok, kind, typ in (
            (_PASSWORD_WORDS, _PASSWORD_VALUE, password_key, _password_ok, "password-after-key", "SECRET"),
            (_ID_WORDS, _ID_VALUE, lambda k: fold(k) in _ID_KEYS or fold(k) in _GENERIC_ID_KEYS, _id_ok,
             "id-number-after-label", ID_NUMBER),
            (_USER_ID_WORDS, _USER_VALUE, lambda k: fold(k) in USER_ID_KEYS, user_id_ok, "username-after-label",
             USERNAME),
            (_STREET_WORDS, _STREET_VALUE, lambda k: fold(k) in _STREET_KEYS, _street_ok, "address-after-key",
             ADDRESS)):
        if not any(w in low for w in words):
            continue
        found = user_id_matches(text, low, value, _COMPARE, _END) if typ == USERNAME else \
            (m for rx in forms(value, _ID_KEY_CHARS, _COMPARE)[:1 if typ == ADDRESS else 3] for m in rx.finditer(text))
        for m in found:
            key = m.group(2) or m.group(3) or ""
            if not is_key(key) or not ok(m.group(4)) or _JOINED_RE.match(text, m.end(4)) \
                    or refs.hit_is_a_reference(text, m.start(4), m.group(4)):
                continue   # a reference in a form of the detector's sources is no value
            if typ == ID_NUMBER and not _a_persons_id(text, m, key, _THING_PARENTS, _xml_parent):
                continue
            if typ == ADDRESS and _a_business_near(text, m.start(), m.end()):
                continue
            out.append((m.start(4), m.end(4), kind, typ))
    return out
