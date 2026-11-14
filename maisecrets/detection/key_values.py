"""A value after a key in structured data (#43, #45): a JSON or YAML field, key=value, an HTML table row, an XML
element and an SQL comparison. The names of #43 (role_names.key_names), the passwords and the id numbers of #45 share
these forms. Kept out of core.py and personal.py, which are at the size limit of a release file."""
from __future__ import annotations

import re

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
_PASSWORD_ENDS = ("password", "passwd", "passphrase", "pwd")
# a key whose value is an id number of a person (Privy, the Benchmark V3 sample, 2026-11-14)
_ID_KEYS = frozenset({
    "driverlicense", "driverslicense", "drivinglicense", "driverlicensenumber", "driverslicensenumber",
    "nationalidentity", "nationalid", "nationalidentitynumber", "nationalidnumber", "identitydocumentnumber",
    "passport", "passportnumber", "passportno", "taxid", "taxidentificationnumber", "taxpayeridentificationnumber",
    "taxpayerid", "itin", "medicalrecordnumber", "healthplanbeneficiarynumber"})
# a key that an invoice, an order or a journal uses too (DocumentNumber INV-2024-0042, idNumber ORD-1234): an id of a
# person only in a person's element or next to the type of a person's document. A word near it is no evidence: an
# invoice has a customerName and an address too (Gate A, round 2)
_GENERIC_ID_KEYS = frozenset({"documentnumber", "idnumber", "identitydocument"})
_PERSON_PARENTS = frozenset({"person", "holder", "applicant", "passenger", "traveler", "traveller", "citizen",
                             "patient", "employee", "guest", "member", "student", "identity", "identification"})
_DOCUMENT_TYPE_RE = re.compile(r"(?i)[\"'`<]?document[_ -]?type[\"'`>]?\s{0,3}[:=>]?\s{0,3}[\"'`]?"
                               r"(?:passport|id[ _-]?card|identity[ _-]?card|national[ _-]?id|driv(?:er|ing))")
_NEAR = 200
# the words one of the keys of a family holds: a text without any of them is not scanned for that family
_PASSWORD_WORDS = ("pass", "pwd")
_ID_WORDS = ("licen", "identit", "passport", "documentnumber", "document_number", "document-number",
             "document number", "document__number", "idnumber", "id_number", "id-number", "id number", "id__number",
             "taxid", "tax_id", "tax-id", "tax id", "tax__id", "taxpayer", "taxidentification", "tax_identification",
             "itin", "medical", "beneficiary", "national")
_ID_KEY_CHARS = r"[A-Za-z0-9 _'’&#;-]"            # driver's-license, driver&#x27;s-license in a table head
_COMPARE = r"(?:=>|<>|!=|[:=])"                   # WHEN "keypassword"<>'…' in SQL
_PASSWORD_VALUE = r"([^\s\"'`<>,;|&]{3,64})"
_ID_VALUE = r"([A-Za-z0-9](?:[A-Za-z0-9]|[ -](?=[A-Za-z0-9])){3,24})"
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


def hits(text: str) -> list:
    """(start, end, kind, type) of a name (#43), a password and an id number (#45) after a key."""
    from .personal import ID_NUMBER, NAME, _THING_PARENTS, _xml_parent
    from .core import _references
    from .role_names import key_names
    refs = _references()
    low = text.lower()
    out = [(s, e, "name-after-label", NAME) for s, e in key_names(text)] if "name" in low else []
    for words, value, is_key, ok, kind, typ in (
            (_PASSWORD_WORDS, _PASSWORD_VALUE, password_key, _password_ok, "password-after-key", "SECRET"),
            (_ID_WORDS, _ID_VALUE, lambda k: fold(k) in _ID_KEYS or fold(k) in _GENERIC_ID_KEYS, _id_ok,
             "id-number-after-label", ID_NUMBER)):
        if not any(w in low for w in words):
            continue
        for rx in forms(value, _ID_KEY_CHARS, _COMPARE):
            for m in rx.finditer(text):
                key = m.group(2) or m.group(3) or ""
                if not is_key(key) or not ok(m.group(4)) or _JOINED_RE.match(text, m.end(4)) \
                        or refs.hit_is_a_reference(text, m.start(4), m.group(4)):
                    continue   # a reference in a form of the detector's sources is no value
                if typ == ID_NUMBER and not _a_persons_id(text, m, key, _THING_PARENTS, _xml_parent):
                    continue
                out.append((m.start(4), m.end(4), kind, typ))
    return out
