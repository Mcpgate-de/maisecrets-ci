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


# ------------------------------------------------------------------------- a person-name key in structured data (#43)
# first_name, family-name-female, "given name", `last name`, full__name__male: the key, folded (lower case, no space,
# _ or -, no gender word at the end), names one person's name. Not user_name, file_name or app_name: no person
_PERSON_NAME_KEYS = frozenset({"firstname", "lastname", "givenname", "familyname", "middlename", "fullname",
                               "surname", "maidenname", "forename"})
_KEY_NAME_RX: list = []
# the last names of the placeholder names of documentation (personal.PLACEHOLDER_NAMES)
_PLACEHOLDER_SURNAMES = frozenset({"doe", "mustermann", "musterfrau", "roe", "bloggs", "normalverbraucher"})
# one word in a name field that is the state of the field in a form or a schema, not a name; the word list knows the
# stem (require, mask) but not every form of it
_FIELD_STATE_WORDS = frozenset({"required", "mandatory", "optional", "missing", "invalid", "redacted", "masked",
                                "hidden", "null", "nil", "empty", "blank", "anonymous", "anonymized", "anonymised",
                                "withheld", "unspecified", "undisclosed", "tbd", "todo", "placeholder", "sample",
                                # a verb or a function word that starts a message after the key (first_name: Was
                                # …), which the word list leaves out
                                "was", "were", "is", "are", "am", "be", "been", "may", "might", "can", "could",
                                "will", "would", "shall", "should", "must", "has", "have", "had", "does", "did",
                                "not", "and", "or", "but", "if", "then", "see", "use",
                                # a validation message in words (Too Short, Can't Be Blank)
                                "too", "can't",
                                # a sort order or the key itself as the value (ORDER BY last_name DESC)
                                "asc", "desc", "firstname", "lastname", "surname", "givenname", "familyname",
                                # the label itself, translated: an i18n catalog under a name key
                                "prénom", "prenom", "nom", "nombre", "apellido", "apellidos", "vorname",
                                "nachname", "cognome", "sobrenome", "voornaam", "achternaam", "imię", "nazwisko",
                                "förnamn", "efternavn", "fornavn", "efternamn"})


# a role before a person-name key (customer_first_name, billingLastName): the name is still a person's. Not user,
# company, account, app or file: their name is a login or a thing
_PERSON_KEY_ROLES = frozenset({"customer", "client", "contact", "employee", "patient", "member", "student", "buyer",
                               "seller", "recipient", "sender", "applicant", "owner", "holder", "cardholder",
                               "passenger", "tenant", "guarantor", "beneficiary", "borrower", "parent", "guardian",
                               "spouse", "child", "emergencycontact", "billing", "shipping", "preferred",
                               "primary", "secondary", "patient", "physician", "doctor", "author", "reviewer"})


def person_name_key(key: str) -> bool:
    """The key of a field, a column or an element names a person's name (#43), also after a role
    (customer_first_name)."""
    k = re.sub(r"[\s_-]+", "", key.split(":")[-1].lower())
    k = re.sub(r"(?:male|female|nonbinary)$", "", k)
    if k in _PERSON_NAME_KEYS:
        return True
    return any(k.endswith(n) and k[:-len(n)] in _PERSON_KEY_ROLES for n in _PERSON_NAME_KEYS)


def _key_name_res() -> list:
    """The forms of structured data: a quoted key or a bare key before : = or =>, an HTML table row, an XML element.
    The value: one to four name words, the whole value of its field."""
    if not _KEY_NAME_RX:
        from .key_values import forms
        from .personal import _NAME_PARTICLE, _NAME_STEM
        value = r"(" + _NAME_STEM + r"(?:[ ](?:" + _NAME_STEM + "|" + _NAME_PARTICLE + r")){0,3})"
        _KEY_NAME_RX.extend(forms(value))
    return _KEY_NAME_RX


def key_names(text: str) -> list:
    """The spans of a person's name after a person-name key in JSON, XML, an HTML table, SQL or key=value (#43): the
    names of API answers and logs, often one word without a sentence around it, that neither a label rule nor the
    name service read. One word passes the checks of one_word_name, more words the checks of a name after a label."""
    from .personal import _NOT_A_NAME_PART, _THING_PARENTS, PLACEHOLDER_NAMES, _name_ok, _reads_as_words, _xml_parent
    out, first, last = [], [], []
    for rx in _key_name_res():
        for m in rx.finditer(text):
            key = m.group(2) or m.group(3) or ""
            if not person_name_key(key):
                continue
            # the element of a thing (a security's fullName, a product's name) names no person, as in the XML rule
            if text.startswith("<", m.start()) and _xml_parent(text, m.start()) in _THING_PARENTS:
                continue
            v = m.group(4).rstrip("'’")
            plain = re.sub(r"-[^\s]*", "", v)
            # a state or a message starts the value (Too Short, Can't Be Blank); a word inside a name does not count
            # (a surname Long or Short)
            if v.split()[0].lower() in _FIELD_STATE_WORDS or v.lower() in _NOT_A_NAME_PART:
                continue
            if " " in v:
                ok = _name_ok(v) and not (_reads_as_words(v, every=True) and _reads_as_words(plain, every=True))
            else:
                # a double surname is one word: each part passes alone (one_word_name refuses a hyphen)
                ok = all(p and one_word_name(p) for p in v.split("-"))
            if ok:
                span = (m.start(4), m.start(4) + len(v))
                out.append(span)
                folded = re.sub(r"[\s_-]+", "", key.lower())
                (first if folded.startswith(("first", "given", "fore")) else last if folded.startswith(
                    ("last", "family", "sur")) else []).append(span)
    # a first and a last name that together make a placeholder (first_name John, last_name Doe) are a fixture, as in
    # a table of name parts (personal.py)
    fixture = {sp for a in first for b in last
               for sp in (a, b) if (text[a[0]:a[1]] + " " + text[b[0]:b[1]]).lower() in PLACEHOLDER_NAMES}
    # the last name of a placeholder alone (Mustermann, Doe): its first name may fail the checks of a name (Max)
    fixture |= {sp for sp in last if text[sp[0]:sp[1]].lower() in _PLACEHOLDER_SURNAMES}
    return sorted(set(out) - fixture)
