"""The street before its number after a strong address label (#49), read by personal.py's address-after-label. Kept
out of personal.py, which is at the size limit of a release file; it imports personal.py only when it runs."""
from __future__ import annotations

import re
from .wordlists import words as _words

_RX: dict = {}


def _rx():
    """The label and the value regexes, built on first use from personal.py's name stem."""
    if not _RX:
        from .personal import _LO, _NAME_STEM
        # a label that names an address of a place to live or to send to, on the line of the address label: `Street
        # Address:`, `home_address:`; `Address:` alone keeps the stricter value. A key the address label does not read
        # (billing_address, mailingAddress) is not covered
        _RX["label"] = re.compile(r"(?i)(?<![a-z])(?:street|home|residential|mailing|billing|postal|property)[ _-]?"
                                  r"address")
        # the street before its number: an optional short form (ul.) or street word (ulica), a capitalised name, up
        # to three more words (a lower-case street word too: Kalinova ulica, Prešernova cesta), a comma, the number
        _RX["value"] = re.compile(
            r"(?:[a-z]{1,4}\.\s|(?i:ulica|ulice|ulitsa|cesta|trg|utca|n[áa]m[ěe]st[íi]|prospekt|aleja|ul)\s)?"
            + _NAME_STEM + r"(?:\s(?:" + _NAME_STEM + r"|[" + _LO + r"]{2,15})){0,3}"
            r",?\s(\d{1,5})[A-Za-z]?(?:/\d{1,4})?")
    return _RX


# the names of products, tools and fillers that a test or a seed writes after an address label (Gate A of #49)
_NOT_A_STREET_NAME = _words("addresses/not-a-street")


def street_number_last(text: str, label_start: int, label_end: int, v: str, line: int) -> bool:
    """Whether a strong address label stands on the line before the label's end (at most 14 characters back) and `v`
    is a street before its number."""
    return bool(_rx()["label"].search(text, max(0, label_start - 14, line), label_end)) and street_number_last_ok(v)


def street_number_last_ok(v: str) -> bool:
    """The street before its number, as Eastern and Central Europe write it: `Kalinova ulica 17`, `Rivne Prospekt, 42`,
    `ul. Łąkowa 5`. Words of letters; one word of four letters and more that is no word of the word list, no product
    or filler name (Plan Basic 2, Kubernetes Ingress 2, Windows Server 2019, ABCD EFGH 12); none of the words of
    personal._NOT_AN_ADDRESS_RE. Without the word list the form is refused."""
    from .core import _word_set
    from .personal import _NOT_AN_ADDRESS_RE
    from .remote import PRODUCT_WORDS
    from .value_checks import _WORDS_OK
    m = _rx()["value"].fullmatch(v)
    if not m or not _WORDS_OK[0] or _NOT_AN_ADDRESS_RE.search(v):
        return False
    known = _word_set()
    words = re.findall(r"[^\W\d_]+", v[:m.start(1)])
    if any(w.lower() in _NOT_A_STREET_NAME or w.lower() in PRODUCT_WORDS for w in words):
        return False
    return any(len(w) >= 4 and w.lower() not in known for w in words)   # the form takes no word in capitals alone
