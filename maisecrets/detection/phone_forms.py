"""Two forms of a phone number that personal.py reads (moved here: personal.py is at the size limit of the release
tree). The international form without its + and the German call cue before `unter`."""
from __future__ import annotations

from .lazy_regex import LazyRx as _LazyRx

# a German call cue before `unter <number>`: erreichbar ab Montag unter 030 …, rufen Sie uns an unter …, bitte
# zurückrufen unter … (ai-gateway #1764: a phone field that holds a sentence). `unter` alone is no cue (Bestellung
# unter 030 …). The value starts with its trunk 0 or + (no date or count) and ends before a space and the 0 or + of a
# second number
_DE_CALL_REGIONS = frozenset({"de", "at", "ch"})
_PHONE_DE_CUE_RE = _LazyRx(r"(?i)(?<![\w-])(?:erreichbar|erreichen|anrufen|anzurufen|ruf(?:en)?\s+(?:sie|mich|uns|an)"
                           r"|rückruf|zurückrufen|zurückzurufen|melden\s+sie\s+sich|meldet\s+euch|kontaktieren)\b"
                           r"[^\n\d]{0,40}?(?<![\w-])unter[ \t]+((?:\+|0)\d(?:[\d\-/]|[ \t](?=[1-9/\-])){4,19}\d)"
                           r"(?![\w]|[.,:]\d)")
# a second number right after the first (unter 030 … 0171 …, unter 030 … oder 0171 …)
_PHONE_DE_NEXT_RE = _LazyRx(r"(?i)[ \t]*(?:,|;|oder|und)?[ \t]*((?:\+|0)\d(?:[\d\-/]|[ \t](?=[1-9/\-])){4,19}\d)"
                            r"(?![\w]|[.,:]\d)")
# the country calling codes of ITU-T E.164 in use, by their first digits: codes of 1 digit (1, 7), of 2 and of 3
_CC1 = frozenset("17")
_CC2 = frozenset({"20", "27", "30", "31", "32", "33", "34", "36", "39", "40", "41", "43", "44", "45", "46", "47", "48",
                  "49", "51", "52", "53", "54", "55", "56", "57", "58", "60", "61", "62", "63", "64", "65", "66", "81",
                  "82", "84", "86", "90", "91", "92", "93", "94", "95", "98"})
_CC3_HEADS = ("21", "22", "23", "24", "25", "26", "29", "35", "37", "38", "42", "50", "59", "67", "68", "69", "85",
              "87", "88", "96", "97", "99")


_DATE_HEAD_RE = _LazyRx(r"(?:19|20)\d\d(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])")


def _e164_without_plus(d: str) -> bool:
    """A number in its international form without its +, as an API stores it in a JSON number or a messenger id
    (49 and the subscriber digits): 11 to 15 digits after a country calling code in use, and in the North American
    plan (1) exactly 11. A timestamp in milliseconds (13 digits from 1) and a national number that lost its trunk 0
    (10 digits, as the seconds of a timestamp) stay no number (ai-gateway #1763)."""
    if not 11 <= len(d) <= 15 or d[0] == "0" or _DATE_HEAD_RE.match(d):
        return False   # a date in front is a timestamp: fax: 20261021120000 (YYYYMMDDhhmmss)
    if d[0] == "1":
        return len(d) == 11 and d[1] not in "01" and d[4] not in "01"   # NANP: area code and exchange from 2
    return d[0] in _CC1 or d[:2] in _CC2 or d[:2] in _CC3_HEADS
