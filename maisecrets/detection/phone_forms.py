"""Two forms of a phone number that personal.py reads (moved here: personal.py is at the size limit of the release
tree). The international form without its + and the German call cue before `unter`."""
from __future__ import annotations

import re

from .lazy_regex import LazyRx as _LazyRx

# a call cue before a number in any country's grouping (#50, the gap to Cloakroom 1.4.0 on the V3 samples): `contact
# us at 0412 873 516`, `by phone at 06 47 83 92 15`, `fax us at 977-639211`, `call 61-3412-7788`. The tool channel
# only; personal._intl_after_cue judges the value (an IP, a date, a list of numbers stay text)
_PHONE_CUE_INTL_RE = _LazyRx(
    r"(?i)(?<![\w-])(?:call(?:ed|ing)?|dial(?:ed|ing)?|text(?:ed)?|fax(?:ed)?(?: \w{1,12}){0,2} (?:at|on|to)"
    r"|reach(?:ed)?(?: \w{1,12}){0,2} (?:at|on)|contact(?:ed)?(?: \w{1,15}){0,4} (?:at|on)"
    r"|(?:by|via) (?:phone|telephone|fax|mobile) (?:at|on)|the (?:phone|telephone|contact) number)"
    r"[ \t]{0,3}:?[ \t]{1,3}(\+?\(?\d{1,5}\)?(?:[ .\-]\d{1,8}){1,5})(?![\w+]|[.,/:-]\d)")

# a German call cue around `unter <number>`: erreichbar ab Montag unter 030 …, erreichbar Mo-Fr 9-17 Uhr unter …,
# rufen Sie uns an unter …, Rückrufe unter …, and the verb at the end: Sie können uns unter 030 … erreichen (ai-gateway
# #1764: a phone field that holds a sentence; #27). `unter` alone is no cue (Bestellung unter 030 …). `unter:` and
# `unter der Nummer` come before the value. The value starts with its trunk 0 or + (no date or count) and ends before
# a space and the 0 or + of a second number. The gap after a cue ends at the end of a sentence
_DE_CALL_REGIONS = frozenset({"de", "at", "ch"})
_DE_NUMBER = r"(?:\+|0)\d(?:[\d\-/]|[ \t](?=[1-9/\-])){4,19}\d"
_DE_END = r"(?![\w]|[.,:]\d)"
_DE_UNTER = r"(?<![\w-])unter(?:[ \t]*(?::|der[ \t]+(?:ruf|telefon|handy|mobil)?nummer))?[ \t]+"
_PHONE_DE_CUE_RE = _LazyRx(
    r"(?i)(?:(?<![\w-])(?:erreichbar|erreichen|anrufen|anzurufen|ruf(?:en)?\s+(?:sie|mich|uns|an)|rückruf\w*"
    r"|zurückrufen|zurückzurufen|melden\s+sie\s+sich|meldet\s+euch|kontaktieren)\b"
    r"(?:[^\n.;!?]|\.(?=\S)){0,40}?(?=" + _DE_UNTER + ")"
    r"|(?=" + _DE_UNTER + _DE_NUMBER + _DE_END + r"[^\n\d]{0,30}?(?<![\w-])(?:erreichen|erreichbar|anrufen|anzurufen"
    r"|zurückrufen|zurückzurufen|kontaktieren)\b))" + _DE_UNTER + "(" + _DE_NUMBER + ")" + _DE_END)
# a second number right after the first (unter 030 … 0171 …, unter 030 … oder 0171 …)
_PHONE_DE_NEXT_RE = _LazyRx(r"(?i)[ \t]*(?:,|;|oder|und)?[ \t]*(" + _DE_NUMBER + ")" + _DE_END)
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


# an IP and a date (year, day or month first) after a call cue are no phone number (#50)
_IPV4_SHAPE_RE = _LazyRx(r"\d{1,3}(?:\.\d{1,3}){3}")
_YMD_SPACED_RE = _LazyRx(r"(?:19|20)\d\d[ .\-/](?:0?[1-9]|1[0-2])[ .\-/](?:0?[1-9]|[12]\d|3[01])(?!\d)")
_MDY_SPACED_RE = _LazyRx(r"(?:0?[1-9]|1[0-2])[ .\-/](?:0?[1-9]|[12]\d|3[01])[ .\-/](?:19|20)\d\d(?!\d)")
_DMY_SPACED_RE = _LazyRx(r"(?:0?[1-9]|[12]\d|3[01])[ .\-/](?:0?[1-9]|1[0-2])[ .\-/](?:19|20)\d\d(?!\d)")


def intl_after_cue(text: str, out: list) -> list:
    """Any country's grouping after a call cue, in the tool channel (#50). The core drops a span that overlaps an
    earlier hit; a span already found is skipped here."""
    from .personal import PHONE, _NANP_SHAPE_RE, _national_phone_ok
    taken = {(a, b) for a, b, _, _ in out}
    for m in _PHONE_CUE_INTL_RE.finditer(text):
        v = m.group(1).rstrip(" .-/")
        span = (m.start(1), m.start(1) + len(v))
        if span in taken or not _national_phone_ok(v) or _not_a_number_after_cue(v):
            continue
        if _NANP_SHAPE_RE.fullmatch(v):
            continue   # a North American number is phone-us-national's and the loose cue's, with their region
        out.append((span[0], span[1], "phone-after-phone-word", PHONE))
    return out


def _not_a_number_after_cue(v: str) -> bool:
    """An IP, a date at the start (a time may follow), round numbers and a list of numbers after `call` or `contact …
    at` (Gate A of #50): an arithmetic run or doublings (05 10 15 20, 128 256 512), a one-digit group unless after +,
    pairs without their trunk 0 or with fewer than three distinct pairs, and without a trunk 0, + or ( more than
    four groups, four equal ones, or two of one length (but the Indian mobile 98765 43219)."""
    groups = re.findall(r"\d+", v)
    nums = [int(g) for g in groups]
    if _IPV4_SHAPE_RE.fullmatch(v) or any(rx.match(v) for rx in (_YMD_SPACED_RE, _DMY_SPACED_RE, _MDY_SPACED_RE)):
        return True
    if all(g.endswith("00") for g in groups) or (len(nums) >= 3 and (
            len({b - a for a, b in zip(nums, nums[1:])}) == 1 or all(b == 2 * a > 0 for a, b in zip(nums, nums[1:])))):
        return True
    if all(len(g) == 2 for g in groups):
        steps = {b - a for a, b in zip(nums, nums[1:])}
        return not v.startswith("0") or groups[0] == "00" or len(set(groups)) < 3 or steps <= {0, 1, -1}
    if not v.startswith("+") and any(len(g) == 1 for g in groups):
        return True
    if v.startswith(("+", "0", "(")):
        return False
    if len(groups) > 4 or (len(groups) == 4 and len({len(g) for g in groups}) == 1):
        return True
    if len(groups) == 2 and len(groups[0]) == len(groups[1]):
        a, b = groups
        return not (len(a) == 5 and a[0] in "6789" and abs(nums[0] - nums[1]) > 10)
    return False
