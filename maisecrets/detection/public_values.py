"""Values that have the shape of personal data but name no person (learned from Cloakroom 1.4.0's safe.py, Apache-2.0):
a bank number that is a run or one repeated digit, and a North American toll-free number. core.py drops a hit of
these types on such a value. A birth-date check for years more than 110 years ago was measured and left out: it
removed no false alarm on the full splits and cost five real birth dates. Kept out of personal.py, which is at the
size limit of a release file."""
from __future__ import annotations

import re

# NANP toll-free area codes in the NANP form (3-3-4, (8xx), a leading 1): business lines. Indian mobile numbers start
# with 8 too (88823 45671): a number in another grouping, or with region in active, stays a hit (Gate A)
_AREA = r"8(?:00|33|44|55|66|77|88)"
_TOLL_FREE_RE = re.compile(r"(?:\+?1[ .-]?)?(?:\(" + _AREA + r"\) ?|" + _AREA + r"[ .-])\d{3}[ .-]\d{4}")
_NUMBER_TYPES = ("US_BANK_NUMBER",)


def _run(digits: str) -> bool:
    """One digit repeated, or a run up or down (12345678, 98765432)."""
    if len(set(digits)) == 1:
        return True
    return digits in "0123456789012345678901234567890" or digits in "9876543210987654321098765432109"


def no_person_value(value: str, typ: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if typ in _NUMBER_TYPES and len(digits) >= 6 and _run(digits):
        return True
    if typ == "PHONE" and _TOLL_FREE_RE.fullmatch(value.strip()):
        from .core import _pii_regions_cached
        return "in" not in _pii_regions_cached()
    return False
