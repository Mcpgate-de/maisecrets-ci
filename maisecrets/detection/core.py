"""Deterministic detection of secrets and PII in text.

Three rule sources, one scanner:

1. **betterleaks** (`rules/betterleaks.toml`, vendored, MIT, version in
   `rules/BETTERLEAKS_VERSION`): about 400 secret shapes with keywords and
   filters. Consumed as data; no betterleaks binary. The filters are Expr
   expressions, read by `rule_filter.py`; a rule whose filter is a program
   that module cannot read is left out. Refresh with
   `scripts/sync_betterleaks.py vX.Y.Z`. betterleaks is the successor of
   gitleaks.
2a. **Own secret rules** (`rules/own_secret_rules.json`, patterns derived from
   gitleaks v8.30.1, MIT): generic-api-key, to which the label filters below
   are tuned, and the token forms the betterleaks rules miss.
2. **Presidio** (`rules/presidio.json`, derived from Microsoft Presidio's
   pattern recognizers, MIT, version in `rules/PRESIDIO_VERSION`): country
   and generic PII shapes with scores and context words. Regions are
   opt-in (`pii_regions`, default `generic` + `de`). Checksum validators for
   the generic and the German types are ported below; the others keep
   their pattern score and need a context word. Refresh with
   `scripts/sync_presidio.py`.
3. **detect-secrets** (`rules/detect_secrets.json`, derived from Yelp
   detect-secrets' KeywordDetector and BasicAuthDetector, Apache-2.0, version
   in `rules/DETECT_SECRETS_VERSION`): credentials recognised by position
   (`password = …`, `api_key: "…"`, `user:pass@host`). Their heuristic
   filters (templated, indirect, sequential, dollar-prefixed) are ported.
4. **Own rules** (`OWN_RULES` below): what none of the three covers. Email
   stays ours (a bounded regex; the unbounded one took 11 s on an 80 KB
   dotted run), phone with a country code, `Bearer …` outside curl,
   `?api_key=…` in a URL, full-length GitLab runner and deploy tokens.

One detector, shared by every hook and every direction. Two detectors with
slightly different rules is how a redaction leaks.
"""
from __future__ import annotations

import base64 as _b64
import bisect
import contextvars
import itertools
import hashlib
import ipaddress
import json
import math
import re
import sys
import threading
import time
import warnings
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from . import checksums
from .lazy_regex import LazyRx as _LazyRx
from . import registry as _registry

RULES_DIR = Path(__file__).resolve().parent / "rules"


@dataclass(frozen=True)
class Match:
    kind: str      # rule id, e.g. "gitlab-pat" or "email"
    type: str      # placeholder type: SECRET, EMAIL, IBAN, CARD, IP, PHONE
    value: str     # the exact text to replace
    start: int
    end: int


class _Lazy:
    """A regex compiled on first use. Rule loading then costs a dict, not 265 compilations.

    A pattern with the class of CJK letters (_CJK) also has a form without it, for a text that holds no CJK letter:
    there the class matches nothing, and both forms find the same. The class made the compilation 5 to 8 times
    slower: 26 ms in each hook process for four rules (e-mail, phone, the two passwords in a sentence)."""
    __slots__ = ("pattern", "flags", "_rx", "_plain", "_plain_rx")

    def __init__(self, pattern: str, flags: int = 0) -> None:
        self.pattern, self.flags, self._rx, self._plain_rx = pattern, flags, None, None
        self._plain = _without_cjk(pattern) if isinstance(pattern, str) and _CJK in pattern else None

    def _get(self) -> re.Pattern[str]:
        if self._rx is None:
            self._rx = re.compile(self.pattern, self.flags)
        return self._rx

    def _for(self, text: str) -> re.Pattern[str]:
        if self._plain is None or _has_cjk(text):
            return self._get()
        if self._plain_rx is None:
            self._plain_rx = re.compile(self._plain, self.flags)
        return self._plain_rx

    def finditer(self, text: str):
        return self._for(text).finditer(text)

    def search(self, text: str):
        return self._for(text).search(text)

    @property
    def groups(self) -> int:
        return self._get().groups


@dataclass(frozen=True)
class Rule:
    """One rule of the detector. A caller makes one with user_rule() and reads the ones of Detector.rules(); it has no
    stable constructor. Of its fields only id, type, keywords and secret_group are promised; the others belong to the
    detector and can change in any version (docs/DETECTION.md, "The API")."""
    id: str
    type: str
    regex: _Lazy
    keywords: tuple[str, ...] = ()
    entropy: float = 0.0
    secret_group: int = 0
    allow_regexes: tuple[tuple[re.Pattern[str], str], ...] = ()   # (pattern, target: secret|match|line)
    stopwords: tuple[str, ...] = ()
    validator: str | None = None
    score: float = 1.0                 # presidio pattern score; 1.0 = shape alone is enough
    context: tuple[str, ...] = ()      # presidio context words; a nearby one lifts a weak score
    require_context: bool = False      # weak shape: accept only with a context word nearby
    whole_match: bool = False          # presidio: the entity is the whole match, never a sub-group
    quote_group: int = 0               # detect-secrets: group of the optional opening quote
    drop: object = None                # betterleaks: the rule's filter and the global one; True drops the finding
    key: str = ""                      # unique, from maisecrets/detection/registry.py: `<source>:<id>`; set by rules()
    form: str = ""                     # keyword | label | shape (registry.form_of); set by rules()
    matcher: str = ""                  # regex | lines | windowed | curl | list | literal | seed (registry.matcher_of)
    filters: frozenset | None = None   # the named checks after a hit (registry.filters_of); set by rules()
    region: str = "generic"            # the country of a regional or Presidio rule, set by its loader
    phase: int = 0                     # registry.PHASES: 1 the built-in rules, 3 the rules of your own; set by rules()


# ----------------------------------------------------------------- helpers --
def _re2_to_python(rx: str) -> str:
    """betterleaks (and gitleaks) regexes are RE2. Python differs in two spots we hit."""
    flags = ""
    if "(?i)" in rx:
        rx = rx.replace("(?i)", "")
        flags = "(?i)"
    for posix, chars in _POSIX_CLASSES.items():   # [[:alnum:]]: Python reads it as a set of the letters ":alnum"
        rx = rx.replace(posix, chars)
    return flags + rx.replace(r"\z", r"\Z")


_POSIX_CLASSES = {"[:alnum:]": "A-Za-z0-9", "[:alpha:]": "A-Za-z", "[:digit:]": "0-9", "[:xdigit:]": "0-9A-Fa-f",
                  "[:upper:]": "A-Z", "[:lower:]": "a-z", "[:word:]": "0-9A-Za-z_"}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


# The entropy of a value rises with its alphabet, so one floor of 3.5 judges a hex value and a base64 value alike:
# generic-api-key gets one floor per alphabet (the smallest of hex, base32, base62, base64, base64url that holds the
# value, else printable). From a fork (danszymkowiak/maisecrets 795b411, Apache-2.0, floors chosen on its bench);
# measured on CredData for 0.6.24 (docs/BENCHMARKS.md, "Rule classes"). Hex keeps 3.5: the fork's 3.449 caught only
# cipher test vectors of the left-out repository and one key, and it took a 32-digit revoked token in developer text
# A floor never rises above the old 3.5 (base32 and printable: a higher floor lost two Nemotron-PII secrets), and
# base64url keeps 3.5: kebab-case names with a digit read as keys under 3.426 (review of 0.6.24)
ENTROPY_BY_ALPHABET = {"hex": 3.5, "base32": 3.5, "base62": 3.322, "base64": 3.252, "base64url": 3.5,
                       "printable": 3.5}
ENTROPY_BY_ALPHABET_RULES = frozenset({"generic-api-key"})
_B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_ALPHABETS = (("hex", frozenset("0123456789abcdefABCDEF")), ("base32", frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")),
              ("base62", frozenset(_B62)), ("base64", frozenset(_B62 + "+/=")), ("base64url", frozenset(_B62 + "-_=")))


def alphabet_of(value: str) -> str:
    """The smallest of hex, base32, base62, base64, base64url that holds the value, else printable."""
    chars = set(value)
    return next((name for name, alpha in _ALPHABETS if chars <= alpha), "printable")


def _base64_of_text(v: str) -> bool:
    """base64 of printable text (`staging-user`, the `Password:` challenge of a mail server's AUTH LOGIN after
    `authentication failed:`), padded or not: an encoded word or name, not a key."""
    if len(v) % 4 == 1 or len(v) < 8:
        return False
    try:
        raw = _b64.b64decode(v + "=" * (-len(v) % 4), validate=True)
    except (ValueError, TypeError):
        return False
    return bool(raw) and all(32 <= b < 127 for b in raw)


def _entropy_ok(rule: Rule, secret: str, channel: str = "prompt") -> bool:
    if rule.id in ENTROPY_BY_ALPHABET_RULES:
        e = shannon_entropy(secret)
        if e >= 3.5:
            return True    # the old floor: a value it took stays a hit
        if channel != "tool":
            return False   # a typed prompt keeps 3.5: an identifier with a digit there is blocked, not masked
        return e >= ENTROPY_BY_ALPHABET[alphabet_of(secret)] and not _base64_of_text(secret)
    return not rule.entropy or shannon_entropy(secret) >= rule.entropy


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


# IBAN length per country (SWIFT IBAN registry). Only an IBAN in lower case is held to it: a hex digest in lower case
# such as `de12…` passes mod 97 one time in 97; an IBAN in capitals keeps the vendored check alone
IBAN_LENGTH = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BI": 27, "BR": 29,
    "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20, "EG": 29,
    "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
    "HN": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
    "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19,
    "MN": 20, "MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24, "PL": 28, "PS": 29,
    "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33, "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24,
    "SM": 27, "SO": 23, "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
    "YE": 30,
}


def _iban_ok(raw: str) -> bool:
    s = raw.replace(" ", "").replace("-", "").upper()   # the vendored pattern takes a space or a hyphen between groups
    if not 15 <= len(s) <= 34 or not s.isalnum():
        return False
    if raw != raw.upper() and IBAN_LENGTH.get(s[:2]) != len(s):
        return False
    rearranged = s[4:] + s[:4]
    return int("".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)) % 97 == 1


# public resolvers: a server every network uses, never a person's address
_RESOLVER_IPS = frozenset({"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
                           "208.67.222.222", "208.67.220.220", "2001:4860:4860::8888", "2001:4860:4860::8844",
                           "2606:4700:4700::1111", "2606:4700:4700::1001"})


def _public_ip(ip: str) -> bool:
    """An address that can name a person: global unicast. Private, loopback, link-local, shared (100.64/10), the
    documentation ranges (192.0.2.0/24, 2001:db8::/32 …), reserved, broadcast and multicast are not; the
    Python standard library's own docs and tests held 666 of them (measured 2026-09-29)."""
    if ":" in ip:
        if not (re.fullmatch(r"[0-9A-Fa-f:.]{7,45}", ip) and ip.count(":") >= 2):
            return False
    elif not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
        return False   # e.g. a CIDR tail the upstream regex swallowed
    if ":" not in ip:
        ip = ".".join(str(int(o)) for o in ip.split("."))   # 085.214.132.005 (final review, 2026-09-30)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    inner = getattr(addr, "sixtofour", None)
    if inner is not None:
        addr = inner    # 2002:55d6:8405::1 carries 85.214.132.5
    return addr.is_global and not addr.is_multicast and str(addr) not in _RESOLVER_IPS


def _de_tax_id_ok(v: str) -> bool:
    """Steuer-ID (IdNr, § 139b AO): eleven digits, the first never 0. In the first ten, exactly one digit occurs twice
    or three times and every other digit once at most; a digit that occurs three times never stands at three places
    in a row. The eleventh is the check digit, ISO 7064 MOD 11,10. Source: ITZBund, "KONZEPT Steueridentifikationsnummer
    (IdNr) nach § 139b AO", version 2.3 of 2016-03-01, section 1, and ELSTER, "Prüfung der Steuer- und
    Steueridentifikationsnummer", 2026-09-02, section 2.2. Presidio's "no digit more than three times" passed 8.7 % of
    random numbers; this rule passes 0.4 % (0.6.19)."""
    if len(v) != 11 or not v.isdigit() or v[0] == "0":
        return False
    digits = [int(d) for d in v]
    repeated = [(d, n) for d, n in Counter(digits[:10]).items() if n > 1]
    if len(repeated) != 1 or repeated[0][1] not in (2, 3):
        return False
    if repeated[0][1] == 3 and any(digits[i] == digits[i + 1] == digits[i + 2] for i in range(8)):
        return False
    product = 10
    for i in range(10):
        total = (digits[i] + product) % 10 or 10
        product = (total * 2) % 11
    check = 11 - product
    return (0 if check == 10 else check) == digits[10]


def _de_social_security_ok(v: str) -> bool:
    """Rentenversicherungsnummer, VKVV § 4 checksum plus birth-date ranges."""
    v = v.upper().replace(" ", "")
    if not re.fullmatch(r"\d{8}[A-Z]\d{3}", v):
        return False
    day, month = int(v[2:4]), int(v[4:6])
    if not (1 <= day <= 31 or 51 <= day <= 81) or not 1 <= month <= 12:
        return False
    letter = str(ord(v[8]) - ord("A") + 1).zfill(2)
    effective = v[:8] + letter + v[9:11]
    weights = [2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1]
    total = 0
    for ch, w in zip(effective, weights):
        prod = int(ch) * w
        total += prod // 10 + prod % 10
    return total % 10 == int(v[11])


def _de_health_insurance_ok(v: str) -> bool:
    v = v.upper().strip()
    if not re.fullmatch(r"[A-Z]\d{9}", v):
        return False
    effective = str(ord(v[0]) - ord("A") + 1).zfill(2) + v[1:9]
    total = 0
    for ch, f in zip(effective, (1, 2) * 5):
        prod = int(ch) * f
        total += prod // 10 + prod % 10 if prod >= 10 else prod
    return total % 10 == int(v[9])


def _de_lanr_ok(v: str) -> bool:
    v = v.strip()
    if len(v) != 9 or not v.isdigit():
        return False
    total = sum(int(d) * w for d, w in zip(v[:6], (4, 9, 4, 9, 4, 9)))
    return int(v[6]) == (10 - total % 10) % 10


def _de_vat_id_ok(v: str) -> bool:
    n = re.sub(r"[\s.\-]", "", v.upper())
    return len(n) == 11 and n.startswith("DE") and n[2:].isdigit()


# the decoded head of a PEM private key: the header, optional armour or encryption headers (PGP's Version:, the
# Proc-Type: and DEK-Info: of a legacy encrypted key), then base64 body characters (as many as the head holds, up to
# 16). A byte order mark may stand before the header
_B64_PEM_PRIVATE_RE = _LazyRx(rb"(?:\xef\xbb\xbf)?-----BEGIN (?P<kind>[A-Z0-9 ]{0,40})PRIVATE KEY(?: BLOCK)?"
                                 rb"-----\r?\n"
                                 rb"(?P<hdrs>(?:[A-Za-z][A-Za-z0-9-]{0,30}: [^\r\n]{0,200}\r?\n)*)(?:\r?\n)?"
                                 rb"(?P<body>[A-Za-z0-9+/]{16}|[A-Za-z0-9+/]{1,15}\Z)")
_OPENSSH_MAGIC = b"b3BlbnNzaC1rZXktdjE"   # base64 of "openssh-key-v1"


def _pem_body_ok(m) -> bool:
    """The body starts as a key does: DER (a SEQUENCE: "M"), the OpenSSH magic, a PGP packet (a tag byte of 0x80 or
    more), or anything after encryption headers (Proc-Type, a PGP armour header). Prose after a banner is no key
    (codex Gate A of 0.6.20)."""
    body, kind = m.group("body"), m.group("kind")
    if m.group("hdrs"):
        return True
    if kind.startswith(b"OPENSSH"):
        return _OPENSSH_MAGIC.startswith(body[:19]) if len(body) < 19 else body.startswith(_OPENSSH_MAGIC[:16])
    if kind.startswith(b"PGP"):
        return body[:1] in b"ghijklmnopqrstuvwxyz0123456789+/"
    return body[:1] == b"M"


# a further line of a wrapped base64 value: after a line break, or after an escaped one (\n in a JSON string)
_B64_LINE_RE = _LazyRx(r"(?:\r?\n|(?:\\r)?\\n)([ \t]*)([A-Za-z0-9+/]+={0,2})(?=[ \t]*(?:\r?\n|$)|[\"',;]|\\[rn])")
_B64_PEM_STARTS = ("LS0tLS1CRUdJTi", "77u/LS0tLS1CRUdJTi")


def _b64_needles(raw: bytes) -> tuple:
    """The base64 text of `raw` at each of the three byte alignments, cut to the characters that `raw` alone decides."""
    import base64
    out = []
    for k in range(3):
        enc = base64.b64encode(b"\0" * k + raw + b"\0\0").decode()
        out.append(enc[-(-8 * k // 6):8 * (k + len(raw)) // 6])
    return tuple(out)


_PRIVATE_KEY_NEEDLES = _b64_needles(b"PRIVATE KEY-----")   # a key later in a bundle (certificate, chain, key)


_PEM_END_RE = _LazyRx(rb"-----END [A-Z0-9 ]{1,60}-----\r?\n?\Z")


def _pem_ended(lines: list) -> bool:
    """Whether the base64 lines so far (each of a width that is a multiple of 4) decode to the end of a PEM block."""
    import base64
    try:
        return _PEM_END_RE.search(base64.b64decode("".join(lines[-2:]), validate=True)) is not None
    except ValueError:
        return False


def _base64_wrapped_end(text: str, start: int, end: int) -> int:
    """The end of a base64 value that `base64` or openssl wrapped at a fixed width. text[start:end] is its first
    line; each further line holds base64 alone and has the width of the first, the last may be shorter. A line of
    another width, a line that starts a new value, or any other text ends the value, and so does a full line that
    decodes to the end of a PEM block (a shorter line after it is the next text: codex Gate A of 0.6.20). A first
    line longer than 120 characters is no wrapped line (the tools wrap at 64 or 76), and one that ends in padding is
    the whole value."""
    width = end - start
    if width > 120 or text[end - 1] == "=":
        return end
    lines = [text[start:end]]   # the last two lines only: a value can be megabytes long
    while True:
        m = _B64_LINE_RE.match(text, end)
        if not m or len(m.group(2)) > width or m.group(2).startswith(_B64_PEM_STARTS):
            return end
        if len(m.group(2)) < width and width % 4 == 0 and _pem_ended(lines):
            return end
        end = m.end(2)
        lines = [lines[-1], m.group(2)]
        if len(m.group(2)) < width or m.group(2).endswith("="):
            return end


def _base64_pem_ok(v: str) -> bool:
    """A base64 value whose decoded start is the header of a PEM private key and its first body characters (a
    Kubernetes Secret's tls.key or ssh-privatekey), or a bundle that holds one later. Only the first 400 characters
    are decoded: the value can be megabytes long."""
    import base64
    flat = "".join(v.replace("\\r", "").replace("\\n", "").split())
    head = flat[:400]
    try:
        raw = base64.b64decode(head[:len(head) // 4 * 4], validate=True)
    except ValueError:
        return False
    m = _B64_PEM_PRIVATE_RE.match(raw)
    if m:
        return _pem_body_ok(m)
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]   # a byte order mark before a bundle (codex Gate A of 0.6.20)
    if not raw.startswith(b"-----BEGIN "):
        return False
    for needle in _PRIVATE_KEY_NEEDLES:   # a bundle: decode around each "PRIVATE KEY-----" (the footer has one too)
        i, seen = flat.find(needle), 0
        while i >= 0 and seen < 50:
            a = max(0, i // 4 * 4 - 80)
            window = flat[a:a + 320]   # room for Proc-Type and DEK-Info before the body (Gate B, round 2)
            try:
                inner = _B64_PEM_PRIVATE_RE.search(base64.b64decode(window[:len(window) // 4 * 4], validate=True))
                if inner and _pem_body_ok(inner):
                    return True
            except ValueError:
                pass
            i, seen = flat.find(needle, i + 1), seen + 1
    return False


def _us_ssn_ok(v: str) -> bool:
    """Presidio's UsSsnRecognizer.invalidate_result (microsoft/presidio 8c98180a46, the last change of
    us_ssn_recognizer.py on main as of 2026-10-11), ported: mixed delimiters,
    one digit repeated, a group of zeros, area 000 or 666, or one of the published sample numbers is no SSN. The
    vendored rule had no validator, so `000-00-0000` in a form was a hit (public benchmark, 2026-10-11)."""
    if len({c for c in v if c in ".- "}) > 1:
        return False
    d = "".join(c for c in v if c.isdigit())
    if not d or len(set(d)) == 1:
        return False
    if d[3:5] == "00" or d[5:] == "0000" or d[:3] in ("000", "666"):
        return False
    return d not in ("1234" + "56789", "9876" + "54320", "0780" + "51120")


_DS_TEMPLATED = _LazyRx(r"^(\{\{.*\}\}|\$\{.*\}|<.*>|%.*%|\$[A-Za-z_][A-Za-z0-9_]*)$")
_DS_INDIRECT = _LazyRx(r"^[A-Za-z_][A-Za-z0-9_.]*\s*(\(.*\)|\[.*\])$")
# words joined by `.`, `_` or `-`, optionally ending where the regex cut the line (`:` of a
# condition, `;` of a statement, `[` before a quoted key): `settings.API_KEY`, `self._password`,
# `os.environ[`, `confirm_password:` were taken for values (false-positive corpus, 2026-09-27)
_DS_REFERENCE = _LazyRx(r"_*[A-Za-z]+(?:(?:\?\.|[._/:-]+)#?[A-Za-z]+)+_*\??[:;\[]?")
_FORMAT_ONLY_RE = _LazyRx(r"(?:%[-+ #0]*\d*(?:\.\d+)?[sdifxXeEgGrcoba%]|\{[^{}]*\}|[^A-Za-z0-9%{])+")


# a short glued value that is a type or a keyword of code or config, or a camelCase identifier:
# password:string, {token:number}, secret=config, api_key=apiKey, auth_token=Bearer (final review,
# 2026-09-28: the 6-character floor for glued values took these for secrets)
_SHORT_WORDS = frozenset({
    "string", "number", "boolean", "object", "integer", "bigint", "symbol", "unknown", "config", "bearer", "secret",
    "tokens", "hidden", "masked", "optional", "default", "require", "undefined", "double", "decimal", "varchar",
    "binary", "buffer", "array", "values", "string[]", "never", "nullable", "boolean[]", "option", "settings",
    "private", "public", "enabled", "disabled", "secretstr", "secretbytes", "securestring"})
_CAMEL_RE = _LazyRx(r"^[a-z]+(?:[A-Z][a-z0-9]*)+$")
# the review of 2026-09-29 (679 snippets of normal work): the next label taken for the value (`DB_PASSWORD=` then
# `API_KEY=`), a generic type (`Option<String>`), a UUID, and a fixture that names itself (`testpass`, `secret123`,
# `Passw0rd!`: letters after undoing the digits and symbols people use for them)
_LABEL_SHAPE = _LazyRx(r"[A-Za-z_][\w.-]*[:=]")
_NAME_LABEL_RE = _LazyRx(r"(?:[A-Z][A-Z0-9_]*|[a-z][a-z0-9_]*|[A-Z][a-z]+(?:[ _-][A-Za-z][a-z]+)*"
                            r"|[a-z]{2,}(?:[A-Z][a-z]{2,})+|[A-Za-z][a-z0-9]+(?:[A-Z][a-z0-9]{2,})*(?:[A-Z][a-z0-9]{2,}|[A-Z]{2,}|[A-Z][a-z0-9]))[.-]?[:=]")
_GENERIC_TYPE = _LazyRx(r"<[A-Za-z_][\w, ]*>")
_VERSION_RE = _LazyRx(r"v?\d+(?:\.\d+){1,3}(?:[-+.]?[A-Za-z0-9]+)?")
_PART_TEMPLATE_RE = _LazyRx(r"\{[A-Za-z_][\w.]*(?:\[[^\]]*\]?)?\}?$|\{[A-Za-z_][\w.]*\}")
_SHELL_EXPANSION_RE = _LazyRx(r"[?:+=-]{1,2}[A-Z_][A-Z0-9_]*")
# the names of anchors and tags are lower case (&creds_2024, &gitlab_token_fields, !vault, !!str); a value with
# capitals after & or ! is a password (&Xk9v2Qm7…, !Passw0rd…; review of b4a7c54)
_ANCHOR_OR_TAG_RE = _LazyRx(r"[&*][a-z_][a-z0-9_-]*|!!?[a-z][a-z0-9_/-]*")
_PATH_IN_VALUE_RE = _LazyRx(r"(?:^|\s)(?:~|\.{1,2})?/[\w.-]+/[\w.-]+")
_ESCAPED_TAIL_RE = _LazyRx(r"(?:\\[nrt])+$")
_SUBSCRIPT_RE = _LazyRx(r"[A-Za-z_][\w.]*\[[\w.,\s]*\]?")
_GLOB_RE = _LazyRx(r"[:/._-]\*$|^\*\.\w+$|/\*[/.]")   # token:*, *.py, logs/*.txt; a star inside a value stays
_NUMBER_RE = _LazyRx(r"\d{1,3}(?:_\d{3})+|\d+(?:_\d+)+")
_PRIVATE_NAME_RE = _LazyRx(r"_[A-Za-z][A-Za-z_]*")
_EMAIL_VALUE_RE = _LazyRx(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_UUID_RE = _LazyRx(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_FIXTURE_WORD = _LazyRx(r"passwor[dt]|passw|pass(?![a-z])|(?<![a-z])pass|secret|token|test|geheim|kennwort")
_LEET = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "$": "s", "@": "a", "1": "i", "!": "i", "|": "l",
                       "7": "t"})


def _deleet(v: str) -> str:
    return v.lower().translate(_LEET)


# the words a fixture is made of around its fixture word: mypassword, wrongpassword, SuperSecret1, rootpass,
# sk_test_123. Longest first, so that `password` is taken before `pass`
_FIXTURE_PARTS = _LazyRx("|".join(sorted((
    "password", "passwort", "passwd", "passw", "pass", "secret", "token", "testing", "test", "geheim", "kennwort",
    "key", "my", "new", "old", "wrong", "bad", "top", "super", "very", "not", "so", "dummy", "fake", "default",
    "admin", "user", "root", "db", "dev", "local", "sample", "example", "secure", "strong", "weak", "correct",
    "valid", "invalid", "other", "some", "your", "the", "sk", "pk", "cs", "rk", "tok", "api", "app", "mock",
    "demo"), key=len, reverse=True)))


def _names_itself(v: str) -> bool:
    """testpass, secret123, Passw0rd!, wrongpassword, SuperSecret1: a fixture word, the words a fixture is made of,
    and at most one other letter. A real password that holds a fixture word keeps a word of its own: Contest-Winter,
    Passion, Latest, Geheimnis, Passatwagen (review, 2026-09-29). Only letters of the value count, not the letters
    that undoing 0, 1, 3 gave."""
    d = _deleet(v)
    if not _FIXTURE_WORD.search(d):
        return False
    covered = [False] * len(d)
    for m in _FIXTURE_PARTS.finditer(d):
        for i in range(m.start(), m.end()):
            covered[i] = True
    return sum(1 for i, c in enumerate(v) if c.isalpha() and not covered[i]) <= 1


_IDENT_WORDS = frozenset({"password", "passwort", "token", "secret", "key", "value", "default", "config", "env",
                          "setting", "settings", "credential", "credentials", "auth", "api", "get", "set", "new", "old",
                          "user", "admin", "current", "stored", "hashed", "encrypted", "load", "read", "fetch",
                          "extract", "parse", "resolve", "build", "create", "from", "to", "with", "vault", "request",
                          "header", "environment", "variable", "store"})


def _short_word(v: str) -> bool:
    w = v.strip().rstrip(",;})]")
    if w.lower() in _SHORT_WORDS:
        return True
    if not _CAMEL_RE.match(w):
        return False
    words = [x.lower() for x in re.findall(r"[A-Z]?[a-z0-9]+", w)]
    # correctHorseBatteryStaple is a passphrase (final review, 2026-09-30)
    return len(words) <= 3 or any(x in _IDENT_WORDS for x in words)


def _ds_value_ok(v: str, min_len: int = 8) -> bool:
    """Port of detect-secrets' heuristic filters for keyword hits."""
    v = v.strip()
    if len(v) < min_len or len(v) > 256:
        return False
    if _DS_TEMPLATED.match(v) or _DS_INDIRECT.match(v):
        return False
    if v.startswith("-----BEGIN"):
        # the armour of a PEM block after a label (`Закрытый ключ: -----BEGIN …`, `password: -----BEGIN …`): the
        # private-key rule takes the whole block, and the cut value took its first ten characters instead
        return False
    if _GENERIC_TYPE.search(v):
        return False   # a generic type: Option<String>, Secret<String>
    if _VERSION_RE.fullmatch(v):
        return False   # a version pin: tokenizers==0.20.3 (requirements.txt, renovate.json)
    if _PART_TEMPLATE_RE.search(v) and not any(c.isdigit() for c in _PART_TEMPLATE_RE.sub("", v)):
        return False   # a template with a name in it: mcp_{user}, {body['transfer_id']}
    if _SHELL_EXPANSION_RE.fullmatch(v) or _PATH_IN_VALUE_RE.search(v):
        return False   # ${REDIS_PASSWORD:?…} cut after its name, a YAML anchor, a command with a path
    if not any(c.isdigit() for c in v) and _DS_REFERENCE.fullmatch(_ESCAPED_TAIL_RE.sub("", v).rstrip("})],;")):
        return False   # process.env.NOTION_CLIENT_SECRET,\n in a JSON string
    if _SUBSCRIPT_RE.fullmatch(v) or _NUMBER_RE.fullmatch(v) or _GLOB_RE.search(v):
        return False   # list[str], 1_234_567, chatgpt_access_token:* (the ai-gateway repository, 2026-09-29)
    if not any(c.isdigit() for c in v) and _DS_REFERENCE.fullmatch(v.rstrip("})],;")):
        return False   # a reference before a closing bracket: no-check}
    if _PRIVATE_NAME_RE.fullmatch(v):
        return False   # a private name: security_token_cleanup = _cleanup_tokens
    if _EMAIL_VALUE_RE.fullmatch(v):
        return False   # an address after a label (user_tokens:<address>): the e-mail rule decides, not a secret
    if _names_itself(v):
        return False   # a value that names itself a password, a secret, a token or a test is a fixture
    if re.match(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?(?![\w])|\$\$\{?[A-Z_][A-Z0-9_]*\}?(?![\w])", v):
        return False   # a shell variable: $PASSWORD, ${DB_PASSWORD}; $$NAME in docker compose (upper case only)
    if "(" in v or ")" in v or "`" in v or "|" in v:
        return False   # a call, an expression or markdown (`re.compile(r"…`, "`/maisecrets:report` |"), not a value
    if not any(c.isalnum() for c in v):
        return False
    if "***" in v or "\u2022\u2022" in v:
        return False   # a mask as a prompt echoes it: "Password: *******" (Python standard library, 2026-09-29)
    if _FORMAT_ONLY_RE.fullmatch(v):
        return False   # a format string: token_range = "%d,%d-%d,%d:" (Python standard library, 2026-09-29)
    if v.count(" ") >= 2:
        return False   # a sentence or an i18n label ("Add API key"), not a value
    if " " in v and not any(c.isdigit() for c in v):
        return False   # two words of prose ("bad payload"), not a value
    if not any(c.isdigit() for c in v) and (_DS_REFERENCE.fullmatch(v) or (
            v.rstrip(";").endswith("!") and "." in v and _DS_REFERENCE.fullmatch(v.rstrip(";")[:-1]))):
        return False   # a reference: NAME_OF_SECRET, self._password, os.environ[, opts.password! (TypeScript)
    if not any(c.isdigit() for c in v) and _short_word(v):
        return False   # a type, a keyword of code or a camelCase identifier, at any length (settings, tokenValue)
    low = v.lower().rstrip(";")
    if low in {"password", "changeme", "placeholder", "example", "none", "null", "true", "false", "redacted"}:
        return False
    # sequential strings (abcdef…, 123456…) and one repeated character (********, xxxxxxxx);
    # two distinct characters after a label are a value (`password:asasasas…`, field report,
    # 2026-09-27: `<= 2` dropped it as filler)
    if len(set(low)) <= 1:
        return False
    if all(ord(low[i + 1]) - ord(low[i]) == 1 for i in range(len(low) - 1)):
        return False
    if _references().names_a_key(low):
        return False   # a reference of the caller's form, not a value
    return True


_LOWER_WORDS_RE = _LazyRx(r"[a-z0-9]+(?:[-_.][a-z0-9]+)*")


_MARKER_RE = _LazyRx(r"\[[^\]]*\]|<[^>]*>|\{[^}]*\}")
# values the new label paths of 0.6.15 read that hold no password (release review of 0.6.15, Gate B): a date or a
# timestamp (passwordLastChanged, AUTH 2024-10-13), a file a tool reads (--password @/run/secrets/pw), a template
# variable a build fills (-p@MYSQL_PWD@), a placeholder to replace (CHANGE_ME_2024). The ds rules keep their own filter
_LABEL_NOT_A_VALUE_RE = _LazyRx(
    r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?"
    r"|@[~.]?/[^\s]*|@[A-Za-z_][A-Za-z0-9_]*@"
    r"|(?i:change[_-]?me)(?:[_-]?[A-Za-z0-9]+)*")


def _label_value_ok(v: str) -> bool:
    # the whole value, its last character too: `2024-10-13!` is a password, no date (codex, verification of 0.6.15).
    # The prose rule ends its value before the punctuation of the sentence, so it needs no strip here
    return not _LABEL_NOT_A_VALUE_RE.fullmatch(v.strip())


def _word_value_ok(v: str, min_len: int = 8, prose_punct: bool = False) -> bool:
    """A value after a label with no `=` or `:` (a CLI flag, Redis AUTH, netrc): as _ds_value_ok, and not letters
    only. Docs write `--password argument`, `AUTH LOGIN`, `--password PASSWORD`; a password of letters alone after such
    a label stays a gap, as it is after the colon forms below 8 characters. A marker a log wrote (`[REDACTED]`,
    `<pw>`, `{password}`) and a Windows path (a backslash) are no value (round 2 of 0.6.15). With prose_punct (the CLI
    flag in a typed sentence) the punctuation after a word is no part of it: "give --password explicitly?" is a
    question (Gate B of 0.6.15); after AUTH or in a netrc, `Sommerurlaub!` stays a value."""
    w = v.strip()
    if _MARKER_RE.fullmatch(w) or w[:1] in "[{<" or "\\" in w:   # the flag regex ends a value at ]: [REDACTED
        return False
    if not _label_value_ok(w):
        return False
    core = w.rstrip(".,;:!?)") if prose_punct else w
    return _ds_value_ok(v, min_len=min_len) and not core.isalpha()


# prose about a password, not one: a hyphen compound whose last part says what was done to it (SHA256-hashed,
# AES-256-encrypted, 1Password-managed, OWASP-ASVS-4.0-compliant), and names of algorithms, encodings and standards
# with their numbers and versions (PBKDF2-SHA256, ISO-8859-1, UTF-16LE, WPA2-PSK, Argon2id-v19, RFC-7617, ARGON2ID).
# A compound with a word of its own stays a value: Xk9-q2-secret, Winter-2024-berlin, Sha256-2024! (round 2)
_PROSE_LAST = frozenset({
    "hashed", "encrypted", "encoded", "decoded", "managed", "protected", "enabled", "disabled", "signed", "salted",
    "compliant", "based", "derived", "generated", "stored", "secured", "wrapped", "rotated", "required", "enforced",
    "backed", "verified", "validated", "compatible", "formatted", "only", "free", "safe", "aware", "style", "format",
    "encryption", "hashing", "encoding"})
_VERSION_PART_RE = _LazyRx(r"v?\d+(?:\.\d+)*")
_ALGORITHM_PARTS = frozenset({
    "md5", "sha1", "sha2", "sha3", "sha224", "sha256", "sha384", "sha512", "pbkdf2", "bcrypt", "scrypt", "argon2",
    "argon2i", "argon2d", "argon2id", "aes", "aes128", "aes192", "aes256", "gcm", "cbc", "ctr", "rsa", "hmac", "des",
    "3des", "blake2b", "blake2s", "blake3", "sha", "crypt", "ntlm", "ntlmv2", "chacha20", "poly1305", "ecdsa",
    "ed25519", "x25519", "pkcs1", "pkcs5", "pkcs8", "pkcs12", "oaep", "pss",
    "iso", "utf", "utf8", "utf16", "utf16le", "utf16be", "utf32", "16le", "16be", "latin1", "cp1252", "ascii",
    "base64", "base32", "hex", "wpa", "wpa2", "wpa3", "psk", "sae", "eap", "tls", "ssl", "rfc", "owasp", "asvs", "nist",
    "fips", "scram", "chap", "totp", "hotp", "kerberos", "x509", "plus", "jwt", "jwe", "jws", "oauth", "oauth2"})


def _prose_word(v: str) -> bool:
    parts = v.lower().split("-")
    if len(parts) >= 2 and parts[-1] in _PROSE_LAST:
        return True
    names = [x for x in parts if not _VERSION_PART_RE.fullmatch(x)]
    return bool(names) and all(x in _ALGORITHM_PARTS for x in names)


def _prose_value_ok(v: str) -> bool:
    """`my password is <value>`: no word of a sentence. A letter and a digit must be in it, and a capital or a
    symbol beyond - _ .: `incorrect`, `base64-encoded`, `hunter2`, `valid.\\n@param` (an escaped line break in
    generated docs) are prose; the shapes `Aa9#aA9a` and `aAA%aAA9A` are values."""
    v = v.strip()
    return (_word_value_ok(v) and not _LOWER_WORDS_RE.fullmatch(v) and "\\" not in v and not _prose_word(v)
            and any(c.isdigit() for c in v) and any(c.isalpha() for c in v))


# one word, a number and at most one sign: the example of a weak password that docs and prompts write in a sentence
# ("The password is Hunter2!", "Das Passwort ist Sommer2024!", tests/fp_corpus.py). After `:` or `=` the label rules
# still take it (_pw_literal_ok); in a sentence it stays text. Two words or a word of no list (Hafen7Kran) are values
_EXAMPLE_PASSWORD_RE = _LazyRx(r"([^\W\d_]{3,})\d{1,4}[^\w\s]?")
# the word for password itself before a number (Passwort1, Salasana1, Haslo2024) is an example in every language, and
# so are the German words of example passwords that the English list lacks (Willkommen1, Hallo123!, Init1234)
_PW_WORD_EXAMPLES = frozenset({"willkommen", "hallo", "init", "start", "geheim", "passwort", "kennwort", "salasana",
                               "hasło", "haslo", "heslo", "senha", "wachtwoord",
                               "passord", "lösenord", "losenord", "adgangskode", "kodeord", "şifre", "sifre",
                               "parola", "contraseña", "contrasena"})


def _example_password(v: str) -> bool:
    m = _EXAMPLE_PASSWORD_RE.fullmatch(v)
    if not m:
        return False
    word = m.group(1).lower()
    return word in _PW_WORD_EXAMPLES or (word.isascii() and word in _word_set())


# a participle or a noun of any language after a name and a number: SHA256-gehasht, Base64-kodiert, AES256-cifrada,
# 2FA-geschützt, SHA256-hash. The parts before it are names with digits or capitals; the last part is a small word
_COMPOUND_PROSE_RE = _LazyRx(r"(?:[A-Za-z]*\d{2,}|\d*[A-Z]{2,}\d*)(?:-(?:[A-Za-z]*\d{2,}|\d*[A-Z]{2,}\d*))*"
                                r"-[^\W\d_A-Z][^\W\d_]{2,}")


_MD_ESCAPE_RE = _LazyRx(r"\\(?=[^\w\s])")


def _sentence_value_ok(v: str) -> bool:
    """A value after a password word and a copula (label-password-after-word): as the prose rule, no example of a weak
    password, and no participle after a name ("Das Passwort ist SHA256-gehasht")."""
    v = v.strip()
    # a Markdown escape before a sign (\*, \$) is no escaped line break of generated docs (valid.\n): judge the sign
    return (_prose_value_ok(_MD_ESCAPE_RE.sub("", v)) and not _example_password(v)
            and not _COMPOUND_PROSE_RE.fullmatch(v))


# one word of any language and a short number: Version2, Schritt2, Kapitel4, Mandant3, Kerberos5 after a space
# (Mausi1234 and Bergsee1987! are passwords)
_WORD_NUMBER_ANY_RE = _LazyRx(r"[^\W\d_][^\W\d_A-Z\u00c4\u00d6\u00dc]{2,}\d{1,2}")


# an id or a reference: a ticket (PBE-3403, #PR-1234), a CVE, a standard and its year (BSI-C5:2020, A07:2021,
# NIST-800-63B, OWASP-ASVS4), a character class (A-Za-z0-9)
_TICKET_ID_RE = _LazyRx(r"#?(?:[A-Za-z][A-Za-z0-9]{1,9}-\d{1,7}|[A-Z]{2,}\d*(?:-(?:[A-Z0-9]+|[A-Z][a-z]{0,3}\d+))+"
                           r"(?::\d{4})?|[A-Z]{2,}\d+"
                           r"|[A-Z]\d{1,3}:\d{4})|(?:.*(?:a-z|A-Z|0-9)){2}.*")
# signs that a sentence after a password word uses for a rule, a range or a pattern: /, >=, ≥, ≤, [, ^, $
_RULE_SIGNS_RE = _LazyRx(r"[/<>\u2264\u2265\[\]^$]")


def _spaced_value_ok(v: str) -> bool:
    """A value after a password word and only a space, an arrow, a dash or a parenthesis (label-password-after-space):
    as after a copula, it starts with a letter or a digit, and it is no run of English words, no id and no rule.
    "Passwort SHA256-Hash", "password iPhone15", "password (PBE-3403)", "Passwort #1-Fehler" and "Passwort (Länge≥12)"
    are prose; a passphrase of English words or a value that starts with a sign needs a `:` or a copula here."""
    v = v.strip()
    return (_sentence_value_ok(v) and v[:1].isalnum() and not _TICKET_ID_RE.fullmatch(v)
            and not _WORD_NUMBER_ANY_RE.fullmatch(v) and not _RULE_SIGNS_RE.search(v) and _wordlike(v) < 0.6)


_DIGEST_PREFIX_RE = _LazyRx(r"(?i)(?:sha\d*|md5|blake\w*|h1)[-:]")
# words and numbers run together: ProdDbPassword2024Rotated, Authentication123, SECRET_NAME_2024. A word has two
# letters at least; a random key has a lone letter (a capital before a digit, a small letter between digits) in it
_WORDS_RUN_RE = _LazyRx(r"(?:[A-Z][a-z]+|[a-z]{2,}|[A-Z]{2,}(?![a-z])|\d+|[_.-])+")


def _keylike(v: str) -> bool:
    """A capital, a small letter and a digit, and not words run together."""
    return (any(c.isupper() for c in v) and any(c.islower() for c in v) and any(c.isdigit() for c in v)
            and not _WORDS_RUN_RE.fullmatch(v))


def _hex_of_text(v: str) -> bool:
    """Hex of printable text: an encoded name or an encoded token, which the tool channel decodes and judges itself."""
    if len(v) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", v):
        return False
    raw = bytes.fromhex(v)
    return all(32 <= b < 127 for b in raw)


def _prose_key_value_ok(v: str) -> bool:
    """A value after a key word in a sentence (label-prose-key): "Use the API key <value> for the call." The sentence
    says less than `api_key=`, so only a random shape: a UUID, hex with a digit and a letter, or a value of letters
    and digits with no run of words (_keylike, or entropy 3.5 and words cover less than half). Not a path, not a
    template (YOUR_API_KEY has no digit), not a version or a dotted name."""
    v = v.strip()
    if _UUID_RE.fullmatch(v):
        return len(set(v.replace("-", ""))) > 6
    if not any(c.isdigit() for c in v) or not any(c.isalpha() for c in v) or _PATH_SEGMENT_RE.search(v):
        return False
    if _base64_of_text(v) or _hex_of_text(v):
        return False   # base64 or hex of text: `id:key` of an Elasticsearch ApiKey in docs, an encoded name
    if re.fullmatch(r"[0-9a-fA-F]+", v):   # 48 hex digits are left to secret-hex48-after-token-word (personal.py)
        return 20 <= len(v) != 48 and len(set(v.lower())) > 6
    return (_keylike(v) or shannon_entropy(v) >= 3.5) and _wordlike(v) < 0.5   # PaymentsServiceV2Prod is words


# values in a list of secrets that are no key: a password hash, a name with a scheme (arn:aws:…, urn:…)
# ($2b$…, $argon2id$…), an Ethereum address (0x and 40 hex), an id with a type prefix (pm_…, sess_…, cus_…). Hex
# alone and base58 stay values here: every label of label-secret-list names secrets (a commit, an ObjectId or a
# Solana mint sits in a list of tokens or ids, which the rule does not read; a base58 check lost 12 % of random keys)
_LIST_NOT_A_KEY_RE = _LazyRx(r"\$[\w-]+\$.*|[a-z][\w+.-]*:.*|0x[0-9a-fA-F]+|[a-z]{2,6}_[A-Za-z0-9_-]+")
# a path has a segment of small letters between slashes (base64 has a slash too, but rarely a word between two)
_PATH_SEGMENT_RE = _LazyRx(r"(?:^|/)[a-z][a-z_.-]{2,}/")
# a word part: two small letters or more after an optional capital, or three capitals or more; it counts as a word
# when it has a vowel (and three letters, unless all small)
_WORD_PART_RE = _LazyRx(r"[A-Z]?[a-z]{2,}|[A-Z]{3,}")
_VOWEL_RE = _LazyRx(r"[aeiouyAEIOUY]")


def _word_shaped(v: str) -> bool:
    """Words make up 60 % of the value or more: TokenizerPiece2024X, iPhone15ProMax, convertToUTF8String. Measured on
    random keys of 16 to 64 characters (base64): 2.6 % are word-shaped by this test."""
    words = (w for w in _WORD_PART_RE.findall(v) if _VOWEL_RE.search(w) and (len(w) >= 3 or w.islower()))
    return sum(len(w) for w in words) >= 0.6 * len(v)


def _list_value_ok(v: str) -> bool:
    """A value in a list after a secret label (label-secret-list): hex of 16 or more with a letter and a digit, or 16
    or more characters that _keylike takes and that are not word-shaped. A path, a password hash, a name with a
    scheme, an address, a typed id, a digest with its algorithm and a filler are no key. Cheap
    checks first: this runs on each value of a list before the filters of scan()."""
    v = v.strip()
    if len(v) < 16 or " " in v or _LIST_NOT_A_KEY_RE.fullmatch(v) or _DIGEST_PREFIX_RE.match(v):
        return False
    if _PATH_SEGMENT_RE.search(v):   # projects/p/secrets/db, secret/data/app, /run/secrets/x
        return False
    if shannon_entropy(v) < 2.5:
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", v):
        ok = any(c.isdigit() for c in v) and any(c.isalpha() for c in v)
    else:
        ok = _keylike(v) and not _word_shaped(v)
    return ok and _ds_value_ok(v, min_len=16)


def _apikey_value_ok(v: str) -> bool:
    """The value after `Authorization: ApiKey`: base64 or base64url (Elasticsearch, Kibana) that decodes to `id:key`,
    both parts not empty and printable. Docs write `ApiKey <base64-encoded id:key>`, `ApiKey ${ES_API_KEY}` and
    `ApiKey YOUR_ENCODED_API_KEY`, which decode to nothing of that form."""
    import base64
    import binascii
    raw = v.strip()
    padded = raw + "=" * (-len(raw) % 4)
    for alt in (None, b"-_"):
        try:
            dec = base64.b64decode(padded, altchars=alt, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            txt = dec.decode("utf-8")
        except UnicodeDecodeError:
            continue
        ident, sep, key = txt.partition(":")
        if sep and ident and key and txt.isprintable() and " " not in txt:
            return True
    return False


# ------------------------------------------------------- label and literal value --
# A password label and a literal value that is no word: `db_password = "<value>"`, `<password><value></password>`,
# `?pwd=<value>`, `IDENTIFIED BY '<value>'`, `ConvertTo-SecureString '<value>'`. The label is read from a frozen list
# of label words; the value must be no word of English or of developer text after undoing leet (P4ssw0rd is a word),
# which keeps `password = "changeme"`, `password: hunter`, `password = os.environ[...]` and `password: ${DB_PASS}`
# text. Word-likeness and the label word classes follow Dan Szymkowiak's backlog ideas (TASK-11.22, TASK-11.23).
# Measured on CredData without repository 2ba83c6a (split by repository: discovery half, validation half).
_WORDS_FILE = "words_en.txt"   # SCOWL en_US 60, 4 to 8 letters (rules/LICENSE-scowl, scripts/sync_words.py)
_WORDS: list = []
# words that the English list lacks: short words, code identifiers, algorithm names, German words of developer prose
# "password" in other languages: the whole value of a locale key (`"password": "Senha"`) is a label text, not a
# password (Opus Gate B of 0.6.17). An exact value only: as words they made Senha123 a word with a number, and 0.6.16
# took it (Gate B round 2)
_PW_TRANSLATIONS = frozenset({
    "senha", "heslo", "geslo", "lozinka", "sifre", "haslo", "parola", "parool", "salasana", "jelszo", "losenord",
    "passord", "adgangskode", "wachtwoord", "kennwort", "passwort", "contrasena", "motdepasse", "sifra", "parole"})
_EXTRA_WORDS = frozenset({
    "api", "key", "id", "db", "url", "uri", "app", "dev", "prod", "test", "user", "pass", "pwd", "sql", "web",
    "admin", "root", "my", "new", "old", "the", "and", "for", "get", "set", "put", "add", "max", "min", "log",
    "tmp", "env", "var", "val", "str", "int", "num", "src", "dst", "cfg", "conf", "auth", "oauth", "jwt", "aws",
    "gcp", "ssh", "rsa", "pem", "http", "https", "www", "com", "org", "net", "io", "js", "py", "go", "is", "on",
    "of", "to", "in", "at", "by", "no", "ok", "yes", "let", "me", "foo", "bar", "baz", "abc", "xyz", "qwerty", "pw",
    "secret", "token", "hello", "world", "demo", "mock", "fake", "dummy", "sample", "example", "default",
    "kwargs", "args", "argv", "self", "this", "opts", "params", "nil", "none", "null", "undefined",
    "md5", "sha1", "sha2", "sha3", "sha224", "sha256", "sha384", "sha512", "pbkdf2", "bcrypt", "scrypt", "argon2",
    "argon2i", "argon2d", "argon2id", "aes", "aes128", "aes192", "aes256", "gcm", "cbc", "ctr", "hmac", "des",
    "blake2b", "blake2s", "blake3", "sha", "crypt", "ntlm", "ntlmv2", "chacha20", "poly1305", "ecdsa", "ed25519",
    "x25519", "pkcs1", "pkcs5", "pkcs8", "pkcs12", "oaep", "pss", "utf8", "utf16", "latin1", "ascii", "base64",
    "base32", "hex", "wpa", "wpa2", "psk", "tls", "ssl", "totp", "hotp", "jwe", "jws", "oauth2", "varchar",
    "bigint", "secretstr", "securestring", "bool", "float", "char", "byte", "bytes", "uuid", "json",
    "yaml", "html", "xml", "csv", "ldap", "smtp", "imap", "ftp", "sftp", "redis", "mysql", "postgres",
    "psql", "mongo", "mongodb", "sqlite", "oracle", "guest", "anon", "localhost",
    "siehe", "geheim", "kennwort", "passwort", "benutzer", "zugang", "zugangsdaten", "anmeldung", "nutzer", "wird",
    "nicht", "oder", "und", "mit", "ohne", "bitte", "hier", "dort", "neu", "alt", "leer", "fehlt", "falsch",
    "richtig", "geheimnis", "schluessel", "sommer", "winter", "herbst", "fruehling", "schl\u00fcssel",
    "fr\u00fchling",
})


def _word_set() -> frozenset:
    """The word list, read on the first password label (about 3 ms). A file that is missing, unreadable, not UTF-8 or
    not a list of words (fewer than 1,000 entries of small ASCII letters, or more than 1 % other lines) counts as no
    list: _WORDS_OK turns false, and the password rule then takes no value of letters only (_pw_literal_ok)."""
    if not _WORDS:
        words: set = set()
        ok = True
        try:
            entries = (RULES_DIR / _WORDS_FILE).read_text(encoding="utf-8").split()
            words = {w for w in entries if w.isascii() and w.isalpha() and w.islower() and len(w) <= 20}
            ok = len(words) >= 1000 and len(entries) - len(words) <= len(entries) // 100
        except (OSError, UnicodeError, ValueError):
            ok = False
        if not ok:
            words = set()
        _WORDS_OK[:] = [ok]
        _WORDS.append(frozenset(words | _EXTRA_WORDS))
    return _WORDS[0]


_WORDS_OK: list = [True]


_COVER_CACHE: dict = {}


def _cover(run: str) -> int:
    """The most letters of `run` that words of the list cover (dynamic programming over words of 2 to 20 letters)."""
    got = _COVER_CACHE.get(run)
    if got is None:
        words = _word_set()
        n = len(run)
        best = [0] * (n + 1)
        for i in range(1, n + 1):
            best[i] = best[i - 1]
            for j in range(max(0, i - 20), i - 1):
                if run[j:i] in words:
                    best[i] = max(best[i], best[j] + (i - j))
        got = best[n]
        if len(_COVER_CACHE) > 20000:
            _COVER_CACHE.clear()
        _COVER_CACHE[run] = got
    return got


_WORD_RUN_RE = _LazyRx(r"[A-Z\u00c4\u00d6\u00dc]?[a-z\u00e4\u00f6\u00fc\u00df]+|[A-Z\u00c4\u00d6\u00dc]+"
                          r"(?![a-z\u00e4\u00f6\u00fc\u00df])|[0-9]+")


def _wordlike(v: str) -> float:
    """The share of the letters of `v` that words cover, after an identifier split (0 to 1)."""
    letters = sum(c.isalpha() for c in v)
    if not letters:
        return 0.0
    words = _word_set()
    covered = 0
    for part in _WORD_RUN_RE.findall(v):
        if part.isalpha():
            low = part.lower()
            covered += len(low) if low in words else _cover(low)
    return covered / letters


def _charset(v: str) -> str:
    if v.isdigit() and v.isascii():
        return "digits"
    if re.fullmatch(r"[0-9a-f]+|[0-9A-F]+", v):
        return "hex"
    if re.fullmatch(r"[A-Za-z]+", v):
        return "alpha"
    if re.fullmatch(r"[A-Za-z0-9]+", v):
        return "alnum"
    return "other"


# a value that says it is no value: a mask, a template, a reference, a word of a form
_LITERAL_PLACEHOLDER_RE = _LazyRx(
    r"(?i)x{3,}|\*{3,}|\.{3}|<[^>]*>|\{\{|\}\}|\$\{|%\(|%s|\$[A-Za-z_]|your[_-]?|example|sample|dummy|placeholder|"
    r"changeme|change_me|redacted|replace|insert|enter[_-]|todo|fixme|foobar|lorem|secret_here|here$|^test|test$|"
    r"^fake|^mock|^none$|^null$|^true$|^false$|^undefined$|^password$|^secret$|^token$|^string$|^empty$|^default$")
_DOTTED_RE = _LazyRx(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+")
_CLOSED_TEMPLATE_RE = _LazyRx(r"\{[A-Za-z_][\w.]*(?:\[[^\]{}]*\])?\}")   # {pw}, {cfg.pw}, {row['pw']}; not a lone {
_CAMEL_SPLIT_RE = _LazyRx(r"(?<=[a-z0-9])(?=[A-Z])")


def _norm_label(name: str) -> list:
    """`dbPassword`, `DB_PASSWORD`, `db.password`, `db-password`, `db:Password` -> ["db", "password"]."""
    name = _CAMEL_SPLIT_RE.sub("_", name.lstrip("$@-"))
    return [t for t in re.split(r"[._:\-]+", name.lower()) if t]


# the last word of a password label, and the words before it that make the label name something else
_PW_LAST = frozenset({"password", "passwd", "passphrase", "passwort", "pwd", "userpwd", "pass", "pw", "passcode",
                      "passw", "pword", "pswd", "psw"})
# the label words of a language that is on (regions.py): Kennwort is a label only with German on, as for the keyword
# rules; passwort counts always, as the English `pass` label allows letters after it
_PW_LAST_OF = {"de": frozenset({"kennwort"})}
_PASS_NEG_PREV = frozenset({"two", "one", "single", "multi", "first", "second", "third", "by", "no", "skip", "sur",
                            "over", "under", "compass", "render", "shader", "high", "low", "band", "all", "each",
                            "next", "last", "test", "tests"})
_LABEL_NEG_WORDS = frozenset({
    "hint", "label", "title", "text", "message", "msg", "error", "err", "prompt", "placeholder", "field", "policy",
    "length", "len", "min", "max", "required", "confirm", "confirmation", "reset", "forgot", "invalid", "incorrect",
    "wrong", "strength", "rule", "rules", "regex", "pattern", "hash", "hashed", "salt", "file", "path", "env", "var",
    "type", "mode", "enabled", "expire", "expires", "expiry", "changed", "change", "validation", "valid", "show",
    "hide", "toggle", "visible", "icon", "button", "btn", "no", "without", "skip", "ask", "input", "form", "dialog",
    "tooltip", "description", "desc", "help", "name", "id", "count", "cmd", "command", "url", "uri", "key", "column",
    "col", "header", "param", "arg", "option", "opt", "flag", "set", "get", "update", "lbl", "str", "string", "i18n",
    "translation", "not", "missing", "empty", "format", "fmt", "encoder", "encoded", "encrypted", "digest",
    "algorithm", "manager", "provider", "store", "storage", "service", "handler", "callback", "validator", "widget"})


def _pw_label(toks: list) -> bool:
    if not toks:
        return False
    last = toks[-1].rstrip("0123456789") or toks[-1]
    if last not in _pw_words(_det()):
        return False
    if last in ("pass", "pw") and len(toks) > 1 and toks[-2] in _PASS_NEG_PREV:
        return False
    return not any(t in _LABEL_NEG_WORDS for t in toks[:-1])


def _sequential(low: str) -> bool:
    return len(low) > 2 and (all(ord(low[i + 1]) - ord(low[i]) == 1 for i in range(len(low) - 1))
                             or all(ord(low[i]) - ord(low[i + 1]) == 1 for i in range(len(low) - 1)))


# what a value after a password label is when it is no password: a number, a ratio, a percentage, a range, a time, a
# duration or a size with its unit (95.2%, 118/124, 8-64, 12:30, ~30d, 24h/7d, 14C/27, 2025/26), a section (§3.2), a
# dotted abbreviation (s.o., z.B.), and a word with a number (Seite#3, Gate-12)
_MEASURE_VALUE_RE = _LazyRx(r"[~<>=+\u00a7#-]?\d+(?:[.,:/-]\d+)*(?:[a-z]{1,3}|[A-Z]{1,2})?"
                               r"(?:[/ -]\d+(?:[.,:]\d+)*(?:[a-z]{1,3}|[A-Z]{1,2})?)*%?")
_ABBREVIATION_RE = _LazyRx(r"(?:[A-Za-z\u00c0-\u024f]{1,4}\.)+[A-Za-z\u00c0-\u024f]{0,4}")
# a path or a reference after a password label names where the password lives: /run/secrets/db, ../x/y, ~/.pw,
# C:\keys\db.pw, \\server\share, file:///etc/pw, vault:secret/db#pw, env:DB_PASSWORD
_PATH_REFERENCE_RE = _LazyRx(r"(?:[/~]|\.{1,2}[/\\]|[A-Za-z]:[/\\]|\\\\)\S*"
                                r"|[A-Za-z][A-Za-z0-9+.-]{2,15}:(?://|[A-Za-z_$])\S*")
_ISO_DURATION_RE = _LazyRx(r"P(?:\d+[YMWD])*(?:T(?:\d+[HMS])+)?")   # P90D, PT15M
_WORD_NUMBER_RE = _LazyRx(r"[A-Za-z\u00c0-\u024f]{2,}[#_. :/-]\d{1,4}|\d{1,4}[#_. :/-][A-Za-z\u00c0-\u024f]{2,}")


def _random_evidence(v: str, tool: bool = False) -> bool:
    """A value that no word covers is a password only with evidence of chance (codex and Opus Gate A/B of 0.6.16): a
    letter, and a digit or a sign beside it, or (letters only) few vowels or a mix of cases that no word boundary
    explains. A word of another language (senhaAtual, wachtwoord) and a measure (95.2%, 12:30, ~30d) stay text."""
    if not any(c.isalpha() for c in v):
        return False
    if (_MEASURE_VALUE_RE.fullmatch(v) or _ABBREVIATION_RE.fullmatch(v) or _WORD_NUMBER_RE.fullmatch(v)
            or _ISO_DURATION_RE.fullmatch(v)):
        return False
    if any(c.isdigit() for c in v) or any(_is_sign(c) and c not in "_-." for c in v):
        return True   # a digit, or a sign that no identifier uses (_ - . join the words of a name: senha_atual)
    parts = [part for part in re.split(r"[_.-]+", v) if part]
    if not v.isascii():
        # another script or accents: a word (a UI string) unless scripts mix or the cases change at random
        return _scripts_mix(v) or any(_case_flips(part) >= 2 for part in parts)
    if tool:
        return True   # a tool result or a file: ASCII letters that no word covers are a password there
    # ASCII letters joined at most by _ - .: one part with a mix of cases that no word boundary explains
    return any(_random_letters(part) for part in parts)


def _is_sign(c: str) -> bool:
    """Punctuation or a symbol. A combining vowel sign of Devanagari or Thai is part of a word, not a sign."""
    import unicodedata
    return unicodedata.category(c)[0] in "PS"


def _case_flips(v: str) -> int:
    """How often a small letter is followed by a capital: once in a camelCase name, often in a random value."""
    return sum(1 for x, y in zip(v, v[1:]) if x.islower() and y.isupper())


def _scripts_mix(v: str) -> bool:
    """Letters of two scripts with case in one value (Latin and Cyrillic, Greek and Latin): no word is written so.
    Scripts without case mix in ordinary words (Japanese kanji and kana) and do not count."""
    import unicodedata
    scripts = {unicodedata.name(c, "?").split(" ")[0].split("-")[0]
               for c in v if c.isalpha() and c.upper() != c.lower()}
    return len(scripts) > 1


def _random_letters(v: str) -> bool:
    """ASCII letters that no word explains: capitals inside short runs (xKqTzLmP)."""
    # a long run of letters with few vowels (a keyboard run, xkcdqwrtzp), counted per word of a camelCase or snake_case
    # name: ctxPtr, grpcSrv and the words of other languages (Pflicht, Svensk) are short or have more vowels
    if len(v) >= 9 and sum(c in "aeiouyAEIOUY" for c in v) < 0.15 * len(v) and v.isalpha() and v[1:].islower():
        return True
    upper = sum(c.isupper() for c in v)
    parts = _WORD_RUN_RE.findall(v)
    return upper >= 2 and len(v) - upper >= 2 and len(parts) >= 3 and len(v) <= 3 * len(parts)


def _pw_strong_evidence(v: str) -> bool:
    """After the weak label `pass` (a boarding pass, a test pass, a season pass): 8 characters and more of three of
    the four classes (small, capital, digit, sign)."""
    classes = (any(c.islower() for c in v) + any(c.isupper() for c in v) + any(c.isdigit() for c in v)
               + any(not c.isalnum() for c in v))
    return len(v) >= 8 and classes >= 3


def _pw_literal_ok(v: str, channel: str = "prompt") -> bool:
    """A password value: 4 to 64 characters, no word after undoing leet (or a word with a number and a sign), not
    digits only, 3 distinct characters or more, no run such as abcd, no placeholder, no space, no dotted reference, no
    fixture word (testpass), no version."""
    if not 4 <= len(v) <= 64 or any(c.isspace() for c in v) or _charset(v) == "digits" or len(set(v)) < 3:
        return False
    if v.lower() in _PW_TRANSLATIONS and v in (v.lower(), v.capitalize(), v.upper()):
        return False   # the word for password in another language: a locale value (SeNhA stays a hit, as in 0.6.16)
    if _sequential(v.lower()) or _LITERAL_PLACEHOLDER_RE.search(v) or _DOTTED_RE.fullmatch(v) or _names_itself(v):
        return False
    if _CLOSED_TEMPLATE_RE.search(v) or _looks_like_regex(v):
        return False   # a template of a format string or a pattern: f'pwd = "{pw}"', "password: {password}"
    if _VERSION_RE.fullmatch(v):
        return False   # a version: v1.2.3-rc1 (undoing leet makes it letters)
    if _PATH_REFERENCE_RE.fullmatch(v):
        return False   # a path or a reference: /run/secrets/db, ./secrets/pw.txt, C:\\keys\\db.pw, vault:…, file:///…
    if _wordlike(_deleet(v)) < 0.3:
        if not _WORDS_OK[0] and v.isalpha():
            return False   # without a word list, a value of letters only may be any word
        if channel == "tool":
            return _random_evidence(v, tool=True)   # a false hit in a tool result masks a value, it blocks no prompt
        return _random_evidence(v)
    # a password made of a word, a number and a sign: Sommer2024!, Herbst2025#, Welcome1! (the form people choose).
    # A word with a number alone (Winter2023, postgres15) stays text here; the keyword rules judge it. So does a name
    # joined by _ - . (ABC_123_DEF) and a reference with : / or \ (b64:!!notbase64, vault:db/pw1!)
    return (len(v) >= 8 and any(c.isalpha() for c in v) and any(c.isdigit() for c in v)
            and any(not c.isalnum() and c not in "_-." for c in v) and not any(c in ":/\\" for c in v)
            and _ds_value_ok(v))


# the forms of label and literal value. A label, then = => := == : , or ( and a quoted value (also inside a wrapper
# such as SecretStr("…")); a label, then = or : and an unquoted value to the end of the line; a query parameter; an
# XML element; SQL's IDENTIFIED BY '…' and PowerShell's ConvertTo-SecureString '…'
_LIT_WRAP = (r"(?:(?:Some|Ok|String::from|str|bytes|SecretString::new|Secret::new|SecretStr|SecretBytes|Optional\.of"
             r"|Box::new|Sensitive|new[ \t]+String)[ \t]*\([ \t]*)?")
# a label starts after no word character, no path or flag part and no `=`: `--password-file=/etc/app/pw` holds no
# label pw, and `pw=pw=pw=…` (1 MB took 5.5 s) starts one label only
_LIT_LABEL = r"(?<![\w.\-$@/\\=])([A-Za-z_$@][\w.\-]{0,60})[\"'\]]?[ \t]*"
# the quoted forms end at the opening quote: _read_quoted reads the literal to its real closing quote
_LIT_QUOTED = _LazyRx(_LIT_LABEL + r"(?<![=!<>])(?:=>|:=|=(?!=)|:|,|\()[ \t]*" + _LIT_WRAP + r"([\"'`])")
_LIT_FORMS = (
    (_LazyRx(r"(?m)" + _LIT_LABEL + r"(?:=|:)[ \t]*([^\s\"'`,()\[\]{}<>]{3,299}[^\s\"'`,;()\[\]{}<>]);?"
                r"(?:[ \t]+(?:#|//|;).*|[ \t]*(?:#|//).*)?[ \t]*$"), 1, 2),
    (_LazyRx(r"[?&;]([\w.\-\[\]]{1,60})=([^&\s\"'#<>]{4,400})"), 1, 2),
    (_LazyRx(r"<([\w:.-]{1,60})(?:\s[^<>]{0,200})?>([^<>\s]{4,400})</"), 1, 2),
)
# SQL's IDENTIFIED BY '…' (a doubled quote and MySQL's backslash escape are part of the value) and PowerShell's
# ConvertTo-SecureString '…' (single quotes: a doubled quote; double quotes: a doubled quote and the backtick escape)
_LIT_SQL = _LazyRx(r"(?i)\bidentified[ \t]+(?:with[ \t]+\w+[ \t]+)?by[ \t]*(?:password[ \t]*)?([\"'])")
_LIT_PS = _LazyRx(r"(?i)ConvertTo-SecureString[ \t]+(?:-String[ \t]+)?([\"'])")
# a password label and its value in a note, where a line goes on after them (CredSweeper's doc samples, Benchmark V3
# dev): `host (pw:<value>)`, `(ID/PW:<value>)`, `<host>/pw:<value>`, `-pwd:<value>`. Only a password label counts
# here (_literal_hits keeps label-pw-literal alone): a key word in parentheses is code more often
_LIT_NOTE = (
    _LazyRx(r"\((?:[A-Za-z]{1,10}[/&])?([A-Za-z_][\w.\-]{0,60})[ \t]*[:=][ \t]*"
            r"([^\s\"'`,()\[\]{}<>]{3,299}[^\s\"'`,;()\[\]{}<>])[ \t]*\)"),
    _LazyRx(r"(?:(?<=[\w)}\]]/)|(?<![^\s])-)((?i:pw|pwd|passwd|password))[ \t]*:[ \t]*"
            r"([^\s\"'`,()\[\]{}<>]{3,299}[^\s\"'`,;.()\[\]{}<>])(?=[\s)]|$)"),
)
# a Kubernetes or Compose env entry whose name is the label of its value: `- name: DB_PASSWORD` and on the next line
# `value: "<value>"` (Benchmark V3, aparte dev). The label rules saw only `value`
_LIT_ENV_ENTRY = _LazyRx(r"(?m)^[ \t]*-[ \t]+name:[ \t]*[\"']?([A-Za-z_][\w.-]{0,60})[\"']?[ \t]*\r?\n"
                         r"[ \t]+value:[ \t]*([\"'])")
# a Terraform variable whose name is the label of its default: `variable "aws_secret_key" { default = "…" }`. The
# label rules saw only `default` (Benchmark V3, llmredactor and aparte dev: 36 keys and passwords in the clear). The
# block up to its default holds no brace (type, description and sensitive come before it)
_LIT_TF = _LazyRx(r"(?<![\w-])variable[ \t]+\"([A-Za-z_][\w-]{0,60})\"[ \t]*\{[^{}]{0,400}?"
                  r"(?<![\w-])default[ \t]*=[ \t]*\"")
_LIT_BOUND = 300   # a literal longer than this, or one that its line ends, is taken to the bound: never a prefix
_BACKSLASH_ESCAPE_RE = _LazyRx(r"\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|(.))", re.S)
_ESCAPED_CHAR = {"n": "\n", "t": "\t", "r": "\r", "0": "\0"}


def _unquote(raw: str, quote: str, backslash: bool, backtick: bool) -> str:
    """The value a literal stands for, for the judgement only (the span stays the raw text): `\u00fc` is ü, `\"` is ",
    a doubled quote is one quote, PowerShell's backtick escapes the next character."""
    v = raw.replace(quote + quote, quote)
    if backslash and "\\" in v:
        v = _BACKSLASH_ESCAPE_RE.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)) if (m.group(1) or m.group(2))
                                     else _ESCAPED_CHAR.get(m.group(3), m.group(3)), v)
    if backtick and "`" in v:
        v = re.sub(r"`(.)", lambda m: _ESCAPED_CHAR.get(m.group(1), m.group(1)), v, flags=re.S)
    return v


def _read_quoted(text: str, i: int, quote: str, backslash: bool = True, backtick: bool = False) -> tuple:
    """Read a quoted literal whose content starts at `i`: (end of the content, closed). A backslash (C, Python, JSON,
    JavaScript, MySQL) or a backtick (PowerShell) escapes the next character, and a doubled quote (SQL, PowerShell, YAML
    single quotes) is one quote of the content, so an escaped quote never ends the value early. Without a closing quote
    on the line within _LIT_BOUND characters the content runs to the line end or the bound."""
    n = len(text)
    stop = min(n, i + _LIT_BOUND)
    j = i
    while j < stop:
        c = text[j]
        if c == "\n" or c == "\r":
            return j, False
        if (backslash and c == "\\") or (backtick and c == "`"):
            j += 2
            continue
        if c == quote:
            if j + 1 < n and text[j + 1] == quote:
                j += 2   # a doubled quote is one quote of the value, also as its first character
                continue
            return j, True
        j += 1
    return min(j, stop), False


# a label that names a secret by its whole tail (`client_secret`, `apiKey`, `x-auth-token`), and a weak label that may
# name one (`key`, `hmac`, `session`, `cookie`). A word before the tail can make it name something else: password_hint,
# public_key, cache_key, primary_key, csrf_token, next_page_token
_SECRET_TAIL_RE = _LazyRx(r"(?:^|_)(?:secret|token|apikey|api_key|access_key|secret_key|private_key|client_secret"
                             r"|auth_token|access_token|refresh_token|session_token|bearer|credentials?|app_secret"
                             r"|consumer_secret|signing_key|encryption_key|master_key|auth_key)$")
_WEAK_TAIL_RE = _LazyRx(r"(?:^|_)(?:key|auth|salt|seed|otp|totp|cred|cookie|session|hmac|psk)$")
_WEAK_NEG_WORDS = frozenset({
    "public", "pub", "primary", "foreign", "sort", "partition", "cache", "idempotency", "row", "map", "lookup",
    "cursor", "object", "s3", "dedup", "dedupe", "routing", "shard", "group", "sequence", "index", "composite",
    "unique", "natural", "surrogate", "react", "list", "item", "translation", "i18n", "locale", "storage", "redis",
    "memcache", "query", "license", "licence", "product", "registry", "gpg", "pgp", "ssh", "host", "known",
    "fingerprint", "csrf", "xsrf", "anti", "forgery", "verification", "page", "next", "continuation", "pagination",
    "sync", "lexer", "tokenizer", "parser", "cancellation", "captcha", "recaptcha"})


# a TOTP or HOTP seed: base32 of 10 to 40 bytes after a one-time-password label (otpauth://… carries it as secret=)
_OTP_WORDS = frozenset({"totp", "hotp", "otp", "mfa", "2fa", "otpauth", "authenticator"})
_OTP_SEED_RE = _LazyRx(r"[A-Z2-7]{16,64}={0,6}")


def _alphabet_size(v: str) -> int:
    if v.isdigit():
        return 10
    if re.fullmatch(r"[0-9a-f]+|[0-9A-F]+", v):
        return 16
    size = 26 * (any(c.islower() for c in v) + any(c.isupper() for c in v)) + 10 * any(c.isdigit() for c in v)
    if any(not c.isalnum() for c in v):
        size += 2 if re.fullmatch(r"[A-Za-z0-9+/=_-]+", v) else 32
    return max(size, 2)


def _norm_entropy(v: str) -> float:
    """Shannon entropy over the most the value's alphabet and length allow (0 to 1): a charset-normalised entropy
    after Dan Szymkowiak's backlog idea (TASK-11.21)."""
    return shannon_entropy(v) / math.log2(max(2, min(_alphabet_size(v), len(v))))


# a value that is a pattern, not a key: a character class with a quantifier, a counted repeat, an escape class, a group
# (`token: '[A-Za-z0-9_-]{20,}'`, `secret: '[a-f0-9]{64}'`, `^\d{6}$`; Opus verification of 0.6.16)
_REGEX_LIKE_RE = _LazyRx(r"\[[^\]]{1,60}\](?:[*+?]|\{\d+(?:,\d*)?\})|\{\d+(?:,\d*)?\}|\\[dwsDWSbB]"
                            r"|\(\?[:=!<]|\.[*+]")


def _looks_like_regex(v: str) -> bool:
    """The whole value is a pattern: it starts with ^ [ ( or \\ , ends with $ ] ) } or a quantifier, and holds a
    pattern part. A password with \\d or .* inside it is no pattern (codex, final round of 0.6.16)."""
    return (len(v) >= 3 and v[0] in "^[(\\" and (v[-1] in "$])}*+?" or v[-2:] in ("\\b", "\\B"))
            and _REGEX_LIKE_RE.search(v) is not None)


def _key_literal_ok(v: str, lo: int, hi: int, words: float, entropy: float) -> bool:
    """A key after a secret or a weak label: ASCII, no space, no placeholder, few word letters, a high normalised
    entropy, and detect-secrets' filters (templates, references, sequences)."""
    if _looks_like_regex(v):
        return False
    if not lo <= len(v) <= hi or not v.isascii() or any(c.isspace() for c in v) or _LITERAL_PLACEHOLDER_RE.search(v):
        return False   # a key is ASCII: a value with § or an umlaut is a split test value or a word
    return _norm_entropy(v) >= entropy and _ds_value_ok(v, 4) and _wordlike(_deleet(v)) < words


def _pw_words_of(languages) -> frozenset:
    return _PW_LAST.union(*(_PW_LAST_OF.get(lang, ()) for lang in languages))


def _pw_words(d: "Detector") -> frozenset:
    """The password label words of the detector's languages; a scan with a rule list of its own, before the
    detector's rules loaded, needs them too."""
    words = d._pw_last_on
    if words is None:
        with d._load_lock:
            if d._pw_last_on is None:
                d._label_class.clear()
                d._pw_last_on = _pw_words_of(active_regions().languages)
            words = d._pw_last_on
    return words


def _label_class(label: str) -> tuple:
    """(password label, secret label, weak label, OTP label, last word) of a label, computed once per label: a list of
    70,000 words reads each word as the label of the next one."""
    cache = _det()._label_class
    got = cache.get(label)
    if got is None:
        toks = _norm_label(label)
        full = "_".join(toks)
        before = toks[:-1]
        # an AWS signature or the key id in a SigV4 scope is no secret value of its own
        # (the session token, x-amz-security-token, is a secret: the rule label-aws-session-token takes it)
        amz = (full.startswith("x_amz") and full != "x_amz_security_token") or bool(
            toks and toks[-1] in ("credential", "signature"))
        named = bool(full) and not amz
        other = any(t in _LABEL_NEG_WORDS or t in _WEAK_NEG_WORDS for t in before)
        secret = named and bool(_SECRET_TAIL_RE.search(full)) and not other
        weak = named and bool(_WEAK_TAIL_RE.search(full)) and not other
        otp = named and bool(set(toks) & _OTP_WORDS)
        got = (_pw_label(toks), secret, weak, otp, toks[-1] if toks else "")
        if len(cache) > 50000:
            cache.clear()
        cache[label] = got
    return got


_COMMON_PAIRS: list = []


def _common_pairs() -> frozenset:
    """The letter pairs that occur 20 times or more in the word list (about 370 of 676). Empty without a word list."""
    if not _COMMON_PAIRS:
        count: dict = {}
        if _word_set() and _WORDS_OK[0]:
            for w in _WORDS[0]:
                for i in range(len(w) - 1):
                    count[w[i:i + 2]] = count.get(w[i:i + 2], 0) + 1
        _COMMON_PAIRS.append(frozenset(p for p, n in count.items() if n >= 20))
    return _COMMON_PAIRS[0]


def reads_as_word(value: str) -> bool:
    """Whether a value reads as a word of some language: letters only (parts joined by _ - .), no evidence of chance,
    and in ASCII at most one rare letter pair in ten. Wartungsfenster, senha_atual and Пароль are words; xqzvbnmq,
    Kx7QpZr9 and qwmzpl are not. The store keeps a word that a label rule took in a tool result quiet (vault.is_quiet):
    masked in later tool results, never looked for in a typed prompt, where it would block every prompt that uses
    the word (field report, 2026-10-14)."""
    parts = [p for p in re.split(r"[_.-]+", value) if p]
    if not parts or not all(p.isalpha() for p in parts) or _random_evidence(value):
        return False
    if not value.isascii():
        return True   # another script or accents, and no mix of scripts or cases (_random_evidence)
    common = _common_pairs()
    if not common:
        return False   # no word list: hunt the value, as 0.6.16 did
    pairs = [p[i:i + 2] for p in (x.lower() for x in parts) for i in range(len(p) - 1)]
    if not pairs:
        return False   # single letters: no evidence of a word
    return sum(q not in common for q in pairs) <= 0.1 * len(pairs)


def english_words() -> frozenset:
    """The word list of the detector: rules/words_en.txt and the built-in developer, code and German words
    (_EXTRA_WORDS). Empty when the file is missing or holds no list of words."""
    words = _word_set()
    return words if words and _WORDS_OK[0] else frozenset()


def _judge_literal(label: str, v: str, quoted: bool = True, channel: str = "prompt") -> str:
    """The rule a label and its literal value fall under, or ""."""
    pw, secret, weak, otp, last = _label_class(label)
    if pw and _pw_literal_ok(v, channel) and (last.rstrip("0123456789") != "pass" or _pw_strong_evidence(v)):
        return "label-pw-literal"
    if secret and _key_literal_ok(v, 8, 200, 0.3, 0.8):
        return "label-secret-literal"
    if (quoted and weak and _key_literal_ok(v, 12, 300, 0.2, 0.85) and not (len(v) == 64 and _charset(v) == "hex")
            and not (last == "key" and _charset(v) == "hex")):
        return "label-weak-key"
    if otp and _OTP_SEED_RE.fullmatch(v) and _wordlike(v) < 0.3:
        return "label-otp-seed"
    return ""


def _literal_hits(text: str, channel: str = "prompt") -> list:
    """(rule id, start of the label, start and end of the value) of each label and literal value of `text`, computed
    once per text and configuration for all the rules that read them: the label words follow the detector's
    languages, and its reference form decides which values are keys."""
    cache = _text_index(text)
    d = _det()
    key = ("literal", channel, d, d._generation, _pw_words(d))
    if key not in cache:
        hits = []
        pos = 0
        while True:
            m = _LIT_QUOTED.search(text, pos)
            if m is None:
                break
            a = m.end()
            q = m.group(2)
            lq = text[m.start(1) - 1:m.start(1)]
            if "," in text[m.end(1):m.start(2)] and not (lq in ("'", '"') and text[m.end(1):m.end(1) + 1] == lq):
                pos = m.start(2)   # f(password, "…"): the next argument; ("password", "…") is a pair of label and value
                continue
            # PowerShell escapes with a backtick in double quotes, after a $ label only: $pw = "…`"…"
            tick = q == '"' and m.group(1).startswith("$")
            end, closed = _read_quoted(text, a, q, backtick=tick)
            raw = text[a:end]
            # past a literal that is a value
            pos = end + 1 if closed else max(end, a)
            if closed and re.match(r"[ \t]*\+", text[end + 1:end + 40]):
                continue   # a string that + continues is an expression
            rid = _judge_literal(m.group(1), _unquote(raw, q, True, tick), quoted=True, channel=channel)
            if rid:
                hits.append((rid, m.start(), a, end))
            else:
                pos = a   # a literal that is no value may be a label itself: f("password", "…"), or hold a JSON text
        for n, (rx, gl, gv) in enumerate(_LIT_FORMS):
            for m in rx.finditer(text):
                rid = _judge_literal(m.group(gl), m.group(gv), quoted=n != 0, channel=channel)
                if rid:
                    hits.append((rid, m.start(), m.start(gv), m.end(gv)))
        for rx in _LIT_NOTE:
            for m in rx.finditer(text):
                if _judge_literal(m.group(1), m.group(2), quoted=False, channel=channel) == "label-pw-literal":
                    hits.append(("label-pw-literal", m.start(), m.start(2), m.end(2)))
        for m in _LIT_ENV_ENTRY.finditer(text):
            q = m.group(2)
            end, closed = _read_quoted(text, m.end(), q)
            rid = closed and _judge_literal(m.group(1), _unquote(text[m.end():end], q, True, False), quoted=True,
                                            channel=channel)
            if rid:
                hits.append((rid, m.start(), m.end(), end))
        for m in _LIT_TF.finditer(text):
            end, closed = _read_quoted(text, m.end(), '"')
            rid = closed and _judge_literal(m.group(1), _unquote(text[m.end():end], '"', True, False), quoted=True,
                                            channel=channel)
            if rid:
                hits.append((rid, m.start(), m.end(), end))
        for rx, backslash in ((_LIT_SQL, True), (_LIT_PS, False)):
            for m in rx.finditer(text):
                q = m.group(1)
                tick = not backslash and q == '"'
                end, _closed = _read_quoted(text, m.end(), q, backslash=backslash, backtick=tick)
                if _pw_literal_ok(_unquote(text[m.end():end], q, backslash, tick), channel):
                    hits.append(("label-pw-literal", m.start(), m.end(), end))
        hits.sort(key=lambda h: h[2])
        cache[key] = hits   # the tool channel takes more values
    return cache[key]


class _Literal:
    """A match of a label and literal rule: group 0 runs from the label to the end of the value, group 1 is the
    value."""
    __slots__ = ("_text", "_a", "_s", "_e")

    def __init__(self, text: str, a: int, s: int, e: int) -> None:
        self._text, self._a, self._s, self._e = text, a, s, e

    def group(self, i: int = 0):
        return self._text[self._a if i == 0 else self._s:self._e]

    def start(self, i: int = 0) -> int:
        return self._a if i == 0 else self._s

    def end(self, i: int = 0) -> int:
        return self._e


def _literal_matches(rule_id: str, text: str, channel: str = "prompt"):
    for rid, a, s, e in _literal_hits(text, channel):
        if rid == rule_id:
            yield _Literal(text, a, s, e)


# the rules that read labels and literal values; they run after every other rule and take only a span no other rule
# took. The keywords skip a text without the label words
LITERAL_RULES = (
    {"id": "label-pw-literal", "keywords": ("pass", "pw", "pwd", "kennwort", "psw", "identified", "securestring")},
    {"id": "label-secret-literal", "keywords": ("secret", "token", "key", "bearer", "credential")},
    {"id": "label-otp-seed", "keywords": ("otp", "mfa", "2fa", "authenticator")},
    {"id": "label-weak-key", "keywords": ("key", "auth", "salt", "seed", "otp", "cred", "cookie", "session", "hmac",
                                          "psk")},
)
_LITERAL_IDS = frozenset(d["id"] for d in LITERAL_RULES)


def _env_key_ok(v: str) -> bool:
    """A key of Strapi's APP_KEYS: base64 of 16 bytes or more with an entropy of random bytes; the placeholders of
    .env.example (toBeModified1) are short and words."""
    try:
        raw = _b64.b64decode(v + "=" * (-len(v) % 4), validate=True)
    except ValueError:   # binascii.Error is a ValueError
        return False
    return len(raw) >= 16 and shannon_entropy(v) >= 3.5 and not _word_shaped(v)


def _laravel_key_ok(v: str) -> bool:
    """Laravel's APP_KEY: base64: and the base64 of a 16- or 32-byte key (AES-128 or AES-256), random."""
    body = v[len("base64:"):] if v.startswith("base64:") else ""
    try:
        raw = _b64.b64decode(body, validate=True)
    except ValueError:
        return False
    return len(raw) in (16, 32) and len(set(raw)) > 8


def _config_key_value_ok(v: str) -> bool:
    """A key or a salt that a config constant assigns (label-php-define-key, label-terraform-default): the
    WordPress salts of wp-config.php are 64 printable signs, and ( ) | ` < > $ are part of them, so the literal
    checks (_key_literal_ok, _ds_value_ok) refuse them as code. ASCII with no space, 16 characters or more, a high
    normalised entropy, no run of words, and no fixture or placeholder: "put your unique phrase here" has spaces."""
    v = v.strip()
    if not 16 <= len(v) <= 256 or not v.isascii() or any(c.isspace() for c in v) or "\\" in v:
        return False
    if _names_itself(v) or looks_like_placeholder(v) or re.search(r"(?i)your|example|sample|changeme|dummy", v):
        return False
    return _norm_entropy(v) >= 0.8 and _wordlike(_deleet(v)) < 0.5


def _random_hex(v: str) -> bool:
    """A hex id that is no counted fixture: AC0123456789abcdef… or one repeated digit is a test value."""
    h = v[2:].lower()
    if not h or any(c not in "0123456789abcdef" for c in h):
        return False
    run = best = 1
    for a, b in zip(h, h[1:]):
        run = run + 1 if int(b, 16) == (int(a, 16) + 1) % 16 else 1
        best = max(best, run)
    return best < 8 and len(set(h)) > 4


VALIDATORS = {
    "random_hex": _random_hex,
    "ds_value": _ds_value_ok,
    "apikey_value": _apikey_value_ok,
    "word_value": _word_value_ok,
    "flag_value": lambda v: _word_value_ok(v, prose_punct=True),
    "glued_value": lambda v: _word_value_ok(v, min_len=6),
    "prose_value": _prose_value_ok,
    # a "!" at the end belongs to the password ("My password is <value>! (don't judge)") only when the value is one
    # without it: "The password is Hunter2!" stays the example of a weak password
    "prose_value_bang": lambda v: _prose_value_ok(v) and _prose_value_ok(v.rstrip("!")),
    "sentence_value": _sentence_value_ok,
    "spaced_value": _spaced_value_ok,
    "prose_key_value": _prose_key_value_ok,
    "config_key_value": _config_key_value_ok,
    "laravel_key": _laravel_key_ok,
    "de_tax_id": _de_tax_id_ok,
    "de_social_security": _de_social_security_ok,
    "de_social_security_spaced": lambda v: _de_social_security_ok(v.replace("\u00a0", " ")),
    "de_health_insurance": _de_health_insurance_ok,
    "de_lanr": _de_lanr_ok,
    "de_bsnr": lambda v: len(v.strip()) == 9 and v.strip().isdigit() and v.strip() != "000000000",
    "de_vat_id": _de_vat_id_ok,
    "luhn": lambda v: _luhn_ok(re.sub(r"\D", "", v)),
    "iban": _iban_ok,
    "public_ip": _public_ip,
    "not_placeholder": lambda v: v.lower() not in {"placeholder", "changeme", "redacted", "example"}
    and not v.startswith("<"),
    "person_email": lambda v: v.split("@", 1)[0].lower() not in _SYSTEM_USERS and not _reserved_domain(v),
    # name%40firma.de in a URL query, a form body or an access log: the same address, percent-encoded
    "person_email_encoded": lambda v: VALIDATORS["person_email"](v.replace("%40", "@")),
    "us_ssn": _us_ssn_ok,
    # checksums.py: ports of Presidio validators that were missing, the German document number, Switzerland, Austria
    # and the crypto wallet secrets
    "de_document": checksums.de_document_ok,
    "de_tax_id_spaced": lambda v: _de_tax_id_ok(re.sub(r"[ \u00a0]", "", v)),
    "pl_pesel": checksums.pl_pesel_ok,
    "es_nif": checksums.es_nif_ok,
    "es_nie": checksums.es_nie_ok,
    "us_npi": checksums.us_npi_ok,
    "se_organisationsnummer": checksums.se_organisationsnummer_ok,
    "uk_vehicle_registration": checksums.uk_vehicle_registration_ok,
    "uk_nhs": checksums.uk_nhs_ok,
    "us_aba": checksums.us_aba_ok,
    "it_fiscal_code": checksums.it_fiscal_code_ok,
    "ch_ahv": checksums.ch_ahv_ok,
    "ch_uid": checksums.ch_uid_ok,
    "at_uid": checksums.at_uid_ok,
    "at_social_security": checksums.at_social_security_ok,
    "wif": checksums.wif_ok,
    "xprv": checksums.xprv_ok,
    "discord_bot_token": checksums.discord_bot_token_ok,
    "base64_pem": _base64_pem_ok,
    # a token of a short public prefix (cio, oy2, AVNS_) whose body reads as words is an identifier
    "token_not_words": lambda v: _wordlike(v[3:]) < 0.5,
}


_RESERVED_MAIL_DOMAINS = ("example.com", "example.net", "example.org")
_RESERVED_MAIL_TLDS = ("test", "example", "invalid", "localhost", "local", "internal")


def _reserved_domain(v: str) -> bool:
    """example.com/.net/.org, the TLDs .test .example .invalid .localhost (RFC 2606, RFC 6761), .local (RFC 6762)
    and .internal (ICANN, 2024): no mailbox of a person on the internet is there. Every README, git fixture and
    test used them (review, 2026-09-29)."""
    local, _, d = v.rpartition("@")
    d = d.lower()
    tld = d.rsplit(".", 1)[-1]
    if tld in ("local", "internal"):
        # hans.mueller@firma.local, jdoe@corp.internal: an Active Directory mailbox names a person (reviews,
        # 2026-09-29); only a system account there is no person
        # a bot or a pipeline is no person either: a CI file that names renovate@repo.local was blocked in Codex,
        # which cannot rewrite a prompt (2026-10-06)
        local = local.lower()
        return (local in _SYSTEM_USERS or local in _SERVICE_MAILBOXES
                or local.endswith(("-bot", "_bot")))
    return (d in _RESERVED_MAIL_DOMAINS or d.endswith(tuple("." + x for x in _RESERVED_MAIL_DOMAINS))
            or tld in _RESERVED_MAIL_TLDS)


_SERVICE_MAILBOXES = frozenset({"alerts", "alert", "monitoring", "backup", "ci", "bot", "renovate", "dependabot",
                                "release", "deploy", "build", "jenkins", "gitlab-runner", "github-actions"})
_SYSTEM_USERS = frozenset({"git", "root", "ubuntu", "ec2-user", "admin", "noreply", "no-reply", "postmaster",
                           "hostmaster", "webmaster", "mailer-daemon", "bounce", "bounces"})


# --------------------------------------------------------------- own rules --
# The letters of Chinese, Japanese and Korean script. Python's \w includes them, and these scripts put no space
# between words: in `メールはta@example.jpまで` the boundaries (?<![\w...]) and (?![\w-]) of the e-mail and phone rules
# never hold, so the address was missed or its span took the words around it. Those rules end a value at a word
# character that is no CJK letter (_NOT_CJK_WORD), and scan() cuts CJK letters off the front of an address (filter
# cjk-head). Ranges: Hangul Jamo, CJK punctuation and kana, Extension A and the base block of the ideographs, Hangul
# syllables, compatibility ideographs and the fullwidth forms. Each class costs about 0.5 ms to compile in every hook
# process, so the rules hold one each (review of 0.6.24).
_CJK = ("\u1100-\u11ff\u3000-\u30ff\u3130-\u318f\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af\uf900-\ufaff"
        "\uff00-\uffef")
_CJK_RANGES = ((0x1100, 0x11ff), (0x3000, 0x30ff), (0x3130, 0x318f), (0x3400, 0x4dbf), (0x4e00, 0x9fff),
               (0xac00, 0xd7af), (0xf900, 0xfaff), (0xff00, 0xffef))
_NOT_CJK_WORD = "(?![" + _CJK + "])\\w"


_CJK_CHAR_RE = _LazyRx("[" + _CJK + "]")


def _has_cjk(text: str) -> bool:
    return not text.isascii() and _CJK_CHAR_RE.search(text) is not None


def _without_cjk(pattern: str) -> str | None:
    """The form of a pattern for a text without a CJK letter: each use of the class _CJK goes. None when a use is
    left that this cannot remove, so the rule keeps its one form."""
    plain = (pattern.replace(_NOT_CJK_WORD, r"\w").replace("(?<=[" + _CJK + "])|", "")
             .replace("[" + _CJK + "]", "(?!)").replace(_CJK, ""))
    return None if "[]" in plain or "[^]" in plain else plain


def _is_cjk(ch: str) -> bool:
    o = ord(ch)
    return any(lo <= o <= hi for lo, hi in _CJK_RANGES)


# the value of a password in a sentence: optional quotes, no stop of the sentence at its end (`!` stays), and a stop,
# a space, a quote or the end after it
# a word before the password word that names whose password it is: WLAN-Passwort, Root-Passwort, wifi-password with a
# hyphen; joined without one only a few German words (Adminpasswort). Other words end in a password word by chance:
# deşifre (decipher), resenha (review)
_PW_COMPOUND = (r"(?:[^\W\d_]{2,20}-|(?:admin|root|master|haupt|einmal|start|initial|wlan|benutzer|nutzer)"
                r"(?=pass|kenn))?")
# a value of Markdown inline code or in bold (`<value>`, **<value>**), or in the corner brackets of Chinese and Japanese
# (「<value>」), is the value without the marks. The value is the shortest run that a space, a quote, the end or the
# stops of a sentence (. , ; : ? ) 。 …) follow: a `*`, `!`, `<` or `\` inside or at the end stays part of it (Abc*12x!,
# Gretel: a password with a Markdown escape)
_SENTENCE_VALUE = (r"(?:\*\*|[\"'`\u201e\u201c\u201a\u2018\u00ab\u00bb\u300c\u300e])?"
                   r"(?=[^\s\d]{0,255}\d)"   # a digit is in it (the checks need one): a word is refused at once
                   r"([^\s\"'`\u201c\u201d\u201e\u201a\u2018\u2019\u00ab\u00bb\u300c-\u300f]{0,255}?"
                   r"[^\s\"'`\u201c\u201d\u201e\u201a\u2018\u2019\u00ab\u00bb.,;:?)\u3002\u2026" + _CJK + r"])"
                   r"(?:\*\*|[\"'`\u201c\u201d\u2018\u2019\u00ab\u00bb\u300d\u300f])?"
                   r"(?=[.,;:?)\u3002\u2026]*(?:[\s\"'`\u201c\u201d\u2018\u2019\u00ab\u00bb" + _CJK + r"]|$))")


OWN_RULES: list[dict] = [
    # ?token=… / &api_key=… in a URL
    {"id": "url-query-secret", "type": "SECRET", "secret_group": 2,
     "regex": r"(?i)[?&]((?:access_?)?token|api[_-]?key|apikey|secret|password|sig|signature)=([^&\s#\"']{8,})"},
    {"id": "email", "type": "EMAIL", "validator": "person_email",
     # the last label is alphabetic: `lodash@4.17.21`, `checkout@v4.1.1` and Homebrew's
     # `python@3.14/3.14.7` are version pins, not addresses (review, 2026-09-26)
     # a look ahead for the @ first: a text without an address is passed at once. A CJK letter ends the address
     # (_NOT_CJK_WORD) and scan() cuts CJK letters off its front (cjk-head): an address next to Japanese text
     "regex": r"(?=[\w.+-]{0,64}@|(?<![\w.+-])[\w.+-]{65,}@)"
              r"(?:\b[\w.+-]{1,64}|(?<![\w.+-])[\w.+-]{64,}|[\w.+-]{64})"
              r"@[\w-]{1,63}(?:\.[\w-]{1,63})*\.[A-Za-z]{2,63}(?!-|" + _NOT_CJK_WORD + r")"},
    # an IBAN in lower case, plain or in groups of four; its validator also wants the country's length
    {"id": "iban-lowercase", "type": "IBAN", "validator": "iban",
     # also after an MT940 subfield code (?31), as PRESIDIO_LEFT_SUBFIELD
     "regex": r"(?:(?<![A-Za-z0-9])|(?<=\?[0-9]{2}))[a-z]{2}[0-9]{2}"
              r"(?:[a-z0-9]{11,30}|(?:[ -][a-z0-9]{4}){2,7}(?:[ -][a-z0-9]{1,3})?)"
              r"(?![A-Za-z0-9])"},
    {"id": "email-percent-encoded", "type": "EMAIL", "validator": "person_email_encoded",
     # the @ as %40 in a query string, a form body, an access log (public benchmark, 2026-10-11: 7 addresses
     # passed); scan() keeps it only where an address is expected (_ENCODED_MAIL_CONTEXT_RE)
     "regex": r"(?:(?<![\w.+%-])|(?<=(?i:mailto%3a))|(?<=%3[Dd]))[\w.+-]{1,64}%40"
              r"[\w-]{1,63}(?:\.[\w-]{1,63})*\.[A-Za-z]{2,63}(?![\w-])"},
    {"id": "phone", "type": "PHONE",
     # a CJK letter before or after the number is a boundary, as in the e-mail rule
     "regex": r"(?:(?<=[" + _CJK + r"])|(?<!\w))(?<!\+)\+(?!0)\d{1,3}[ \-]?(?:\(?\d{1,5}\)?[ \-]?)\d{2,5}"
              r"(?:[ \-]?\d{2,5}){1,4}(?![\w.](?<![xX])\d|" + _NOT_CJK_WORD + r")"},
    # bare token prefixes newer than the vendored rulesets live in rules/prefixes.txt (see _load_prefixes)
    {"id": "auth-scheme", "type": "SECRET", "secret_group": 3,
     "regex": r"(?<![\w-])(Bearer|Basic)([ \t]+)([A-Za-z0-9._~+/=-]{16,})"},
    # a password with no user in a URL: redis://:pw@host, the form Redis and some brokers use. ds-basic-auth needs a
    # user before the colon; same characters and the same value filter otherwise (corpus of 0.6.7)
    {"id": "url-password-no-user", "type": "SECRET", "secret_group": 1, "validator": "ds_value",
     "regex": r"://:([^:/?#\[\]@!$&'()*+,;=\s]+)@"},
    # the secret half of an AWS key pair has no prefix of its own; the console, a CSV export
    # and a chat paste show it within a few lines after the AKIA… id (field report, 2026-09-26). Each line part is
    # bounded at 400 characters: unbounded, each id scanned the rest of its line, and a line of ids took O(n^2)
    # (32K: 2.3 s, 256K: 97 s, past the client's timeout). The longest field form, the console's credentials CSV
    # row (user, password, id, secret, console link), puts about 150 characters around the secret.
    {"id": "aws-secret-after-access-key", "type": "SECRET", "secret_group": 1,
     "regex": r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])(?:[^\n]{0,400}\n){0,4}?[^\n]{0,400}?"
              r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])"},
    # a password with no shape where no `=` or `:` stands between label and value (public benchmark holdout v7,
    # 2026-10-12: all ten leaked passwords had one of these five forms). They are label rules (LABEL_RULES): the
    # keyword filters of scan() and the test-code rule apply as to `password=<value>`.
    # `pg_dump --password '<value>'`, `--db-password <value>`, PowerShell `-Password <value>`; the `=` form is
    # ds-keyword-equal-signs. A flag before a space, so `--password-stdin` and `--password-file` stay options
    {"id": "label-cli-password", "type": "SECRET", "secret_group": 2, "validator": "flag_value",
     "regex": r"(?<![\w-])--?(?!(?i:no|ask|skip|prompt|without|one|two|single|multi|first|second)[-_])"
              r"(?:[A-Za-z][A-Za-z0-9]*[-_])*"
              r"(?i:password|passwd|passphrase|pass|pwd)[ \t]+"
              r"(['\"]?)(?!-|(?:file|env|fd):|stdin(?![\w-]))(?:pass:)?([^\s'\"<>]{1,256}?)\1(?=$|[\s;|&)\]\\])"},
    # `mysql -u app -p'<value>' db`: the value glued to -p (a space after -p asks for it; -P is the port)
    {"id": "label-mysql-p", "type": "SECRET", "secret_group": 2, "validator": "glued_value",
     "regex": r"(?<![\w-])(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mysqlcheck|mysqlpump|mariadb"
              r"|mariadb-dump|mariadb-admin)(?:\.exe)?(?![\w-])[^\n|;&]{0,400}?[ \t]-p(['\"]?)([^\s'\"<>]{1,256}?)\1"
              r"(?=$|[\s;|&)\]])"},
    # redis-cli: `127.0.0.1:6379> AUTH <value>` (or AUTH <user> <value>) at a prompt or the start of a line, and
    # `redis-cli -a <value>`. AUTH in capitals, as Redis documents it; `auth token expired` is prose
    {"id": "label-redis-auth", "type": "SECRET", "secret_group": 2, "validator": "word_value",
     "regex": r"(?m)(?:^[ \t]*|>[ \t]?)AUTH[ \t]+(?![=:]|LOGIN[ \t])(?:[^\s'\"]+[ \t]+)?"
              r"(?!(?:CRAM-MD5|DIGEST-MD5|SCRAM-SHA-[0-9]+(?:-PLUS)?|XOAUTH2|OAUTHBEARER|GSSAPI|NTLM|EXTERNAL"
              r"|ANONYMOUS|PLAIN|LOGIN)[ \t]*$)"   # an SMTP or IMAP AUTH names a SASL mechanism (Gate B of 0.6.15)
              r"(['\"]?)([^\s'\"<>]{1,256})\1[ \t]*$"},
    {"id": "label-redis-cli-a", "type": "SECRET", "secret_group": 2, "validator": "word_value",
     "regex": r"(?<![\w-])redis-cli(?![\w-])[^\n|;&]{0,400}?[ \t]-a[ \t]+"
              r"(['\"]?)([^\s'\"<>]{1,256}?)\1(?=$|[\s;|&)\]])"},
    # .netrc: `machine <host> login <user> password <value>`, on one line or on several. The host has a dot, a colon
    # or a digit (or is localhost): "on my dev machine the password changed" is prose. `default` starts an entry at a
    # line start, or anywhere before `login` (a second entry on the line, a grep prefix); "the default password
    # policy_v2" is prose (round 2 of 0.6.15)
    {"id": "label-netrc-password", "type": "SECRET", "secret_group": 1, "validator": "word_value",
     "regex": r"(?:(?<![\w-])machine[ \t]+(?:[^\s]*[.:0-9][^\s]*|localhost)"
              r"|(?<![^\n])[ \t]*default|(?<![\w-])default(?=[ \t]+login[ \t]))"
              r"(?:\s+(?:login|account|port)[ \t]+[^\s]+)*"
              r"\s+password[ \t]+([^\s]{1,256})"},
    # prose: "my password is <value>". Only a value that is no word of a sentence: it holds a capital or a symbol
    # beyond - _ . and a digit or a symbol ("the password is incorrect" stays prose). English only: the German
    # sentence of tests/fp_corpus.py (`Das Passwort ist` and a season and a year) is kept silent
    {"id": "label-prose-password", "type": "SECRET", "secret_group": 1, "validator": "prose_value_bang",
     "regex": r"(?i)(?<![\w-])(?:password|passwd|passphrase)[ \t]+(?:is|was)[ \t]*:?[ \t]+"
              r"[\"'„“]?([^\s\"'“”]{0,255}[^\s\"'“”.,;:!?)]!*)[\"'“”]?(?=[.,;:!?)]*(?:[\s\"'<\\]|$))"},
    # a typed sentence with no `:` or `=` after the password word (field report, 2026-10-16: Codex sent the value of
    # "Passwort <value>." in the clear). The words of each label language that is on (_PW_WORDS_OF). With a copula
    # ("Kennwort ist <value>", "mot de passe est <value>") the value check of the prose rule above: a digit and a
    # letter, and a capital or a sign beyond - _ . ("Passwort ist geheim" stays text). With only a space, an arrow,
    # a dash or a parenthesis ("Passwort <value>.", "password -> <value>") the sentence says less, so the value must
    # also be no run of English words (SHA256-Hash, iPhone15, JDK21-Update) and no ticket id (PBE-3403). A stop of
    # the sentence after the value is no part of it; `!` is, as passwords end with it
    {"id": "label-password-after-word", "type": "SECRET", "secret_group": 1, "validator": "sentence_value",
     "regex": r"(?i)(?:(?<![\w-])" + _PW_COMPOUND + r"(?:{pairs})[ \t]+|{cjk_pairs})" + _SENTENCE_VALUE,
     "languages": True},
    {"id": "label-password-after-space", "type": "SECRET", "secret_group": 1, "validator": "spaced_value",
     "regex": r"(?i)(?:(?<![\w-])" + _PW_COMPOUND + r"(?:{words})|{cjk_words})(?![\w-])"
              r"(?:[ \t]*(?:->|=>|\u2192|\u2013|\u2014)[ \t]*|[ \t]+-{1,2}[ \t]+|[ \t]+\(?[ \t]*)"
              + _SENTENCE_VALUE,
     "languages": True},
    # three more forms of a typed sentence (benchmark V3, Nemotron dev: about 540 passwords in the clear). An
    # apposition, "the password, <value>, works": the value check after a space, as a list of words follows a comma
    # too. "the password for <account> is <value>": up to five words between the password word and the copula,
    # English only. "use <value> as the password": the value before the word, after a verb that hands it over, with
    # the check after a space (no ticket id: "use PBE-3403 as the password ticket")
    {"id": "label-password-apposition", "type": "SECRET", "secret_group": 1, "validator": "spaced_value",
     "regex": r"(?i)(?<![\w-])" + _PW_COMPOUND + r"(?:{words})(?![\w-])[ \t]*,[ \t]+" + _SENTENCE_VALUE,
     "languages": True},
    {"id": "label-password-for-is", "type": "SECRET", "secret_group": 1, "validator": "sentence_value",
     "regex": r"(?i)(?<![\w-])(?:password|passphrase|passcode)[ \t]+(?:for|of|on|to)[ \t]+(?:[\w.@'-]+[ \t]+){1,5}?"
              r"(?:is|was)[ \t]*:?[ \t]+" + _SENTENCE_VALUE},
    # the same with other words between the password word and the copula: "the wifi password here is <value>", "the
    # VPN password I use for it is <value>" (Benchmark V3, aparte dev). One to four words, none of them a copula, and
    # the value check of a sentence
    {"id": "label-password-words-is", "type": "SECRET", "secret_group": 1, "validator": "sentence_value",
     "regex": r"(?i)(?<![\w-])(?:password|passphrase|passcode)[ \t]+(?!(?:for|of|on|to)[ \t])"
              r"(?:(?!(?:is|was)[ \t])[\w.@'-]+[ \t]+){1,4}?(?:is|was)[ \t]*:?[ \t]+" + _SENTENCE_VALUE},
    {"id": "label-password-use-as", "type": "SECRET", "secret_group": 1, "validator": "spaced_value",
     "regex": r"(?i)(?<![\w-])(?:use|using|enter|type|set|with)[ \t]+(?:\*\*|[\"'`„“])?"
              r"([^\s\"'`“”]{4,255}?)(?:\*\*|[\"'`“”])?[ \t]+as[ \t]+"
              r"(?:(?:the|your|my|a|an|its|their|our)[ \t]+)?(?:(?:new|temporary|initial|default|admin|root)[ \t]+)?"
              r"(?:password|passphrase|passcode)(?![\w-])"},
    # each quoted value of a list after a label that names secrets: `"api_keys": ["<v1>", "<v2>"]`,
    # `passwords = ['<v1>']`, Go `Secrets: []string{"<v1>"}`. The label rules took no value that starts with a
    # bracket, so a whole list of keys stayed in the clear. Only a label that names secrets and nothing else: a bare
    # `tokens` is the output of a tokenizer, and code_tokens, cache_tokens or revokedTokens name no secret (Gate B of
    # 0.6.16: 30 false alarms in developer text). The regex finds the label and the opening bracket; _list_matches
    # reads the values and keeps only those that look like a key (_list_value_ok). No tuple: the Elasticsearch client
    # takes api_key=("<id>", "<key>"), and the id is public
    {"id": "label-secret-list", "type": "SECRET", "secret_group": 2,
     "regex": r"(?i)(?<![\w$.-])[\"']?(passwords?|passwd|secrets?|api[_-]?(?:keys?|tokens?|secrets?)"
              r"|(?:access|auth|refresh|bearer)[_-]?tokens?|client[_-]?secrets?|private[_-]?keys?|secret[_-]?keys?"
              r"|credentials)[\"']?[ \t]*(?::=|=>|[:=])[ \t]*(\[\][\w.]*[ \t]*\{|[\w.]*\[\][ \t]*\{|\[)"},
    # four token formats with a public prefix and no rule in the vendored sets (0.6.16). The third NTLMSSP message in
    # base64 (`Authorization: NTLM TlRMTVNTUAAD…`: its response is derived from the password hash; the negotiate and
    # challenge messages carry none); a
    # NATS nkey seed (S, the key type, 56 base32 characters; the public key starts with N, U, A … and stays text);
    # a PASERK secret, local or wrapped key (k1. to k4.; k4.public., k4.lid. and the other ids stay text); a PASETO
    # token (v1. to v4., local or public: a bearer token as a JWT is one)
    {"id": "ntlmssp-message", "type": "SECRET",
     "regex": r"(?<![A-Za-z0-9+/])TlRMTVNTUAAD[A-Za-z0-9+/]{30,}={0,2}"},
    {"id": "nats-nkey-seed", "type": "SECRET",
     "regex": r"(?<![A-Za-z0-9])S[UNOACXP][A-Z2-7]{56}(?![A-Za-z0-9])"},
    {"id": "paserk-secret-key", "type": "SECRET",
     "regex": r"(?<![\w.])k[1-4]\.(?:local|secret|local-wrap|secret-wrap|local-pw|secret-pw|seal)\."
              r"(?:[A-Za-z0-9_-]+\.){0,3}[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"},   # dot-separated parts, no end dot
    {"id": "paseto-token", "type": "SECRET",
     "regex": r"(?<![\w.])v[1-4]\.(?:local|public)\.[A-Za-z0-9_-]{30,}(?:\.[A-Za-z0-9_-]+)?"},
    # the STS session token of temporary AWS credentials: a presigned URL carries it as the query parameter
    # X-Amz-Security-Token (percent-encoded), a request as the header of that name. The other X-Amz- parameters (the
    # key id in X-Amz-Credential, X-Amz-Signature, X-Amz-Date) stay text; the session token grants access until it
    # expires. 100 to 4096 characters: real tokens have several hundred
    {"id": "label-aws-session-token", "type": "SECRET", "secret_group": 1,
     "regex": r"(?i)(?<![\w-])x-amz-security-token(?:[\"']?[ \t]*[:=][ \t]*[\"']?)([A-Za-z0-9%+/=_-]{100,4096})"
              r"(?![A-Za-z0-9%+/=_-])"},
    # Elasticsearch's API key in an Authorization header: `Authorization: ApiKey <base64 of id:key>`, as a header
    # line, in curl -H, or as the key of a header object (`authorization: 'ApiKey <value>'`). Only after the header
    # name: prose names the scheme ("send ApiKey followed by …", Gate B of 0.6.16)
    # crypto wallet secrets (0.6.19): each is found by its checksum and needs no label. A Bitcoin private key in Wallet
    # Import Format (Base58Check, version 0x80: 51 characters from 5, or 52 from K or L for a compressed key; on testnet
    # 0xEF, from 9 or c), and a BIP32 extended private key (xprv, and the yprv, zprv, Yprv, Zprv, tprv, uprv, vprv,
    # Uprv, Vprv of SLIP-0132). The public forms (an address, an xpub) are no secret and stay text
    {"id": "crypto-wif-private-key", "type": "SECRET", "validator": "wif",
     "regex": r"(?<![1-9A-HJ-NP-Za-km-z])(?:[59][1-9A-HJ-NP-Za-km-z]{50}|[KLc][1-9A-HJ-NP-Za-km-z]{51})"
              r"(?![1-9A-HJ-NP-Za-km-z])"},
    {"id": "crypto-extended-private-key", "type": "SECRET", "validator": "xprv",
     "regex": r"(?<![1-9A-HJ-NP-Za-km-z])[xyztuvYZUV]prv[1-9A-HJ-NP-Za-km-z]{100,108}"
              r"(?![1-9A-HJ-NP-Za-km-z])"},
    # three token formats with no literal prefix, so not in rules/prefixes.txt (0.6.19). A Telegram bot token: the
    # bot's id, a colon and 34 or 35 characters starting with A (the Bot API documentation's example has 34), alone
    # or in the API URL .../bot<token>/sendMessage (Gate B of 0.6.19). A Mailchimp API key: 32 hex digits and the
    # data centre (-us1 …). A Discord bot token: three base64url parts, the first the bot's user id in base64, which
    # the validator decodes: a random three-part value is not a run of 17 to 20 digits there
    {"id": "telegram-bot-token", "type": "SECRET",
     "regex": r"(?:(?<=/bot)|(?<![0-9A-Za-z_:-]))[0-9]{5,16}:A[0-9A-Za-z_-]{33,34}"
              r"(?![0-9A-Za-z_-])"},
    {"id": "mailchimp-api-key", "type": "SECRET",
     "regex": r"(?<![0-9A-Za-z])[0-9a-f]{32}-us[0-9]{1,2}(?![0-9A-Za-z])"},
    {"id": "discord-bot-token", "type": "SECRET", "validator": "discord_bot_token",
     "regex": r"(?<![0-9A-Za-z_.-])[MNO][0-9A-Za-z_-]{23,27}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27,38}"
              r"(?![0-9A-Za-z_.-])"},
    # a BIP39 seed phrase: 12 to 24 words of the English list whose checksum holds (checksums.bip39_spans; the regex is
    # never run). Twelve words carry a checksum of 4 bits, so one list of ordinary words in 16 passes ("client connect
    # system process input output error return result update file edit", Gate A of 0.6.19): a phrase of 12 needs a word
    # such as seed, mnemonic or wallet in the 200 characters before it or on its line; 15 and more (5 to 8 bits) stand
    # alone
    {"id": "crypto-seed-phrase", "type": "SECRET", "regex": r"(?!)"},
    # a Twilio Account SID (AC and 32 hex digits) next to its name: the SID and the auth token together log in, and
    # the holdout sets of the public benchmark (2026-10-14) leaked three. Without the name, AC and 32 hex digits are
    # also hashes and ids
    {"id": "twilio-account-sid-labelled", "type": "SECRET", "secret_group": 1, "validator": "random_hex",
     "regex": r"(?i:twilio|account_?sid|(?<![a-z])sid(?![a-z]))[^\n]{0,40}?(?<![A-Za-z0-9])(AC[0-9a-f]{32})"
              r"(?![A-Za-z0-9])"},
    {"id": "auth-scheme-apikey", "type": "SECRET", "secret_group": 1, "validator": "apikey_value",
     "regex": r"(?i:authorization)[\"']?\]?[ \t]*[:=][ \t]*[\"'`]?ApiKey[ \t]+([A-Za-z0-9+/_-]{8,1024}={0,2})"
              r"(?![\w+/=-])"},
    # a PEM private key in base64: the tls.key or ssh-privatekey of a Kubernetes Secret, a CI variable, a Helm value.
    # The run starts with the base64 of "-----BEGIN"; the validator decodes its first 400 characters and keeps it only
    # if the header names a PRIVATE KEY and base64 body follows, or if a bundle holds one later (a certificate alone
    # stays text). The whole value is the secret, also when `base64` or openssl wrapped it at a fixed width, with
    # real or escaped line breaks (_base64_wrapped_end).
    # In 0.6.19 no rule found it, also not after a label (a catalog survey, 2026-10-14)
    {"id": "private-key-base64", "type": "SECRET", "validator": "base64_pem",
     "regex": r"(?<![A-Za-z0-9+/])(?:77u/)?LS0tLS1CRUdJTi[A-Za-z0-9+/]{16,}={0,2}"},
    # token formats whose literal prefix is shorter than four characters, so not in rules/prefixes.txt (0.6.20). The
    # character after the prefix is checked by a lookbehind written after the prefix, so the regex still starts with
    # its literal and the engine skips a text without it. Sources: crates.io and NuGet from Nosey Parker (Apache-2.0),
    # Dropbox, Firecrawl and ElevenLabs from Kingfisher (Apache-2.0); each regex is written here. A crates.io or NuGet
    # key needs one digit, and its body must not read as words: an identifier such as cioServiceConfiguration… is no
    # key. ElevenLabs: exactly 48 hex digits after sk_ (Stripe's sk_live_ and sk_test_ have an underscore there).
    # Firecrawl and ElevenLabs keys are hex by design, so a digest after fc- or sk_ is taken too (no hit in the
    # developer texts or in CredData's code files, 0.6.20)
    {"id": "crates-io-api-token", "type": "SECRET", "validator": "token_not_words",
     "regex": r"cio(?:(?<![A-Za-z0-9_]cio)|(?<=\\[nrt]cio))(?=[A-Za-z]{0,31}[0-9])[A-Za-z0-9]{32}(?![A-Za-z0-9_])"},
    {"id": "nuget-api-key", "type": "SECRET", "validator": "token_not_words",
     "regex": r"oy2(?:(?<![A-Za-z0-9_]oy2)|(?<=\\[nrt]oy2))(?=[a-z]{0,42}[0-9])[a-z0-9]{43}(?![A-Za-z0-9_])"},
    {"id": "dropbox-short-lived-token", "type": "SECRET",
     "regex": r"sl\.(?:(?<![A-Za-z0-9_.-]sl\.)|(?<=\\[nrt]sl\.))"
              r"(?:u\.)?(?=[A-Za-z_-]{0,2047}[0-9])[A-Za-z0-9_-]{130,2048}(?![A-Za-z0-9_-])(?!\.[A-Za-z0-9_-])"},
    {"id": "firecrawl-api-key", "type": "SECRET",
     "regex": r"fc-(?:(?<![A-Za-z0-9_-]fc-)|(?<=\\[nrt]fc-))[a-f0-9]{32}(?![A-Za-z0-9_-])(?!\.[A-Za-z0-9]|\{)"},
    {"id": "elevenlabs-api-key-bare", "type": "SECRET",
     "regex": r"sk_(?:(?<![A-Za-z0-9_]sk_)|(?<=\\[nrt]sk_))[0-9a-f]{48}(?![A-Za-z0-9_])(?!\.[A-Za-z0-9]|\{)"},
    # an Aiven service password (GitLab's rule, MIT): AVNS_ and 15 to 123 characters. A name of words after the prefix
    # (AVNS_Configuration01) is no password (codex Gate A of 0.6.20)
    {"id": "aiven-service-password", "type": "SECRET", "validator": "token_not_words",
     "regex": r"AVNS_(?:(?<![A-Za-z0-9_]AVNS_)|(?<=\\[nrt]AVNS_))[0-9A-Za-z_-]{15,123}(?![0-9A-Za-z_-])"},
    # SonarQube's analysis tokens (GitLab's rules, MIT): sqa_ (global) and sqp_ (project) and 40 hex digits, the shape
    # of a git commit id after a word such as "sqa" (software quality assurance), so only with "sonar" near it (Gate B
    # of 0.6.20). The user token squ_ stands alone (rules/prefixes.txt)
    {"id": "sonarqube-analysis-token", "type": "SECRET", "context": ("sonar", "sonarqube", "sonarcloud"),
     "require_context": True,
     "regex": r"sq[ap]_(?:(?<![A-Za-z0-9_]sq[ap]_)|(?<=\\[nrt]sq[ap]_))[0-9a-f]{40}(?![A-Za-z0-9_])"},
]


# Fallbacks that run after the vendored rules (0.6.20): forms of a key whose vendored rule fixes one length, so the
# standard form keeps its vendored rule id. Found in a measurement on real session transcripts (values not kept):
# OpenAI project keys of other lengths around T3BlbkFJ (the base64 of "OpenAI"; the vendored rule takes 20, 58 or 74
# characters on each side) and Anthropic API keys of other lengths (the vendored rule takes exactly 93 characters
# before AA). Each also takes a key before a full stop, which the vendored terminators refuse. The vendored rule of
# such a key matches whole or not at all; GitLab's trigger and job tokens are in rules/prefixes.txt, as the vendored
# rule there takes the first part of a longer token (codex Gate A)
FALLBACK_RULES: list[dict] = [
    {"id": "openai-api-key-any", "type": "SECRET",
     "regex": r"sk-(?:(?<![A-Za-z0-9_-]sk-)|(?<=\\[nrt]sk-))"
              r"(?:proj|svcacct|admin)-[A-Za-z0-9_-]{8,400}?T3BlbkFJ[A-Za-z0-9_-]{8,400}(?![A-Za-z0-9_-])"},
    {"id": "anthropic-api-key-any", "type": "SECRET",
     "regex": r"sk-ant-(?:(?<![A-Za-z0-9_-]sk-ant-)|(?<=\\[nrt]sk-ant-))(?:api03|admin01)-[A-Za-z0-9_-]{60,140}AA"
              r"(?![A-Za-z0-9_-])"},
    # 0.6.21, from the values that leaked in the public benchmark's holdout sets: an OpenAI or Anthropic key and a
    # Slack token with a shorter tail and no marker of the forms above. The sk- tail needs a digit, a capital and a run
    # of 16 letters and digits; the Slack tail starts with digits and a hyphen, as Slack writes it:
    # sk-admin-sidebar-navigation-item2X and xoxb-background-worker-release-2024 are names. A key that a rule above
    # takes (T3BlbkFJ inside, api03- and AA at the end) is left to it
    {"id": "openai-anthropic-key-relaxed", "type": "SECRET",
     "regex": r"(?<![\w-])sk-(?:proj|ant|svcacct|admin)-"
              r"(?![A-Za-z0-9_-]{0,400}T3BlbkFJ)"
              r"(?!(?:api03|admin01)-[A-Za-z0-9_-]{60,140}AA"
              r"(?![A-Za-z0-9_-]))"
              r"(?=[A-Za-z0-9_-]{0,200}[0-9])"
              r"(?=[A-Za-z0-9_-]{0,200}[A-Z])"
              r"(?=[A-Za-z0-9_-]{0,200}?[A-Za-z0-9]{16})[A-Za-z0-9_-]{20,}"},
    {"id": "slack-token-relaxed", "type": "SECRET",
     "regex": r"(?<![\w-])(?:xoxb-|xoxp-|xoxa-|xoxr-)\d{2,}-[A-Za-z0-9-]{12,}"},
    # the password of a URL with a sign that RFC 3986 reserves (! $ & + , ; = *; an @ after it stays in it): a database
    # URL as people write it, unescaped (postgres://app:<value>@db:5432). ds-basic-auth stops at these signs and the
    # e-mail rule took `<rest>@host` (Benchmark V3, aparte and llmredactor dev). Only the password, as there: the user
    # stays text. A template (${DB_PASSWORD}, $(cat …)) fails the value check
    {"id": "url-password-signs", "type": "SECRET", "secret_group": 1, "validator": "ds_value",
     "regex": r"(?<![\w+.-])[A-Za-z][A-Za-z0-9+.-]{1,15}://[^\s:/?#\[\]@'\"`<>]{1,64}:"
              r"(?=[^\s/@'\"`<>]{0,127}[!$&*+,;=])((?:[^\s/@'\"`<>]|@(?=[^\s/@'\"`<>]*@)){3,128})"
              r"@(?=[A-Za-z0-9\[_])"},
    # the application keys of two frameworks in an .env file (Benchmark V3, aparte dev: 11 keys in the clear). Laravel's
    # APP_KEY=base64:<the base64 of 32 bytes>: `key` alone is a weak label, which the literal rules take only quoted.
    # Strapi's APP_KEYS=<k1>,<k2>,…: each key of the unquoted list (_list_matches reads them)
    {"id": "label-laravel-app-key", "type": "SECRET", "secret_group": 1, "validator": "laravel_key",
     "regex": r"(?m)^[ \t]*(?:export[ \t]+)?APP_KEY[ \t]*=[ \t]*[\"']?(base64:[A-Za-z0-9+/]{20,44}={0,2})(?![\w+/=])"},
    {"id": "label-env-key-list", "type": "SECRET", "secret_group": 2,
     "regex": r"(?m)^[ \t]*(?:export[ \t]+)?(APP_KEYS)[ \t]*=[ \t]*([\"']?)"},
    # a key that a sentence owns and names: "my stripe key is <value>", "our google api key for the map widget is
    # <value>", "the session JWT is <value>" (Benchmark V3, aparte dev). label-prose-key wants the key word right before
    # the value; here a possessive or an article starts it, up to two words name the service, and up to four words
    # after for/of/on/in name the use. The value check of label-prose-key: a random shape of 16 characters or more. A
    # public or publishable key (Stripe's pk_) is no secret
    {"id": "label-prose-key-owned", "type": "SECRET", "secret_group": 1, "validator": "prose_key_value",
     "regex": r"(?i)(?<![\w-])(?:my|our|your|the|his|her|their)[ \t]+(?:(?!public|publishable)[\w.-]+[ \t]+){0,2}?"
              r"(?:key|token|secret|jwt)(?:[ \t]+(?:for|of|on|in)(?:[ \t]+[\w.@'-]+){1,4}?)?[ \t]+(?:is|was)"
              r"[ \t]*:?[ \t]+[`\"'„“]?(?!pk_)([A-Za-z0-9_+/=.-]{15,511}[A-Za-z0-9_+/=])[`\"'“”]?"
              r"(?=[.,;:!?)]?(?:\s|$))"},
    # a key or a salt of PHP's define() (wp-config.php: AUTH_KEY, NONCE_SALT): the WordPress salts hold ( ) | ` and
    # the literal rules took them for code (Benchmark V3, aparte dev: 16 salts in the clear). Only a name that ends in
    # KEY, SALT, SECRET or TOKEN; a password is label-pw-literal's
    {"id": "label-php-define-key", "type": "SECRET", "secret_group": 3, "validator": "config_key_value",
     "regex": r"(?<![\w$>:])define[ \t]*\([ \t]*(['\"])(?:[A-Z][A-Z0-9]*_)*(?:KEY|SALT|SECRET|TOKEN)\1[ \t]*,[ \t]*"
              r"(['\"])((?:(?!\2)[^\\\n]){16,256})\2[ \t]*\)"},
    # a key in a sentence: "Use the API key <value> for the call", "the access token is <value>", "the API key,
    # <value>, expires". No `:` or `=` tells that a value follows, so the value must look random (prose_key_value)
    # and have 16 characters at least. A bare `token` is the word of a tokenizer too; its values (a number, a word)
    # fail the value check. After the vendored rules: a key of a known format keeps its rule id
    {"id": "label-prose-key", "type": "SECRET", "secret_group": 1, "validator": "prose_key_value",
     "regex": r"(?i)(?<![\w-])(?:api[ _-](?:key|token|secret)|access[ _-]?(?:token|key)|auth(?:entication)?[ _-]?"
              r"(?:token|key)|bearer[ _-]?token|secret[ _-]?key|client[ _-]?secret|(?:personal[ _-]?access|private)"
              r"[ _-]?token|token)s?(?:[ \t]+(?:is|was))?[ \t]*[:,(]?[ \t]+[`\"'„“]?"
              r"([A-Za-z0-9_+/=.-]{15,511}[A-Za-z0-9_+/=])[`\"'“”]?(?=[.,;:!?)]?(?:\s|$))"},
]


# ------------------------------------------------------------- rule loading --
# betterleaks rules left out: a filter that is a program (let bindings; rule_filter.Unsupported) would run without
# it, and maisecrets' own label rules cover these shapes (ds-keyword, url-query-secret, the email rule)
BETTERLEAKS_SKIP_UNSUPPORTED = True

# Corrections to vendored betterleaks rules. scripts/sync_betterleaks.py overwrites rules/betterleaks.json, so they
# live here and apply when the rules load. Each names the upstream regex it expects ("expect"); after a re-sync that
# changes that regex, tests/test_rules_from_the_catalogs.py goes red, and the correction is checked against the new
# rule (and dropped if upstream fixed it). Found by a coverage measurement against other catalogs (0.6.20):
# - three keyword lists named only the provider, so a bare token without the provider's name was never searched;
#   the token's own prefix is now a keyword too (the regex is unchanged). The Airtable regex also used the RE2 class
#   [[:alnum:]], which Python read as a set of six characters; _re2_to_python now translates the POSIX classes
# - WakaTime's waka_ key is waka_ and a UUID (Kingfisher's rule and examples); the regex took no hyphen
BETTERLEAKS_PATCHES = {
    "resend-api-key.1": {"add_keywords": ("re_",)},
    "ionic-personal-access-token": {"add_keywords": ("ion_",)},
    "airtable-personnal-access-token": {"add_keywords": ("pat",)},
    "microsoft-teams-webhook": {
        "expect": r"https://[a-z0-9]+\.webhook\.office\.com/"
                  r"webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@"
                  r"[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/"
                  r"IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}",
        # the ids also in capital hex (the vendored [a-z0-9] stays, so no old hit is lost), a word boundary on both
        # sides, and a further path part after the last id stays in the hit (codex Gate A of 0.6.39)
        "regex": r"https(?:(?<![A-Za-z0-9]https)|(?<=\\[nrt]https))://[a-z0-9]+\.webhook\.office\.com/"
                 r"webhookb2/[0-9a-zA-F]{8}-(?:[0-9a-zA-F]{4}-){3}[0-9a-zA-F]{12}@"
                 r"[0-9a-zA-F]{8}-(?:[0-9a-zA-F]{4}-){3}[0-9a-zA-F]{12}/"
                 r"IncomingWebhook/[0-9a-zA-F]{32}/[0-9a-zA-F]{8}-(?:[0-9a-zA-F]{4}-){3}[0-9a-zA-F]{12}"
                 r"(?:/[0-9A-Za-z_-]{20,})?(?![0-9A-Za-z_-])",
        "reason": "the ids were capturing groups, so a hit masked 17 of 204 characters; the whole URL is the "
                  "credential (0.6.39, #11)"},
    "wakatime-api-key.2": {
        "expect": r"""(?i)\b(waka_[a-z0-9]{36,64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)""",
        "regex": r"""(?i)\b(waka_(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[a-z0-9]{36,64}))"""
                 r"""(?:\\?['"\x60]|[\s;]|\\[nr]|$)"""},
}


# The terminator that 336 vendored rules end with takes a quote, a space, ";" or a line end, which is right for an
# assignment and wrong for a sentence: "the key is <token>." or "(<token>)" lost the whole hit. The terminator now
# also takes sentence punctuation before a space or the end of the text; a dot before a letter (a host name) is still
# no end, nor is punctuation next to a quote: `"<value>", "next"` and `<key>: "…"` are code, not a sentence (two
# false alarms in the FP bank). The terminator is outside the secret group, so no value changes (0.7.11)
_VENDORED_END = r"""(?:\\?['"\x60]|[\s;]|\\[nr]|$)"""
_SENTENCE_END = r"""(?:\\?['"\x60]|[\s;]|\\[nr]|$|(?<!['"\x60])[.,:!?)](?=\s|$)(?!\s*['"\x60]))"""


def _patched(r: dict) -> dict:
    """The rule with its BETTERLEAKS_PATCHES entry applied, then the sentence terminator. A regex correction applies
    only to the regex it expects."""
    patch = BETTERLEAKS_PATCHES.get(r.get("id"))
    r = dict(r)
    if patch and patch.get("add_keywords"):
        r["keywords"] = list(r.get("keywords") or []) + [k for k in patch["add_keywords"]
                                                        if k not in (r.get("keywords") or [])]
    if patch and patch.get("regex") and r.get("regex") == patch["expect"]:
        r["regex"] = patch["regex"]
    if r.get("regex", "").endswith(_VENDORED_END):
        r["regex"] = r["regex"][:-len(_VENDORED_END)] + _SENTENCE_END
    return r


def _load_own_secret_rules() -> list[Rule]:
    """maisecrets' own secret rules (rules/own_secret_rules.json; patterns derived from gitleaks v8.30.1, MIT), with
    their entropy and allowlists: generic-api-key, to which the keyword window (_WINDOWED) and the label filters of
    scan() are tuned, and the token forms the betterleaks rules miss (etsy, jfrog, a bare Fly.io token, a labelled
    Atlassian token, a legacy Vault token, …). They run after betterleaks, so they only fill its gaps."""
    cfg = json.loads((RULES_DIR / "own_secret_rules.json").read_text(encoding="utf-8"))
    rules: list[Rule] = []
    for r in cfg["rules"]:
        allow: list[tuple[re.Pattern[str], str]] = []
        stop: list[str] = []
        for al in r.get("allowlists", []) or []:
            # as in gitleaks: no regexTarget means the secret, "match" the whole match, "line" the line
            target = al.get("regexTarget", "secret")
            for arx in al.get("regexes", []) or []:
                allow.append((_Lazy(_re2_to_python(arx)), target))
            stop += [s.lower() for s in al.get("stopwords", []) or []]
        rules.append(Rule(
            id=r["id"], type="SECRET", regex=_Lazy(_re2_to_python(r["regex"])),
            keywords=tuple(k.lower() for k in r.get("keywords", []) or ()),
            entropy=float(r.get("entropy", 0) or 0), secret_group=int(r.get("secretGroup", 0) or 0),
            allow_regexes=tuple(allow), stopwords=tuple(stop),
        ))
    return rules


def _load_betterleaks() -> list[Rule]:
    """The vendored betterleaks rules (rules/betterleaks.json, synced by scripts/sync_betterleaks.py). A rule with
    skipReport is a component that betterleaks never reports alone (a client id beside its secret); a rule without a
    regex matches by file path only. Each filter, and the global one, is read by rule_filter; a filter that module
    cannot read leaves its rule out."""
    from . import rule_filter
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")   # "possible nested set" in some regexes
        # betterleaks.json is the same rules as JSON, for a Python without tomllib; a test keeps the two equal
        cfg = json.loads((RULES_DIR / "betterleaks.json").read_text(encoding="utf-8"))
        global_drop = rule_filter.compile_filter(cfg["filter"]) if cfg.get("filter") else None
        rules: list[Rule] = []
        # 379 filters are 45 different texts: each text is read once. A filter is a pure function of its text, so the
        # rules with the same text share it (the parse of every filter was two thirds of rules(), 2026-10-16)
        read: dict = {}
        for r in cfg.get("rules", []):
            if "regex" not in r or r.get("skipReport"):
                continue
            r = _patched(r)
            own = None
            if r.get("filter"):
                if r["filter"] not in read:
                    try:
                        read[r["filter"]] = rule_filter.compile_filter(r["filter"])
                    except rule_filter.Unsupported:
                        read[r["filter"]] = None
                own = read[r["filter"]]
                if own is None and BETTERLEAKS_SKIP_UNSUPPORTED:
                    continue
            drop = _combine_drops(own, global_drop)
            rules.append(Rule(
                id=r["id"], type="SECRET", regex=_Lazy(_re2_to_python(r["regex"])),
                keywords=tuple(k.lower() for k in r.get("keywords", []) or ()),
                secret_group=int(r.get("secretGroup", 0) or 0), drop=drop,
            ))
    return rules


def _combine_drops(*drops):
    live = [d for d in drops if d is not None]
    if not live:
        return None
    return lambda env: any(d(env) for d in live)


# entity -> placeholder type (short, stable); anything else keeps its entity name
ENTITY_TYPE = {"EMAIL_ADDRESS": "EMAIL", "IBAN_CODE": "IBAN", "CREDIT_CARD": "CARD",
               "IP_ADDRESS": "IP", "PHONE_NUMBER": "PHONE"}
# covered by OWN_RULES with bounded regexes and validators, or not PII worth a placeholder. The German ID card and
# passport are REGIONAL_RULES: Presidio reads the 9th character as an ICAO check digit over the first 8, but the card
# prints the 9-character number without its check digit (it stands in the machine-readable zone only), so 37 of 40
# real-shaped numbers and the number of the official specimen card were missed (survey of other detectors, 0.6.19).
# de-handelsregister: a company's register number, public in the Handelsregister and no personal data
# uk-postcode: a postcode alone identifies no one (a fork's bench, 2026-10-12: every hit was a false alarm); a street
# address with its postcode is personal.py's
PRESIDIO_SKIP = {"email", "url", "date", "mac-address", "uuid", "phone", "de-id-card", "de-passport",
                 "crypto", "de-handelsregister", "uk-postcode"}
# validator id per presidio recognizer id; a recognizer with a validator we did not port
# keeps its pattern score and is treated as weak (context required)
PRESIDIO_VALIDATOR = {"iban": "iban", "credit-card": "luhn", "ip": "public_ip",
                      "de-tax-id": "de_tax_id", "de-social-security": "de_social_security",
                      "de-health-insurance": "de_health_insurance", "de-lanr": "de_lanr",
                      "de-bsnr": "de_bsnr", "de-vat-id": "de_vat_id", "us-ssn": "us_ssn",
                      # 0.6.19: with the context word alone a value with a wrong check digit was a hit
                      "pl-pesel": "pl_pesel", "es-nif": "es_nif", "es-nie": "es_nie", "nhs": "uk_nhs",
                      "aba-routing": "us_aba", "it-fiscal-code": "it_fiscal_code",
                      # 0.6.24, from a fork (danszymkowiak/maisecrets d72ea2b, Apache-2.0): Presidio's own checks
                      "us-npi": "us_npi", "se-organisationsnummer": "se_organisationsnummer",
                      "uk-vehicle-registration": "uk_vehicle_registration"}
# shapes that are plain digit runs: even with a valid checksum, ask for a context word. The validators ported in
# 0.6.19 keep the context word they needed before: a check digit alone passes one value in 10 to 26
PRESIDIO_ALWAYS_CONTEXT = {"de-tax-id", "de-tax-number", "de-bsnr", "de-lanr", "de-plz", "de-kfz",
                           "de-fuehrerschein", "nhs", "aba-routing", "medical-license", "pl-pesel", "es-nif",
                           "es-nie", "it-fiscal-code", "us-npi", "se-organisationsnummer",
                           "uk-vehicle-registration"}
# A card number that passes Luhn is masked in a tool result without a card word nearby (0.6.24). Measured on the four
# labelled PII datasets: +340 card numbers, +49 false alarms (41 of them identifiers of structured financial messages
# in Gretel), CredData +2 false alarms; docs/BENCHMARKS.md. A typed prompt keeps the card word: a block there costs
# more than a mask. A documented test card stays text (rules/public_test_values.txt). From a fork
# (danszymkowiak/maisecrets 795b411, d5807ea, Apache-2.0)
CARD_ALONE_IN_TOOL = frozenset({"credit-card"})
# issuer prefixes and lengths (ISO/IEC 7812 IIN ranges of the networks): Visa, Mastercard, American Express, Discover,
# JCB (also its 15-digit 2131 and 1800), Diners Club, UnionPay
_CARD_ISSUERS = _LazyRx(r"4\d{15}|5[1-5]\d{14}|2(?:2[2-9]|[3-6]\d|7[01])\d{13}|2720\d{12}|3[47]\d{13}"
                           r"|6(?:011|5\d\d|4[4-9]\d)\d{12}|35(?:2[89]|[3-8]\d)\d{12}|3(?:0[0-5]|[68]\d)\d{11}|62\d{14}"
                           r"|(?:2131|1800)\d{11}")
_CARD_GROUPS = _LazyRx(r"\d{4}([ -])\d{4}\1\d{4}\1\d{4}|\d{4}([ -])\d{6}\2\d{5}|\d{4}([ -])\d{6}\3\d{4}")


# a label that names an id (order_id, event_id, "job_id", invoice no, imei, serial): the number after it is that id
_ID_LABEL_BEFORE_RE = _LazyRx(r"(?i)(?:(?:^|[^a-z])(?:imei|serial|reference|ref)|(?:id|no|nr|num|number|#))[\"']?"
                                 r"\s{0,3}[:=#]\s{0,3}[\"']?\s{0,3}$")


def _card_shaped(text: str, start: int, secret: str) -> bool:
    """A number written as a card: in groups of four (4-6-5 for Amex, 4-6-4 for Diners) or as one run, with the
    prefix and the length of a card network, and not part of a decimal, a phone number or a longer digit run. A float,
    a timestamp and an IMEI pass Luhn as often as a card does (review of 0.6.24); the issuer table keeps them out."""
    v = secret.strip()
    end = start + len(secret)
    sep = re.sub(r"\d", "", v)[:1]
    fifth = bool(sep) and re.match(re.escape(sep) + r"\d{4}(?!\d)", text[end:end + 6])
    # a comma before the number is a CSV cell (17,4532 0151 ...), not a decimal: a decimal is no group of four
    if start and text[start - 1] in "+.-0123456789" or text[end:end + 1].isalnum() \
            or re.match(r"\.\d", text[end:end + 2]) or fifth:
        return False   # a decimal, a phone number, a longer run, a fifth group (an expiry such as 12/28 may follow)
    if _ID_LABEL_BEFORE_RE.search(text, max(0, start - 30), start):
        return False   # order_id=4111 ...: an id that passes Luhn
    # an unbroken run too, with the prefix and the length of a card network: Benchmark V1, Gretel cards 299 to 431,
    # Mendeley +119, 14 more false alarms in Gretel, the false-alarm bank +0. A float, a timestamp, an IMEI and an
    # order id stay out by the checks above and by the issuer table (no 15-digit 35..., no 17...)
    return bool((_CARD_GROUPS.fullmatch(v) or v.isdigit()) and _CARD_ISSUERS.fullmatch(re.sub(r"\D", "", v)))


# a Presidio pattern with no boundary: PESEL's eleven digits matched inside a longer digit run
PRESIDIO_DIGIT_BOUNDED = {"pl-pesel"}
# single patterns that need a context word although their recognizer does not: DE and nine digits that pass the
# checksum are also FIX tags and XML identifiers; a real VAT ID stands next to USt-IdNr or VAT. The spaced form
# (de-vat-id#1) has a low score and needs its word already
PRESIDIO_PATTERN_CONTEXT = {"de-vat-id#0"}
# card words the vendored recognizer lacks: its words are English, so a card number after "Karte" in a German bank
# statement reached the model. The number must still pass Luhn. A short word that means something else in a
# neighbour language (kort: short in Danish and Dutch) stays out
PRESIDIO_EXTRA_CONTEXT = {
    # 2026-10-19, Benchmark V1: a CSV or JSON key `steuer_id` over a valid tax id; the checksum still decides
    "de-tax-id": ("steuer_id", "steuer_identifikationsnummer", "steuer-identifikationsnummer", "steuer_idnr"),
    "credit-card": ("karte", "kreditkarte", "kartennummer", "kartennr", "debitkarte", "bankkarte", "ec-karte",
                    "girocard", "carte", "cartes", "carta", "tarjeta", "creditcard", "kaart", "cart\u00e3o", "karta",
                    # 0.6.24, review: the PAN of a payment log, a camelCase key, and the Nordic and Polish words
                    "pan", "cardnumber", "ccnum", "ccnumber", "karty", "kortnummer", "kaartnummer", "korttinumero",
                    "kreditkort", "kortnr"),
}
# A bare run of 8 to 17 digits with "account" or "bank" nearby (us-bank) also takes the dates of a finance document,
# written YYYYMMDD: Benchmark V1, Gretel, 1,435 of its false alarms. A window of 30 characters before the number took
# 3,447, but lost 681 card and 251 account numbers that only this rule found (Mendeley, Nemotron), so first only the
# date went; the label window below came after the card fix (docs/BENCHMARKS.md, "Rule changes measured with
# Benchmark V1")
PRESIDIO_NO_DATE = frozenset({"us-bank"})
# The label of a us-bank number stands before it, on its own line, within 60 characters ("the account number associated
# with this loan is ..."). Presidio's window (80 before, 40 after, across lines) also took a bare number whose line
# named no account: Benchmark V1, Gretel, 1,920 of its false alarms (5,607 to 3,687). It costs 73 of 9,051 account
# numbers in Nemotron, mostly table rows whose label is the header line above. 30 characters lost 251 there; across
# lines took 948 false alarms back for 25. It needs the card fix: before it, 681 Mendeley card numbers were found only
# by this rule (docs/BENCHMARKS.md, "Rule changes measured with Benchmark V1")
PRESIDIO_LABEL_BEFORE = {"us-bank": 60}
# A driver license written in hyphenated groups (Wisconsin A123-4567-8901-23, Illinois A123-4567-8901): Presidio's
# pattern ends at a word boundary, so it took the letter and the first digits and left the rest in the clear
# (Benchmark V1, Gretel dev: 114 licenses with 11 of 15 characters unmasked). The hit takes up to four following
# groups of digits when the token ends there
PRESIDIO_HYPHEN_TAIL = frozenset({"us-license#0"})
_HYPHEN_DIGITS_TAIL_RE = _LazyRx(r"(?:-\d{1,5}){1,4}(?![\w-])")
# A us-bank match is the whole number or nothing: `\b[0-9]{8,17}\b` took the ten digits after the hyphen of an account
# number written 482-3917265104, and that shorter hit won the overlap against the label rule that had the whole number,
# so three digits reached the model. Benchmark V1, Nemotron: 2,197 account numbers found only in part. The same for the
# digits of a driver license after a letter prefix (CL-4882019): the label rule had the whole certificate number
PRESIDIO_WHOLE_DIGIT_RUN = frozenset({"us-bank", "us-license#1"})
# A DEA certificate number has no word boundary in Presidio's pattern: it matched two letters and seven digits inside a
# longer license number and left the letters before and the digits after in the clear (Benchmark V2, Nemotron dev: 121
# medical licenses found in part). A validated hit takes the whole token of letters and digits around it
PRESIDIO_WHOLE_TOKEN = frozenset({"medical-license"})
# Presidio tags every US/UK/IN/AU/… recognizer as language "en", so language is the wrong
# switch: an Indian PAN rule produced 290 false positives in one German transcript. The
# switch is the REGION, derived from the recognizer id; "generic" is always on.
REGION_OF_ID = {"nhs": "uk", "aba-routing": "us", "medical-license": "us"}
DEFAULT_PII_REGIONS = ("generic",)   # without a config: the rules of no country

# country rules of our own (0.6.19): forms Presidio has no pattern for, and Switzerland and Austria, which it has no
# rules for. The design follows a fork of this project (Apache-2.0, see NOTICE). Each rule names its region; a rule
# with require_context needs one of its context words within 80 characters before or 40 after the value.
_DE_TAX_ID_CONTEXT = ("steueridentifikationsnummer", "steuer-id", "steuerid", "steuerliche identifikationsnummer",
                      "steuerliche identifikation", "persönliche identifikationsnummer", "steuer identifikation",
                      "idnr", "steuer-idnr", "identifikationsnummer", "bzst",
                      "steuer_id", "steuer_identifikationsnummer", "steuer-identifikationsnummer", "steuer_idnr")
_DE_ID_CARD_CONTEXT = ("personalausweis", "ausweis", "personalausweisnummer", "ausweisnummer", "ausweis-nr",
                       "ausweisnr", "personalausweisnr", "dokumentennummer", "ausweisdokument", "npa",
                       "neuer personalausweis", "bundespersonalausweis", "identity card", "id card", "id-card",
                       "national id", "mrz")
_DE_PASSPORT_CONTEXT = ("reisepass", "passnummer", "reisepassnummer", "reisepass-nr", "pass-nr", "passnr",
                        "reisepassnr", "dokumentennummer", "passport", "passport number", "mrz")
_CH_AHV_CONTEXT = ("ahv", "avs", "ahv-nr", "ahv-nummer", "ahvn13", "avs-nr", "sozialversicherungsnummer",
                   "sozialversicherung", "versichertennummer", "sv-nummer", "numéro avs", "numero avs", "n° avs",
                   "no avs", "assurance sociale", "assicurazione sociale")
_AT_SV_CONTEXT = ("sozialversicherungsnummer", "versicherungsnummer", "sv-nummer", "sv-nr", "svnr", "vsnr",
                  "e-card", "sozialversicherung")
_VAT_CONTEXT = ("uid", "uid-nr", "uid-nummer", "ust-id", "ust-idnr", "ustid", "umsatzsteuer",
                "umsatzsteuer-identifikationsnummer", "mwst", "mwst-nr", "tva", "iva", "vat", "vat id", "vat number",
                "unternehmens-identifikationsnummer")
_DOC = "CFGHJKLMNPRTVWXYZ"
REGIONAL_RULES: list = [
    # the German ID card and passport: 9 characters as printed on the card, or 10 with the ICAO check digit as in the
    # machine-readable zone. BSI TR-03123-2 v1.8.2, 3.2.1, and the BMI sheet "Die Dokumentennummer in deutschen
    # Ausweisen und Pässen" (2023-11-01): the consonants C F G H J K L M N P R T V W X Y Z and the digits (0 only before
    # 2021-11), the first a letter since 2023-11 (the specimens of 2010, 2019 and 2021 start with one too)
    {"id": "de-id-card", "region": "de", "type": "DE_ID_CARD", "validator": "de_document",
     "context": _DE_ID_CARD_CONTEXT, "require_context": True,
     "regex": rf"(?<![A-Za-z0-9])[{_DOC}][{_DOC}0-9]{{8}}[0-9]?(?![A-Za-z0-9])"},
    {"id": "de-passport", "region": "de", "type": "DE_PASSPORT", "validator": "de_document",
     "context": _DE_PASSPORT_CONTEXT, "require_context": True,
     "regex": rf"(?<![A-Za-z0-9])[{_DOC}][{_DOC}0-9]{{8}}[0-9]?(?![A-Za-z0-9])"},
    # the Steuer-ID as the tax office prints it, 2-3-3-3 digits; the 11 digits in one run are Presidio's de-tax-id
    {"id": "de-tax-id-spaced", "region": "de", "type": "DE_TAX_ID", "validator": "de_tax_id_spaced",
     "context": _DE_TAX_ID_CONTEXT, "require_context": True,
     "regex": r"(?<![\d.,/-])(?<!\d[ \u00a0])[1-9][0-9][ \u00a0][0-9]{3}[ \u00a0][0-9]{3}[ \u00a0][0-9]{3}"
              r"(?![0-9]|[ \u00a0][0-9])"},
    # the Rentenversicherungsnummer as the SV-Ausweis prints it: 2, 6 (birth date), 1 letter, 3, with spaces; the run
    # without spaces is Presidio's de-social-security, which needs no context word in the same date-checked form
    {"id": "de-social-security-spaced", "region": "de", "type": "DE_SOCIAL_SECURITY",
     "validator": "de_social_security_spaced",
     "regex": r"(?<![\w.,/-])[0-9]{2}[ \u00a0](?:0[1-9]|[12][0-9]|3[01]|5[1-9]|[67][0-9]|8[01])(?:0[1-9]|1[0-2])"
              r"[0-9]{2}[ \u00a0][A-Z][ \u00a0][0-9]{3}(?![\w])"},
    # Switzerland: the AHV/AVS number with its dots stands alone; the 13 digits without them need a context word
    {"id": "ch-ahv", "region": "ch", "type": "CH_AHV", "validator": "ch_ahv", "context": _CH_AHV_CONTEXT,
     "regex": r"(?<![\d.])756\.[0-9]{4}\.[0-9]{4}\.[0-9]{2}(?![0-9]|\.[0-9])"},
    {"id": "ch-ahv-digits", "region": "ch", "type": "CH_AHV", "validator": "ch_ahv", "context": _CH_AHV_CONTEXT,
     "require_context": True, "regex": r"(?<![\d.])756[0-9]{10}(?![0-9]|\.[0-9])"},
    # a company number is public in its register: like the German VAT ID, only next to a word that names it
    {"id": "ch-uid", "region": "ch", "type": "CH_UID", "validator": "ch_uid", "context": _VAT_CONTEXT,
     "require_context": True,
     "regex": r"(?<![\w-])CHE[- ]?[0-9]{3}\.?[0-9]{3}\.?[0-9]{3}(?:[ ]?(?:MWST|TVA|IVA))?(?![\w]|[.,][0-9])"},
    # Austria
    {"id": "at-uid", "region": "at", "type": "AT_UID", "validator": "at_uid", "context": _VAT_CONTEXT,
     "require_context": True, "regex": r"(?<![\w-])ATU[ ]?[0-9]{8}(?![\w])"},
    {"id": "at-social-security", "region": "at", "type": "AT_SOCIAL_SECURITY", "validator": "at_social_security",
     "context": _AT_SV_CONTEXT, "require_context": True,
     "regex": r"(?<![\d.,/-])[1-9][0-9]{3}[ \u00a0]?(?:0[1-9]|[12][0-9]|3[01])(?:0[1-9]|1[0-2])[0-9]{2}(?![0-9])"},
]


def _load_regional(regions: tuple[str, ...] = DEFAULT_PII_REGIONS) -> list[Rule]:
    return [Rule(id=d["id"], type=d["type"], regex=_Lazy(d["regex"]), validator=d["validator"],
                 context=tuple(d.get("context", ())), require_context=d.get("require_context", False),
                 whole_match=True, region=d["region"])
            for d in REGIONAL_RULES if d["region"] in regions]


def presidio_region(rec_id: str) -> str:
    if rec_id in REGION_OF_ID:
        return REGION_OF_ID[rec_id]
    head = rec_id.split("-", 1)[0]
    return head if len(head) == 2 and rec_id.count("-") >= 1 else "generic"


# an IBAN after a subfield code of an MT940 bank statement export (`:86:...?31DE89...?32NAME`): Presidio's left
# boundary refuses a digit before the country code, so the counterparty IBAN reached the model. From a fork
# (danszymkowiak/maisecrets 8c943ee, Apache-2.0); the subfield code is `?` and two digits
_IBAN_LEFT = "(?<![A-Z0-9])"
PRESIDIO_LEFT_SUBFIELD = {"iban": "(?:(?<![A-Z0-9])|(?<=\\?[0-9]{2}))"}


# Presidio's card pattern takes the first digits 1, 3, 4, 5 and 6, so a Mastercard of the 2-series (2221 to 2720,
# issued since 2017) and a 15-digit JCB (2131) never reached the Luhn check. Benchmark V1, Mendeley: 681 such card
# numbers, all Luhn-valid, were covered only by chance, by the us-bank rule (2026-10-19). The first group takes those
# two ranges too; the correction applies only to the upstream text it expects.
_CARD_FIRST_UPSTREAM = r"((4\d{3})|(5[0-5]\d{2})|"
PRESIDIO_CARD_FIRST = {"credit-card": r"((4\d{3})|(5[0-5]\d{2})|(2(?:22[1-9]|2[3-9]\d|[3-6]\d\d|7[01]\d|720))|(2131)|"}


def _presidio_regex(rec_id: str, regex: str) -> str:
    left = PRESIDIO_LEFT_SUBFIELD.get(rec_id)
    if left and regex.startswith(_IBAN_LEFT):
        return left + regex[len(_IBAN_LEFT):]
    first = PRESIDIO_CARD_FIRST.get(rec_id)
    if first and regex.count(_CARD_FIRST_UPSTREAM) == 1:
        # a Visa number of 19 digits (ISO/IEC 7812 allows 13, 16 and 19): Presidio's groups end at 17 digits, and
        # Mendeley's 2,081 such numbers (Luhn-valid, each after a card word) stayed in the clear (2026-10-20). It
        # keeps the rule's Luhn check and its card word: alone in a tool result the issuer check takes 16 digits only
        return "(?:" + regex.replace(_CARD_FIRST_UPSTREAM, first) + r")|\b4\d{18}\b"
    return regex


def _load_presidio(regions: tuple[str, ...] = DEFAULT_PII_REGIONS) -> list[Rule]:
    data = json.loads((RULES_DIR / "presidio.json").read_text(encoding="utf-8"))
    out: list[Rule] = []
    for rec in data["recognizers"]:
        region = presidio_region(rec["id"])     # once, here: the rule carries it from now on
        if rec["id"] in PRESIDIO_SKIP or region not in regions:
            continue
        validator = PRESIDIO_VALIDATOR.get(rec["id"])
        weak = rec["id"] in PRESIDIO_ALWAYS_CONTEXT or (rec["validator"] and validator is None)
        for i, pat in enumerate(rec["patterns"]):
            rule_id = rec["id"] if len(rec["patterns"]) == 1 else f"{rec['id']}#{i}"
            out.append(Rule(
                id=rule_id,
                type=ENTITY_TYPE.get(rec["entity"], rec["entity"]),
                regex=_Lazy(rf"(?<!\d)(?:{_re2_to_python(pat['regex'])})(?!\d)" if rec["id"] in PRESIDIO_DIGIT_BOUNDED
                            else _presidio_regex(rec["id"], _re2_to_python(pat["regex"]))),
                validator=validator, score=float(pat["score"]),
                context=tuple(c.lower() for c in rec.get("context", [])) + PRESIDIO_EXTRA_CONTEXT.get(rec["id"], ()),
                require_context=weak or rule_id in PRESIDIO_PATTERN_CONTEXT,
                whole_match=True, region=region,
            ))
    return out


# detect-secrets' denylist is English (plus Spanish contraseña). The labels it lacks, English
# ones such as `pass:` and `token:` and those of other languages such as `passwort:`, come from
# rules/labels/<language>.txt for each active label language (maisecrets/detection/regions.py).
# The two keyword rules whose quote is optional, and the group of that quote. Their value class
# runs to the end of the line, spaces included, and the whole span was then judged: a password
# followed by "and" and an address was rejected as prose, so the password reached the model
# (field report, 2026-09-27). An unquoted value ends at the first whitespace; only a quoted one
# holds spaces. A cut value that is one capitalised word ("secret: Developers, Webhooks, …",
# "a secret: PostToolUse must …", both in this repository) is the start of a sentence.
_DS_QUOTE_GROUP = {"ds-keyword-colon": 3, "ds-keyword-equal-signs": 4}
# the end of the label in the vendored colon rules, and the same with up to three spaces, tabs,
# no-break or narrow no-break spaces before the colon
_COLON_AFTER_LABEL = "([]\\'\"]{0,2})?:"
_COLON_AFTER_LABEL_SPACED = "([]\\'\"]{0,2})?[ \\t\u00a0\u202f]{0,3}:"
# and with a backslash before each quote: a JSON object inside a string, as a log line, an HTTP body in a test or a
# tool output shows it (`{\"password\":\"<value>\"}`). The label's quotes were no closer, so no value was read
# (Samsung CredData, line by line: 62 such credentials missed, 2026-10-12). The backslash before the value's opening
# quote is skipped only before a quote; the one before its closing quote is cut in scan()
_COLON_AFTER_LABEL_ESCAPED = "((?:\\\\?[]'\"]){0,2})?[ \\t\u00a0\u202f]{0,3}:"
_ESCAPABLE_COLON_RULES = ("ds-keyword-colon", "ds-keyword-colon-quotes-required")   # group 2: the label's quote
_COLON_THEN_QUOTE = (":\\s*([\\'\"`]?)", ":(\\s*)([\\'\"`])")
_ESCAPED_QUOTE_SKIP = "(?:\\\\(?=[\"']))?"
_WHITESPACE_RE = _LazyRx(r"\s")
# the label tail of the vendored keyword rules: `<keyword>\w*` and then a separator. On `password=` and a long run of
# letters with no space, each keyword inside the run (pwd, key) took the rest of the run and gave it back one character
# at a time (the rule with a quote and a semicolon tried 50 more characters each time): quadratic, 320 KB took 10 s,
# also in 0.6.15. What follows `\w*` in these rules never starts with a word character (a quote, ], a space, a colon,
# =, or `[^\s]{0,50}?` that a shorter run can only reach less far with), so the regex matches only where `\w*` takes
# the whole run. _KeywordTail finds each keyword, jumps to the end of its word run with an index of the runs, and runs
# the rest of the regex once per run end: the same matches, in linear time. tests/test_scan_bounds.py compares it
# with the vendored regex on runs of 0 to 5000 characters
class _KeywordTail:
    r"""A vendored keyword regex `(<alternatives>)\w*<tail>` matched without backtracking into the word run."""
    __slots__ = ("pattern", "flags", "_prefix", "_alts", "_any", "_tail", "_heads", "_cross", "_rx")

    def __init__(self, pattern: str, keywords_prefix: str, alts: list, flags: int) -> None:
        self.pattern, self.flags, self._prefix, self._alts = pattern, flags, keywords_prefix, alts
        self._any = self._tail = None
        self._heads: list = []

    def _compile(self) -> None:
        if self._any is not None:
            return
        tail = self.pattern[len(self._prefix) + len("\\w*"):]
        any_ = re.compile(self._prefix, self.flags)
        groups = any_.groups
        # the alternatives that can match a character outside a word (mot de passe): only they can start inside a
        # word run and end past it. Every other one ends inside the run, at the run's end once \w* has run
        cross = [a for a in self._alts if _CROSS_CHARS_RE.search(_LOOKAROUND_RE.sub("", a))]
        self._rx = re.compile(self.pattern, self.flags)
        # one head per alternative, in the regex's order; the others never match but keep their group numbers
        self._heads = [re.compile("(?<!mai)(" + "|".join(a if j == i else "(?!)" + a for j, a in enumerate(self._alts))
                                  + ")", self.flags) for i in range(len(self._alts))]
        self._tail = re.compile("()" * groups + tail, self.flags)   # empty groups keep the numbers of backreferences
        self._cross = re.compile("(?<!mai)(?:" + "|".join(cross) + ")", self.flags) if cross else None
        self._any = any_   # last: another thread takes a set _any for a complete rule

    def finditer(self, text: str):
        self._compile()
        if _LONG_WORD_RUN_RE.search(text) is None:
            # no word run of 200 characters: the vendored regex backtracks at most that far per keyword, and its C
            # loop is faster than this one on ordinary lines
            yield from self._rx.finditer(text)
            return
        tails: dict = {}
        word = _WORD_RUN_ANY_RE
        pos, n = 0, len(text)
        while pos <= n:
            m = self._any.search(text, pos)
            if m is None:
                return
            p = m.start()
            w = word.match(text, m.end())
            if w is None or w.end() - m.end() < 200:
                # a short word run after the keyword: the vendored regex at p backtracks at most that far, and it is
                # the same regex. Only a keyword before a long run takes the loop below (codex verification of 0.6.16:
                # one long word made the whole text slow)
                r = self._rx.match(text, p)
                if r is not None:
                    yield r
                    pos = r.end() if r.end() > p else p + 1
                else:
                    pos = p + 1
                continue
            hit = None
            e = -1
            # the first alternative that matches at p is the one the regex tries first: the search found it already
            for h in itertools.chain((m,), (head.match(text, p) for head in self._heads)):
                if h is None:
                    continue
                q = h.end()
                w = word.match(text, q)
                e = w.end() if w is not None else q     # \w* takes the whole run after the keyword
                if e not in tails:
                    tails[e] = self._tail.match(text, e)
                t = tails[e]
                if t is not None:
                    hit = _HeadTail(text, h, t)
                    break
            if hit is None:
                pos = p + 1
                run = word.match(text, p)
                if run is not None and run.end() == e and e > pos:
                    # p starts a word run whose rest failed: a keyword later in the run that stays in it fails too.
                    # Only an alternative that leaves the run can start a match before its end
                    c = self._cross.search(text, pos, e + 256) if self._cross is not None else None
                    pos = c.start() if c is not None and c.start() < e else e
                continue
            yield hit
            pos = hit.end() if hit.end() > p else p + 1

    def search(self, text: str):
        return next(self.finditer(text), None)

    @property
    def groups(self) -> int:
        self._compile()
        return self._tail.groups


class _HeadTail:
    """A match of _KeywordTail: the groups of the keyword from the head, the rest from the tail."""
    __slots__ = ("_text", "_h", "_t", "_n")

    def __init__(self, text: str, h, t) -> None:
        self._text, self._h, self._t, self._n = text, h, t, h.re.groups

    def group(self, i: int = 0):
        if i == 0:
            return self._text[self._h.start():self._t.end()]
        return self._h.group(i) if i <= self._n else self._t.group(i)

    def start(self, i: int = 0) -> int:
        if i == 0:
            return self._h.start()
        return self._h.start(i) if i <= self._n else self._t.start(i)

    def end(self, i: int = 0) -> int:
        if i == 0:
            return self._t.end()
        return self._h.end(i) if i <= self._n else self._t.end(i)

    def span(self, i: int = 0) -> tuple:
        return self.start(i), self.end(i)


_WORD_RUN_ANY_RE = _LazyRx(r"\w+")
_LONG_WORD_RUN_RE = _LazyRx(r"\w{200}")
_LOOKAROUND_RE = _LazyRx(r"\(\?<?[=!][^()]*\)")
_CROSS_CHARS_RE = _LazyRx(r"[ .\[-]|\\[sWdbBSD]")   # a space, a dot, a class, a hyphen or a non-word escape
_CAPITALISED_WORD_RE = _LazyRx(r"(?:[A-Z][a-z]+)+")
# the stops of a sentence after an unquoted value (the regex never ends a value on a comma)
_SENTENCE_STOP = ".;"
# rules whose value check is cheap and refuses most candidates: it runs before the checks of the code around a value
_VALIDATE_FIRST = frozenset({"label-password-after-word", "label-password-after-space", "label-password-apposition",
                             "label-password-for-is", "label-password-use-as", "label-password-words-is"})


def _load_detect_secrets(languages: tuple[str, ...] = ("en",)) -> list[Rule]:
    data = json.loads((RULES_DIR / "detect_secrets.json").read_text(encoding="utf-8"))
    from .regions import load_labels
    labels = [lab for lang in languages for lab in load_labels(lang)]
    # Chinese and Japanese write the fullwidth colon (密码：<value>, パスワード：<value>; Linux-PAM's zh_CN prompt is
    # 密码：). Only with one of them on: the rules of every other language stay as they were
    cjk = any(lang in _NO_SPACE_LANGUAGES for lang in languages)
    # every denylist word contains one of these; each label adds its own literal
    kws = tuple(sorted({"key", "pass", "pwd", "secret", "contrase"} | {lab.prefilter for lab in labels}))
    denylist = "|".join(data["denylist"])
    out: list[Rule] = []
    for r in data["rules"]:
        flags = re.IGNORECASE if r.get("ignorecase") else 0
        # the product's own name carries "secret": `/maisecrets:shortcut` was stored as a secret
        # named "shortcut" (field report, 2026-09-27); "mai" + keyword is never a label
        keywords = "(?<!mai)(" + "|".join([denylist] + [lab.regex for lab in labels]) + ")"
        regex = r["regex"].replace("(" + denylist + ")", keywords, 1)
        # the vendored value group must start with a word character, so `$+4jJzBixvQD9#`,
        # `@f6a-VtyEOYr!` and `-NA#C-X-gb4T%` were never values (2026-09-27); any first character
        # a character a password starts with may start one (not {, [, (, \\, /, <: code and paths), and
        # _ds_value_ok refuses a shell variable ($VAR, ${VAR}) as before
        regex = regex.replace("(?=\\w+)", "(?=[\\w!#$%&*+\\-@^~?.])")
        # French typography puts a space (often a no-break space) before the colon, and people type
        # `password : x` in every language; the vendored colon rules allowed none, so
        # `mot de passe : <value>` and `password : <value>` were no hit (2026-09-28)
        regex = regex.replace(_COLON_AFTER_LABEL, _COLON_AFTER_LABEL_SPACED, 1)

        if _COLON_AFTER_LABEL_SPACED in regex:
            regex = regex.replace(_COLON_AFTER_LABEL_SPACED, _COLON_AFTER_LABEL_ESCAPED, 1)
            for q in _COLON_THEN_QUOTE:   # the skip goes right before the group of the opening quote
                at = q.rindex("([")
                regex = regex.replace(q, q[:at] + _ESCAPED_QUOTE_SKIP + q[at:], 1)
            if cjk:
                regex = regex.replace(_COLON_AFTER_LABEL_ESCAPED, _COLON_AFTER_LABEL_ESCAPED[:-1] + "[:\uff1a]", 1)
        if regex.startswith(keywords + "\\w*") and len(regex) > len(keywords) + 3:
            rx = _KeywordTail(regex, keywords, list(data["denylist"]) + [lab.regex for lab in labels], flags)
        else:
            rx = _Lazy(regex, flags)
        out.append(Rule(id=r["id"], type="SECRET", regex=rx,
                        keywords=() if r["id"] == "ds-basic-auth" else kws,
                        secret_group=int(r["group"]), validator="ds_value",
                        quote_group=_DS_QUOTE_GROUP.get(r["id"], 0)))
    return out


def _load_prefixes() -> list[Rule]:
    """Bare token prefixes newer than the vendored rulesets: maisecrets/detection/rules/prefixes.txt, one
    per line `id  regex`, extended by pull request. The whole match is the secret. The release tree for the
    directory ships the same rules as prefixes.json (scripts/build_release_tree.py), which is read when it is there."""
    shipped = RULES_DIR / "prefixes.json"
    if shipped.is_file():
        return [Rule(id=d["id"], type="SECRET", regex=_Lazy(d["regex"]))
                for d in json.loads(shipped.read_text(encoding="utf-8"))]
    out: list[Rule] = []
    for line in (RULES_DIR / "prefixes.txt").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rule_id, regex = line.split(None, 1)
        out.append(Rule(id=rule_id, type="SECRET", regex=_Lazy(regex.strip())))
    return out


def _load_literal(languages: tuple[str, ...] = ("en",)) -> list[Rule]:
    # the label words of the languages belong to the detector's snapshot: rules() sets them, not each list built
    # here (rule_specs and explain_allowed build one too)
    return [Rule(id=d["id"], type="SECRET", regex=_Lazy(r"(?!)()"), secret_group=1, keywords=d["keywords"])
            for d in LITERAL_RULES]


def _own_regex(d: dict, languages: tuple) -> str:
    """The regex of an own rule. A rule with `languages` takes the words of the label languages that are on; with
    none of its languages on it never matches."""
    want = d.get("languages")
    if not want:
        return d["regex"]
    if want is not True:
        return d["regex"] if any(lang in languages for lang in want) else r"(?!)()"
    langs = ("en",) + tuple(lang for lang in languages if lang != "en")
    words = [w for lang in langs if lang not in _NO_SPACE_LANGUAGES for w in _PW_WORDS_OF.get(lang, ())]
    # Chinese and Japanese write no space between words, so a word before the password word (我的密码, 新しいパスワード)
    # is a word character: their words take an alternative of their own with no word start. With neither language on
    # it never matches, and the rule is the one of the other languages
    cjk_words = [w for lang in langs if lang in _NO_SPACE_LANGUAGES for w in _PW_WORDS_OF.get(lang, ())]
    # a copula joins only the words of its own language (Finnish "on" after salasana, never "password on GitLab16");
    # a language whose people write the English word (Italian: "password è") joins it to the English words
    pairs, cjk_pairs = [], []
    for lang in langs:
        copulas = sorted(_PW_COPULAS_OF.get(lang, ()), key=lambda c: (-len(c), c))
        if copulas:
            own = _PW_WORDS_OF.get(lang) or _PW_WORDS_OF["en"]
            if lang in _NO_SPACE_LANGUAGES:   # 密码是<value>, パスワードは <value>: a space after the copula or none
                cjk_pairs.append("(?:" + "|".join(own) + r")[ \t]*(?:" + "|".join(copulas) + r")[ \t]*[:\uff1a]?[ \t]*")
                continue
            gap = r"[ \t]*" if lang == "th" else r"(?![\w-])[ \t]+"   # Thai writes no space between words
            pairs.append("(?:" + "|".join(own) + ")" + gap + "(?:" + "|".join(copulas) + r")[ \t]*:?")
    return (d["regex"].replace("{words}", "|".join(words)).replace("{pairs}", "|".join(pairs))
            .replace("{cjk_words}", "|".join(cjk_words) or "(?!)")
            .replace("{cjk_pairs}", "|".join(cjk_pairs) or "(?!)"))


# the words for "password" per label language (rules/labels/<language>.txt names the same words for the keyword
# rules), and the words that join it to its value in a sentence ("ist", "est", "är"). Only words that name a password
# and nothing else: `pass`, `pw` and `pin` start ordinary sentences ("boarding pass LH4821X", "PIN 4821 der SIM")
_PW_WORDS_OF = {
    "en": (r"password", r"passwd", r"passphrase"),
    "de": (r"passwort", r"kennwort"),
    "es": (r"contrase(?:ñ|n)a", r"clave[ \t]+de[ \t]+acceso"),
    "fr": (r"mot[ \t]+de[ \t]+passe",),
    "pt": (r"senha", r"palavra[ -]passe"),
    "nl": (r"wachtwoord",),
    "pl": (r"has(?:ł|l)o",),
    "tr": (r"(?:ş|s)ifre", r"parola"),
    "nb": (r"passord(?:et)?",),
    "sv": (r"l(?:ö|o)senord(?:et)?",),
    "da": (r"adgangskoden?", r"kodeord(?:et)?"),
    "fi": (r"salasana",),
    "cs": (r"heslo",),
    "ko": (r"비밀번호(?:는|가)?", r"패스워드(?:는|가)?", r"암호(?:는|가)?"),
    "th": (r"รหัสผ่าน",),
    "ru": (r"пароль",),
    "zh": (r"密[码碼]",),
    "ja": (r"パスワード",),
}
_PW_COPULAS_OF = {
    "en": ("is", "was"), "de": ("ist", "lautet", "war"), "es": ("es", "era"), "fr": ("est", "était"),
    "it": ("è",), "pt": ("é", "era"), "nl": ("is", "was"), "pl": ("to", "jest"), "nb": ("er", "var"),
    "sv": ("är", "var"), "da": ("er", "var"), "fi": ("on", "oli"), "cs": ("je",), "th": ("คือ",),
    # Russian has no copula in the present tense: это (this is) and был (was) stand in its place; "пароль: <value>" and
    # "пароль — <value>" are the colon rules and label-password-after-space. Chinese 是, 为 and 為; Japanese は
    "ru": ("это", "был"), "zh": ("是", "为", "為"), "ja": ("は",),
}
# the label languages that write no space between words (the CJK alternatives of _own_regex)
_NO_SPACE_LANGUAGES = frozenset({"zh", "ja"})


def _load_own(languages: tuple = ("en",)) -> list[Rule]:
    return [Rule(id=d["id"], type=d["type"], regex=_Lazy(_own_regex(d, languages)),
                 secret_group=d.get("secret_group", 0), validator=d.get("validator"),
                 context=tuple(d.get("context", ())), require_context=d.get("require_context", False))
            for d in OWN_RULES] + _load_prefixes()


def _user_rules() -> list[Rule]:
    """The rules of the person's folders (maisecrets/user_rules.py). A rule that fails a check is quarantined there;
    anything else that fails leaves them out, never the built-in rules."""
    try:
        return list(_sources().user_rules())
    except Exception:  # noqa: BLE001 - rules of your own are an addition; they never stop a hook
        return []


def _rule_sources(active) -> list:
    """(source, rules) of every rule list source, in the order of registry.BANDS."""
    own = _load_own(active.languages)
    n_own = len(OWN_RULES)
    return [
        ("own-secret", [r for r in own[:n_own] if r.type == "SECRET"]),
        ("prefixes", own[n_own:]),
        ("detect-secrets", _load_detect_secrets(active.languages)),
        ("betterleaks", _load_betterleaks()),
        ("own-json", _load_own_secret_rules()),
        ("fallback", [Rule(id=d["id"], type=d["type"], regex=_Lazy(d["regex"]), secret_group=d.get("secret_group", 0),
                           validator=d.get("validator")) for d in FALLBACK_RULES]),
        ("regional", _load_regional(active.regions)),
        ("presidio", _load_presidio(active.regions)),
        ("own-pii", [r for r in own[:n_own] if r.type != "SECRET"]),
        ("literal", _load_literal(active.languages)),
        ("user", _user_rules()),
    ]


def _ranked(active) -> list:
    """(priority, rule) of every rule, sorted by priority = (phase, band, seq) (maisecrets/detection/registry.py)."""
    from .registry import BANDS, PHASES, filters_of, form_of, key_of, matcher_of
    rules_phase, user_phase = PHASES["rules"], PHASES["user"]
    out = []
    for source, rs in _rule_sources(active):
        phase, band = (user_phase if source == "user" else rules_phase), BANDS[source]
        for seq, r in enumerate(rs):
            object.__setattr__(r, "key", key_of(source, r.id))   # fields of the frozen rule, set once at load
            object.__setattr__(r, "form", form_of(r.id))
            object.__setattr__(r, "matcher", matcher_of(r.id, source))
            object.__setattr__(r, "filters", filters_of(r.id))
            object.__setattr__(r, "phase", phase)
            out.append(((phase, band, seq), r))
    out.sort(key=lambda x: x[0])
    return out


def rule_specs(active=None) -> list:
    """(spec, rule) for each rule of every source, sorted by priority (maisecrets/detection/registry.py). The allow
    list is not
    applied here: `maisecrets rules list` shows a switched-off rule too."""
    from . import registry
    active = active or active_regions()
    languages = ",".join(active.languages)
    source_of = {band: source for source, band in registry.BANDS.items()}
    upstream = _upstream_rules()
    patches = {"detect-secrets": registry.DETECT_SECRETS_PATCHES,
               "betterleaks": registry.betterleaks_patches(BETTERLEAKS_PATCHES, registry.patched_upstream(RULES_DIR)),
               "presidio": registry.presidio_patches(_this_module())}
    out = []
    for (_, band, seq), r in _ranked(active):    # the same rules, marked the same way, as rules() takes them
        source = source_of[band]
        out.append((registry.make(source, r.id, r.type, seq, region=r.region, channel=registry.CHANNEL[source],
                                  language=languages if source in ("detect-secrets", "literal") else "",
                                  upstream=upstream.get((source, r.id.split("#", 1)[0])),
                                  patches=_patches_of(source, r.id, patches)), r))
    return out


def pass_specs() -> list:
    """The specs of the passes outside the rule list (registry.pass_specs): the password export and the personal-data
    rules of maisecrets/detection/personal.py, when this copy of the detector has it."""
    try:
        from . import personal
    except ImportError:
        personal = None
    if personal is None:
        return _registry.pass_specs(EXPORT_RULE, "SECRET", (), frozenset(), {})
    p = personal
    return _registry.pass_specs(EXPORT_RULE, "SECRET", tuple(p.RULE_IDS), p.PROMPT_RULES, p.TYPES,
                                regions=p.REGIONS, needs=p.NEEDS)


def _patches_of(source: str, rule_id: str, patches: dict) -> tuple:
    if source == "detect-secrets":
        return tuple(p for p in patches["detect-secrets"] if p.rule_key in ("detect-secrets:*", "detect-secrets:"
                                                                              + rule_id))
    if source == "betterleaks":
        return patches["betterleaks"].get(rule_id, ())
    if source == "presidio":
        return patches["presidio"].get(rule_id.split("#", 1)[0], ()) + (
            patches["presidio"].get(rule_id, ()) if "#" in rule_id else ())
    return ()


def _this_module():
    return sys.modules[__name__]


def _upstream_rules() -> dict:
    """{(source, upstream id): registry.Upstream} of the vendored rule files, for rule_specs() only: no hook reads
    them."""
    from .registry import Upstream, canonical_sha256

    def version(name: str) -> str:
        try:
            return (RULES_DIR / name).read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    out = {}
    for source, file, key, ver, lic in (("betterleaks", "betterleaks.json", "rules", "BETTERLEAKS_VERSION",
                                         "LICENSE-betterleaks"),
                                        ("detect-secrets", "detect_secrets.json", "rules", "DETECT_SECRETS_VERSION",
                                         "LICENSE-detect-secrets"),
                                        ("presidio", "presidio.json", "recognizers", "PRESIDIO_VERSION",
                                         "LICENSE-presidio")):
        v = version(ver)
        for r in json.loads((RULES_DIR / file).read_text(encoding="utf-8"))[key]:
            if "id" in r:
                out[(source, r["id"])] = Upstream(source, v, r["id"], canonical_sha256(r), lic)
    return out


def allow_list() -> tuple[frozenset, frozenset]:
    """(exact values, rule ids) of the allow list of the detector, read once per detector."""
    d = _det()
    if d._allow is None:
        try:
            d._allow = d._sources_now().allow_list()
        except Exception:  # noqa: BLE001 - an allow list that cannot be read allows nothing
            d._allow = (frozenset(), frozenset())
    return d._allow


def rules() -> list[Rule]:
    """Every rule, sorted by its rank in maisecrets/detection/registry.py (priority). Own secret rules first (longer
    shapes win
    the span), then betterleaks and the own rules of
    own_secret_rules.json, the fallback and regional rules, then PII, then the literal rules, then the rules of your
    own. A scan runs the personal-data step (_personal_hits) before the rules of your own (_in_scan_order). A user rule
    never takes a span before a built-in rule: a NAME rule that took a part of an e-mail address left the rest of it in
    the clear (Opus review of block 1). A user rule runs in both channels. A rule id on the allow list is switched
    off. Each detector loads its own list once."""
    d = _det()
    rules_now = d._rules
    if rules_now is not None:
        return rules_now
    with d._load_lock:   # one load at a time: a second thread waits for the first one's snapshot
        if d._rules is None:
            active = active_regions()
            every = [r for _, r in _ranked(active)]
            off = allow_list()[1]
            if off:
                every = [r for r in every if not switched_off(r.id, off)]
            d._active = active
            d._loaded_for = (every, active.regions)
            d._label_class.clear()   # the password label words depend on the languages
            d._pw_last_on = _pw_words_of(active.languages)
            d._rules = every         # last: a set rule list marks a complete snapshot
        return d._rules


def _pii_regions_cached() -> tuple:
    """The regions of the loaded rules. A rule list that a slow rule of your own left changes them not."""
    d = _det()
    current = rules()
    if d._loaded_for[0] is not current:
        d._loaded_for = (current, (d._active or active_regions()).regions)   # a list a caller set: the reader
    return d._loaded_for[1]


def reset_rules() -> None:
    """Read every rule and the allow list again at the next scan of the detector (tests, and a CLI run after a
    change)."""
    d = _det()
    d._forget(allow=True, times=True)
    d._sources_now().reset()



# The time each rule of your own spent inside its regex in this process (seconds), and the characters it ran over.
# Only the regex counts, around each step of its finditer: the work on each hit is no time of the rule (Opus review,
# round 3: a correct rule with 170k hits was taken out by the wall time of its loop). The sum runs over every scan of
# the process, so a slow text split over many strings of one tool result adds up (same review).
# The detector keeps these sums (_regex_time, _regex_chars, _regex_rule) and the step that runs now (_running).
# A rule of your own may spend this long in its regex in one process (seconds, plus USER_RULE_BUDGET_PER_MB for each
# MB of text it ran over); a rule that spends more is left out from then on (maisecrets/user_rules.py, note_slow)
USER_RULE_BUDGET = 0.5
USER_RULE_BUDGET_PER_MB = 0.1


def slowest_user_rule():
    """(rule, seconds) of the rule of your own with the most time inside its regex in this process, the step that
    runs now included; None when no rule of your own ran."""
    best = None
    d = _det()
    with d._lock:
        running = list(d._running.values())
        times = dict(d._regex_time)
        rules_by_id = dict(d._regex_rule)
    now = time.perf_counter()
    for rule, since in running:
        times[rule.id] = times.get(rule.id, 0.0) + (now - since)
        rules_by_id[rule.id] = rule
    for rid, took in times.items():
        if best is None or took > best[1]:
            best = (rules_by_id[rid], took)
    return best


def _timed(rule: Rule, found, chars: int):
    """The matches of a rule of your own; the time inside its regex adds to the rule's sum for the process. Over the
    budget, the rule is left out of this process and, by the state file, of the next ones. The sums belong to the
    detector of the scan."""
    d = _det()
    times, chars_of, running, lock = d._regex_time, d._regex_chars, d._running, d._lock
    me = threading.get_ident()
    with lock:
        d._regex_rule[rule.id] = rule
        chars_of[rule.id] = chars_of.get(rule.id, 0) + chars
    try:
        while True:
            t = time.perf_counter()
            running[me] = (rule, t)
            try:
                m = next(found)
            except StopIteration:
                break
            finally:
                took = time.perf_counter() - t
                with lock:
                    running.pop(me, None)
                    times[rule.id] = times.get(rule.id, 0.0) + took
            yield m
    finally:
        with lock:
            took, ran_over = times.get(rule.id, 0.0), chars_of.get(rule.id, 0)
        if took > USER_RULE_BUDGET + USER_RULE_BUDGET_PER_MB * ran_over / 1e6:
            _too_slow(d, rule, took)


def _too_slow(d: "Detector", rule: Rule, spent: float) -> None:
    with d._load_lock:   # the rule list belongs to the load: a reset in another thread must not get it back
        if d._rules is not None:
            d._rules = [r for r in d._rules if r is not rule]
    try:
        d._sources_now().note_slow(rule, spent * 1000)
    except Exception:  # noqa: BLE001 - the rule is out of this process either way
        pass


def _term_matches(text: str) -> list:
    """The terms (maisecrets/terms.py): names, case numbers, customer names. A bad terms.txt raises
    terms.TermsError, a ConfigError: the hook fails closed. Without any list the terms module is never imported (it
    costs about 13 ms, and each hook call is a new process): maisecrets/term_files.py says whether one is there.
    The sources of the scan give them (Sources.term_matches)."""
    return _sources().term_matches(text)


TERM_RULE = "term"                 # the pass of the terms in maisecrets/detection/registry.py (phase "terms")
TERM_KEY = "terms:" + TERM_RULE    # its key; `enabled` takes either, or the kind `term:<id>` of one entity


def _term_hits(text: str, enabled, found: list, taken_starts: list, taken_ends: list, overlaps, take) -> None:
    """The terms pass (registry phase "terms"): after the rules of your own. A term that
    a rule found too (an email address, a token-shaped case number) claims the span (_claim)."""
    if enabled is not None and TERM_RULE not in enabled and TERM_KEY not in enabled and not any(
            str(k).startswith("term:") for k in enabled):
        return
    for m in sorted(_term_matches(text), key=lambda x: x.start):
        if not ((enabled is None or TERM_RULE in enabled or TERM_KEY in enabled or m.kind in enabled)
                and m.end > m.start):
            continue
        if not overlaps(m.start, m.end):
            take(m, True)
        else:
            _claim(m, text, found, taken_starts, taken_ends)


def _import_matches(text: str) -> list:
    """The imported values (maisecrets/values.py). A damaged import raises values.ValuesError, a ConfigError: the
    hook fails closed. Without any import the values module is never imported: maisecrets/value_files.py says
    whether one is there. The sources of the scan give them (Sources.import_matches)."""
    return _sources().import_matches(text)


IMPORT_RULE = "import"                 # the pass of the imported values in detection/registry.py (phase "imports")
IMPORT_KEY = "imports:" + IMPORT_RULE  # its key; `enabled` takes either, or the kind `import:<id>:<value id>`


def _import_hits(text: str, enabled, found: list, taken_starts: list, taken_ends: list, overlaps, take) -> None:
    """The imports pass (registry phase "imports"): after the terms. An import only adds
    masking: a span that a rule or a term took keeps its kind and its placeholder (a rule hit stays resolvable), and
    only the parts of the imported value outside every taken span are hits of the import (_term_rest)."""
    if enabled is not None and IMPORT_RULE not in enabled and IMPORT_KEY not in enabled and not any(
            str(k).startswith("import:") for k in enabled):
        return
    found_here = _import_matches(text)
    # a reference stays whole: an import hit inside its key would turn a resolvable reference into a masked one
    # (Gate B, round 1); a display text inside a reference is text, and an imported value in it is masked (round 2)
    refs: list = _references().key_spans(text) if found_here else []
    for m in sorted(found_here, key=lambda x: x.start):
        if not ((enabled is None or IMPORT_RULE in enabled or IMPORT_KEY in enabled or m.kind in enabled)
                and m.end > m.start):
            continue
        if refs and any(a < m.end and m.start < b for a, b in refs):
            continue
        if not overlaps(m.start, m.end):
            take(m, True)
        else:
            _term_rest(m, text, found, taken_starts, taken_ends)


def use_regions(given) -> None:
    """Where every later scan of this process takes its regions and label languages from: a regions.Active, a function
    that returns one (asked when the rules load: the first scan and each reset_rules(), as the config is read
    without it), or None for the config of this computer
    (home.regions_from_config). The hook entry of the plugin (hooks.main) gives its config reader here; a caller
    without a config gives the regions it wants. The rule list of other regions, and the rule ids taken from it, are
    dropped. It configures the default detector, which detect.scan() and the other functions of this module use; a
    Detector of its own takes its regions when it is made."""
    _DEFAULT._given_regions = given
    _DEFAULT._forget()   # the rules and the shape rules of the old list (is_fixture)


def active_regions():
    """The regions and label languages of the scans of the detector (maisecrets/detection/regions.py): what its caller
    gave,
    else the config of this computer."""
    given = _det()._given_regions
    if given is not None:
        return given() if callable(given) else given
    try:
        from ..home import regions_from_config
    except Exception:  # noqa: BLE001 - no home.py (the standalone skill) or one that cannot load: no config, as before
        from . import regions
        return regions.resolve({})
    return regions_from_config()


class Sources:
    """What a scan takes besides its built-in rules: the rules of your own and the allow list, the term lists and the
    imported values. A caller gives one object for all of them (use_sources). This base has none of them; the
    plugin's readers of the home folder are maisecrets/sources.py, the default when no caller gives its own. The
    rules of your own and the allow list are asked once per rule load, the terms and the imports for each text."""

    def user_rules(self) -> list:
        """The rules of your own (Rule objects)."""
        return []

    def allow_list(self) -> tuple:
        """(values, rule ids) that the allow list lets through."""
        return frozenset(), frozenset()

    def term_matches(self, text: str) -> list:
        """The Match of each listed term in the text."""
        return []

    def import_matches(self, text: str) -> list:
        """The Match of each imported value in the text."""
        return []

    def note_slow(self, rule, ms: float) -> None:
        """A rule of your own took too long and is out of this process."""

    def reset(self) -> None:
        """Forget what was read; the next scan reads again (reset_rules)."""


NO_SOURCES = Sources()


def use_sources(given) -> None:
    """The sources of every later scan of this process: a Sources object, or None for the plugin's readers of the home
    folder (maisecrets/sources.py). What the old sources gave is dropped: the rule list, the allow list, and the time
    their rules of your own spent (a rule of the new sources with the same id starts at zero). Call it between scans,
    never while one runs in another thread: a running scan adds the time of an old rule to the old sums, which the
    new sources no longer read. It configures the default detector."""
    _DEFAULT._given_sources = given
    _DEFAULT._forget(allow=True, times=True)


def _sources() -> Sources:
    return _det()._sources_now()


def _plugin_sources() -> Sources:
    try:
        from ..sources import PLUGIN_SOURCES
    except ImportError:   # the standalone skill ships the detector without the plugin: no sources, as before
        return NO_SOURCES
    return PLUGIN_SOURCES


class References:
    """How the caller writes a reference into text, as far as a scan must know it: a reference is never a finding, and
    an import never cuts its key. Each method is one question a scan asks; this base knows no reference form. The
    plugin's form is maisecrets/placeholder.py (REFERENCES), the default when no caller gives its own
    (use_references)."""

    def names_a_key(self, low: str) -> bool:
        """A lower-case value after a label that is a reference key: no value."""
        return False

    def key_spans(self, text: str) -> list:
        """(start, end) of each part of a reference that an import hit must not cut."""
        return []

    def cell_spans(self, text: str, a: int, b: int) -> list:
        """(start, end) of each complete reference inside text[a:b], in order: no export cell value."""
        return []

    def inside(self, text: str, pos: int) -> bool:
        """Whether pos lies inside a reference that is open there."""
        return False

    def hit_is_a_reference(self, text: str, start: int, secret: str) -> bool:
        """Whether a hit at start with this secret is a reference or holds one."""
        return False

    def has_marks(self, value: str) -> bool:
        """Whether a personal-data value holds a mark of a reference."""
        return False


NO_REFERENCES = References()


def use_references(given) -> None:
    """The reference form of every later scan of the default detector: a References object, or None for the plugin's
    (maisecrets/placeholder.py). Call it between scans."""
    _DEFAULT._given_references = given
    _DEFAULT._generation += 1   # a cache of the label hits read the old form


def _references() -> References:
    given = _det()._given_references
    if given is not None:
        return given
    try:
        from ..placeholder import REFERENCES
    except ImportError:   # a copy of the detector without placeholder.py: no reference form
        return NO_REFERENCES
    return REFERENCES


class Host:
    """What a scan reads of the computer it runs on: the person's own user name (their home path is no personal
    data: the client names the working directory anyway) and the year (a birth date lies before it). A value left
    None is read from this computer at each use; a caller that wants a scan independent of the host gives both."""

    __slots__ = ("user", "year")

    def __init__(self, user: str | None = None, year: int | None = None):
        self.user, self.year = user, year

    def user_name(self) -> str:
        if self.user is not None:
            return self.user.lower()
        import getpass
        try:
            return getpass.getuser().lower()
        except Exception:  # noqa: BLE001 - no user name (a container without a passwd entry)
            return ""

    def this_year(self) -> int:
        return self.year if self.year is not None else time.gmtime().tm_year


THIS_COMPUTER = Host()


class Detector:
    """A detector with its own configuration: the regions and label languages (a regions.Active, or a function that
    returns one, asked when the rules load: the first scan and each reset()), the sources (a Sources object) and
    the reference form (a References object).
    None takes the default of each: the config of this computer, the plugin's readers of the home folder, the
    plugin's placeholder form, each when it is there. `host` (a Host) says what a scan reads of its computer;
    None reads this computer's user name and year. A detector loads its rule list, its allow list and the caches
    that follow from them once, and keeps them for itself: two detectors in one process, also in two threads or one
    inside a scan of the other, never see each other's configuration. The functions of this module (scan, findings,
    rules, ...) use the detector of the scan that runs, else the default detector (use_regions, use_sources and
    use_references configure it)."""

    def __init__(self, regions=None, sources=None, references=None, host=None):
        self.host = THIS_COMPUTER if host is None else host
        self._given_regions = regions
        self._given_sources = sources
        self._given_references = references
        self._generation = 0                # one more at each change of the configuration (_forget)
        self._rules = None                  # the rule list (rules())
        self._loaded_for = (None, ())       # the rule list and the regions it was loaded for
        self._allow = None                  # (exact values, rule ids) of the allow list
        self._shape_ids = None              # the ids of the shape rules of the list (is_fixture)
        self._order = (None, ())            # a rule list and its scan order (_in_scan_order)
        self._label_class = {}              # the class of each label, under the label words of the languages
        self._pw_last_on = None             # the password label words of the languages (_pw_words)
        self._active = None                 # the regions and languages the rule list was loaded for
        self._regex_time = {}               # the time each rule of your own spent inside its regex (seconds),
        self._regex_chars = {}              # the characters it ran over,
        self._regex_rule = {}               # and the rule of each id
        self._running = {}                  # thread id -> (rule, perf_counter at the start) while a step runs
        self._lock = threading.Lock()       # the sums and the running steps of several threads
        self._load_lock = threading.RLock()  # one rule load at a time, and a reset not inside one

    def _forget(self, allow: bool = False, times: bool = False) -> None:
        with self._load_lock:
            self._generation += 1
            self._rules = None
            self._pw_last_on = None
            self._shape_ids = None
            if allow:
                self._allow = None
            if times:
                self._regex_time, self._regex_chars, self._regex_rule = {}, {}, {}

    def _sources_now(self) -> Sources:
        return _plugin_sources() if self._given_sources is None else self._given_sources

    def _run(self, fn, *args, **kwargs):
        token = _CURRENT.set(self)
        try:
            return fn(*args, **kwargs)
        finally:
            _CURRENT.reset(token)

    def activate(self) -> "_Activation":
        """A context manager: in its block, every scan of this thread (detect.scan and each function of this module,
        also from a caller such as a hook) uses this detector."""
        return _Activation(self)

    def scan(self, text: str, enabled: set[str] | None = None, channel: str = "prompt", path: str = "",
             rule_list: list[Rule] | None = None) -> list[Match]:
        """The matches of the text under this detector's configuration (detect.scan)."""
        return self._run(scan, text, enabled, channel, path, rule_list)

    def findings(self, text: str, channel: str = "prompt", path: str = "") -> list[Match]:
        """The matches without the fixtures of a pasted test (detect.findings)."""
        return self._run(findings, text, channel, path)

    def rules(self) -> list[Rule]:
        """The rule list of this detector, sorted by rank (detect.rules)."""
        return self._run(rules)

    def regions(self):
        """The regions and label languages this detector scans with (a regions.Active): those its rule list was
        loaded for. A function given as regions is asked when the rules load (the first scan, and after reset()), so
        a changed config takes effect at reset()."""
        self.rules()
        return self._active

    def allow_list(self) -> tuple:
        """(exact values, rule ids) of the allow list of this detector (detect.allow_list)."""
        return self._run(allow_list)

    def explain_allowed(self, value: str) -> str | None:
        """Why the allow list of this detector lets this value through, or None (detect.explain_allowed)."""
        return self._run(explain_allowed, value)

    def reset(self) -> None:
        """Read the rules and the allow list again at the next scan (detect.reset_rules)."""
        self._run(reset_rules)

    def slowest_user_rule(self):
        """(rule, seconds) of the rule of your own of this detector with the most time in its regex, or None."""
        return self._run(slowest_user_rule)


class _Activation:
    def __init__(self, detector: Detector):
        self._detector, self._tokens = detector, []

    def __enter__(self) -> Detector:
        self._tokens.append(_CURRENT.set(self._detector))
        return self._detector

    def __exit__(self, *exc) -> None:
        _CURRENT.reset(self._tokens.pop())


_CURRENT: contextvars.ContextVar = contextvars.ContextVar("maisecrets_detector", default=None)
_DEFAULT = Detector()   # the detector of the functions of this module; it reads nothing before its first scan


def _det() -> Detector:
    """The detector of the scan that runs in this thread (Detector.scan), else the default detector."""
    d = _CURRENT.get()
    return _DEFAULT if d is None else d


def switched_off(rule_id: str, ids: frozenset) -> bool:
    """A rule id on the allow list, also with the `#n` of one of several patterns of a Presidio rule."""
    return rule_id in ids or rule_id.split("#", 1)[0] in ids


def _pii_regions() -> tuple[str, ...]:
    return active_regions().regions


SECRET_TYPES = frozenset({"SECRET"})
# a value that is obviously a placeholder is never a secret, whichever rule matched it
PLACEHOLDER_VALUES = frozenset({"changeme", "change_me", "password", "placeholder", "example", "redacted",
                                "secret", "your_api_key", "xxxxxxxx", "todo", "none", "null"})
PLACEHOLDER_PARTS = ("your_", "your-", "bogus", "dummy", "example", "sample", "placeholder", "changeme",
                     "xxxxxxxx", "test-token", "secure-token", "<redacted", "fake")
_TEMPLATE_NAME = _LazyRx(r"^[A-Z]+(?:_[A-Z]+)+$")   # YOUR_PORTKEY_API_KEY: words joined by underscores, no digits


# a placeholder word counts at the start of the value, after a character that is not a letter or a
# digit (ghp_fake…, sk-dummy-key, <redacted>), or at the end (the AWS documentation key ends in
# EXAMPLE). Inside a run of letters and digits it is chance: a random GitHub token holds "fAKe" or
# "DuMmy" about once in 20,000, and it was then let through as a placeholder (found by a random
# test token on windows-latest, 2026-09-27)
_PARTS = "|".join(re.escape(p) for p in PLACEHOLDER_PARTS)
_PLACEHOLDER_PART_RE = _LazyRx(f"(?<![a-z0-9])(?:{_PARTS})|(?:{_PARTS})(?:key)?$")


_PUBLIC_TEST_VALUES: list = []
# an encoded address is an address after `=` (email=, to=, login=), after mailto%3A, or after a mail word; elsewhere
# name%40version.com is a package, a git ref or an asset name (codex review)
_ENCODED_MAIL_CONTEXT_RE = _LazyRx(
    r"(?i)(?:=|%3d|mailto(?::|%3a)"
    r"|\b(?:to|from|cc|bcc)[ \t]*[:=][ \t]*"   # `to` and `from` alone are paths and imports: path/to/pkg%40v.com
    r"|\b(?:e-?mail|mail|sender|recipient|bounce|reply-to|contact|login|users?|username)[ \t]*[:=/]?[ \t]*)$")
_DIGITS_ONLY_RE = _LazyRx(r"\+?[\d\s().-]+")
# `sent to name%40host` in prose: `to` and spaces, not `path/to/` or `import x to`
_ENCODED_MAIL_TO_RE = _LazyRx(r"(?i)(?<![/\w])(?:sent|send|mailed|forwarded|reply|replied|receipt|invoice|copy)"
                                 r"[^\n/]{0,20}?(?<![/\w])to[ \t]+$")


def _encoded_mail_expected(text: str, start: int, end: int) -> bool:
    """Where an address with its @ as %40 is an address: after a mail word or `=` (_ENCODED_MAIL_CONTEXT_RE), after
    `sent to` in prose, or as a whole cell of a CSV row (a column of a roster export, holdout 2026-10-15)."""
    line = _line_start(text, start)
    if _ENCODED_MAIL_CONTEXT_RE.search(text, max(line, start - 40), start) or _ENCODED_MAIL_TO_RE.search(
            text, max(line, start - 40), start):
        return True
    value = text[start:end]
    # a cell may have spaces around it (`Dana, name%40host.de`) and quotes ("name%40host.de"), in that order
    while start > line and text[start - 1] == " ":
        start -= 1
    while text[end:end + 1] == " ":
        end += 1
    if text[start - 1:start] == '"' and text[end:end + 1] == '"':
        start, end = start - 1, end + 1   # a quoted cell: "name%40host.de"
        while start > line and text[start - 1] == " ":
            start -= 1
        while text[end:end + 1] == " ":
            end += 1
    before, after = text[start - 1:start] if start > line else "", text[end:end + 1]
    if before not in ("", ",", ";", "\t") or after not in ("", "\n", "\r", ",", ";", "\t") or start - line > 4000:
        return False
    # the column's header names a mail address: a CSV header in the first five lines (a file, an export, a query
    # result with a line before it); a row without such a header stays text (review of 0.6.24)
    sep = before or (after if after in (",", ";", "\t") else ",")
    if not before and not after:
        return False   # a value alone on its line is no cell of a row
    labels = value.rsplit("%40", 1)[-1].lower().split(".")
    if labels[-1] in _FILE_EXTENSIONS or sum(x.isdigit() for x in labels) >= 2:
        return False   # logo%402x.png is an asset at twice the size, pkg%401.0.0-beta.rc a version
    import csv   # here: the hooks pay for every module at import
    col = len(next(csv.reader([text[line:start + 1]], delimiter=sep), [""])) - 1
    # the first five lines of the text, and up to 20 lines above the row within 4,000 characters: a header after a
    # preamble of an export (review of 0.6.25)
    above = text[max(0, line - 4000):max(0, line - 1)].split("\n")[-20:]
    for head in text[:4000].split("\n")[:5] + above[::-1]:
        cells = next(csv.reader([head], delimiter=sep), [])
        # a header holds names, not values: a row with an address in it is data, even with mailbox.org in it. Each
        # line counts on its own: a title line above the header (`Report for user list, 2026-10-01`) does not hide it
        if (len(cells) > col and "%40" not in head and "@" not in head and text.find(head) < line
                and _names_a_mail_column(cells[col])):
            return True
    return False


# a header cell of a column of addresses: a mail word in a few languages, or a word that names who an address
# belongs to (contact, login, user, recipient). Before 0.6.25 only "mail" counted, and an encoded address under a
# header such as `contact` or `login` passed. `to` and `from` are left out: a migration table has them as columns
_MAIL_COLUMN_RE = _LazyRx(r"(?i)mail|courriel|correo|e-?post(?![a-z])|s\u00e4hk\u00f6posti")
# the owner word must be the last word of the header: login_user and user are addresses, end_user_id and
# contact_asset are an id and a file (review of 0.6.25)
_OWNER_WORDS = frozenset({"contact", "contacts", "login", "logins", "user", "users", "username", "usernames",
                          "sender", "recipient", "recipients", "upn", "benutzer", "benutzername", "kontakt",
                          "empf\u00e4nger", "absender", "destinataire", "exp\u00e9diteur", "utilisateur"})
_OWNER_PAIRS = (["user", "name"], ["reply", "to"], ["principal", "name"])
# an owner word before one of these is the same column: Recipient Address, Login Name, sender_addr
_OWNER_TAILS = frozenset({"address", "addr", "name", "adresse"})
# the extension of a file that an asset name ends in: name%402x.png is an image at twice the size
_FILE_EXTENSIONS = frozenset({"png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "bmp", "tif", "tiff", "js",
                              "mjs", "cjs", "ts", "css", "map", "json", "html", "htm", "xml", "txt", "pdf",
                              "woff", "woff2", "ttf", "otf", "mp3", "mp4", "webm", "wasm", "gz", "tgz", "jar",
                              "heic", "heif", "lottie", "scss", "sass", "less", "jsx", "tsx", "csv", "yaml", "yml",
                              "toml", "lock", "wav", "ogg", "mov", "zip", "md", "mdx", "vue", "svelte", "rst",
                              "adoc", "ipynb"})


def _names_a_mail_column(cell: str) -> bool:
    cell = cell.strip().strip("\"'")
    if _MAIL_COLUMN_RE.search(cell):
        return True
    words = [w.lower() for w in re.findall(r"[^\W\d_]+", re.sub(r"([^\W\d_])(?<=[a-z\u00df-\u00ff])([A-Z])", r"\1 \2",
                                                                  cell))]
    if words and words[-1] in _OWNER_TAILS and len(words) >= 2 and words[-2] in _OWNER_WORDS:
        return True
    return bool(words) and (words[-1] in _OWNER_WORDS or words[-2:] in _OWNER_PAIRS)


def is_public_test_value(value: str, kind: str) -> bool:
    """A value that vendor documentation publishes for tests, for one placeholder type (rules/public_test_values.txt):
    a payment test card is no CARD, the Stripe API reference key and the jwt.io example are no SECRET, a Twilio test
    number is no PHONE. The same digits under another type stay a hit: a bank account that happens to equal a test
    card is still a bank account (codex review). 18 of 21 false alarms of a public benchmark were such values
    (2026-10-11). The file holds full sha256 digests, never the values."""
    if not _PUBLIC_TEST_VALUES:
        entries = set()
        for line in (RULES_DIR / "public_test_values.txt").read_text(encoding="utf-8").splitlines():
            fields = line.split("#", 1)[0].split()
            if len(fields) == 2:   # digest and type; a malformed line must not break every scan
                entries.add((fields[1], fields[0]))
        _PUBLIC_TEST_VALUES.append(frozenset(entries))
    v = value.strip("\"'` ")
    if _DIGITS_ONLY_RE.fullmatch(v):
        v = re.sub(r"\D", "", v)
    return (kind, hashlib.sha256(v.encode("utf-8")).hexdigest()) in _PUBLIC_TEST_VALUES[0]


def looks_like_placeholder(value: str) -> bool:
    v = value.strip("\"'` ")
    low = v.lower()
    return low in PLACEHOLDER_VALUES or bool(_PLACEHOLDER_PART_RE.search(low)) or bool(_TEMPLATE_NAME.match(v))


# ------------------------------------------------------------- test fixtures --
# A label rule finds a value by its label alone, so a test password looks like a real one: `PASSWD = '<word>'` in the
# tests of the Python standard library (2026-09-29). In test code the value is a fixture, and a
# block or a placeholder there only stops the work. A token shape (glpat-, AKIA, a PEM key) and personal data stay
# hits in test code too: a real token or a copy of customer data in a test is a leak.
# The id prefixes of the label rules and of the keyword rules (the detect-secrets ones and maisecrets' own label rules
# with no `=` or `:`) live in maisecrets/detection/registry.py; a rule carries its form (Rule.form), a stored kind is
# read with
# registry.is_label. The names stay for the scripts and tests that read them.
LABEL_RULES = _registry.LABEL_PREFIXES
KEYWORD_RULES = _registry.KEYWORD_PREFIXES
_TEST_PATH_RE = _LazyRx(r"(?:^|[/\\])(?i:tests?|__tests__|spec|testdata|test_data|e2e)[/\\]"
                           r"|(?:^|[/\\]|[a-z])Tests?\.\w+$"
                           r"|(?:^|[/\\])[^/\\]*[._-]e2e[._-][^/\\]*$"
                           r"|(?:^|[/\\])(?:test_[^/\\]*|[^/\\]*_test\.\w+|[^/\\]*\.(?:test|spec)\.\w+|conftest\.py)$")
# a file of real values even under tests/: an .env, a recorded HTTP cassette (review, 2026-09-29)
_REAL_VALUE_FILE_RE = _LazyRx(r"(?i)(?:^|[/\\])(?:\.env[^/\\]*|[^/\\]*\.env(?:\.[^/\\]*)?|[^/\\]*\.har"
                                 r"|[^/\\]*\.har\.\w+|(?:cassettes?|(?:__)?recordings?(?:__)?|recorded|tapes|vcr"
                                 r"|__nock-fixtures__)[/\\].*)$")
_TEST_MARKER_RE = _LazyRx(
    r"(?m)^(?:(?:async[ \t]+)?def[ \t]+test_?\w*[ \t]*\(|[ \t]*class[ \t]+Tests?(?:[A-Z_(:]|$)|[ \t]*@pytest\."
    r"|[ \t]*@Test\b|[ \t]*#\[test\]"
    r"|[ \t]*(?:import|from)[ \t]+(?:pytest|unittest)\b|[ \t]*func[ \t]+Test\w*\("
    r"|[ \t]*(?:describe|it|test|beforeEach)[ \t]*\()")
_TEST_METHOD_RE = _LazyRx(r"(?m)^[ \t+-]+(?:async[ \t]+)?def[ \t]+test_?\w*[ \t]*\([ \t]*self\b")
_CLASS_LINE_RE = _LazyRx(r"(?m)^[ \t+-]*class[ \t]+\w|^@@[^\n]*\bclass[ \t]+\w")
_TEST_CLASS_LINE_RE = _LazyRx(r"[ \t+-]*class[ \t]+Tests?(?:[A-Z_(:]|$)|@@[^\n]*\bclass[ \t]+Tests?(?:[A-Z_(:]|\b)")
# `assert` alone is no marker: production code asserts too (review, 2026-09-29). A diff starts a new file here
_DIFF_FILE_RE = _LazyRx(r"(?m)^(?:diff --git |\+\+\+ |--- a/)")
_GREP_PATH_RE = _LazyRx(r"((?:[A-Za-z]:)?[^\s:]+):\d+[:-]")
_TEST_LOOKBACK_LINES = 40


def is_test_path(path: str) -> bool:
    return bool(path) and bool(_TEST_PATH_RE.search(path)) and not _REAL_VALUE_FILE_RE.search(path)


def in_test_code(text: str, start: int, path: str = "") -> bool:
    """Whether the hit at `start` sits in test code: the file is a test file, a grep line names one, or a test
    marker (`def test_`, `assert`, `describe(` …) stands in its line or in the 40 lines before it."""
    if is_test_path(path):
        return True
    line_start = _line_start(text, start)
    m = _GREP_PATH_RE.match(text, line_start)
    if m and is_test_path(m.group(1)):
        return True
    nl = _newlines(text)
    i = bisect.bisect_left(nl, line_start)       # the line of the hit is line i
    begin = nl[i - _TEST_LOOKBACK_LINES - 1] + 1 if i > _TEST_LOOKBACK_LINES else 0
    diffs = _positions(text, "diff", _DIFF_FILE_RE)
    j = bisect.bisect_left(diffs, line_start)
    if j and diffs[j - 1] >= begin:
        begin = diffs[j - 1]      # a marker of another file in the same diff does not count
    end = _line_end(text, start)
    markers = _positions(text, "marker", _TEST_MARKER_RE)
    k = bisect.bisect_left(markers, begin)
    if k < len(markers) and markers[k] < end:
        return True
    # an indented `def test_…(self` counts when no class other than a test class stands nearer above it: a test
    # method in a diff hunk or a paste, but not `def test_connection(self)` in class Db (reviews, 2026-09-30)
    defs = _positions(text, "defs", _TEST_METHOD_RE)
    k = bisect.bisect_left(defs, end) - 1
    if k < 0 or defs[k] < begin:
        return False
    classes = _positions(text, "classes", _CLASS_LINE_RE)
    c = bisect.bisect_left(classes, end) - 1   # the class nearest above the hit, also one after the method
    if c < 0 or classes[c] < begin:
        return True
    return bool(_TEST_CLASS_LINE_RE.match(text, classes[c]))


def is_fixture(m: "Match", text: str, path: str = "") -> bool:
    """A label-rule hit in test code: not a secret the person typed (see LABEL_RULES). The first rule to claim a
    span wins, and the label rules run before the shape rules: `token = "<a JWT>"` got the kind of a label rule and
    was dropped with the fixtures (review, 2026-09-29). A value that a shape rule finds on its own stays a hit."""
    if not (m.type == "SECRET" and _registry.is_label(m.kind) and in_test_code(text, m.start, path)):
        return False
    return not scan(m.value, enabled=_shape_rule_ids())


def _shape_rule_ids() -> set:
    d = _det()
    if d._shape_ids is None:
        d._shape_ids = {r.id for r in rules() if (r.form or _registry.form_of(r.id)) == "shape"}
    return d._shape_ids


# ------------------------------------------------------------------ scanner --
_CTX_CACHE: dict[tuple[str, ...], re.Pattern[str]] = {}


def _has_context_word(window: str, context: tuple[str, ...]) -> bool:
    """A context word counts as a whole word: "ort" must not fire inside "report"."""
    if not context:
        return False
    rx = _CTX_CACHE.get(context)
    if rx is None:
        rx = re.compile(r"(?<![a-z0-9äöüß])(?:" + "|".join(re.escape(c) for c in context) + r")(?![a-z0-9äöüß])")
        _CTX_CACHE[context] = rx
    return rx.search(window) is not None


_LABEL_ONLY_RE = _LazyRx(r"[:=]\s*$")
# a line of code that ends in a colon is a condition, not a label: `if kind != "SECRET":` and
# `continue` on the next line was taken for a labelled secret (twice in this repository's own
# pre-commit check, 2026-09-27)
# Code syntax only: a comparison operator, or a line that opens a block with a keyword and has
# no space between the keyword and the rest of a sentence. "for the db, password:" and "if
# needed, passwort:" are labels in a sentence and must still take the next line (review,
# 2026-09-27: matching the bare words hid them).
_CODE_CONDITION_RE = _LazyRx(r"(?:==|!=|<=|>=|\bis not\b|^\s*(?:def|class)\s+\w+\s*[(:])")
# a keyword rule reads `if not token: <statement>` as label and value: the statement word went into the vault
# and every later text with that word was redacted, code included (field report, 2026-09-29). A statement
# keyword is never a value. A check of the whole line ("it opens a block") was tried and dropped: the colon
# of the label itself satisfied it, and `with password: <value>` went through (review, 2026-09-29)
_CODE_WORDS = frozenset({"break", "continue", "return", "pass", "raise", "throw", "yield", "await", "elif",
                         "else"})

# the word after a label in an error message or a log line: "pwd: expected bytes, got str" (Python standard library,
# 2026-09-29), "token: invalid", "password: required". None is a password anyone chooses
_MESSAGE_WORDS = frozenset({"expected", "invalid", "missing", "required", "incorrect", "wrong", "failed", "denied",
                            "unsupported", "mismatch", "rejected", "expired", "revoked", "unset", "empty", "unknown",
                            "must", "cannot", "should", "not", "no", "abgelaufen", "unbekannt", "erforderlich",
                            "vergessen", "unver\u00e4ndert", "ung\u00fcltig", "ungueltig", "gesperrt",
                            "ge\u00e4ndert", "widerrufen", "zur\u00fcckgesetzt"})


def is_code_word(value: str) -> bool:
    """A statement keyword or a word of an error message: a keyword rule never takes it as a value."""
    w = value.strip().rstrip(";").lower()
    return w in _CODE_WORDS or w in _MESSAGE_WORDS


def code_words() -> frozenset:
    """The statement keywords and the words of error messages that a keyword rule never takes as a value."""
    return _CODE_WORDS | _MESSAGE_WORDS


_NL_RE = _LazyRx("\n")
# the last text and its index (line breaks, lines, positions, literal hits), one per thread: scan() and is_fixture()
# ask about one text, and two scans in two threads must not read the index of each other's text
_TEXT_INDEX = threading.local()


def _text_index(text: str) -> dict:
    """The index of `text` in this thread, made at the first question about it."""
    t = _TEXT_INDEX
    if getattr(t, "text", None) is not text:
        t.text, t.cache = text, {"nl": [m.start() for m in _NL_RE.finditer(text)]}
    return t.cache


def _newlines(text: str) -> list:
    """The offsets of the line breaks of `text`, computed once per text. A search for the start or the end of a line
    at each keyword hit was one pass over the line, and a one-line text of 2 MB took 14.5 s (review of 3e5d53e,
    2026-09-30)."""
    return _text_index(text)["nl"]


def _line_start(text: str, pos: int) -> int:
    nl = _newlines(text)
    i = bisect.bisect_left(nl, pos)
    return nl[i - 1] + 1 if i else 0


def _line_end(text: str, pos: int) -> int:
    nl = _newlines(text)
    i = bisect.bisect_left(nl, pos)
    return nl[i] if i < len(nl) else len(text)


def _split_lines(text: str) -> tuple:
    """The lines of `text` and of its lower-case form, split once per text: the seven keyword rules each split a
    megabyte again (review of 3e5d53e, 2026-09-30)."""
    cache = _text_index(text)
    if "lines" not in cache:
        cache["lines"] = (text.split("\n"), _lower(text).split("\n"))
    return cache["lines"]


def _positions(text: str, name: str, rx: re.Pattern) -> list:
    """The start offsets of the matches of `rx` in `text`, computed once per text (see _newlines)."""
    cache = _text_index(text)
    if name not in cache:
        cache[name] = [m.start() for m in rx.finditer(text)]
    return cache[name]


_IDENT_RE = _LazyRx(r"[A-Za-z_][A-Za-z0-9_]*")
_LABEL_WINDOW = 200   # characters before a value in which its label is looked for


def _before_value(text: str, start: int) -> str:
    """The text of the value's line before it, at most _LABEL_WINDOW characters."""
    return text[max(_line_start(text, start), start - _LABEL_WINDOW):start]
_LABEL_TAIL_RE = _LazyRx(r"([A-Za-z_][\w.]*)\\?[\"']?\s*(?::=|=|:)\s*\\?[\"'`]?$")   # \" in JSON in a string
_OPERATOR_AFTER_RE = _LazyRx(r"[ \t]+[|&^*+][ \t]+[A-Za-z_(]")
_SELF_ATTR_RE = _LazyRx(r"(?:^|[\s,(])(?:self|this|cls)\.\w+$")


def value_is_code(text: str, start: int, end: int, secret: str) -> bool:
    """A keyword rule read `name = <expression>` in source code as label and value. Three forms, all measured in the
    Python standard library (2026-09-29): the same name on both sides (`authkey=authkey`), an unquoted name that an
    operator continues (`TOKEN_ENDS = TSPECIALS | WSP`), and an unquoted name given to an attribute of the object
    (`self.token = nextchar`). A quoted value, and `spring.datasource.password=<value>`, stay values."""
    v = secret.strip().strip("'\"`;,")
    before = _before_value(text, start)
    m = _LABEL_TAIL_RE.search(before)
    if not m:
        return False
    label = m.group(1)
    name = label.rsplit(".", 1)[-1].lower()
    if v.lower() == name or v.lower().startswith(name + "#"):
        return True   # also a documentation anchor: 'token': 'token#module-token'
    if before[-1:] in "'\"`" or not _IDENT_RE.fullmatch(v):
        return False
    if len(name) >= 3 and not any(c.isdigit() for c in v) and (v.lower().startswith(name) or v.lower().endswith(name)):
        return True   # a name made from the label: token = tokenizer, token = nexttoken
    if "=" in m.group(0) and _OPERATOR_AFTER_RE.match(text, end):
        return True   # an assignment only: `password: <value> | then log in` is prose
    return bool(_SELF_ATTR_RE.search(before[:m.start(1) + len(label)]))


# gitleaks' generic-api-key takes `key = "Europe/Dublin"`: words joined by `/` without a digit are a time zone or a
# path, never a key (Python standard library, 2026-09-29)
_WORD_PATH_RE = _LazyRx(r"[A-Z]?[a-z]+(?:_[A-Z]?[a-z]+)*(?:/[A-Z]?[a-z]+(?:_[A-Z]?[a-z]+)*)+")
# a signed number in code: `a = +4294967296`, `f(+12345678)`
_SECTION_BEFORE_RE = _LazyRx(r"(?i)(?:\bRFC[ -]?\d{3,5}|\bCore|\bsection|\bsec\.|\bchapter|\bKapitel|\bAbschnitt"
                                r"|\u00a7)[ ,:(]*\u00a7?[ ]*$")
# whole words of the label: TELEMETRY_OFFSET is no telephone (Codex review, 2026-09-30)
_PHONE_LABEL_RE = _LazyRx(r"(?i)phone|(?<![a-z])(?:telefon|mobil|handy(?!man)|fax|contact|kontakt|rufnummer|whatsapp"
                             r"|msisdn|festnetz|hotline|durchwahl)|(?<![a-z])(?:tel|cell|sms)(?![a-z])")
_NUMBER_BEFORE_RE = _LazyRx(r"(?:=\s+|[(\[]\s*|return\s+)$")   # not KEY=+49…, not a CSV column


def _phone_ok(text: str, start: int, secret: str) -> bool:
    """E.164 has at most 15 digits; a run of 0 and 1 is a binary number; a signed number without separators after
    `=`, `(` or `,` is a number in code (Python standard library, 2026-09-29)."""
    digits = re.sub(r"\D", "", secret)
    if len(digits) > 15 or set(digits) <= {"0", "1"}:
        return False
    if re.search(r"[ \-()]", secret) or not _NUMBER_BEFORE_RE.search(text, max(0, start - 8), start):
        return True
    # CONTACT_PHONE = +49… (Codex review), phone(+49…), [+49…] after a phone word (final review, 2026-09-30)
    return bool(_PHONE_LABEL_RE.search(_label_before(text, start)) or _PHONE_LABEL_RE.search(
        text, max(0, start - 24), start))


# gitleaks' generic-api-key starts with a lazy `[\w.-]{0,50}?` before its keyword, so the regex
# engine tries up to 50 prefixes at every position of the text: 80 % of a log scan's time
# (2026-09-27). Its keywords are found by a plain search first, and the rule runs only in a
# window around each: from 50 characters before the keyword (the prefix cannot cross a line) to
# the end of the 8th line after it (the separators may hold line breaks; the window ends after a
# newline, which the value's terminator class takes the same way as in the whole text).
_WINDOWED = {"generic-api-key": _LazyRx(r"(?i)access|auth|api|credential|creds|key|passw(?:or)?d|secret|token")}


def _windowed(rule: Rule, kw: re.Pattern, text: str):
    spans: list[list[int]] = []
    nl = _newlines(text)
    for k in kw.finditer(text):
        a = max(_line_start(text, k.start()), k.start() - 50)
        # the separators may hold several line breaks (`password for prod:` + blank line +
        # value, review 2026-09-27). The regex allows 3 whitespace characters before the separator
        # and 5 after it, so the value can start after 8 line breaks: the window runs to the end
        # of the 9th line (8 cut `password\n\n\n:\n\n\n\n\n<value>` off, differential test 2026-09-27)
        i = bisect.bisect_left(nl, k.end()) + 8
        b = nl[i] + 1 if i < len(nl) else len(text)
        if spans and a <= spans[-1][1]:
            spans[-1][1] = max(spans[-1][1], b)
        else:
            spans.append([a, b])
    last_end = -1
    for a, b in spans:
        for m in rule.regex.finditer(text[a:b]):
            if m.start() + a < last_end:
                continue
            last_end = m.end() + a
            yield _Shifted(m, a)


_EMPTY_RE = _LazyRx("")
_WORD_RE_ANY = _LazyRx(r"[a-z]+")   # the words of a seed phrase, whatever stands between them
# the words that make 12 list words a seed phrase: the phrase's own names, and the labels of a secret (a phrase after
# "Password:" or "private key:" was text, Gate B of 0.6.19)
_SEED_CONTEXT_RE = _LazyRx(r"(?i)(?<![a-z])(?:seed|mnemonic|bip-?39|recovery|wallet|metamask|ledger|trezor|phrase"
                              r"|backup|secret|passphrase|password|passwort|kennwort|words|wörter|private|keys?"
                              r"|token|wiederherstellung)(?![a-z])")   # a whole word: not tokenization, keyboard


def _matches(rule: Rule, text: str, channel: str = "prompt"):
    """detect-secrets keyword rules are line rules: run them per line, keep absolute offsets.

    A label that ends its line (``passwort:`` and the value on the next line, as a console
    or a chat renders it) is scanned together with the next non-empty line; only a hit whose
    value starts in that next line is taken from the pair (field report, 2026-09-26)."""
    matcher = rule.matcher or _registry.matcher_of(rule.id, "literal" if rule.id in _LITERAL_IDS else "")
    curl = _curl_parts(rule) if matcher == "curl" else None
    if curl is not None:
        yield from _curl_matches(curl, text)
        return
    if matcher == "list":
        yield from _list_matches(rule, text)
        return
    if matcher == "literal":
        yield from _literal_matches(rule.id, text, channel)
        return
    if matcher == "seed":
        for a, b, words in checksums.bip39_spans(text):
            # the context word stands outside the phrase: seed, phrase and wallet are words of the list
            if words < 15 and not (_SEED_CONTEXT_RE.search(text, max(0, min(a - 200, _line_start(text, a))), a)
                                   or _SEED_CONTEXT_RE.search(text, b, max(b, _line_end(text, b)))):
                continue
            yield _Spanned(_EMPTY_RE.match(text, b), a, text)
        return
    kw = _WINDOWED.get(rule.id) if matcher == "windowed" else None
    if kw is not None and len(text) > 4096:
        yield from _windowed(rule, kw, text)
        return
    if matcher != "lines" or not _newlines(text):
        yield from rule.regex.finditer(text)
        return
    pos = 0
    lines, low = _split_lines(text)
    low = low if rule.keywords else None
    for i, line in enumerate(lines):
        # the regex needs one of the rule's keywords in this line (every denylist word contains
        # one); skipping the other lines cut a history scan from 71 s to a fraction (2026-09-27)
        if low is not None and len(low) == len(lines) and not any(k in low[i] for k in rule.keywords):
            pos += len(line) + 1
            continue
        for m in rule.regex.finditer(line):
            yield _Shifted(m, pos)
        if _LABEL_ONLY_RE.search(line) and not _CODE_CONDITION_RE.search(line):
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines):
                pair = "\n".join(lines[i:j + 1])
                for m in rule.regex.finditer(pair):
                    g = rule.secret_group if 0 < rule.secret_group <= (rule.regex.groups or 0) else 0
                    if m.start(g) > len(line):
                        yield _Shifted(m, pos)
        pos += len(line) + 1


# betterleaks' two curl rules start with `\bcurl\b` and then `.*` (or `.*?`) over up to 5 more lines before the -H or
# -u part. RE2 runs that in linear time; Python's `re` scans the rest of the line again from each `curl`, and a line
# with many of them took O(n^2) (32K characters: 10 s, past the hook's time limit). Here the -H/-u part (the tail)
# is found on its own, and the nearest `curl` before it must stand within the same line breaks as the regex allows.
_CURL_HEADS = (r"\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})", r"\bcurl\b(?:.*|.*(?:[\r\n]{1,2}.*){1,5})")
_CURL_PARTS: dict = {}


def _curl_parts(rule: Rule):
    """(curl regex, tail regex) of a curl rule whose regex starts with a known head; None for any other rule, and
    for a curl rule whose regex a sync changed (it then runs as it is: correct, only slower)."""
    if not rule.id.startswith("curl-"):
        return None
    key = (rule.id, rule.regex.pattern, rule.regex.flags)
    if key not in _CURL_PARTS and (rule.regex.flags or 0) & re.DOTALL:
        _CURL_PARTS[key] = None   # the split bounds the lines between curl and its flag; a dot over every line has none
    if key not in _CURL_PARTS:
        p = rule.regex.pattern
        flags = "(?i)" if p.startswith("(?i)") else ""
        body = p[len(flags):]
        head = next((h for h in _CURL_HEADS if body.startswith(h)), None)
        tail = body[len(head):] if head else ""
        if tail.endswith(r"(?:\s|\Z)"):
            # the space after a credential was part of the match, so finditer skipped a credential that started
            # right after it: `-u a:x --user b:y` lost b:y (Gate B of 0.6.15); a lookahead keeps it
            tail = tail[:-len(r"(?:\s|\Z)")] + r"(?=\s|\Z)"
        own = rule.regex.flags or 0
        _CURL_PARTS[key] = None if head is None else (re.compile(flags + r"\bcurl\b", own),
                                                      re.compile(flags + tail, own))
    return _CURL_PARTS[key]


def _curl_matches(parts, text: str):
    """The matches of a curl rule in linear time. A match takes each -H/-u part whose nearest `curl` before it is
    at most 5 line breaks away (`[\\r\\n]{1,2}` is one break, so a blank line counts once); its group 0 starts at
    that `curl`. The regex took only the first (-H, lazy) or the last (-u, greedy) part after one `curl`; this
    takes each one."""
    head, tail = parts
    starts: list[int] = []
    ends: list[int] = []
    for c in head.finditer(text):
        starts.append(c.start())
        ends.append(c.end())
    if not starts:
        return
    nl = _newlines(text)
    for t in tail.finditer(text):
        i = bisect.bisect_right(ends, t.start()) - 1
        if i < 0:
            continue
        lo, hi = bisect.bisect_left(nl, ends[i]), bisect.bisect_left(nl, t.start())
        if hi - lo > 10:
            continue
        breaks = run = 0
        for j in range(lo, hi):
            run = run + 1 if j > lo and nl[j] == nl[j - 1] + 1 else 1
            breaks += run % 2                    # two line feeds in a row are one `[\r\n]{1,2}`
        if breaks <= 5:
            yield _Spanned(t, starts[i], text)


# one quoted value of a list and what follows it: a comma (the next value) or the closing bracket. Up to two line
# breaks around it: a list written one value per line
_LIST_ITEM_RE = _LazyRx(r"[ \t]*(?:\r?\n[ \t]*){0,2}([\"'`])([^\"'`\\\n]{1,256})\1"
                           r"[ \t]*(?:\r?\n[ \t]*){0,2}(,|[\]})])")
# a key of an unquoted list in an .env line (label-env-key-list): base64 and the comma after it
_ENV_LIST_ITEM_RE = _LazyRx(r"()([A-Za-z0-9+/]{16,88}={0,2})(,|(?![A-Za-z0-9+/=]))")



def _list_matches(rule: Rule, text: str):
    """Each quoted value of the list that starts after a label of label-secret-list and that looks like a key
    (_list_value_ok), as group 2 of a match whose group 0 starts at the label. The values are checked here, before
    the filters of scan(): a list of 10,000 words cost each word the whole chain. The list ends at its closing
    bracket or at a value that is not a quoted string, at any length: a cut at 1 MB left the keys after it in the
    clear (codex Gate A of 0.6.16). A label inside a list already read is skipped, so each character is read once."""
    done = -1
    env = rule.id == "label-env-key-list"
    item_re, value_ok = (_ENV_LIST_ITEM_RE, _env_key_ok) if env else (_LIST_ITEM_RE, _list_value_ok)
    for lab in rule.regex.finditer(text):
        if lab.start() < done:
            continue
        pos = lab.end()
        while True:
            it = item_re.match(text, pos)
            if it is None:
                break
            if value_ok(it.group(2)):
                yield _Spanned(it, lab.start(), text)
            if it.group(3) != ",":
                break
            pos = it.end()
        done = pos


class _Spanned:
    """A tail match whose group 0 starts earlier, at its `curl`."""
    __slots__ = ("_m", "_start", "_text")

    def __init__(self, m: re.Match, start: int, text: str) -> None:
        self._m, self._start, self._text = m, start, text

    def group(self, i: int = 0):
        return self._text[self._start:self._m.end()] if i == 0 else self._m.group(i)

    def start(self, i: int = 0) -> int:
        return self._start if i == 0 else self._m.start(i)

    def end(self, i: int = 0) -> int:
        return self._m.end(i)


class _Shifted:
    """A match object whose offsets are shifted into the enclosing text."""
    __slots__ = ("_m", "_off")

    def __init__(self, m: re.Match, off: int) -> None:
        self._m, self._off = m, off

    def group(self, i: int = 0):
        return self._m.group(i)

    def start(self, i: int = 0) -> int:
        return self._m.start(i) + self._off

    def end(self, i: int = 0) -> int:
        return self._m.end(i) + self._off


def _names_its_label(text: str, start: int, secret: str) -> bool:
    """`POSTGRES_PASSWORD: postgres`, `password: password`: the value is a word of its own label, a default. With
    one label on the line the whole line counts (`ALTER USER postgres WITH PASSWORD 'postgres'`); with more, only
    the label of the value: in `smtp.host=mail.contoso.de smtp.password=contoso` the word is another value
    (review, 2026-09-29)."""
    before = _before_value(text, start)
    m = _LABEL_TAIL_RE.search(before)
    # another label on the line, also one before the window: then only the value's own label counts (an earlier
    # smtp.user= label, 225 characters of prose, then the password label and a word of the prose; review of 3e5d53e)
    wide = text[max(_line_start(text, start), start - 1000):start]
    if m and (len(re.findall(r"[:=]", before[:m.start()])) > 0 or len(re.findall(r"[:=]", wide)) > 1):
        before = m.group(1)
    words = set(re.findall(r"[a-z]+", before.lower()))
    v = secret.strip("\"'` ").rstrip(".,;:!?")
    if v.lower() in words:
        return True   # also at the end of a sentence
    parts = [p.lower() for p in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", v)]
    return len(parts) >= 2 and "".join(parts) == v.lower() and set(parts) <= words   # token_data: TokenData


# lookarounds, not ^: search(text, pos) anchors ^ at the start of the text, never at pos (a file's line 19 passed)
# Four checks from a fork (danszymkowiak/maisecrets f2c9ee2, 24e0162, 3355cb8; Apache-2.0), measured on CredData
# again for 0.6.24 against the password-label rules of 0.6.16 and 0.6.17: the name of a constant with a dash and an
# underscore, a time or a ratio after a colon label, a number of seconds before the full stop of a sentence, and a
# keyword that opens a sentence in a markdown table cell
# the words of a name (each with a vowel, or DB) and a counter of one or two digits: PROD-DB-PASS_7, MY_SECRET_VALUE_1;
# a run of capitals without a vowel or with a longer suffix is a value (review of 0.6.24)
_CONSTANT_NAME_RE = _LazyRx(r"(?:[A-Z]*[AEIOUY][A-Z]*|DB)(?:[-_](?:[A-Z]*[AEIOUY][A-Z]*|DB))+_\d{1,2}")
_TIME_OR_RATIO_RE = _LazyRx(r"\d+:[a-z]+")
_PROSE_AFTER_RE = _LazyRx(r" (?:and|or|of|for|with|to|in|the|is|are|und|oder|der|die|das|mit|für|ist|sind)"
                             r"(?![^\W_])")


def _number_of(secret: str) -> str:
    """The value without its quotes and the full stop of a sentence: `TOKEN_TTL = 3600.`"""
    v = secret.strip("\"' ")
    return v[:-1] if v.endswith(".") else v


def _in_table_cell(text: str, start: int) -> bool:
    """The value at `start` sits in a row of a markdown table."""
    return text[_line_start(text, start):start].lstrip().startswith("|")


_MEASURE_LABEL_RE = _LazyRx(r"(?i)(?<![a-z])(?:ttl|timeout|expir\w*|lifetime|max|min|len|length|size|count|limit"
                               r"|port|age|seconds|minutes|hours|days|retries|interval|ms|budget|refresh|rotation|cost"
                               r"|price|quota|window|delay|offset|threshold|rate|bytes|exp|iat|nbf|at|counter|index"
                               r"|generation)(?![a-z])")
# a label that names a secret: a UUID after it is one (Postmark server token, Scaleway secret key, a uuid4 API key)
_SECRET_LABEL_RE = _LazyRx(r"(?i)(?:token|secret[_-]?key|secret|secret[_-]?value|api[_-]?key|apikey|access[_-]?key"
                              r"|auth[_-]?key|\w+[_-]key|password|passwd|pwd|passphrase)\\?[\"']?\s*(?::=|=>|[:=])\s*\\?[\"'`]?$")
_ELISION_RE = _LazyRx(r"(?:\.\.\.|\u2026)$")
# a label that names a derived thing: secret_id, password_hash, token_type, hashed_secret. Anchored at the value: in
# `secret_name: x, password: <value>` the password stays a hit
_DERIVED_LABEL_RE = _LazyRx(
    r"(?i)(?:(?:secret|password|passwd|pwd|token|key)[_-]?(?:id|name|hash|hashed|len|length|path|file|arn|ref|url|uri"
    r"|version|type|policy|rules?|last(?:_\w+)?)|hashed_(?:secret|password|token)|(?:secret|password|token|key)Id"
    r"|(?:secret|password|token)Name)\\?[\"']?\s*(?::=|=>|[:=])\s*\\?[\"'`]?$")


def _yyyymmdd(v: str) -> bool:
    """An 8-digit number in the shape of a date of the years 1900 to 2099: 20231015. On purpose the shape, not the
    calendar: 20230231 is no day, but next to "account" it reads as a date field, not as an account number."""
    return len(v) == 8 and v.isdigit() and v[:2] in ("19", "20") and "01" <= v[4:6] <= "12" and "01" <= v[6:] <= "31"


def _label_before(text: str, start: int) -> str:
    """The label of the value at `start`: `TTL_REFRESH_TOKEN` in `TTL_REFRESH_TOKEN = 15552000`."""
    m = _LABEL_TAIL_RE.search(_before_value(text, start))
    return m.group(1) if m else ""


def _pass_equals_user(whole: str, secret: str) -> bool:
    """`postgres:postgres@`, `curl -u admin:admin`: a password equal to the user name is a default."""
    sec = secret.strip("\"' ")
    if ":" in sec:    # curl-auth-user: the secret group is user:pass
        u, _, pw = sec.partition(":")
        return u != "" and u.strip("\"' ").lower() == pw.strip("\"' ").lower()
    w = whole.strip("\"' ")
    head = w.split("://", 1)[1] if "://" in w else w
    user = head.split(":", 1)[0].strip("\"' ").rsplit(" ", 1)[-1]
    return user != "" and user.lower() == sec.lower()


def _line_of(text: str, start: int, end: int) -> str:
    a = text.rfind("\n", 0, start) + 1
    b = text.find("\n", end)
    return text[a: b if b >= 0 else len(text)]


def _allowed(rule: Rule, text: str, m: re.Match, secret: str) -> bool:
    """True when an allowlist says this hit is fine (i.e. skip it)."""
    if rule.stopwords and any(s in secret.lower() for s in rule.stopwords):
        return True
    for rx, target in rule.allow_regexes:
        # "match" is the whole match: `keyboard = …`, `public_key: …`, `api_version = …` are allowed
        # by their label, which the secret alone never shows (false-positive corpus, 2026-09-27)
        if target == "line":
            probe = _line_of(text, m.start(), m.end())
        else:
            probe = m.group(0) if target == "match" else secret
        if rx.search(probe):
            return True
    return False


_TOKEN_CHAR_RE = _LazyRx(r"[A-Za-z0-9_\-]")
# GitLab's routable token: payload, ".", version (2 base36), ".", length (2) and CRC32 (7) in base36: 9 characters;
# the older form has one dot: payload, ".", 9 characters (lib/authn/token_field/generator/routable_token.rb)
_ROUTABLE_TAIL_RE = _LazyRx(r"\.(?:[0-9a-z]{2}\.)?[0-9a-z]{9}(?![0-9A-Za-z_-])")
_GITLAB_PREFIX_RE = _LazyRx(r"gl[a-z]+-")


def _lower(text: str) -> str:
    """Lower case for the prefilters and context words. The Turkish capital İ lowers to i plus a
    combining dot, so `ŞİFRE:` held no `ifre` (Codex review, 2026-09-28); the dot is dropped. The
    result is not the length of the input: never take an offset of the original into it."""
    return text.lower().replace("i\u0307", "i")


# X-Amz-Credential=AKIA…/20261008/eu-central-1/s3/aws4_request: the access key id names the key, it is not the
# secret half; a presigned URL carries it in the clear by design (corpus of 0.6.7: 142 such hits in tool output)
_SIGV4_CREDENTIAL_RE = _LazyRx(r"\b(?i:x-amz-credential|credential)(?:=|%3[Dd])$")
# and the scope that must follow it: /date/region/service/aws4_request, plain or percent-encoded. A bare
# Credential=AKIA… is no SigV4 scope and stays a hit (codex review of 0.6.8)
_SIGV4_SCOPE_RE = _LazyRx(r"(?:/|%2[Ff])\d{8}(?:/|%2[Ff])[a-z0-9-]+(?:/|%2[Ff])[a-z0-9-]+(?:/|%2[Ff])aws4_request"
                             r"(?=$|[\s&,;\"'#])")    # then a query or header separator: not aws4_requestX (codex)
# a whole reference or a whole date in the password place of a URL: redis://:%24%7BREDIS_PASSWORD%7D@…,
# redis://:2026-10-08@…; an encoded $ or { inside a real password stays a value (codex, Opus review of 0.6.8)
_URL_PASSWORD_NOT_A_VALUE_RE = _LazyRx(r"%24[A-Za-z_][A-Za-z0-9_]*|%24%7[Bb][A-Za-z_][A-Za-z0-9_]*%7[Dd]"
                                          r"|\d{4}-\d{2}-\d{2}")    # a time has a colon, which this rule never takes


def _url_password_not_a_value(v: str) -> bool:
    """A whole encoded reference, or a date the calendar has (2026-02-31 is a value: codex review of 0.6.8)."""
    if not _URL_PASSWORD_NOT_A_VALUE_RE.fullmatch(v):
        return False
    if v.startswith("%"):
        return True
    import datetime
    try:
        datetime.date.fromisoformat(v)
    except ValueError:
        return False
    return True


# PostgreSQL's tools take --password (-W) as a switch with no value (Gate B of 0.6.15)
_PG_TOOL_RE = _LazyRx(r"(?<![\w-])(?:psql|pg_dump|pg_dumpall|pg_restore|pg_basebackup|createdb|dropdb|createuser"
                         r"|dropuser|vacuumdb|reindexdb|clusterdb|pgbench)(?:\.exe)?(?![\w-])")


def _command_start(text: str, pos: int) -> int:
    """The start of the shell command that holds pos: after the last | ; & on its line (round 2 of 0.6.15)."""
    a = _line_start(text, pos)
    cut = max(text.rfind(c, a, pos) for c in "|;&")
    return cut + 1 if cut >= a else a


def scan(text: str, enabled: set[str] | None = None, channel: str = "prompt", path: str = "",
         rule_list: list[Rule] | None = None) -> list[Match]:
    """Return non-overlapping matches, leftmost first; the first rule to claim a span wins. channel "tool" (a tool
    result or a file) takes a password after a password label without evidence of chance, and the cells of a
    password export (path: the file the text came from, if any). `rule_list` scans with those rules and the password
    export of a tool result, without the allow list and the sources (`maisecrets rules check`).
    `enabled` names rules by id or by key (maisecrets/detection/registry.py): an id that two rules share enables both,
    a key one
    of them."""
    # the channel and the path travel as arguments: a nested scan (is_fixture) or a scan in another thread has its own
    return _scan(text, enabled, rule_list=rule_list, channel="tool" if channel == "tool" else "prompt", path=path or "")


# a label rule (LABEL_RULES): its header labels the cell, so a word in it is stored quiet and a fixture in test code
# is dropped, as after `password:`
EXPORT_RULE = "label-password-export"
EXPORT_KEY = "export:" + EXPORT_RULE    # its key in maisecrets/detection/registry.py: `enabled` takes either
# the file names of password exports: a browser's (Chrome, Edge, Firefox, Safari), Bitwarden, 1Password, LastPass,
# KeePass and KeePassXC, Dashlane, and any table whose name says passwords
_EXPORT_NAME_RE = _LazyRx(r"(?i)(?:passw|kennw|logins?\b|bitwarden|1password|lastpass|keepass|dashlane|enpass"
                             r"|nordpass|roboform)[^/\\]*\.(?:csv|tsv|txt)$")
# a header names what its cells hold by its words (camelCase, _ - . and spaces split them): the last word, or the
# last two together. A flag (is_secret, has_password) holds no value; `token` alone is often an NLP column
_HEADER_WORD_RE = _LazyRx(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
_EXPORT_SECRET_WORDS = frozenset({"password", "passwd", "pwd", "passphrase", "passwort", "kennwort", "secret", "totp",
                                  "hotp", "otp", "otpauth"})
_EXPORT_SECRET_PAIRS = frozenset({"apikey", "secretkey", "privatekey", "accesstoken", "otpauth", "otpsecret",
                                  "mfasecret"})
_EXPORT_ID_WORDS = frozenset({"username", "user", "login", "loginname", "email", "mail", "url", "uri", "website",
                              "site", "web", "origin", "hostname", "host", "title", "name", "account", "benutzer",
                              "benutzername"})
_EXPORT_DELIMITERS = (",", ";", "\t")


def _header_words(cell: str) -> list:
    return [w.lower() for w in _HEADER_WORD_RE.findall(cell.strip().strip("\"'"))]


def _export_column(cell: str) -> str:
    """SECRET for a header whose cells are passwords, TOTP seeds or keys; ID for one that names an entry or its
    login; "" for any other."""
    w = _header_words(cell)
    if not w or w[0] in ("is", "has"):
        return ""
    if w[-1] in _EXPORT_SECRET_WORDS or "".join(w[-2:]) in _EXPORT_SECRET_PAIRS:
        return "SECRET"
    if w[-1] in _EXPORT_ID_WORDS or "".join(w[-2:]) in _EXPORT_ID_WORDS:
        return "ID"
    return ""


_CELL_MAX = 8192   # a quote that no quote closes within this many characters opens no cell: the cell ends its line


def _csv_cells(text: str, pos: int, delim: str):
    """The cells of the CSV row that starts at pos, as (start, end) of each cell's content (its quotes excluded), and
    the start of the next row. A quoted cell may hold the delimiter, a doubled quote and a line break."""
    cells = []
    n = len(text)
    i = pos
    while True:
        q = -1
        if i < n and text[i] == '"':
            j = i + 1
            limit = min(n, i + _CELL_MAX)
            while True:
                q = text.find('"', j, limit)
                if q < 0 or not text.startswith('""', q):
                    break
                j = q + 2
            if q >= 0 and q + 1 < n and text[q + 1] not in delim + "\r\n":
                q = -1   # no cell ends so: the quote opened no cell, and the cell ends its line
        if q >= 0:
            cells.append((i + 1, q))
            i = q + 1
        else:
            j = i
            while j < n and text[j] not in delim + "\r\n":
                j += 1
            cells.append((i, j))
            i = j
        if i < n and text[i] == delim:
            i += 1
            continue
        if i < n and text[i] == "\r":
            i += 1
        if i < n and text[i] == "\n":
            i += 1
        return cells, i


# what a cell of a schema, a form or a masked export holds instead of a password
_NOT_A_CELL_VALUE = frozenset({"true", "false", "null", "none", "nil", "undefined", "string", "str", "text", "int",
                               "integer", "bool", "boolean", "varchar", "yes", "no", "n/a", "na", "-", "--", "*",
                               "required", "optional", "hidden", "redacted", "masked", "empty", "password", "passwort",
                               "secret", "totp", "otp"})


def _outside_placeholders(text: str, a: int, b: int) -> list:
    """The parts of text[a:b] outside complete references (References.cell_spans), each trimmed: a reference is no
    value."""
    parts, pos = [], a
    for ra, rb in _references().cell_spans(text, a, b):
        parts.append((pos, ra))
        pos = rb
    parts.append((pos, b))
    out = []
    for pa, pb in parts:
        while pa < pb and text[pa] in " \t":
            pa += 1
        while pb > pa and text[pb - 1] in " \t":
            pb -= 1
        if pb > pa:
            out.append((pa, pb))
    return out


def _not_a_cell_value(v: str) -> bool:
    low = v.strip().lower()
    return low in _NOT_A_CELL_VALUE or (len(set(low)) == 1 and low[0] in "*\u2022x#.")


# a header row starts at the start of its line (code is indented) and each cell is a column name: up to four words,
# no brackets, operators or colons (a signature `def login(user, password):`, a call, a list line ending in a comma)
_HEADER_LINE_RE = _LazyRx(r"[\"'\w]")
_HEADER_CELL_RE = _LazyRx(r"[ \t]*\"?[A-Za-z][\w.#/-]*(?: [\w.#/-]+){0,3}\"?[ \t]*")
_NAME_RE = _LazyRx(r"\"?[A-Za-z][\w.-]*\"?")
_EXPORT_HINT_RE = _LazyRx(r"pass|pwd|kennw|totp|otp|secret|apikey|api_key|private_?key|access_?token")


def _export_hits(text: str, low: str, path: str = "") -> list:
    """The values in the password, TOTP and secret columns of a password export: a table whose header row names a
    secret column and an entry column (url, username, name, title, ...), or a secret column alone when the file name
    is an export's (passwords.csv, bitwarden_export.csv, ...). No rule finds a bare password in a cell: an export read
    whole put every password in front of the model."""
    if not _EXPORT_HINT_RE.search(low):
        return []
    by_name = bool(path) and _EXPORT_NAME_RE.search(path) is not None
    out = []
    pos = 0
    n = len(text)
    while pos < n:
        end = text.find("\n", pos)
        end = n if end < 0 else end
        line = text[pos:end].lower()   # not low: a lowered text can be longer than the original (Turkish I)
        header = None
        if _EXPORT_HINT_RE.search(line) and _HEADER_LINE_RE.match(line):
            best = None
            for delim in _EXPORT_DELIMITERS:
                if delim not in line:
                    continue
                cells, nxt = _csv_cells(text, pos, delim)
                if len(cells) < 2 or not all(_HEADER_CELL_RE.fullmatch(text[a:b]) and (
                        text[a - 1:a] == '"' or " " not in text[a:b].strip()) for a, b in cells):
                    continue   # each cell a column name, of several words only when quoted: code, SQL, prose and
                    # a test table are no header
                if len(cells) == 2 and not by_name and not all(_NAME_RE.fullmatch(text[a:b]) for a, b in cells):
                    continue   # two columns: names without a space (user_name,password), never `user, password`
                kinds = [_export_column(text[a:b]) for a, b in cells]
                if "SECRET" in kinds and ("ID" in kinds or by_name) and (best is None or len(cells) > len(best[1])):
                    best = (delim, cells, kinds, nxt)
            header = best
        if header is None:
            pos = end + 1
            continue
        delim, cells, kinds, pos = header
        secret_cols = [i for i, k in enumerate(kinds) if k == "SECRET"]
        width = len(cells)
        weak = width == 2 and not by_name
        while pos < n:
            if text.startswith(("\n", "\r\n"), pos):
                break   # an empty line ends the table
            row, nxt = _csv_cells(text, pos, delim)
            if len(row) != width:
                break   # no longer a row of this table: an export's rows all have the header's width
            for i in secret_cols:
                if i < len(row):
                    a, b = row[i]
                    while a < b and text[a] in " \t":
                        a += 1
                    while b > a and text[b - 1] in " \t":
                        b -= 1
                    if b <= a or _not_a_cell_value(text[a:b]) or (weak and _WHITESPACE_RE.search(text, a, b)):
                        continue   # a two-column table is a weaker sign: a cell with a space there is prose
                    for pa, pb in _outside_placeholders(text, a, b):
                        out.append(Match(EXPORT_RULE, "SECRET", text[pa:pb], pa, pb))
            pos = nxt
    return out


def _any_keyword(keywords: tuple, low: str, known: dict) -> bool:
    """Whether the lower-case text holds one of the keywords. Each keyword is searched once per text: a search runs
    over the whole text, and the same keyword gates several rules."""
    for k in keywords:
        hit = known.get(k)
        if hit is None:
            hit = known[k] = k in low
        if hit:
            return True
    return False


def _scan(text: str, enabled: set[str] | None = None, _copy: bool = False,
          rule_list: list[Rule] | None = None, channel: str = "prompt", path: str = "") -> list[Match]:
    """_copy: the text is the normaliser's cleaned copy of a tool result, which is not cleaned again."""
    if not text:
        return []
    low = _lower(text)
    found: list[Match] = []
    taken_starts: list[int] = []
    taken_ends: list[int] = []
    allowed = allow_list()[0] if rule_list is None else frozenset()
    allowed_spans: list[tuple[int, int]] = []

    def overlaps(a: int, b: int) -> bool:
        """Whether [a, b) overlaps a span already taken. The spans never overlap each other, so only the two
        neighbours by start can; a scan over all of them was quadratic in the hits (review of b4a7c54)."""
        i = bisect.bisect_left(taken_starts, a)
        return (i > 0 and taken_ends[i - 1] > a) or (i < len(taken_starts) and taken_starts[i] < b)

    def take(m: Match, own: bool = False) -> None:
        """Take the span and report it, unless the allow list names the value exactly. An allowed value takes no span:
        a later rule whose hit is longer still reports it (an allowed domain let the whole e-mail address through;
        Opus review of block 1). A later hit inside an allowed value of a built-in rule is a part of that value and
        is not reported; an allowed hit of a rule of your own (`own`) reserves nothing."""
        if m.value in allowed:
            if not own:
                allowed_spans.append((m.start, m.end))
            return
        if any(a <= m.start and m.end <= b for a, b in allowed_spans):
            return
        i = bisect.bisect_left(taken_starts, m.start)
        taken_starts.insert(i, m.start)
        taken_ends.insert(i, m.end)
        found.append(m)
    if channel == "tool" and not _copy and (enabled is None or EXPORT_RULE in enabled or EXPORT_KEY in enabled):
        # first: a cell of a password export is a value as a whole, and no other rule claims a part of it
        for m in _export_hits(text, low, path):
            take(m)
    keywords_in: dict = {}      # keyword -> whether the text holds it: the 652 keywords of the rules are 519 texts
    for rule in (_in_scan_order(rules()) if rule_list is None else rule_list):
        if rule is _PERSONAL:
            # the personal data of 0.6.21 and the cleaned copy of the tool channel run after every built-in rule and
            # before the rules of your own: a rule of your own never takes a span that a built-in step would have
            # found (review of the rebase on 0.6.21: a user rule cut an address that the copy saw whole)
            _personal_hits(text, enabled, found, taken_starts, taken_ends, overlaps, channel)
            if channel == "tool" and not _copy:
                _scan_cleaned_copy(text, enabled, found, taken_starts, taken_ends, channel, path)
            continue
        if rule is _TERMS:
            _term_hits(text, enabled, found, taken_starts, taken_ends, overlaps, take)
            continue
        if rule is _IMPORTS:
            _import_hits(text, enabled, found, taken_starts, taken_ends, overlaps, take)
            continue
        if enabled is not None and rule.id not in enabled and rule.key not in enabled:
            continue
        if rule.keywords and not _any_keyword(rule.keywords, low, keywords_in):
            continue
        # a rule that cannot fire without a context word need not run its regex without one
        alone = channel == "tool" and rule.id in CARD_ALONE_IN_TOOL
        if (rule.context and (rule.require_context or rule.score < 0.5) and not alone
                and not _has_context_word(low, rule.context)):
            continue
        own = _runs_after_personal(rule)
        form = rule.form or _registry.form_of(rule.id)    # a rule list a caller built has no form set
        keyword = form == "keyword"
        filters = rule.filters if rule.filters is not None else _registry.filters_of(rule.id)
        hits = _matches(rule, text, channel)
        for m in (_timed(rule, hits, len(text)) if own and rule_list is None else hits):
            ngroups = rule.regex.groups or 0
            if rule.whole_match:
                g = 0
            elif 0 < rule.secret_group <= ngroups:
                g = rule.secret_group
            else:
                g = next((i for i in range(1, ngroups + 1) if m.group(i)), 0)
            start, end = m.start(g), m.end(g)
            if end <= start:
                continue
            secret = m.group(g)
            if rule.id in PRESIDIO_HYPHEN_TAIL:
                tail = _HYPHEN_DIGITS_TAIL_RE.match(text, end)
                if tail:
                    end = tail.end()
                    secret = text[start:end]
            if "cjk-head" in filters and _is_cjk(secret[0]):
                # the address took the Japanese, Chinese or Korean words before it (\w holds their letters)
                k = next((i for i, ch in enumerate(secret) if not _is_cjk(ch)), len(secret))
                start += k
                secret = text[start:end]
                if not secret or secret[0] in "@.":
                    continue
            if "base64-wrapped-end" in filters:
                end = _base64_wrapped_end(text, start, end)   # the further lines of a wrapped value
                secret = text[start:end]
            if ("escaped-label-quote" in filters and "\\" in (m.group(2) or "")
                    and text[start - 2:start] not in ('\\"', "\\'")):
                # the label's quote is escaped: JSON inside a string, whose values are escaped strings. A value without
                # an escaped quote is code or a literal: `\"access_token\": finding[\"secret\"]` (19 hits in the
                # vendored rules file, Gate A of 0.6.15), an escaped null (Gate B)
                continue
            if secret.endswith("\\") and text[end:end + 1] in ("\"", "'") and "escaped-value-quote" in filters:
                secret, end = secret[:-1], end - 1   # {\"password\":\"<value>\"}: the backslash escapes the quote
            if ("escaped-label-quote" in filters and "\\" in (m.group(2) or "")
                    and not _label_value_ok(secret)):
                continue   # {\"passwordLastChanged\":\"2024-10-01T12:00:00Z\"}: the new escaped path, no password
            if rule.quote_group and not m.group(rule.quote_group):
                if _has_cjk(secret) and not _is_cjk(secret[0]):
                    # 密码：<value>，请保密: Chinese and Japanese put no space after the value, so its end is the
                    # first CJK letter or fullwidth sign. A value that starts with one is cut by no rule here
                    k = next(i for i, ch in enumerate(secret) if _is_cjk(ch))
                    secret = secret[:k]
                    end = start + len(secret)
                cut = _WHITESPACE_RE.search(secret)
                if cut:
                    # the regex never ends a value on a comma; the cut keeps that rule
                    secret = secret[:cut.start()].rstrip(",")
                    end = start + len(secret)
                    if _CAPITALISED_WORD_RE.fullmatch(secret):
                        continue
            if keyword and _ANCHOR_OR_TAG_RE.fullmatch(secret.strip()):
                # a quoted scalar is never an anchor: the colon must stand right before it (review of b4a7c54)
                nxt = re.match(r"[ \t]+([^\s#]+)", text[end:end + 300])
                if nxt:
                    # password: &pw <value>, password: !vault <value>: the value follows the anchor or the tag
                    # (review of 3e5d53e: the value after it was never scanned); its quotes are no part of it
                    a, b = end + nxt.start(1), end + nxt.end(1)
                    if b - a >= 2 and text[a] == text[b - 1] and text[a] in "'\"":
                        a, b = a + 1, b - 1
                    start, end = a, b
                    secret = text[start:end]
                elif _before_value(text, start).rstrip(" \t").endswith(":"):
                    continue   # a YAML anchor or alias alone after a colon label: &gitlab_token_fields
            if rule.id in _VALIDATE_FIRST and not VALIDATORS[rule.validator](secret):
                continue   # a word after a password word in a sentence: the cheap check first (else 3x slower)
            if keyword and (is_code_word(secret) or value_is_code(text, start, end, secret)):
                continue
            if "word-path" in filters and _WORD_PATH_RE.fullmatch(secret.strip("'\"")):
                continue
            if keyword and _names_its_label(text, start, secret):
                continue
            if (keyword and _LABEL_SHAPE.fullmatch(secret.strip())
                    and _NAME_LABEL_RE.fullmatch(secret.strip()) and "\n" in text[m.start():start]):
                continue   # the next line is a label of its own: `DB_PASSWORD=\nAPI_KEY=`, `Zugangsdaten:\nBenutzer:`
            if (keyword and _number_of(secret).isdigit()
                    and _MEASURE_LABEL_RE.search(_label_before(text, start))):
                continue   # a limit or a duration: TTL_REFRESH_TOKEN = 2592000, also at the end of a sentence
            if "constant-name" in filters and _CONSTANT_NAME_RE.fullmatch(secret.strip("\"'`")):
                continue   # the name of a constant, not its value: PROD-DB-PASS_7
            if "time-or-ratio" in filters and _TIME_OR_RATIO_RE.fullmatch(secret.strip("\"'`")):
                continue   # 0:default after `secret:`
            if (keyword and secret.isalpha() and secret.islower() and _PROSE_AFTER_RE.match(text, end)
                    and _in_table_cell(text, start)):
                continue   # | token: counts and ... |: a sentence in a markdown table cell goes on after the word
            if "template-value" in filters and secret.startswith("{"):
                continue   # a template: ?token={body['transfer_id']}, ?token={SLACK_AUTO_TOKEN}
            if ("words-not-token" in filters and not any(c.isdigit() for c in secret)
                    and re.fullmatch(r"[A-Za-z]+(?:[_-][A-Za-z]+)+", secret)):
                continue   # words, not a token: Bearer test_access_token
            if "derived-label" in filters and (
                    (_UUID_RE.fullmatch(secret.strip("\"'` ")) and rule.id != "label-prose-key"   # its words name a key
                     and not _SECRET_LABEL_RE.search(
                        text, max(_line_start(text, start), start - 60), start))
                    or (_ELISION_RE.search(secret) and len(secret.rstrip(".\u2026")) < 20)
                    or _DERIVED_LABEL_RE.search(text, max(_line_start(text, start), start - 60), start)):
                continue   # a UUID, an elided value (sk-...), or a label that names a derived thing (secret_id)
            if "user-equals-password" in filters and _pass_equals_user(m.group(0), secret):
                continue
            if ("sigv4-scope" in filters and _SIGV4_CREDENTIAL_RE.search(text, max(0, start - 24), start)
                    and _SIGV4_SCOPE_RE.match(text, end)):
                continue   # the key id in a SigV4 credential scope (a presigned URL, an Authorization header)
            if ("pg-password-switch" in filters and text[start - 1:start] not in "'\""
                    and _PG_TOOL_RE.search(text, _command_start(text, start), start)):
                continue   # `psql --password app_db`: a switch that asks for the password, then the database
            if "url-password-value" in filters and _url_password_not_a_value(secret):
                continue
            if "password-value" in filters and not _ds_value_ok(secret.strip("\"'")):
                continue
            if "encoded-mail-context" in filters and not _encoded_mail_expected(text, start, end):
                continue
            if "phone-shape" in filters and not _phone_ok(text, start, secret):
                continue
            if rule.type == "IP" and _SECTION_BEFORE_RE.search(text, max(0, start - 24), start):
                continue   # a section number: RFC 6749 4.1.2.1, OIDC Core 3.1.2.1, section 7.1.2.3
            if overlaps(start, end):
                continue
            if rule.entropy and not _entropy_ok(rule, secret, channel):
                continue
            if rule.drop is not None and rule.drop({"secret": secret, "match": m.group(0), "path": "",
                                                    "line": text[_line_start(text, start):_line_end(text, end)]}):
                continue                     # the betterleaks filter of the rule, or the global one
            if rule.validator:
                try:
                    if (rule.validator == "ds_value" and 0 < start and text[start - 1] in ":="
                            and not _references().inside(text, start)):   # not inside a reference
                        # a value glued to its label, with no space after the colon, is typed on purpose: 6 characters
                        # count. With a space between them 8 stay the floor, against prose such as
                        # "password: string" (field report, 2026-09-27: a 7-letter password passed)
                        ok = _ds_value_ok(secret, min_len=6) and (len(secret.strip()) >= 8 or not _short_word(secret))
                    else:
                        ok = VALIDATORS[rule.validator](secret)
                except (ValueError, IndexError, TypeError):
                    ok = False   # a validator that cannot parse the value has not validated it
                if not ok:
                    continue
            if rule.type == "SECRET" and "seed-phrase" not in filters and looks_like_placeholder(secret):
                # the checksum of a seed phrase is its proof; "example" and "sample" are words of the list
                continue
            labelled = rule.type == "SECRET" and form != "shape"
            # a seed phrase is compared in one form: its words with one space between them
            as_published = " ".join(_WORD_RE_ANY.findall(secret)) if "seed-phrase" in filters else secret
            if is_public_test_value(as_published, rule.type) and not labelled:
                # a documented test card, key or number that a shape rule found. A published key that a label assigns
                # (PROD_PASSWORD=<the Stripe docs key>) is used as a credential and stays a hit: being public does not
                # make the same bytes no secret there (review of 0.6.12). The label rules run first, so no later rule
                # claims a span around a skipped key; a value of another type around a test card stays its own hit
                continue
            if rule.type == "SECRET" and len(secret) >= 16 and len(set(secret[-12:])) <= 1:
                continue   # a prefix and one repeated character: glpat-AAAAAAAAAAAAAAAAAAAA is a placeholder
            if alone and not _card_shaped(text, start, secret) and not _has_context_word(
                    _lower(text[max(0, start - 80):min(len(text), end + 40)]), rule.context):
                continue   # without a card word, only a number written as a card: groups and an issuer prefix
            if (rule.score < 1.0 or rule.require_context) and not alone:
                # presidio semantics: a weak shape passes only with a context WORD nearby
                # cut from the original text, then lowered: a lowered text is not the same length (the
                # Turkish İ lowers to two characters), so its offsets are not the original's
                window = _lower(text[max(0, start - 80):min(len(text), end + 40)])
                has_context = _has_context_word(window, rule.context)
                if rule.require_context and not has_context:
                    continue
                if rule.score < 0.5 and not has_context:
                    continue
                if rule.id in PRESIDIO_NO_DATE and _yyyymmdd(secret):
                    continue
                if rule.id in PRESIDIO_WHOLE_DIGIT_RUN and (
                        re.match(r"-[A-Za-z0-9]", text[end:end + 2])
                        or re.search(r"[A-Za-z0-9]-$", text[max(0, start - 2):start])):
                    continue
                if rule.id in PRESIDIO_WHOLE_TOKEN:
                    while start > 0 and text[start - 1].isascii() and text[start - 1].isalnum():
                        start -= 1
                    while end < len(text) and text[end].isascii() and text[end].isalnum():
                        end += 1
                    secret = text[start:end]
                label_window = PRESIDIO_LABEL_BEFORE.get(rule.id)
                if label_window:
                    line_start = text.rfind("\n", 0, start) + 1
                    if not _has_context_word(_lower(text[max(line_start, start - label_window):start]), rule.context):
                        continue
            if _allowed(rule, text, m, secret):
                continue
            # a reference is never a hit, alone or inside a larger span such as the user:pass of a curl command
            # around one (the README example was flagged, 2026-09-26)
            if _references().hit_is_a_reference(text, start, secret):
                continue
            if rule.type == "SECRET":
                # a fixed-length shape (betterleaks: glpat-[\w-]{20}) stops inside a longer token and
                # the tail would stay in the clear (4 chars of a 24-char token, 2026-09-26): the
                # value runs to the end of the token characters
                end2 = end
                gitlab = _GITLAB_PREFIX_RE.match(secret)
                while end2 < len(text) and end2 - end < (400 if gitlab else 128) and _TOKEN_CHAR_RE.match(text[end2]):
                    end2 += 1
                if gitlab and end2 - end > 128 and not _ROUTABLE_TAIL_RE.match(text, end2):
                    # the payload of a routable GitLab token runs up to 235 characters before its ".01.<id>" tail
                    # (routable_token.rb), past the 128; a run without that tail keeps the bound (0.6.20)
                    end2 = end + 128
                if end2 > end and _TOKEN_CHAR_RE.match(secret[-1]) and not overlaps(end, end2):
                    end = end2
                    secret = text[start:end]
                # a routable GitLab token ends in ".<version>.<id>" (glpat-...CA.01.0y0znlm9w): the token
                # characters stop at the dot, and the tail stayed in the clear (field report, 2026-10-06)
                tail = _ROUTABLE_TAIL_RE.match(text, end) if _GITLAB_PREFIX_RE.match(secret) else None
                if tail and not overlaps(end, tail.end()):
                    end = tail.end()
                    secret = text[start:end]
            if (keyword and len(secret) > 1 and secret[-1] in _SENTENCE_STOP
                    and (end >= len(text) or text[end].isspace())):
                # `password: <value>.` ends a sentence: the stop is no part of the value, or the store keeps a wrong
                # password (field report, 2026-10-16). A value that ends with a dot is written in quotes. The checks
                # above judged the value with its stop, as before: the cut moves the end of a hit, never makes one
                # one stop; two dots or more are an ellipsis and stay (tests/test_leak_direction.py: <value>!...)
                cut = len(secret) if secret.endswith("..") else len(secret) - 1
                end -= len(secret) - cut
                secret = secret[:cut]
            if rule.type == "PHONE":
                ext = _PHONE_EXTENSION_RE.match(text, end)
                if ext:
                    end = ext.end()
                    secret = text[start:end]
            take(Match(rule.id, rule.type, secret, start, end), own)
    found.sort(key=lambda x: x.start)
    return found


_PERSONAL = object()             # the place of _personal_hits in the scan order
# the extension right after a phone number is part of it: (212) 555-0143x204, +1 212 555 0143 ext. 31. A phone hit
# that stopped before it left the extension in the clear (Benchmark V2, Gretel dev: 61 numbers found in part)
_PHONE_EXTENSION_RE = _LazyRx(r"(?i)[ ]?(?:x|ext\.?|extension)[ ]?\d{1,6}(?![\w.]?\d)")
_TERMS = object()                # the place of _term_hits: registry phase "terms", after the rules of your own
_IMPORTS = object()              # the place of _import_hits: registry phase "imports", after the terms


def _runs_after_personal(rule: Rule) -> bool:
    """A rule of your own: its phase (registry.PHASES["user"]) puts it after the personal-data step. A rule list that a
    caller built has no phase; its rules of your own have the id prefix `user:`."""
    return rule.phase == _registry.PHASES["user"] if rule.phase else rule.id.startswith("user:")


def _in_scan_order(every: list) -> tuple:
    """The rules of a list in scan order: the built-in ones, then the personal-data step and the cleaned copy, then the
    rules of your own (ids with `user:`), then the terms, then the imported values. Kept per list, so a scan pays for
    it once."""
    d = _det()
    if d._order[0] is not every:
        d._order = (every, tuple(r for r in every if not _runs_after_personal(r)) + (_PERSONAL,)
                    + tuple(r for r in every if _runs_after_personal(r)) + (_TERMS, _IMPORTS))
    return d._order[1]


def _personal_hits(text: str, enabled, found: list, taken_starts: list, taken_ends: list, overlaps,
                   channel: str = "prompt") -> None:
    """Personal data after a label or in a fixed form (maisecrets/detection/personal.py), after every other rule: a
    span that
    another rule took stays its own, and a placeholder or a documentation value is no hit."""
    try:
        from . import personal
    except ImportError:   # a copy of detect.py without its sibling modules
        return
    allowed, off = allow_list()
    by_start, gone = None, set()
    company: list = []
    every = sorted(personal.hits(text, channel, _pii_regions_cached(), company))
    # the decision belongs to an address rule that runs: a rule that `enabled` or the allow list turns off decides
    # nothing (Gate B of this change)
    company = [c for c in company if (enabled is None or c[4] in enabled or "personal:" + c[4] in enabled)
               and not (off and c[4] in off)]
    if company:
        _free_company_numbers(text, found, taken_starts, taken_ends, company,
                              [(s, e) for s, e, _, t in every if t == personal.NAME])
    for start, end, kind, typ in every:
        if enabled is not None and kind not in enabled and "personal:" + kind not in enabled:
            continue
        if typ == personal.PHONE:
            ext = _PHONE_EXTENSION_RE.match(text, end)
            if ext:
                end = ext.end()
        value = text[start:end]
        if value in allowed or (off and kind in off):
            continue   # the allow list holds for these rules too: an exact value, or `rule: <id>`
        low = value.lower()
        if _references().has_marks(value) or "example" in low or low in personal.PLACEHOLDER_NAMES \
                or looks_like_placeholder(value) or is_public_test_value(value, typ):
            continue
        if kind in personal.ONLY_WIDENS and not overlaps(start, end):
            continue   # a form that only completes a hit another rule made: alone it would mask company addresses
        if overlaps(start, end):
            # an address takes the postcode that a region rule found inside it (de-plz): the whole address is the
            # value. A phone number wrapped over two lines takes the first line that the phone rule found. Any other
            # hit keeps its span
            lo, hi = bisect.bisect_left(taken_starts, start), bisect.bisect_left(taken_starts, end)
            if (typ != personal.ADDRESS and kind != "phone-wrapped-line") or hi == lo or hi - lo > 32 or (
                    lo > 0 and taken_ends[lo - 1] > start):
                continue
            if by_start is None:   # once per scan: a list scan per overlap was quadratic in the hits (review)
                by_start = {f.start: f for f in found}
            inside = [by_start[x] for x in taken_starts[lo:hi] if x in by_start]
            inside = [f for f in inside if f.end <= end and f.type not in SECRET_TYPES]
            wider = typ == personal.ADDRESS or all(f.type == typ for f in inside)
            if not wider or not inside or hi - lo != len(inside):
                continue
            gone.update(id(f) for f in inside)   # removed from `found` once, after the loop
            for f in inside:
                by_start.pop(f.start, None)
                i = bisect.bisect_left(taken_starts, f.start)
                del taken_starts[i], taken_ends[i]
        found.append(Match(kind, typ, value, start, end))
        if by_start is not None:
            by_start[start] = found[-1]
        i = bisect.bisect_left(taken_starts, start)
        taken_starts.insert(i, start)
        taken_ends.insert(i, end)
    if gone:
        found[:] = [f for f in found if id(f) not in gone]


# between a company's address and its VAT ID: separators, the country, and a VAT label (USt-IdNr., VAT ID, UID, also
# the recipient's: Ihre, Kunden-) with at most one line break. Any other text (a second address, a name, the sender's
# label: Unsere, meine; a value, a blank line) ends the company's block
_SEP = r"[ \t,;|·\"'()]{0,6}(?:\r?\n[ \t,;|·\"'()]{0,6})?"
_VAT_GAP_RE = _LazyRx(r"(?i)" + _SEP + r"(?:(?:deutschland|germany)" + _SEP + r")?"
                         r"(?:(?:(?:ihre|your|kunden|customer|recipient|client|empfänger)[ _-]?)?"
                         r"(?:ust|vat|umsatzsteuer|uid|mwst)(?:[ ._-]?(?:id|identifikationsnummer|identification"
                         r"|nummer|number|no|nr)\.?){0,2}[\"']?[ ]?[:#=]?" + _SEP + r")?")
_COMPANY_REACH = 800
_CUSTOMER_VALUE_RE = _LazyRx(r"(?i)(?<![\w-])(?:kunde|customer)[\"']?[ \t]{0,3}[:=][ \t\"']{0,3}$")
COMPANY_NUMBER_TYPES = frozenset({"DE_PLZ", "DE_VAT_ID"})


def _free_company_numbers(text: str, found: list, taken_starts: list, taken_ends: list, company: list,
                          names: list) -> None:
    """The postcode and the VAT ID follow the company decision of the address rules. An address rule leaves an address
    as text when a word of a company or a public place stands near it; personal._company_window keeps the addresses
    whose holder is a company: a legal form (GmbH, AG, Ltd, Inc) ends the company's name right before the address.
    Its postcode (de-plz) and a German VAT ID right after it are no personal data either. Masked alone, they left
    the street of the same address in the clear, and that half mask protected nothing (field report, 2026-10-16: an
    invoice to a GmbH). Each entry of `company` is (lo, legal form, address start, address end, address rule).
    A name of a person (a personal NAME hit) in the paragraph up to 160 characters before the legal form, or between
    it and the value, keeps the value masked (tests/test_company_address_window.py); a NAME hit that ends right
    before the legal form is the company's name (Kunde: Beispiel GmbH). A sole trader has no legal form,
    so the postcode and the VAT ID of a sole trader stay masked."""
    drop = set()
    company = sorted(company, key=lambda c: c[2])
    starts = [c[2] for c in company]
    for f in found:
        if f.type not in COMPANY_NUMBER_TYPES:
            continue
        # an address rule's window and value are bounded (a line back of at most 160 characters, a value of at most
        # a few hundred), so only the addresses that start near the value can hold it: a text of many company
        # addresses stays linear. An address beyond this reach keeps its postcode masked, never the other way
        i = bisect.bisect_left(starts, f.start - _COMPANY_REACH)
        j = bisect.bisect_right(starts, f.start + 1)
        for lo, form, a, b, _ in company[i:j]:
            if f.type == "DE_PLZ":
                if not (a <= f.start and f.end <= b):
                    continue
            elif not (b <= f.start and _VAT_GAP_RE.fullmatch(text, b, f.start)):
                continue
            para = text.rfind("\n\n", max(0, form - 160), form)
            g = max(0, form - 160) if para < 0 else para
            k = bisect.bisect_left(names, (g,))
            # a name that ends right before the legal form, as the value of a customer key, is the company's own
            # (Kunde: Beispiel GmbH)
            while k < len(names) and names[k][0] < f.end and not text[names[k][1]:form].strip(" \t") \
                    and _CUSTOMER_VALUE_RE.search(text, max(0, names[k][0] - 16), names[k][0]):
                k += 1
            if not (k < len(names) and names[k][0] < f.end):
                drop.add(id(f))
            break
    if not drop:
        return
    for f in found:
        if id(f) in drop:
            i = bisect.bisect_left(taken_starts, f.start)
            del taken_starts[i], taken_ends[i]
    found[:] = [f for f in found if id(f) not in drop]


_WINDOW_BEFORE = 2048  # context a rule may read before a value: a label 200, a context word 80, an AWS key id up to
_WINDOW_AFTER = 512    # four lines of 400 before its secret (aws-secret-after-access-key); after it: a context word 40


def _changed_windows_scan(text: str, norm, enabled, channel: str = "prompt", path: str = "") -> list:
    """The hits of the cleaned copy, scanned only around its changed lines: each changed line with the whole lines
    that hold the _WINDOW_BEFORE characters before it and the _WINDOW_AFTER characters after it, windows that touch
    merged. A line the stages left alone holds the hits the raw scan already has, and a rescan of the whole text
    doubled the time of a 70 KB tool result with one coloured line or one JWT."""
    copy, starts, ends = norm.text, norm.starts, norm.ends
    windows: list = []
    a = 0
    n = len(copy)
    while a <= n:
        b = copy.find("\n", a)
        b = n if b < 0 else b
        # the original range of this line, from after the previous line break to this one: deleted characters at
        # its edges and a line that only deleted characters held count as a change (Gate A, round 2)
        oa = ends[a - 1] if a > 0 else 0
        ob = starts[b] if b < n else len(text)
        if ob - oa != b - a or text[oa:ob] != copy[a:b]:
            wa = copy.rfind("\n", 0, max(0, a - _WINDOW_BEFORE)) + 1 if a > _WINDOW_BEFORE else 0
            wb = copy.find("\n", min(n, b + _WINDOW_AFTER))
            wb = n if wb < 0 else wb
            if windows and wa <= windows[-1][1] + 1:
                windows[-1][1] = max(windows[-1][1], wb)
            else:
                windows.append([wa, wb])
        a = b + 1
    out = []
    for wa, wb in windows:
        for m in _scan(copy[wa:wb], enabled, _copy=True, channel=channel, path=path):
            out.append(Match(m.kind, m.type, m.value, m.start + wa, m.end + wa))
    return out


def _scan_cleaned_copy(text: str, enabled, found: list, taken_starts: list, taken_ends: list,
                       channel: str = "prompt", path: str = "") -> None:
    """The tool channel also scans a copy of the text without terminal and encoding disguises (ANSI codes, zero-width
    characters, HTML entities, fullwidth letters, base64 and hex runs: maisecrets/detection/normalise.py). A hit of the
    copy
    redacts its original range, hidden characters included. The raw text's own hits came first and keep their spans,
    except a part of a value that the copy sees whole: the whole replaces the part, or the rest reaches the model."""
    try:
        from .normalise import normalise
    except ImportError:   # a copy of detect.py without its sibling modules: the raw scan alone
        return
    norm = normalise(text)
    if norm.text is text:
        return
    by_start = {f.start: f for f in found}   # the taken spans never overlap, so a start names one
    copy_hits = _changed_windows_scan(text, norm, enabled, channel, path)
    if enabled is None or EXPORT_RULE in enabled or EXPORT_KEY in enabled:
        # a header in colour or in entities: the table is read whole in the copy, not only around changed lines
        copy_hits = _export_hits(norm.text, _lower(norm.text), path) + copy_hits
    for m in copy_hits:
        start, end = norm.span(m.start, m.end)
        lo = bisect.bisect_left(taken_starts, start)
        if lo > 0 and taken_ends[lo - 1] > start:
            lo -= 1
        inside = [by_start[a] for a in taken_starts[lo:bisect.bisect_left(taken_starts, end)]]
        if inside:
            if not all(start <= f.start and f.end <= end for f in inside) or \
                    all((f.start, f.end) == (start, end) for f in inside):
                continue
            for f in inside:
                found.remove(f)
                del by_start[f.start]
                i = bisect.bisect_left(taken_starts, f.start)
                del taken_starts[i], taken_ends[i]
        found.append(Match(m.kind, m.type, text[start:end], start, end))
        by_start[start] = found[-1]
        i = bisect.bisect_left(taken_starts, start)
        taken_starts.insert(i, start)
        taken_ends.insert(i, end)


def _claim(m: Match, text: str, found: list, starts: list, ends: list) -> None:
    """A listed term (maisecrets/terms.py) that a rule found too, as an email address or a token-shaped case number:
    the rule keeps its type, the span grows to cover both, and the kind is the term's. So the store keeps the entity
    id, never the term, and the placeholder is never resolved (C26). Without this the rule's kind won, the store kept
    the term, and its placeholder was resolved into commands and files (codex review of block 2)."""
    hit = [f for f in found if f.start < m.end and m.start < f.end]
    if not hit:
        return                   # an allowed value holds the span: the person allowed exactly that text
    if any(_WORD_CHAR_RE.search(text, f.start, m.start) or _WORD_CHAR_RE.search(text, m.end, f.end) for f in hit):
        # a rule hit that holds more than the term (a password with a listed name in it) keeps its span and its
        # kind: the store keeps the value whole, and a later output with it is masked whole. As a term the rest of
        # the password went out in clear in each later output (#19). The parts of the term outside the taken
        # spans are its own hits
        _term_rest(m, text, found, starts, ends)
        return
    a, b = min([m.start] + [f.start for f in hit]), max([m.end] + [f.end for f in hit])
    for f in hit:
        found.remove(f)
        i = starts.index(f.start)
        del starts[i], ends[i]
    if any(x < b and a < y for x, y in zip(starts, ends)):
        found.extend(hit)        # the union would reach another taken span: leave the rules' hits as they were
        for f in hit:
            i = bisect.bisect_left(starts, f.start)
            starts.insert(i, f.start)
            ends.insert(i, f.end)
        return
    i = bisect.bisect_left(starts, a)
    starts.insert(i, a)
    ends.insert(i, b)
    found.append(Match(m.kind, hit[0].type, text[a:b], a, b))


_WORD_CHAR_RE = _LazyRx(r"\w")


def _term_rest(m: Match, text: str, found: list, starts: list, ends: list) -> None:
    """The parts of a term outside every taken span, each a hit of the term when it holds a word character."""
    lo, hi = bisect.bisect_left(ends, m.start + 1), bisect.bisect_left(starts, m.end)
    pos, pieces = m.start, []
    for x, y in zip(starts[lo:hi], ends[lo:hi]):
        if x > pos:
            pieces.append((pos, min(x, m.end)))
        pos = max(pos, y)
    if pos < m.end:
        pieces.append((pos, m.end))
    for a, b in pieces:
        if _WORD_CHAR_RE.search(text, a, b):
            i = bisect.bisect_left(starts, a)
            starts.insert(i, a)
            ends.insert(i, b)
            found.append(Match(m.kind, m.type, text[a:b], a, b))


def contains_secret(text: str) -> bool:
    return any(m.type in SECRET_TYPES for m in scan(text))


# ------------------------------------------------------------------------------------------------- facade --
# What a module outside the detection core may use besides scan(), is_fixture(), Match, rules() and the other names
# without an underscore. The plugin (hooks, the value check, the rules of your own) called private names of this
# module; a test (tests/test_detection_boundary.py) now refuses such a use in the forms it names, so the core can
# change its inside without breaking a caller. Each name below is the private object itself or a function of the same
# steps: no behaviour moves.
LazyRx = _LazyRx            # a regex compiled at its first use
LazyRegex = _Lazy           # a compiled rule pattern with a time budget (the rules of your own)


_USER_TYPE_RE = _LazyRx(r"[A-Z][A-Z0-9_]{0,40}")


def user_rule(id: str, type: str, pattern: str, keywords=(), secret_group: int = 0) -> Rule:
    """A rule of your own for Sources.user_rules: the stable way to make one (docs/DETECTION.md, "The API").

    `id` names the rule (it becomes `user:<id>`, so no rule of your own takes the name of a built-in one), `type` the
    placeholder type (SECRET, EMAIL, a name of your own in capitals), `pattern` a Python regex, `keywords` words of
    which one must be in the text before the regex runs (lower case, the cheap prefilter), and `secret_group` the
    group that holds the value (0: the whole match). A wrong argument raises ValueError. The Rule it returns is no
    stable type: its other fields belong to the detector and can change in any version."""
    if not isinstance(id, str) or not id or any(c.isspace() for c in id):
        raise ValueError("user_rule: id must be a word without spaces")
    if not isinstance(type, str) or not _USER_TYPE_RE.fullmatch(type):
        raise ValueError("user_rule: type must be capitals, digits and _ (SECRET, EMAIL, MY_TYPE)")
    try:
        groups = re.compile(pattern).groups
    except (re.error, TypeError) as e:
        raise ValueError(f"user_rule: the pattern does not compile ({e})") from None
    if not isinstance(secret_group, int) or isinstance(secret_group, bool) or not 0 <= secret_group <= groups:
        raise ValueError(f"user_rule: secret_group must be 0 to {groups}, the groups of the pattern")
    words = tuple(str(k).lower() for k in keywords)
    if any(not w for w in words):
        raise ValueError("user_rule: a keyword is empty")
    rid = id if id.startswith("user:") else "user:" + id
    return Rule(id=rid, type=type, regex=_Lazy(pattern, 0), keywords=words, secret_group=secret_group)
re2_to_python = _re2_to_python   # a pattern in RE2 syntax, as Python's re reads it


def findings(text: str, channel: str = "prompt", path: str = "") -> list[Match]:
    """The hits of scan() without the fixtures of a pasted test (is_fixture). The scan runs in the channel of the
    caller; is_fixture runs after it, and its own check of a value scans in the prompt channel, as before."""
    return [m for m in scan(text, channel=channel, path=path) if not is_fixture(m, text, path)]


def explain_allowed(value: str) -> str | None:
    """Why the allow list lets this value through, or None. Only for a value no rule caught: the scan with every rule,
    without the allow list, shows whether the list took a hit out (`rule: <id>` or an exact value)."""
    values, ids = allow_list()
    if not values and not ids:
        return None
    if value in values or value.strip() in values:
        return "your allow list allows this exact value"
    every = [r for _, r in _ranked(active_regions())]
    for m in scan(value, rule_list=every):
        if m.value in values or m.value.strip() in values:
            return "your allow list allows this exact value"
        if switched_off(m.kind, ids):
            return f"your allow list switches off the rule {m.kind}"
    return None


def bare_value_is_a_credential(v: str) -> bool:
    """The evidence of chance that makes a value without a label a credential, after the caller's own checks of form
    (maisecrets/check_value.py): no value that names itself; a password literal; else entropy for its alphabet, no
    base64 of a text, no word, and no leetspeak word."""
    if _names_itself(v):
        return False
    if _pw_literal_ok(v):
        return True
    return (shannon_entropy(v) >= ENTROPY_BY_ALPHABET[alphabet_of(v)]
            and not _base64_of_text(v) and not reads_as_word(v)
            and _wordlike(_deleet(v)) < 0.3 and _ds_value_ok(v))

