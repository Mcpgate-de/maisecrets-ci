"""The value checks of the detector: entropy, the check digits, the filters of a value after a label, the word list,
the forms of a label and a literal value, and the placeholder words.

maisecrets/detection/core.py imports each name of this module, so `core.<name>` (and `detect.<name>`) is the same
object. A patch of one of these names on the core does not reach the functions of this module: patch this module."""
from __future__ import annotations

import base64 as _b64
import ipaddress
import math
import re
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

from .lazy_regex import LazyRx as _LazyRx

if TYPE_CHECKING:
    from .core import Rule

RULES_DIR = Path(__file__).resolve().parent / "rules"


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


def _pw_words_of(languages) -> frozenset:
    return _PW_LAST.union(*(_PW_LAST_OF.get(lang, ()) for lang in languages))


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


# The domains of SSH algorithm and extension names (RFC 4251 section 6: name@domain), as `ssh -Q kex`, sshd_config and
# `ssh -vvv` print them: sntrup761x25519-sha512@openssh.com, curve25519-sha256@libssh.org. They name no person, and an
# agent that saw a placeholder could not tell which algorithms a server offers (field report, 2026-10-27)
_SSH_NAME_DOMAINS = frozenset({"openssh.com", "libssh.org", "lysator.liu.se", "putty.projects.tartarus.org"})
_SSH_BARE_NAMES = frozenset({"zlib", "ping", "limits", "keepalive", "no-more-sessions"})


def _ssh_algorithm_name(v: str) -> bool:
    """An SSH name: on an SSH domain, with a dash or a digit in its name (a person there has a short name with
    neither), or one of the few bare extension names."""
    local, _, d = v.lower().rpartition("@")
    if d not in _SSH_NAME_DOMAINS:
        return False
    return "-" in local or any(c.isdigit() for c in local) or local in _SSH_BARE_NAMES


# Ids in the form of an address that name no person: a room or a shared calendar in a Google Calendar event
# (c_<id>@resource.calendar.google.com, <id>@group.calendar.google.com), the iCalUID of an event (<event id>@google.com,
# the id in base32hex) and the Message-ID of a Gmail message (<id>@mail.gmail.com). calendar_list_events gave one
# finding per room, event and message (gateway shadow, 2026-10-28)
_ID_MAIL_DOMAINS = frozenset({"resource.calendar.google.com", "group.calendar.google.com",
                              "group.v.calendar.google.com", "import.calendar.google.com", "mail.gmail.com"})
_ICAL_UID_RE = _LazyRx(r"[0-9a-v]{20,1024}(?:_\d{8}(?:t\d{6}z)?)?")


def _mail_shaped_id(v: str) -> bool:
    """A calendar resource, a shared calendar, an event's iCalUID or a Gmail Message-ID: an id, not a mailbox."""
    local, _, d = v.lower().rpartition("@")
    return d in _ID_MAIL_DOMAINS or (d == "google.com" and bool(_ICAL_UID_RE.fullmatch(local)))


_SERVICE_MAILBOXES = frozenset({"alerts", "alert", "monitoring", "backup", "ci", "bot", "renovate", "dependabot",
                                "release", "deploy", "build", "jenkins", "gitlab-runner", "github-actions"})
_SYSTEM_USERS = frozenset({"git", "root", "ubuntu", "ec2-user", "admin", "noreply", "no-reply", "postmaster",
                           "hostmaster", "webmaster", "mailer-daemon", "bounce", "bounces"})


# ------------------------------------------------------------- placeholders --
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


def looks_like_placeholder(value: str) -> bool:
    v = value.strip("\"'` ")
    low = v.lower()
    return low in PLACEHOLDER_VALUES or bool(_PLACEHOLDER_PART_RE.search(low)) or bool(_TEMPLATE_NAME.match(v))
