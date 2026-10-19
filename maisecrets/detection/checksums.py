"""Check digits and checksums for the detector (detect.py): national identifiers that Presidio validates but whose
validators were not yet ported, the identifiers of regions Presidio has no rules for (Switzerland, Austria), the German
document number, and three kinds of crypto wallet secret (a BIP39 seed phrase, a WIF private key, a BIP32 extended
private key).

Each function takes the matched text and returns True only for a value whose checksum holds. A function that cannot
parse its value returns False. No function here reads a file except the BIP39 word list, once.

Sources of the algorithms: Presidio's validate_result of each recognizer (MIT, see rules/LICENSE-presidio) for PESEL,
NIF, NIE, NHS, ABA and the codice fiscale; ICAO Doc 9303 Part 3 for the 7-3-1 check digit; eCH-0097 for the Swiss UID;
the AHV number is an EAN-13; the Austrian numbers follow the published algorithms of the Hauptverband (VSNR) and of the
BMF (UID). The Swiss rules follow a fork of this project (Apache-2.0, see NOTICE). BIP39, BIP32 and the WIF format are
the Bitcoin Improvement Proposals 39 and 32 and the Base58Check encoding.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
import string
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent / "rules"


def _digits(v: str) -> str:
    return re.sub(r"\D", "", v)


def _luhn_sum(digits: str) -> int:
    """The Luhn sum of a digit string whose last digit is not doubled (a complete number)."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10


# ------------------------------------------------------------------ Germany --
# ICAO Doc 9303 Part 3, 4.9: a digit counts its value, A to Z count 10 to 35, the filler < counts 0; weights 7, 3, 1
def icao_check_digit(s: str) -> int:
    total = 0
    for i, c in enumerate(s):
        if c.isdigit():
            val = int(c)
        elif "A" <= c <= "Z":
            val = ord(c) - 55
        elif c == "<":
            val = 0
        else:
            raise ValueError(c)
        total += val * (7, 3, 1)[i % 3]
    return total % 10


# the characters of a German ID card or passport number since 2010/2007: the digits and the consonants
# C F G H J K L M N P R T V W X Y Z (no vowel and no B, D, Q or S, which a reader confuses with 8, 0, O and 5)
DE_DOCUMENT_CHARS = frozenset("CFGHJKLMNPRTVWXYZ" + string.digits)


def de_document_ok(v: str) -> bool:
    """A German ID card or passport number: 9 characters of DE_DOCUMENT_CHARS, as the card prints it, or the same 9
    and the ICAO check digit, as the machine-readable zone prints it. The check digit is not part of the printed number:
    its 9th character can be a letter (the official specimen card's number ends in a digit by chance)."""
    v = v.strip().upper()
    if len(v) not in (9, 10) or any(c not in DE_DOCUMENT_CHARS for c in v[:9]):
        return False
    if len(v) == 10:
        return v[9].isdigit() and icao_check_digit(v[:9]) == int(v[9])
    return True


# ---------------------------------------------------------------- Presidio --
def pl_pesel_ok(v: str) -> bool:
    """PESEL: weights 1 3 7 9 1 3 7 9 1 3, the check digit is (10 - sum mod 10) mod 10."""
    if len(v) != 11 or not v.isdigit():
        return False
    total = sum(int(d) * w for d, w in zip(v[:10], (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)))
    return (10 - total % 10) % 10 == int(v[10])


_NIF_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def es_nif_ok(v: str) -> bool:
    """Spanish DNI/NIF: the letter is _NIF_LETTERS[number mod 23] (Presidio removes - and spaces first)."""
    v = re.sub(r"[- ]", "", v.strip()).upper()
    digits = _digits(v)
    return bool(digits) and v[-1:] == _NIF_LETTERS[int(digits) % 23]


def es_nie_ok(v: str) -> bool:
    """Spanish NIE: X, Y or Z (read as 0, 1, 2), the digits, and the NIF letter of that whole number."""
    v = re.sub(r"[- ]", "", v.strip()).upper()
    if not 8 <= len(v) <= 9 or v[:1] not in ("X", "Y", "Z") or not v[1:-1].isdigit():
        return False
    return v[-1] == _NIF_LETTERS[int(str("XYZ".index(v[0])) + v[1:-1]) % 23]


def uk_nhs_ok(v: str) -> bool:
    """NHS number: the ten digits weighted 10 down to 1 sum to a multiple of 11."""
    d = re.sub(r"[- ]", "", v.strip())
    if len(d) != 10 or not d.isdigit() or len(set(d)) == 1:
        return False                    # 000 000 0000 passes the sum and is a placeholder
    return sum(int(c) * w for c, w in zip(d, range(10, 0, -1))) % 11 == 0


def us_aba_ok(v: str) -> bool:
    """ABA routing number: weights 3 7 1, the sum is a multiple of 10, and the first two digits a Federal Reserve
    routing symbol (00 to 12, 21 to 32, 61 to 72, 80). 000000000 passes the sum and is a placeholder."""
    d = re.sub(r"[- ]", "", v.strip())
    if len(d) != 9 or not d.isdigit() or len(set(d)) == 1:
        return False
    head = int(d[:2])
    if not (head <= 12 or 21 <= head <= 32 or 61 <= head <= 72 or head == 80):
        return False
    return sum(int(c) * w for c, w in zip(d, (3, 7, 1) * 3)) % 10 == 0



def us_npi_ok(v: str) -> bool:
    """US NPI (CMS): Luhn over the prefix 80840 and the ten digits; a body of one repeated digit is no number."""
    d = re.sub(r"[- ]", "", v.strip())
    return len(d) == 10 and d.isdigit() and len(set(d[:-1])) > 1 and _luhn_sum("80840" + d) == 0


def se_organisationsnummer_ok(v: str) -> bool:
    """Swedish organisationsnummer: ten digits, the third at least 2, Luhn."""
    d = _digits(v)
    if len(d) == 12 and d.startswith("16"):
        d = d[2:]                        # the century form 16NNNNNN-NNNN of an organisation
    return len(d) == 10 and int(d[2]) >= 2 and _luhn_sum(d) == 0


def uk_vehicle_registration_ok(v: str) -> bool:
    """A UK number plate: in the current form (two letters, an age identifier, three letters) the age identifier is 02
    to 29 or 51 to 79. Presidio leaves the older prefix and suffix forms unjudged; they pass."""
    d = re.sub(r"[- ]", "", v.strip()).upper()
    if len(d) == 7 and d[:2].isalpha() and d[2:4].isdigit() and d[4:].isalpha():
        return 2 <= int(d[2:4]) <= 29 or 51 <= int(d[2:4]) <= 79
    return True

# codice fiscale: the value of a character at an odd place (1st, 3rd, ...); at an even place a digit counts its value
# and a letter its place in the alphabet from 0
_IT_ODD = dict(zip(string.digits + string.ascii_uppercase,
                   (1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8,
                    12, 14, 16, 10, 22, 25, 24, 23)))


def it_fiscal_code_ok(v: str) -> bool:
    """Italian codice fiscale: the 16th character is the check letter of the first 15."""
    v = v.strip().upper()
    if not re.fullmatch(r"[A-Z0-9]{15}[A-Z]", v):
        return False
    total = sum(_IT_ODD[c] if i % 2 == 0 else (int(c) if c.isdigit() else ord(c) - 65) for i, c in enumerate(v[:15]))
    return chr(65 + total % 26) == v[15]


# -------------------------------------------------------------- Switzerland --
def ch_ahv_ok(v: str) -> bool:
    """AHV/AVS number (AHVN13): 756 and ten digits, the last an EAN-13 check digit (weights 1 and 3 from the left)."""
    d = _digits(v)
    if len(d) != 13 or not d.startswith("756"):
        return False
    total = sum(int(c) * (3 if i % 2 else 1) for i, c in enumerate(d[:12]))
    return (10 - total % 10) % 10 == int(d[12])


def ch_uid_ok(v: str) -> bool:
    """Swiss company UID (eCH-0097): CHE, eight digits and a mod-11 check digit, weights 5 4 3 2 7 6 5 4. A check of 10
    is never issued."""
    m = re.match(r"\s*CHE[-\s]?(\d{3})\.?(\d{3})\.?(\d{3})", v.upper())
    if not m:
        return False
    d = "".join(m.groups())
    check = 11 - sum(int(c) * w for c, w in zip(d[:8], (5, 4, 3, 2, 7, 6, 5, 4))) % 11
    return check != 10 and check % 11 == int(d[8])


# ------------------------------------------------------------------ Austria --
def at_uid_ok(v: str) -> bool:
    """Austrian VAT number: ATU and eight digits, the last (6 - Luhn sum of the seven before it) mod 10."""
    m = re.fullmatch(r"ATU(\d{8})", re.sub(r"[\s.-]", "", v.upper()))
    if not m:
        return False
    d = m.group(1)
    return (6 - _luhn_sum(d[:7])) % 10 == int(d[7])


def at_social_security_ok(v: str) -> bool:
    """Austrian social insurance number (VSNR): a serial of three digits, a check digit, and the birth date DDMMYY. The
    check digit is the sum of the other nine digits, weighted 3 7 9 . 5 8 4 2 1 6, mod 11; a sum of 10 is never
    issued."""
    d = re.sub(r"\s", "", v)
    if len(d) != 10 or not d.isdigit() or d[0] == "0":
        return False
    total = sum(int(c) * w for c, w in zip(d, (3, 7, 9, 0, 5, 8, 4, 2, 1, 6))) % 11
    return total != 10 and total == int(d[3])


# ------------------------------------------------------------------- crypto --
B58_ALPHABET = string.digits[1:] + "".join(c for c in string.ascii_uppercase if c not in "IO") + "".join(
    c for c in string.ascii_lowercase if c != "l")
_B58_INDEX = {c: i for i, c in enumerate(B58_ALPHABET)}


def b58check_decode(s: str) -> bytes | None:
    """The payload of a Base58Check string, or None when a character is not Base58 or the checksum (the first four
    bytes of SHA-256 twice) does not hold."""
    n = 0
    for c in s:
        i = _B58_INDEX.get(c)
        if i is None:
            return None
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) < 5:
        return None
    payload, check = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != check:
        return None
    return payload


_SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)


def _private_key_ok(k: bytes) -> bool:
    return len(k) == 32 and 0 < int.from_bytes(k, "big") < _SECP256K1_N


def wif_ok(s: str) -> bool:
    """A Bitcoin private key in Wallet Import Format: Base58Check of 0x80 (0xEF on testnet), the 32-byte key, and 0x01
    for a key whose public key is compressed."""
    p = b58check_decode(s)
    if p is None or p[:1] not in (b"\x80", b"\xef"):
        return False
    if len(p) == 34:
        return p[33] == 1 and _private_key_ok(p[1:33])
    return len(p) == 33 and _private_key_ok(p[1:])


# BIP32 extended private keys and the variants of SLIP-0132: xprv, yprv, zprv, Yprv, Zprv on mainnet, tprv, uprv, vprv,
# Uprv, Vprv on testnet. The key data is 0x00 and the 32-byte private key
_XPRV_VERSIONS = frozenset(bytes.fromhex(h) for h in ("0488ADE4", "049D7878", "04B2430C", "0295B005", "02AA7A99",
                                                       "04358394", "044A4E28", "045F18BC", "024285B5", "02575048"))


def xprv_ok(s: str) -> bool:
    p = b58check_decode(s)
    return (p is not None and len(p) == 78 and p[:4] in _XPRV_VERSIONS and p[45] == 0
            and _private_key_ok(p[46:78]))


def discord_bot_token_ok(v: str) -> bool:
    """A Discord bot token's first part is the bot's user id (a snowflake of 17 to 20 digits) in base64."""
    head = v.split(".", 1)[0]
    try:
        raw = base64.urlsafe_b64decode(head + "=" * (-len(head) % 4))
    except (ValueError, binascii.Error):
        return False
    return 17 <= len(raw) <= 20 and raw.isdigit() and raw[:1] != b"0"


_BIP39: list = []


def bip39_words() -> dict:
    """The English BIP39 word list (rules/bip39_english.txt): word -> index."""
    if not _BIP39:
        words = (RULES_DIR / "bip39_english.txt").read_text(encoding="utf-8").split()
        _BIP39.append({w: i for i, w in enumerate(words)})
    return _BIP39[0]


def _bip39_bits_ok(bits: str) -> bool:
    """The checksum of a phrase given as its 11-bit indexes in one bit string."""
    cs = len(bits) // 33
    entropy = int(bits[:-cs], 2).to_bytes((len(bits) - cs) // 8, "big")
    return f"{hashlib.sha256(entropy).digest()[0]:08b}"[:cs] == bits[-cs:]


def bip39_ok(words: list) -> bool:
    """12, 15, 18, 21 or 24 words of the list whose last bits (one per 3 words) are the first bits of SHA-256 of the
    rest: a random choice of 12 words passes once in 16, of 24 words once in 256."""
    index = bip39_words()
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    try:
        return _bip39_bits_ok("".join(f"{index[w]:011b}" for w in words))
    except KeyError:
        return False


# a run of 12 or more lowercase words of 3 to 8 letters, one space, one line break or a comma between two of them
_WORD_RUN_RE = re.compile(r"(?<![A-Za-z0-9_'-])[a-z]{3,8}(?:(?:,?[ \t]{1,3}|[ \t]*\r?\n[ \t]*)[a-z]{3,8}){11,}"
                          r"(?![A-Za-z0-9_'-])")
_WORD_RE = re.compile(r"[a-z]+")
# a run of list words much longer than a phrase is a word list (the BIP39 list itself, a dictionary), not a phrase:
# with dozens of windows one passes by chance, and the list file was masked whole (Gate B of 0.6.19)
BIP39_MAX_RUN = 48


def bip39_spans(text: str) -> list:
    """(start, end, words) of each seed phrase in the text, words the length of its longest valid window. Within each
    run of 12 to BIP39_MAX_RUN words of the list, every window of 12, 15, 18, 21 or 24 words whose checksum holds is a
    phrase, and the span runs from the first such window to the end of the last: a word of the list next to the phrase
    ("seed phrase: ...") can start a window that passes by chance (one in 16 for 12 words), and taking only that window
    left the phrase's last word in the clear."""
    out = []
    index = None
    for run in _WORD_RUN_RE.finditer(text):
        if index is None:
            index = bip39_words()
        words = list(_WORD_RE.finditer(run.group()))
        i = 0
        while i + 12 <= len(words):
            if words[i].group() not in index:
                i += 1
                continue
            j = i
            while j < len(words) and words[j].group() in index:
                j += 1                     # words[i:j] are all on the list
            if j - i > BIP39_MAX_RUN:
                i = j + 1
                continue
            bits = "".join(f"{index[w.group()]:011b}" for w in words[i:j])
            first = last = None
            longest = 0
            for a in range(i, j - 11):
                for n in (12, 15, 18, 21, 24):
                    if a + n <= j and _bip39_bits_ok(bits[(a - i) * 11:(a - i + n) * 11]):
                        first = a if first is None else first
                        last = max(last or 0, a + n)
                        longest = max(longest, n)
            if first is not None:
                out.append((run.start() + words[first].start(), run.start() + words[last - 1].end(), longest))
            i = j + 1
    return out
