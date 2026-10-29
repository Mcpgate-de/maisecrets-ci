"""Rules that a survey of other detectors (Presidio, python-stdnum, detect-secrets, trufflehog, a fork of this project)
showed missing or wrong in 0.6.18: the German document number, the printed forms of the Steuer-ID and the
Rentenversicherungsnummer, the Steuer-ID's repeat rule, crypto wallet secrets, Swiss and Austrian numbers, the ported
check digits of five Presidio recognizers, and token prefixes.

Run: python3 -m unittest tests.test_rules_from_other_detectors -v
Every value is generated at run time from a seeded generator, so no literal sits in the tree. Each rule has a valid
value that is a hit and a twin with a wrong check character that is not.
"""
from __future__ import annotations

import base64
import hashlib
import os
import random
import string
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
from _timing import assert_linear  # noqa: E402

from maisecrets import checksums, detect, regions  # noqa: E402

J = "".join
D = string.digits
U = string.ascii_uppercase


_DETECTOR_OF: dict = {}


def found(text: str, region: tuple = ("de",), channel: str = "prompt") -> list:
    """(kind, type, value) of each hit with the given regions. One detector per regions setting loads its rules once."""
    if region not in _DETECTOR_OF:
        active = regions.Active(regions=("generic", *region), languages=("en", "de"), source="test")
        _DETECTOR_OF[region] = detect.Detector(regions=active)
    return [(m.kind, m.type, m.value) for m in _DETECTOR_OF[region].scan(text, channel=channel)]


def types_of(text: str, value: str, region: tuple = ("de",), channel: str = "prompt") -> list:
    """The types of the hits that cover the whole value."""
    a = text.index(value)
    return [t for k, t, v in found(text, region, channel) if v == value or (value in v and text.find(v) <= a)]


def rd(r: random.Random, n: int, alphabet: str = D) -> str:
    return J(r.choice(alphabet) for _ in range(n))


def complete(body: str, ok, alphabet: str = D) -> str:
    """body and the one check character from alphabet that ok accepts (the first one)."""
    for c in alphabet:
        if ok(body + c):
            return body + c
    raise AssertionError("no check character")


def twin(value: str, ok, pos: int = -1, alphabet: str = D) -> str:
    """The value with the character at pos changed so that ok rejects it."""
    p = pos % len(value)
    for c in alphabet:
        w = value[:p] + c + value[p + 1:]
        if w != value and not ok(w):
            return w
    raise AssertionError("no twin")


# --------------------------------------------------------------- Germany --
DOC = "CFGHJKLMNPRTVWXYZ"


def doc_number(r: random.Random) -> str:
    """A 9-character German document number: a letter first, at least one digit, the 9th a letter or a digit."""
    while True:
        v = r.choice(DOC) + rd(r, 8, DOC + D)
        if any(c.isdigit() for c in v) and v[-1].isalpha():
            return v


class GermanDocumentNumberTests(unittest.TestCase):
    def test_the_icao_check_digit_matches_the_published_specimens(self):
        # ICAO Doc 9303 Part 3 4.9; the BMI specimen passport of 2021 prints CZ6311T47 and the MRZ check digit 2
        self.assertEqual(checksums.icao_check_digit(J(["CZ63", "11T47"])), 2)
        self.assertEqual(checksums.icao_check_digit(J(["L898", "902C3"])[:-1]), 3)

    def test_a_number_whose_ninth_character_is_a_letter_is_found_after_its_label(self):
        r = random.Random(1)
        for _ in range(40):
            v = doc_number(r)
            for text in (f"Personalausweisnummer: {v}", f"Meine Ausweisnummer ist {v}, bitte eintragen."):
                with self.subTest(text=text):
                    self.assertEqual(types_of(text, v), ["DE_ID_CARD"])
            self.assertEqual(types_of(f"Reisepassnummer {v}", v), ["DE_PASSPORT"])

    def test_the_specimen_numbers_are_found_with_and_without_the_check_digit(self):
        for v in (J(["L01X", "00T47"]), J(["L01X", "00T471"]), J(["LZ63", "11T47"]), J(["T220", "00129"])):
            with self.subTest(v=v):
                self.assertEqual(types_of(f"Personalausweis: {v}", v), ["DE_ID_CARD"])
        self.assertEqual(types_of("Reisepass " + J(["CZ63", "11T472"]), J(["CZ63", "11T472"])), ["DE_PASSPORT"])

    def test_a_wrong_check_digit_a_vowel_or_no_label_is_no_hit(self):
        r = random.Random(2)
        for _ in range(40):
            v = doc_number(r)
            full = v + str(checksums.icao_check_digit(v))
            bad = full[:-1] + str((int(full[-1]) + 1) % 10)
            with self.subTest(v=v):
                self.assertEqual(types_of(f"Ausweisnummer: {full}", full), ["DE_ID_CARD"])
                self.assertEqual(found(f"Ausweisnummer: {bad}"), [])
                self.assertEqual(found(v), [])
                self.assertEqual(found(f"Ausweisnummer: {v[:4]}A{v[5:]}"), [])   # A is no character of the number
                self.assertEqual(found(f"Ausweisnummer: 1{v[1:]}"), [])          # the first is a letter

    def test_the_official_word_dokumentennummer_is_a_label(self):
        v = doc_number(random.Random(21))
        self.assertEqual(types_of(f"Dokumentennummer: {v}", v), ["DE_ID_CARD"])   # Gate B of 0.6.19: Presidio's word

    def test_pass_alone_is_no_passport_label(self):
        v = doc_number(random.Random(3))
        self.assertEqual(found(f"pass {v} to the builder"), [])


def tax_id(r: random.Random) -> str:
    while True:
        body = rd(r, 1, D[1:]) + rd(r, 9)
        try:
            return complete(body, detect._de_tax_id_ok)
        except AssertionError:
            continue


class SteuerIdTests(unittest.TestCase):
    def test_exactly_one_digit_twice_or_three_times_and_never_three_in_a_row(self):
        ok = detect._de_tax_id_ok
        # ITZBund, KONZEPT IdNr 2.3, section 1, and the example of both sources: 9 at places 3, 5 and 6
        self.assertTrue(ok(J(["6592", "9970", "489"])))
        bodies = {"two digits twice": "1123345678", "one digit three times in a row": "1112345678",
                  "one digit four times": "1121314156", "no digit twice": "1234567890"}
        for why, body in bodies.items():
            with self.subTest(why=why):
                self.assertFalse(any(ok(body + c) for c in D))
        self.assertTrue(any(ok("1213456780" + c) for c in D))     # one digit twice
        self.assertTrue(any(ok("1121345678" + c) for c in D))     # three times, two of them adjacent

    def test_a_random_number_passes_rarely(self):
        r = random.Random(4)
        n = 20000
        passed = sum(detect._de_tax_id_ok(rd(r, 1, D[1:]) + rd(r, 10)) for _ in range(n))
        self.assertLess(passed / n, 0.01)

    def test_the_printed_form_with_spaces_is_found_after_its_label(self):
        r = random.Random(5)
        for _ in range(40):
            v = tax_id(r)
            spaced = f"{v[:2]} {v[2:5]} {v[5:8]} {v[8:]}"
            bad = twin(spaced, lambda s: detect._de_tax_id_ok(s.replace(" ", "")))
            with self.subTest(v=spaced):
                self.assertEqual(types_of(f"Steuer-ID: {spaced}", spaced), ["DE_TAX_ID"])
                self.assertEqual(found(f"Steuer-ID: {bad}"), [])
                self.assertEqual(found(spaced), [])
                self.assertEqual(found(f"Steuer-ID: {spaced} 12"), [])      # a longer run of groups


def rv_number(r: random.Random) -> str:
    while True:
        body = rd(r, 2) + f"{r.randint(1, 28):02d}{r.randint(1, 12):02d}{r.randint(0, 99):02d}" + r.choice(U) + rd(r, 2)
        try:
            return complete(body, detect._de_social_security_ok)
        except AssertionError:
            continue


class RentenversicherungsnummerTests(unittest.TestCase):
    def test_the_printed_form_with_spaces_is_found(self):
        r = random.Random(6)
        for _ in range(40):
            v = rv_number(r)
            spaced = f"{v[:2]} {v[2:8]} {v[8]} {v[9:]}"
            bad = twin(spaced, detect._de_social_security_ok)
            with self.subTest(v=spaced):
                self.assertEqual(types_of(f"Rentenversicherungsnummer {spaced}", spaced), ["DE_SOCIAL_SECURITY"])
                self.assertEqual(types_of(spaced, spaced), ["DE_SOCIAL_SECURITY"])
                nbsp = spaced.replace(" ", "\u00a0")                        # Gate A of 0.6.19
                self.assertEqual(types_of(nbsp, nbsp), ["DE_SOCIAL_SECURITY"])
                self.assertEqual(found(bad), [])


# ------------------------------------------------------------------ crypto --
B58 = checksums.B58_ALPHABET


def b58check(payload: bytes) -> str:
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def wif(r: random.Random, compressed: bool, version: bytes = b"\x80") -> str:
    return b58check(version + bytes(r.getrandbits(8) for _ in range(32)) + (b"\x01" if compressed else b""))


def xprv(r: random.Random, version: str = "0488ADE4") -> str:
    """BIP32: version, depth, parent fingerprint and child number (9 bytes), chain code, 0x00 and the private key."""
    return b58check(bytes.fromhex(version) + bytes(r.getrandbits(8) for _ in range(9 + 32)) + b"\x00"
                    + bytes(r.getrandbits(8) for _ in range(32)))


def seed_phrase(r: random.Random, n: int) -> str:
    words = list(checksums.bip39_words())
    ent = bytes(r.getrandbits(8) for _ in range(n * 11 * 32 // 33 // 8))
    bits = J(f"{x:08b}" for x in ent) + f"{hashlib.sha256(ent).digest()[0]:08b}"[:n // 3]
    return " ".join(words[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11))


class CryptoSecretTests(unittest.TestCase):
    def test_the_word_list_is_the_bip39_english_list(self):
        # a Windows checkout writes CRLF line ends (core.autocrlf); the list is the same words either way
        raw = (detect.RULES_DIR / "bip39_english.txt").read_bytes().replace(b"\r\n", b"\n")
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda")

    def test_a_wif_key_is_a_secret_and_a_changed_character_is_not(self):
        r = random.Random(7)
        for i in range(40):
            v = wif(r, compressed=bool(i % 2))
            bad = twin(v, checksums.wif_ok, pos=-2, alphabet=B58)
            with self.subTest(v=v):
                self.assertEqual(types_of(v, v), ["SECRET"])
                self.assertEqual(types_of(f"key: {v}\n", v, channel="tool"), ["SECRET"])
                self.assertEqual(found(f"here {bad} there"), [])
            test_key = wif(r, compressed=bool(i % 2), version=b"\xef")       # testnet (Gate A of 0.6.19)
            # Base58Check holds, the key does not: zero, the curve order or more, a compression flag other than 1
            for payload in (b"\x80" + bytes(32), b"\x80" + b"\xff" * 32 + b"\x01",
                            b"\x80" + bytes(r.getrandbits(8) for _ in range(32)) + b"\x02"):
                self.assertFalse(checksums.wif_ok(b58check(payload)))
            self.assertEqual(types_of(test_key, test_key), ["SECRET"])

    def test_an_extended_private_key_is_a_secret_and_an_extended_public_key_is_not(self):
        r = random.Random(8)
        for version in ("0488ADE4", "049D7878", "04B2430C", "0295B005", "02AA7A99", "04358394", "024285B5"):
            v = xprv(r, version)
            pub = b58check(bytes.fromhex("0488B21E") + bytes(r.getrandbits(8) for _ in range(9 + 32)) + b"\x02"
                           + bytes(r.getrandbits(8) for _ in range(32)))
            with self.subTest(version=version):
                self.assertEqual(types_of(f"wallet {v}", v), ["SECRET"])
                self.assertEqual(found(f"wallet {twin(v, checksums.xprv_ok, pos=-3, alphabet=B58)}"), [])
                self.assertEqual(found(f"wallet {pub}"), [])
                self.assertFalse(checksums.xprv_ok(pub))                  # its version is a public key's
                no_key = b58check(bytes.fromhex(version) + bytes(r.getrandbits(8) for _ in range(9 + 32)) + b"\x03"
                                  + bytes(r.getrandbits(8) for _ in range(32)))
                self.assertFalse(checksums.xprv_ok(no_key))               # key data must start with 0x00
                pub_version = b58check(bytes.fromhex("0488B21E") + bytes(r.getrandbits(8) for _ in range(9 + 32))
                                       + b"\x00" + bytes(r.getrandbits(8) for _ in range(32)))
                self.assertFalse(checksums.xprv_ok(pub_version))          # the version of an xpub

    def test_a_seed_phrase_is_found_whole_and_one_with_a_wrong_checksum_is_not(self):
        r = random.Random(9)
        words = list(checksums.bip39_words())
        misses = 0
        for i in range(60):
            n = (12, 24)[i % 2]
            v = seed_phrase(r, n)
            for text in (f"My seed phrase: {v}\nkeep it safe", f"wallet backup\n{v}\n", f"{v}  # recovery"):
                with self.subTest(text=text):
                    self.assertEqual(types_of(text, v), ["SECRET"])
            with self.subTest(bare=v):
                # 24 words (8 checksum bits) stand alone; 12 (4 bits) need a word such as seed or wallet
                self.assertEqual(types_of(v, v), ["SECRET"] if n == 24 else [])
            if n == 12:
                # the last word carries the checksum: another word there fails 15 times in 16
                bad = v.rsplit(" ", 1)[0] + " " + words[(words.index(v.rsplit(" ", 1)[1]) + 1) % 2048]
                misses += not found("seed: " + bad)
        self.assertGreaterEqual(misses, 24)

    def test_a_list_of_words_is_no_seed_phrase(self):
        r = random.Random(10)
        words = list(checksums.bip39_words())
        prose = ("This function reads the config file, then it opens a socket and sends the first batch of "
                 "records to the server; when the queue is empty it waits for more input from the user.")
        self.assertEqual(found(prose), [])
        # Gate A of 0.6.19: twelve ordinary list words whose checksum holds by chance, also after a word that only
        # starts like a seed word
        twelve = " ".join(["client connect system process input output", "error return result update file edit"])
        self.assertEqual(found(twelve), [])
        self.assertEqual(found("tokenization " + twelve), [])
        self.assertEqual(found("keyboard: " + twelve), [])
        eleven = " ".join(r.choice(words) for _ in range(11))
        self.assertEqual(found(eleven), [])
        self.assertEqual(found(seed_phrase(r, 12).title()), [])   # capitalised words are no phrase

    def test_a_phrase_after_a_secret_label_needs_no_seed_word(self):
        v = seed_phrase(random.Random(19), 12)
        for label in ("Password: ", "Passwort: ", "private key: ", "my 12 words: ", "token: "):
            with self.subTest(label=label):
                self.assertEqual(types_of(label + v, v), ["SECRET"])

    def test_the_word_list_itself_and_the_reference_vectors_are_no_phrase(self):
        listing = (detect.RULES_DIR / "bip39_english.txt").read_text()
        self.assertEqual([h for h in found(listing, channel="tool") if h[0] == "crypto-seed-phrase"], [])
        vector = " ".join(["aban" + "don"] * 11 + ["about"])      # BIP39 reference test vector
        self.assertEqual(found("seed: " + vector), [])
        self.assertEqual(found("seed:\n" + vector.replace(" ", "\n")), [])   # one word per line (Gate A, round 2)
        other = " ".join(["ozone drill grab", "fiber curtain grace", "pudding thank cruise", "elder eight picnic"])
        self.assertEqual(found("seed: " + other), [])                # each of the 24 English vectors
        entries = [ln for ln in (detect.RULES_DIR / "public_test_values.txt").read_text().splitlines()
                   if "BIP39 reference vector" in ln]
        self.assertEqual(len(entries), 48)                           # 24 mnemonics and their 24 xprv
        # 12 consecutive words of the list in one run, no seed word: the checksum alone does not make a phrase
        words = list(checksums.bip39_words())
        r = random.Random(20)
        hits = sum(bool(found(" ".join(r.choice(words) for _ in range(12)))) for _ in range(200))
        self.assertEqual(hits, 0)

    def test_a_long_run_of_words_takes_linear_time(self):
        # 20,000 words, then an eighth of them: at most 16 times the CPU time (tests/_timing.py), not a fixed 5 s
        words = list(checksums.bip39_words())
        r = random.Random(11)
        run = [r.choice(words) for _ in range(20000)]
        assert_linear(self, detect.scan, lambda n: " ".join(run[:n]), 20000, hang=7.0, wall=20.0)


# ----------------------------------------------------- Switzerland, Austria --
class SwissAndAustrianNumberTests(unittest.TestCase):
    def test_an_ahv_number_with_dots_stands_alone_and_without_them_needs_its_label(self):
        r = random.Random(12)
        for _ in range(40):
            v = complete("756" + rd(r, 9), checksums.ch_ahv_ok)
            dotted = f"{v[:3]}.{v[3:7]}.{v[7:11]}.{v[11:]}"
            bad = twin(dotted, checksums.ch_ahv_ok)
            with self.subTest(v=dotted):
                self.assertEqual(types_of(dotted, dotted, region=("ch",)), ["CH_AHV"])
                self.assertEqual(types_of(f"AHV-Nr. {v}", v, region=("ch",)), ["CH_AHV"])
                self.assertEqual(found(v, region=("ch",)), [])
                self.assertEqual(found(bad, region=("ch",)), [])
                self.assertEqual(found(dotted, region=("de",)), [])      # region ch only

    def test_a_swiss_and_an_austrian_company_number_need_a_vat_word(self):
        r = random.Random(13)
        for _ in range(40):
            uid = next(u for u in ("CHE" + rd(r, 8) + c for _ in range(50) for c in D) if checksums.ch_uid_ok(u))
            uid_f = f"CHE-{uid[3:6]}.{uid[6:9]}.{uid[9:]}"
            atu = complete("ATU" + rd(r, 7), checksums.at_uid_ok)
            with self.subTest(uid=uid_f, atu=atu):
                self.assertEqual(types_of(f"UID: {uid_f} MWST", uid_f, region=("ch",)), ["CH_UID"])
                self.assertEqual(found(uid_f, region=("ch",)), [])
                self.assertEqual(found(f"UID: {twin(uid_f, checksums.ch_uid_ok)}", region=("ch",)), [])
                self.assertEqual(types_of(f"UID-Nummer {atu}", atu, region=("at",)), ["AT_UID"])
                self.assertEqual(found(atu, region=("at",)), [])
                self.assertEqual(found(f"UID-Nummer {twin(atu, checksums.at_uid_ok)}", region=("at",)), [])

    def test_an_austrian_social_insurance_number_needs_its_label_and_its_check_digit(self):
        r = random.Random(14)
        n = 0
        while n < 40:
            serial, date = rd(r, 1, D[1:]) + rd(r, 2), f"{r.randint(1, 28):02d}{r.randint(1, 12):02d}{rd(r, 2)}"
            good = [serial + c + date for c in D if checksums.at_social_security_ok(serial + c + date)]
            if not good:
                continue
            n += 1
            v = good[0]
            bad = twin(v, checksums.at_social_security_ok, pos=3)
            with self.subTest(v=v):
                self.assertEqual(types_of(f"Sozialversicherungsnummer: {v}", v, region=("at",)),
                                 ["AT_SOCIAL_SECURITY"])
                self.assertEqual(found(f"Sozialversicherungsnummer: {bad}", region=("at",)), [])
                self.assertEqual(found(v, region=("at",)), [])


# ------------------------------------------------ ported Presidio checks --
def pesel(r):
    return complete(rd(r, 2) + r.choice("02468") + rd(r, 1, D[1:]) + f"{r.randint(1, 28):02d}" + rd(r, 4),
                    checksums.pl_pesel_ok)


def nif(r):
    n = rd(r, 8)
    return n + "TRWAGMYFPDXBNJZSQVHLCKE"[int(n) % 23]


def nie(r):
    p, n = r.choice("XYZ"), rd(r, 7)
    return p + n + "TRWAGMYFPDXBNJZSQVHLCKE"[int(str("XYZ".index(p)) + n) % 23]


def nhs(r):
    while True:
        try:
            v = complete(rd(r, 9), checksums.uk_nhs_ok)
            return f"{v[:3]} {v[3:6]} {v[6:]}"
        except AssertionError:
            continue


def aba(r):
    head = r.choice([f"{x:02d}" for x in (*range(0, 13), *range(21, 33))])   # a Federal Reserve routing symbol
    return complete(head + rd(r, 6), checksums.us_aba_ok)


def fiscal(r):
    cons = "BCDFGHJKLMNPQRSTVWXYZ"
    body = (rd(r, 3, cons) + rd(r, 3, cons) + rd(r, 2) + r.choice("ABCDEHLMPRST") + f"{r.randint(1, 28):02d}"
            + r.choice("ABCDEFGHILM") + rd(r, 3))
    return complete(body, checksums.it_fiscal_code_ok, U)


PORTED = [  # (name, region, generator, validator, label, twin alphabet)
    ("PESEL", "pl", pesel, checksums.pl_pesel_ok, "PESEL", D),
    ("DNI", "es", nif, checksums.es_nif_ok, "DNI", U),
    ("NIE", "es", nie, checksums.es_nie_ok, "NIE", U),
    ("NHS", "uk", nhs, checksums.uk_nhs_ok, "NHS number", D),
    ("ABA", "us", aba, checksums.us_aba_ok, "ABA routing number", D),
    ("codice fiscale", "it", fiscal, checksums.it_fiscal_code_ok, "codice fiscale", U),
]


class PortedCheckDigitTests(unittest.TestCase):
    def test_a_valid_value_after_its_label_is_a_hit_and_its_twin_is_not(self):
        for name, region, gen, ok, label, alpha in PORTED:
            r = random.Random(name)
            for _ in range(30):
                v = gen(r)
                bad = twin(v, ok, alphabet=alpha)
                with self.subTest(name=name, v=v):
                    self.assertTrue(found(f"{label}: {v}", region=(region,)))
                    self.assertEqual(found(f"{label}: {bad}", region=(region,)), [])
                    self.assertEqual(found(v, region=(region,)), [])          # still needs its label

    def test_a_number_of_one_repeated_digit_is_a_placeholder(self):
        self.assertEqual(found("NHS number: 000 000 0000", region=("uk",)), [])
        self.assertEqual(found("ABA routing number: 000000000", region=("us",)), [])
        body = "41" + "1" * 6
        sum_ok = next(body + c for c in D if sum(int(x) * w for x, w in zip(body + c, (3, 7, 1) * 3)) % 10 == 0)
        self.assertFalse(checksums.us_aba_ok(sum_ok))                      # 41 is no routing symbol

    def test_a_pesel_inside_a_longer_digit_run_is_no_hit(self):
        v = pesel(random.Random(15))
        self.assertEqual(found(f"PESEL 9{v}", region=("pl",)), [])
        self.assertEqual(found(f"PESEL {v}0", region=("pl",)), [])


# ---------------------------------------------------------------- tokens --
AN = string.ascii_letters + D
HEXL = "0123456789abcdef"
B64U = AN + "_-"


def _uuid(r):
    return "-".join(rd(r, n, HEXL) for n in (8, 4, 4, 4, 12))


def discord_bot(r):
    head = base64.urlsafe_b64encode(str(r.randint(10 ** 17, 10 ** 19 - 1)).encode()).decode().rstrip("=")
    return J([head, ".", rd(r, 6, B64U), ".", rd(r, 27, B64U)])


# rule id -> (a token, a look-alike that is not one). Every part after the prefix is random
TOKENS = {
    "google-oauth-access-token": lambda r: (J(["ya", "29."]) + rd(r, 120, B64U), J(["ya", "29."]) + rd(r, 12, AN)),
    "tailscale-key": lambda r: ((J(["tskey", "-auth-"]) + rd(r, 12, AN) + "-" + rd(r, 33, AN),
                                 J(["tskey", "-auth-"]) + rd(r, 12, AN)) if r.random() < 0.5 else
                                (J(["tskey", "-k"]) + rd(r, 10, AN) + "CNTRL-" + rd(r, 32, AN),
                                 J(["tskey", "-k"]) + rd(r, 10, AN) + "CNTRL-" + rd(r, 8, AN))),
    "discord-webhook-url": lambda r: (J(["https://discord.com/api/web", "hooks/"]) + rd(r, 19) + "/" + rd(r, 68, B64U),
                                      J(["https://discord.com/api/web", "hooks/"]) + rd(r, 19)),
    "salesforce-refresh-token": lambda r: (J(["5Aep", "861"]) + rd(r, 80, AN), J(["5Aep", "861"]) + rd(r, 20, AN)),
    "cloudflare-api-token": lambda r: (J(["cf", "k_"]) + rd(r, 48, AN), J(["cf", "k_"]) + rd(r, 20, AN)),
    "hubspot-private-app-token": lambda r: (J(["pat", "-na1-"]) + _uuid(r), J(["pat", "-na1-"]) + rd(r, 8, HEXL)),
    "new-relic-user-key": lambda r: (J(["NR", "AK-"]) + rd(r, 27, U + D), J(["NR", "AK-"]) + rd(r, 10, U + D)),
    "new-relic-insert-key": lambda r: (J(["NR", "II-"]) + rd(r, 32, AN), J(["NR", "II-"]) + rd(r, 12, AN)),
    "new-relic-rest-api-key": lambda r: (J(["NR", "RA-"]) + rd(r, 42, HEXL), J(["NR", "RA-"]) + rd(r, 20, HEXL)),
    "new-relic-admin-key": lambda r: (J(["NR", "AA-"]) + rd(r, 27, HEXL), J(["NR", "AA-"]) + rd(r, 12, HEXL)),
    "new-relic-query-key": lambda r: (J(["NR", "IQ-"]) + rd(r, 32, AN), J(["NR", "IQ-"]) + rd(r, 12, AN)),
    "new-relic-pixie-api-key": lambda r: (J(["px", "-api-"]) + _uuid(r), J(["px", "-api-"]) + rd(r, 8, HEXL)),
    "anthropic-oauth-token": lambda r: (J(["sk-ant", "-o", r.choice(["at", "rt"]), "01-"]) + rd(r, 95, B64U),
                                        J(["sk-ant", "-oat01-"]) + rd(r, 20, AN)),
    "flutterwave-secret-key": lambda r: (J(["FLW", "SECK-"]) + rd(r, 32, HEXL) + "-X",
                                         J(["FLW", "SECK-"]) + rd(r, 8, HEXL)),
    "doppler-token": lambda r: (J(["dp", ".", r.choice(["st.prd", "sa", "ct", "scim", "audit"]), "."]) + rd(r, 43, AN),
                                J(["dp", ".st."]) + rd(r, 10, AN)),
    "square-oauth-secret": lambda r: (J(["sq0", "csp-"]) + rd(r, 43, B64U), J(["sq0", "csp-"]) + rd(r, 12, AN)),
    "contentful-personal-token": lambda r: (J(["CF", "PAT-"]) + rd(r, 43, B64U), J(["CF", "PAT-"]) + rd(r, 12, AN)),
    "mapbox-secret-token": lambda r: (J(["sk", ".eyJ"]) + rd(r, 60, B64U) + "." + rd(r, 22, B64U),
                                      J(["pk", ".eyJ"]) + rd(r, 60, B64U) + "." + rd(r, 22, B64U)),
    "kong-konnect-token": lambda r: (J(["kp", "at_"]) + rd(r, 49, AN), J(["kp", "at_"]) + rd(r, 12, AN)),
    "fireworks-api-key": lambda r: (J(["f", "w_"]) + rd(r, 32, AN), J(["f", "w_"]) + rd(r, 12, AN)),
    "infisical-service-token": lambda r: (J(["s", "t."]) + _uuid(r) + "." + rd(r, 32, HEXL) + "." + rd(r, 32, HEXL),
                                          J(["s", "t."]) + _uuid(r) + "." + rd(r, 12, HEXL)),
    "sonarcloud-org-token": lambda r: (J(["sq", "co_"]) + rd(r, 59, AN), J(["sq", "co_"]) + rd(r, 12, AN)),
    "adafruit-io-key": lambda r: (J(["ai", "o_"]) + rd(r, 28, AN), J(["ai", "o_"]) + rd(r, 12, AN)),
    "pypi-test-upload-token": lambda r: (J(["pypi-AgENdGVz", "dC5weXBpLm9yZw"]) + rd(r, 150, B64U),
                                         J(["pypi-AgENdGVz", "dC5weXBpLm9yZw"]) + rd(r, 20, AN)),
    "telegram-bot-token": lambda r: (rd(r, 1, D[1:]) + rd(r, 8) + ":A" + rd(r, 34, B64U),
                                     rd(r, 9) + ":" + rd(r, 12, AN)),
    "mailchimp-api-key": lambda r: (rd(r, 32, HEXL) + "-us" + str(r.randint(1, 21)), rd(r, 32, HEXL) + "-eu1"),
    "discord-bot-token": lambda r: (discord_bot(r), J([rd(r, 26, AN), ".", rd(r, 6, AN), ".", rd(r, 27, AN)])),
}


class TokenFormatTests(unittest.TestCase):
    def test_each_token_is_found_whole_by_its_rule_and_a_look_alike_is_not(self):
        for rule_id, gen in TOKENS.items():
            r = random.Random(rule_id)
            for _ in range(20):
                tok, miss = gen(r)
                for text in (tok, f"export TOKEN_VALUE={tok}\n", f"here it is: {tok} thanks"):
                    with self.subTest(rule=rule_id, text=text):
                        self.assertIn((rule_id, "SECRET", tok), found(text))
                with self.subTest(rule=rule_id, miss=miss):
                    self.assertNotIn(rule_id, [k for k, _t, _v in found(f"see {miss} there")])

    def test_every_rule_has_a_token(self):
        text = (detect.RULES_DIR / "prefixes.txt").read_text().split("# 0.6.20,")[0]   # 0.6.20: its own test file
        new = {line.split()[0] for line in text.splitlines()
               if line.strip() and not line.startswith("#")} - {"gitlab-runner-token", "gitlab-deploy-token-any",
                                                                 "webhook-signing-secret", "cloudflare-user-api-token"}
        self.assertEqual(new | {"telegram-bot-token", "mailchimp-api-key", "discord-bot-token", "fireworks-api-key",
                                "infisical-service-token"}, set(TOKENS))

    def test_each_prefix_rule_starts_its_matches_with_a_literal_of_four_characters(self):
        # a literal that every match holds lets the regex engine skip a text without it
        try:
            from re import _parser as sre_parse
        except ImportError:   # Python before 3.11
            import sre_parse
        for line in (detect.RULES_DIR / "prefixes.txt").read_text().splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            rule_id, rx = line.split(None, 1)
            run = best = 0
            for op, av in sre_parse.parse(rx):
                if op is sre_parse.LITERAL:
                    run += 1
                    continue
                if op is sre_parse.BRANCH:
                    alts = av[1]                    # (?:a|b): each alternative a run of literals
                    if all(all(o is sre_parse.LITERAL for o, _ in alt) for alt in alts):
                        run += min(len(alt) for alt in alts)
                        continue
                if op is sre_parse.SUBPATTERN and all(o is sre_parse.LITERAL for o, _ in av[-1]):
                    run += len(av[-1])              # (?i:aep861)
                    continue
                best, run = max(best, run), 0
            with self.subTest(rule=rule_id):
                self.assertGreaterEqual(max(best, run), 4)

    def test_a_long_run_of_near_misses_takes_linear_time(self):
        r = random.Random(16)
        for rule_id, gen in TOKENS.items():
            tok, _ = gen(r)
            with self.subTest(rule=rule_id):             # each copy one short of a match; not a fixed 3 s of CPU
                assert_linear(self, found, lambda n, tok=tok: (tok[:-2] + "  ") * n, 1000, hang=7.0, wall=20.0)

    def test_a_telegram_token_of_the_documented_short_form_is_found(self):
        r = random.Random(18)
        tok = rd(r, 6) + ":A" + rd(r, 33, B64U)        # the Bot API example: a 6-digit id, 34 characters
        self.assertIn(("telegram-bot-token", "SECRET", tok), found(f"bot {tok}"))
        url = J(["https://api.tele", "gram.org/bot", tok, "/sendMessage"])     # Gate B of 0.6.19
        self.assertIn(("telegram-bot-token", "SECRET", tok), found(f"curl {url}"))

    def test_an_identifier_after_aio_is_no_key(self):
        self.assertEqual(found("from x import " + J(["ai", "o_ConnectionPoolManagerFactory"])), [])

    def test_a_discord_bot_token_needs_a_user_id_in_its_first_part(self):
        r = random.Random(17)
        for _ in range(40):
            tok = discord_bot(r)
            self.assertTrue(checksums.discord_bot_token_ok(tok))
            fake = J(["M", rd(r, 25, AN), ".", rd(r, 6, AN), ".", rd(r, 27, AN)])
            self.assertFalse(checksums.discord_bot_token_ok(fake))


if __name__ == "__main__":
    unittest.main()
