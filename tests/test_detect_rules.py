"""The detector (detect.py): rule loaders, validators, placeholders, context words, the scanner's
overlap and extension rules, the label on the next line, the keyword window, and two corpora.

Run: python3 -m unittest tests.test_detect_rules -v
Every token is generated at run time from a seeded alphabet, so no literal sits in the tree and
the repository's own secret scan stays clean.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import string
import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402  first: a temp vault home, never the real one
# never the real store and never the keychain: the jsonfile backend in the temp home
Path(_isolate.HOME).mkdir(parents=True, exist_ok=True)
Path(_isolate.HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import checksums, detect, hooks  # noqa: E402

AN = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
_R = random.Random(11)


def rnd(n: int, alphabet: str = AN, r: random.Random = _R) -> str:
    return "".join(r.choice(alphabet) for _ in range(n))


def scan(text: str, **kw) -> list[detect.Match]:
    """detect.scan with every `§` removed first. A `§` splits a credential keyword in this file,
    so the CI scan of the tree (`no_secrets_in_tree`) does not take the corpus for secrets."""
    return detect.scan(text.replace("§", ""), **kw)


def _mixed(n: int, seed: int) -> str:
    """A value that reads like a password: a capital first, then letters in both cases with a digit
    in every third place. Generated here: a fixed literal of this shape in the file was read as a
    shipped credential by the Anthropic directory (2026-09-27)."""
    r = random.Random(seed)
    out = []
    for i in range(n):
        if i == 0:
            out.append(r.choice(string.ascii_uppercase))
        elif i % 3 == 2:
            out.append(r.choice("23456789"))
        else:
            out.append(r.choice(string.ascii_letters.replace("l", "").replace("O", "")))
    return "".join(out)


PW12, PW16, PW18, PW11 = _mixed(12, 1), _mixed(16, 2), _mixed(18, 3), _mixed(11, 4)
# a pass phrase with a space, and one with a symbol, in the place of two well-known passwords
PHRASE, SYMBOL = _mixed(7, 5).lower() + " " + _mixed(6, 6).lower(), _mixed(9, 7) + "&" + "3"


def kinds(text: str, **kw) -> list[tuple[str, str]]:
    return [(m.kind, m.value) for m in scan(text, **kw)]


def luhn_complete(body: str) -> str:
    """Append the Luhn check digit (independent of detect._luhn_ok)."""
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:            # these are doubled once the check digit is appended
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return body + str((10 - total % 10) % 10)


def iban_complete(cc: str, bban: str) -> str:
    """Compute the ISO 13616 check digits (independent of detect._iban_ok)."""
    num = "".join(str(int(c, 36)) for c in bban + cc + "00")
    return f"{cc}{98 - int(num) % 97:02d}{bban}"


def tax_id_check(first10: str) -> str:
    """ISO 7064 MOD 11,10 check digit (independent of detect._de_tax_id_ok)."""
    p = 10
    for ch in first10:
        s = (int(ch) + p) % 10
        p = ((s if s else 10) * 2) % 11
    return str((11 - p) % 10)


# ------------------------------------------------------------------ loaders --
class RuleLoaderTests(unittest.TestCase):
    def test_betterleaks_rules_are_secret_rules_with_their_filters(self):
        rules = detect._load_betterleaks()
        self.assertGreater(len(rules), 350)
        self.assertEqual({r.type for r in rules}, {"SECRET"})
        self.assertEqual(len({r.id for r in rules}), len(rules))
        self.assertTrue(all(r.drop is not None for r in rules), "the global filter applies to every rule")
        for r in rules:
            with self.subTest(rule=r.id):
                r.regex.search("")

    def test_generic_api_key_keeps_its_gitleaks_form_with_its_allowlists(self):
        rules = detect._load_own_secret_rules()
        self.assertEqual(rules[0].id, "generic-api-key")
        loaded = {r.id for r in detect._load_betterleaks()}
        self.assertFalse({r.id for r in rules} & loaded, "an own rule never shares an id with betterleaks")
        by_id = {r.id: r for r in rules}
        generic = by_id["generic-api-key"]
        self.assertEqual(generic.entropy, 3.5)
        self.assertIn("token", generic.keywords)
        self.assertTrue(all(k == k.lower() for r in rules for k in r.keywords))
        self.assertTrue(all(s == s.lower() for s in generic.stopwords))
        self.assertIn("line", {t for _, t in generic.allow_regexes})
        # RE2 flags and anchors are rewritten for Python: every regex compiles
        for r in rules:
            with self.subTest(rule=r.id):
                r.regex.search("")

    def test_re2_flags_move_to_the_front_and_z_becomes_Z(self):
        self.assertEqual(detect._re2_to_python(r"abc(?i)def\z"), r"(?i)abcdef\Z")
        self.assertEqual(detect._re2_to_python(r"plain"), "plain")

    def test_presidio_regions_are_opt_in(self):
        generic = {r.id.split("#")[0] for r in detect._load_presidio(("generic",))}
        with_de = {r.id.split("#")[0] for r in detect._load_presidio(("generic", "de"))}
        with_us = {r.id.split("#")[0] for r in detect._load_presidio(("generic", "us"))}
        self.assertIn("iban", generic)
        self.assertFalse(any(i.startswith("de-") for i in generic))
        self.assertIn("de-tax-id", with_de)
        self.assertIn("aba-routing", with_us)
        self.assertNotIn("aba-routing", with_de)
        self.assertFalse(generic & detect.PRESIDIO_SKIP)

    def test_presidio_region_is_derived_from_the_recognizer_id(self):
        for rec, region in [("de-tax-id", "de"), ("us-ssn", "us"), ("nhs", "uk"), ("aba-routing", "us"),
                            ("iban", "generic"), ("credit-card", "generic"), ("abc-x", "generic")]:
            with self.subTest(rec=rec):
                self.assertEqual(detect.presidio_region(rec), region)

    def test_presidio_rules_carry_type_validator_and_weakness(self):
        rules = {r.id: r for r in detect._load_presidio(("generic", "de"))}
        self.assertEqual((rules["iban"].type, rules["iban"].validator, rules["iban"].require_context),
                         ("IBAN", "iban", False))
        self.assertEqual(rules["credit-card"].type, "CARD")
        self.assertTrue(rules["de-tax-id"].require_context)            # a plain digit run
        self.assertTrue(rules["de-fuehrerschein"].score < 1.0)
        self.assertIn("de-social-security#0", rules)                   # several patterns: numbered ids
        self.assertIn("de-social-security#1", rules)
        self.assertNotIn("de-id-card#0", rules)                        # REGIONAL_RULES: no check digit printed
        self.assertTrue(all(r.whole_match for r in rules.values()))
        self.assertTrue(all(c == c.lower() for r in rules.values() for c in r.context))

    def test_detect_secrets_rules_know_the_german_labels(self):
        rules = detect._load_detect_secrets()
        self.assertTrue(all(r.validator == "ds_value" and r.type == "SECRET" for r in rules))
        basic = [r for r in rules if r.id == "ds-basic-auth"][0]
        self.assertEqual(basic.keywords, ())
        self.assertNotIn("kennw", detect._load_detect_secrets(("en",))[0].keywords)
        colon = [r for r in detect._load_detect_secrets(("en", "de")) if r.id == "ds-keyword-colon"][0]
        self.assertIn("kennw", colon.keywords)
        from maisecrets.regions import load_labels
        for lab in load_labels("de"):
            self.assertIn(lab.regex, colon.regex.pattern)

    def test_prefix_rules_skip_comments_and_blank_lines(self):
        rules = detect._load_prefixes()
        ids = [r.id for r in rules]
        self.assertIn("gitlab-runner-token", ids)
        self.assertFalse(any(i.startswith("#") for i in ids))
        text = (detect.RULES_DIR / "prefixes.txt").read_text(encoding="utf-8")
        live = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        self.assertEqual(len(rules), len(live))

    def test_rule_order_is_own_secrets_then_detect_secrets_betterleaks_presidio_then_own_pii(self):
        ids = [r.id for r in detect.rules()]
        pos = {i: n for n, i in enumerate(ids)}
        self.assertLess(pos["url-query-secret"], pos["ds-keyword-colon"])
        self.assertLess(pos["ds-keyword-colon"], pos["generic-api-key"])
        self.assertLess(pos["generic-api-key"], pos["iban"])
        self.assertLess(pos["iban"], pos["email"])
        n = len(detect.LITERAL_RULES)   # the label and literal rules run last: they take only what no rule took
        self.assertEqual(ids[-n:], [d["id"] for d in detect.LITERAL_RULES])
        self.assertEqual(ids[-n - 4:-n], ["email", "iban-lowercase", "email-percent-encoded", "phone"])
        self.assertIs(detect.rules(), detect.rules())

    def test_a_broken_config_falls_back_to_the_default_regions(self):
        # the tests pin MAISECRETS_LOCALE=de_DE (tests/_isolate.py), so "auto" is de
        with mock.patch("maisecrets.home.load_config", side_effect=RuntimeError("broken")):
            self.assertEqual(detect._pii_regions(), ("generic", "de"))
        with mock.patch("maisecrets.home.load_config", return_value={"regions": ["us"]}):
            self.assertEqual(detect._pii_regions(), ("generic", "us"))
        with mock.patch("maisecrets.home.load_config", return_value={"regions": []}):
            self.assertEqual(detect._pii_regions(), ("generic",))

    def test_shannon_entropy(self):
        self.assertEqual(detect.shannon_entropy(""), 0.0)
        self.assertEqual(detect.shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(detect.shannon_entropy("abab"), 1.0)
        self.assertAlmostEqual(detect.shannon_entropy("abcd"), 2.0)


# --------------------------------------------------------------- validators --
class ValidatorTests(unittest.TestCase):
    def test_luhn_accepts_every_completed_number_and_refuses_a_changed_check_digit(self):
        r = random.Random(1)
        for _ in range(300):
            body = rnd(r.randint(11, 18), string.digits, r)
            good = luhn_complete(body)
            bad = good[:-1] + str((int(good[-1]) + r.randint(1, 9)) % 10)
            with self.subTest(good=good):
                self.assertTrue(detect._luhn_ok(good))
                self.assertFalse(detect._luhn_ok(bad))
        self.assertTrue(detect.VALIDATORS["luhn"](" ".join(["4111"] + ["1111"] * 3)))

    def test_iban_checksum_length_and_case(self):
        r = random.Random(2)
        for _ in range(200):
            bban = rnd(r.randint(11, 30), string.digits + string.ascii_uppercase, r)
            good = iban_complete(r.choice(["DE", "GB", "FR", "NL"]), bban)
            with self.subTest(good=good):
                self.assertTrue(detect._iban_ok(good))
                # lower case holds only with the country's length: a lower-case hex digest passes mod 97 too
                self.assertEqual(detect._iban_ok(good.lower()), detect.IBAN_LENGTH[good[:2]] == len(good))
                spaced = " ".join(good[i:i + 4] for i in range(0, len(good), 4))
                self.assertTrue(detect._iban_ok(spaced))
                self.assertFalse(detect._iban_ok(good[:2] + f"{(int(good[2:4]) + 1) % 100:02d}" + good[4:]))
        self.assertTrue(detect._iban_ok(" ".join(["DE89", "3704", "0044", "0532", "0130", "00"])))
        self.assertFalse(detect._iban_ok(iban_complete("DE", "1234567890")))     # 14 characters
        self.assertFalse(detect._iban_ok(iban_complete("DE", "1" * 31)))         # 35 characters

    def test_public_ip(self):
        for ip, ok in [("93.184.216.34", True), ("172.15.0.1", True), ("172.32.0.1", True), ("193.168.1.1", True),
                       ("10.1.2.3", False), ("127.0.0.1", False), ("0.0.0.0", False), ("192.168.0.1", False),
                       ("172.16.0.1", False), ("172.31.255.255", False), ("169.254.1.1", False),
                       ("256.1.1.1", False), ("1.2.3.4/24", False), ("1.2.3", False),
                       ("2a00:1450:4001::200e", True), ("::1", False), ("::", False),
                       ("fe80::1", False), ("fc00::1", False), ("fd12:3456::1", False), ("0:0:0:0::0", False),
                       ("2a00:1450", False), ("zz::zz:zz", False),
                       # no address of a person: documentation ranges, shared, reserved, broadcast, multicast and
                       # the public resolvers (the standard library's docs and tests held 666, 2026-09-29)
                       ("192.0.2.1", False), ("198.51.100.7", False), ("203.0.113.9", False), ("2001:db8::1", False),
                       ("100.64.1.1", False), ("240.0.0.1", False), ("255.255.255.255", False), ("224.0.0.251", False),
                       ("ff02::1", False), ("8.8.8.8", False), ("1.1.1.1", False), ("2606:4700:4700::1111", False)]:
            with self.subTest(ip=ip):
                self.assertEqual(detect._public_ip(ip), ok)

    def test_german_tax_id(self):
        self.assertTrue(detect._de_tax_id_ok("86095742719"))
        for bad in ("86095742710", "06095742719", "8609574271", "8609574271x", "11112345671"):
            with self.subTest(bad=bad):
                self.assertFalse(detect._de_tax_id_ok(bad))
        # the frequency rule: no digit more than three times in the first ten
        self.assertFalse(any(detect._de_tax_id_ok("1111234567" + str(c)) for c in range(10)))
        # a leading zero is refused although the check digit is right
        lead0 = "0609574271"
        self.assertFalse(detect._de_tax_id_ok(lead0 + tax_id_check(lead0)))
        self.assertTrue(detect._de_tax_id_ok("8609574271" + tax_id_check("8609574271")))

    def test_german_social_security_number(self):
        for good in ("65170839J003", "65 170839 J 003", "65170839j003"):
            self.assertTrue(detect._de_social_security_ok(good), good)
        for bad in ("65170839J004", "65170839J00", "651708393003", "65321339J003", "65170039J003",
                    "65171339J003"):
            with self.subTest(bad=bad):
                self.assertFalse(detect._de_social_security_ok(bad))
        # day + 50 (a second number for the same date) is a valid day; day 32 and month 13 are not,
        # whatever the check digit
        self.assertTrue(any(detect._de_social_security_ok(f"65510839J00{c}") for c in range(10)))
        self.assertTrue(any(detect._de_social_security_ok(f"65810839J00{c}") for c in range(10)))
        for invalid in ("653208", "651713", "658208", "651700"):
            with self.subTest(invalid=invalid):
                self.assertFalse(any(detect._de_social_security_ok(f"{invalid}39J00{c}") for c in range(10)))

    def test_icao_check_digit_and_the_german_document_number(self):
        # ICAO Doc 9303 Part 3 4.9: weights 7 3 1, A to Z count 10 to 35, < counts 0
        icao = checksums.icao_check_digit
        self.assertEqual(icao("".join(["L898", "902C"])), 3)        # the ICAO specimen passport number
        self.assertEqual(icao("".join(["L898", "902C<<"])), 3)
        with self.assertRaises(ValueError):
            icao("L898-902C")
        ok = checksums.de_document_ok
        body = "".join(["L898", "902C3"])
        self.assertTrue(ok(body))                                   # 9 characters as printed: no check digit
        self.assertTrue(ok(body.lower()))
        self.assertTrue(ok(body + str(icao(body))))                 # 10 as in the machine-readable zone
        self.assertFalse(ok(body + str((icao(body) + 1) % 10)))
        self.assertFalse(ok(body[:-1]))
        # BSI TR-03123-2 3.2.1: never A, B, D, E, I, O, Q, S or U
        for letter in "ABDEIOQSU":
            with self.subTest(letter=letter):
                self.assertFalse(ok("L8989" + letter + "2C3"))

    def test_german_health_insurance_number(self):
        self.assertTrue(detect._de_health_insurance_ok("A123456780"))
        self.assertTrue(detect._de_health_insurance_ok("a123456780"))
        for bad in ("A123456781", "1123456780", "A12345678", "AB23456780"):
            with self.subTest(bad=bad):
                self.assertFalse(detect._de_health_insurance_ok(bad))

    def test_german_lanr_bsnr_and_vat_id(self):
        # LANR 123456|6|01: 1*4+2*9+3*4+4*9+5*4+6*9 = 144, check (10 - 4) % 10 = 6
        self.assertTrue(detect._de_lanr_ok("123456601"))
        for bad in ("123456701", "12345660", "12345660x"):
            self.assertFalse(detect._de_lanr_ok(bad), bad)
        bsnr = detect.VALIDATORS["de_bsnr"]
        self.assertTrue(bsnr("123456789"))
        self.assertFalse(bsnr("000000000"))
        self.assertFalse(bsnr("12345678"))
        for good in ("DE123456789", "de 123.456.789", "DE-123-456-789"):
            self.assertTrue(detect._de_vat_id_ok(good), good)
        for bad in ("AT123456789", "DE12345678", "DE1234567890", "DE12345678X"):
            self.assertFalse(detect._de_vat_id_ok(bad), bad)

    def test_ds_value_filters(self):
        ok = [PW11, PHRASE, SYMBOL, "a" * 7 + "B9"]
        rejected = {
            "short": PW11[:7], "long": PW11[:3] * 90, "jinja": "{{ vault_password }}", "shell": "${DB_PASSWORD}",
            "angle": "<your password>", "percent": "%DB_PASSWORD%", "dollar": "$DB_PASSWORD",
            "call": "get_secret(name)", "index": "settings[key]", "paren": "value)1234567", "backtick": "`abc1234567`",
            "pipe": "abc | 1234567", "no alnum": "!@#$%^&*-+", "sentence": "my key 12",
            "two words": "bad payload", "identifier": "NAME_OF_SECRET", "word": "placeholder", "word 8": "ChangeMe",
            "repeated": "aaaaaaaaaa", "sequential letters": "abcdefghij", "sequential digits": "123456789",
            "own placeholder": "⟦secret_c1⟧xx", "legacy placeholder": "<SECRET_c12>",
        }
        for v in ok:
            self.assertTrue(detect._ds_value_ok(v), v)
        for why, v in rejected.items():
            with self.subTest(why=why):
                self.assertFalse(detect._ds_value_ok(v))

    def test_not_placeholder_and_person_email(self):
        np = detect.VALIDATORS["not_placeholder"]
        self.assertTrue(np(PW12))
        self.assertFalse(np("PLACEHOLDER"))
        self.assertFalse(np("<token>"))
        pe = detect.VALIDATORS["person_email"]
        self.assertTrue(pe("anna@acme.de"))
        for system in ("git@github.com", "noreply@acme.de", "Root@host.de", "mailer-daemon@x.org"):
            self.assertFalse(pe(system), system)

    def test_a_validator_that_cannot_parse_its_value_rejects_the_hit(self):
        def boom(_v):
            raise ValueError("unparseable")
        with mock.patch.dict(detect.VALIDATORS, {"iban": boom}):
            self.assertEqual(kinds("IBAN " + " ".join(["DE89", "3704", "0044", "0532", "0130", "00"])), [])


# ------------------------------------------------------------- placeholders --
class PlaceholderValueTests(unittest.TestCase):
    def test_every_placeholder_value_is_recognised_in_quotes_too(self):
        for v in detect.PLACEHOLDER_VALUES:
            for form in (v, v.upper(), f'"{v}"', f"'{v}'", f"`{v}` "):
                self.assertTrue(detect.looks_like_placeholder(form), form)

    def test_placeholder_parts_and_template_names(self):
        for v in ("your_token_1234", "my-dummy-key-99", "EXAMPLEKEY123", "abc_fake123456", "PORTKEY_API_KEY",
                  "<redacted-by-ops>", "xxxxxxxx1234", "tok0000000000EXAMPLE"):
            self.assertTrue(detect.looks_like_placeholder(v), v)
        for v in (PW12, "ABC_123_DEF", PW11, "PORTKEY"):
            self.assertFalse(detect.looks_like_placeholder(v), v)

    def test_a_placeholder_word_inside_a_random_token_is_chance_not_a_placeholder(self):
        # a random GitHub token holds fAKe or DuMmy in its body about once in 20,000; it was let
        # through as a placeholder (windows-latest, 2026-09-27)
        for word in ("fAKe", "DuMmy", "SaMPle", "eXaMpLe", "BoGuS"):
            with self.subTest(word):
                token = "ghp_" + (rnd(8) + "Q" + word + "7" + rnd(40))[:36]
                self.assertFalse(detect.looks_like_placeholder(token), token)
                self.assertEqual([v for _, v in kinds(f"GITHUB_TOKEN={token}")], [token])
                self.assertEqual(kinds(f"see {token} here"), [("github-pat", token)])

    def test_a_secret_shaped_placeholder_is_never_a_hit(self):
        # the key of the AWS documentation, decoded at run time: the directory scanner joins string
        # pieces and read "AKIA" + "…" + "EXAMPLE" as a literal credential (2026-09-27)
        aws_doc = bytes.fromhex("414b4941494f53464f444e4e374558414d504c45").decode()
        for text in (f"id {aws_doc}", "password = changeme", "password = YOUR_DB_PASSWORD",
                     'api_key = "your_api_key_here_123"', "token: dummy-" + rnd(20)):
            with self.subTest(text=text):
                self.assertEqual(kinds(text), [])

    def test_a_span_that_holds_our_placeholder_is_never_a_hit(self):
        for text in ("password = ⟦SECRET_c1⟧", "curl -u app:⟦SECRET_c1⟧ https://example.org",
                     "password = <SECRET_c2>", "https://user:<SECRET_c3>@example.org/x",
                     "Authorization: Bearer ⟦SECRET_c4⟧", "api_key: ⟦SECRET_c5:ab•••⟧", "secret: ⟦SECRET_c6⟧"):
            with self.subTest(text=text):
                self.assertEqual(kinds(text), [])

    def test_a_legacy_placeholder_inside_a_longer_value_is_not_a_hit(self):
        self.assertEqual(kinds("password = pre<SECRET_c7>post9"), [])


# ------------------------------------------------------------ context words --
class ContextWordTests(unittest.TestCase):
    def test_a_context_word_counts_only_as_a_whole_word(self):
        self.assertEqual(kinds("Ort: 10115"), [("de-plz", "10115")])
        self.assertEqual(kinds("PLZ 10115"), [("de-plz", "10115")])
        self.assertEqual(kinds("Report 10115"), [])
        self.assertEqual(kinds("Sportort 10115"), [])
        self.assertEqual(kinds("Ortsname 10115"), [])
        self.assertFalse(detect._has_context_word("anything", ()))

    def test_a_digit_run_needs_its_context_word_near_the_value(self):
        tax = "86095742719"
        self.assertEqual(kinds(f"Steuer-ID: {tax}"), [("de-tax-id", tax)])
        self.assertEqual(kinds(f"{tax} ist meine Steuer-ID"), [("de-tax-id", tax)])
        self.assertEqual(kinds(tax), [])
        # the word is in the text, but more than 80 characters before the value
        self.assertEqual(kinds("Steuer-ID bitte. " + "x " * 60 + tax), [])

    def test_a_weak_card_shape_needs_a_context_word_near_it(self):
        card = " ".join(["4929", "1844", "0817", "2239"])   # synthetic, not in rules/public_test_values.txt
        self.assertFalse(detect.is_public_test_value(card, "CARD"))
        self.assertEqual(kinds(f"card {card}"), [("credit-card", card)])
        self.assertEqual(kinds(card), [])
        self.assertEqual(kinds("card " + "x " * 60 + card), [])
        self.assertEqual(kinds("visa " + card[:-1] + "2"), [])       # context, but not a Luhn number

    def test_german_identifiers_with_their_context(self):
        for text, kind, value in [("Rentenversicherungsnummer 65170839J003", "de-social-security#0", "65170839J003"),
                                  ("Personalausweis L898902C3", "de-id-card", "L898902C3"),
                                  ("Reisepass L898902C3", "de-passport", "L898902C3"),
                                  ("Krankenversichertennummer A123456780", "de-health-insurance", "A123456780"),
                                  ("LANR 123456601", "de-lanr", "123456601"),
                                  ("USt-IdNr DE123456789", "de-vat-id#0", "DE123456789")]:
            with self.subTest(kind=kind):
                self.assertEqual(kinds(text), [(kind, value)])
        self.assertEqual(kinds("kvnr A123456781"), [])                 # wrong check digit


# ------------------------------------------------------------ scanner rules --
class ScanRuleTests(unittest.TestCase):
    GLPAT = "glpat-" + rnd(20)

    def test_contains_secret_asks_for_a_secret_type_only(self):
        self.assertTrue(detect.contains_secret(f"token {self.GLPAT}"))
        self.assertFalse(detect.contains_secret("mail anna.berg@acme.de and IBAN "
                                                + " ".join(["DE89", "3704", "0044", "0532", "0130", "00"])))
        self.assertFalse(detect.contains_secret(""))

    def test_enabled_limits_the_rules(self):
        text = f"token {self.GLPAT} mail anna.berg@acme.de"
        self.assertEqual({k for k, _ in kinds(text)}, {"gitlab-pat", "email"})
        self.assertEqual(kinds(text, enabled={"gitlab-pat"}), [("gitlab-pat", self.GLPAT)])
        self.assertEqual(kinds(text, enabled={"email"}), [("email", "anna.berg@acme.de")])
        self.assertEqual(kinds(text, enabled=set()), [])
        self.assertEqual(detect.scan(""), [])

    def test_a_url_password_with_no_user_is_a_secret(self):
        pw = rnd(14, AN)
        self.assertEqual(kinds(f"REDIS_URL=redis://:{pw}@cache.example.org:6379/0"), [("url-password-no-user", pw)])
        self.assertEqual(kinds(f"rediss://:{pw}@cache.internal:6380"), [("url-password-no-user", pw)])
        # an encoded $ or { inside a real password stays a value, and so does a half reference or an impossible
        # date (codex, Opus review of 0.6.8)
        for enc in (pw[:4] + "%24" + pw[4:], pw[:4] + "%7B" + pw[4:], "%24%7BREDIS_PASS", "%24REDIS_PASS%7D",
                    "2026-99-08", "2026-10-08T99", "2026-02-31", "2026-04-31", "2025-02-29", "0000-01-01"):
            with self.subTest(enc=enc):
                self.assertEqual(kinds(f"redis://:{enc}@cache:6379"), [("url-password-no-user", enc)])
        # a reference, a default word, a short value and a port stay text
        for text in ("redis://:${REDIS_PASSWORD}@redis:6379", "redis://:changeme@localhost", "redis://:pw@localhost",
                     "see https://:443@x", "redis://:%24%7BREDIS_PASSWORD%7D@localhost", "redis://:2026-10-08@x",
                     "redis://:%24REDIS_PASSWORD@localhost", "redis://:2024-02-29@x"):
            with self.subTest(text=text):
                self.assertEqual(kinds(text), [])
        self.assertEqual(kinds(f"postgres://app:{pw}@db.example.org/app"), [("ds-basic-auth", pw)],
                         "with a user the detect-secrets rule keeps the span")

    def test_the_key_id_in_a_sigv4_credential_scope_is_not_a_secret(self):
        kid = "AKIA" + rnd(16, string.ascii_uppercase + "234567")       # base32, as the aws-access-token rule reads it
        scope = f"{kid}%2F20261008%2Feu-central-1%2Fs3%2Faws4_request"
        for text in (f"https://b.s3.amazonaws.com/k?X-Amz-Credential={scope}&X-Amz-Signature=" + "9f3c" * 16,
                     f"https://b.s3.amazonaws.com/k?x-amz-algorithm=AWS4&X-Amz-Credential%3D{scope}",
                     f"https://b.s3.amazonaws.com/k?x-amz-credential={scope}&x-amz-signature=" + "9f3c" * 16,
                     f"Authorization: AWS4-HMAC-SHA256 Credential={kid}/20261008/eu-central-1/s3/aws4_request"):
            with self.subTest(text=text[:40]):
                self.assertEqual(kinds(text), [])
        # the same id anywhere else stays a hit: it shows where the secret half is (and the premise of the cases)
        # a bare Credential= with no date/region/service/aws4_request scope is no SigV4 scope (codex review of 0.6.8)
        for text in (f"aws_access_key_id = {kid}", f"export AWS_ACCESS_KEY_ID={kid}", f"id {kid} in a note",
                     f"Credential={kid}", f"Credential={kid} and more", f"X-Amz-Credential={kid}&x=1",
                     f"Credential={kid}/20261008/eu-central-1/s3/aws4_requestX",
                     f"Credential={kid}/20261008/eu-central-1/s3/aws4_request_extra",
                     *(f"Credential={kid}/20261008/eu-central-1/s3/aws4_request{tail}"
                       for tail in (".x", ":x", "%41", "/x", "%2Fx"))):
            with self.subTest(text=text[:40]):
                self.assertEqual(kinds(text), [("aws-access-token", kid)])

    def test_the_first_rule_to_claim_a_span_wins(self):
        ghp = "ghp_" + rnd(36)
        # detect-secrets runs before betterleaks: the keyword rule claims the span of the github token
        self.assertEqual(kinds(f"password = {ghp}"), [("ds-keyword-equal-signs", ghp)])
        self.assertEqual(kinds(f"password = {ghp}", enabled={"github-pat"}), [("github-pat", ghp)])

    def test_results_are_leftmost_first_and_never_overlap(self):
        r = random.Random(4)
        pieces = [lambda: "glpat-" + rnd(20, AN, r), lambda: "ghp_" + rnd(36, AN, r),
                  lambda: f"password = {rnd(14, AN, r)}", lambda: "anna.berg@acme.de", lambda: "93.184.216.34",
                  lambda: "IBAN " + iban_complete("DE", rnd(18, string.digits, r)), lambda: "+49 170 1234567",
                  lambda: "Bearer " + rnd(24, AN, r), lambda: "https://x.org/?token=" + rnd(16, AN, r),
                  lambda: "plain words", lambda: "\n"]
        for _ in range(40):
            text = " ".join(r.choice(pieces)() for _ in range(12))
            ms = detect.scan(text)
            with self.subTest(text=text[:80]):
                self.assertEqual([m.start for m in ms], sorted(m.start for m in ms))
                for a, b in zip(ms, ms[1:]):
                    self.assertLessEqual(a.end, b.start)
                for m in ms:
                    self.assertEqual(text[m.start:m.end], m.value)
                self.assertGreaterEqual(len(ms), 1)

    def test_a_fixed_length_shape_runs_to_the_end_of_the_token_up_to_128_more(self):
        self.assertEqual(kinds(f"x {self.GLPAT}-tail_9 y"), [("gitlab-pat", self.GLPAT + "-tail_9")])
        self.assertEqual(kinds(f"x {self.GLPAT}.rest"), [("gitlab-pat", self.GLPAT)])
        long = self.GLPAT + "Q" * 200
        self.assertEqual([len(v) for _, v in kinds(f"x {long} y")], [len(self.GLPAT) + 128])

    def test_a_label_takes_the_next_non_empty_line(self):
        v = PW12
        for text in ("passwort:\n" + v, "passwort:\n\n\n" + v, "password =\n" + v, "Secret:\r\n" + v):
            with self.subTest(text=text):
                self.assertIn(v, [val for _, val in kinds(text)])
        self.assertEqual(kinds("passwort:\n\n\n"), [])                  # a label at the end of the text

    def test_a_hit_from_the_label_pair_starts_in_the_next_line(self):
        # the pair would read "abc:\n<value>" as one value; only a hit that starts after the label counts
        for text in ("pass§word: abc:\n" + PW11, "sec§ret: xy1:\n\n" + PW12,
                     "pass§word: \"abc:\n" + PW11 + "\""):
            with self.subTest(text=text):
                self.assertFalse([v for _, v in kinds(text) if "\n" in v])

    def test_code_that_ends_in_a_colon_does_not_take_the_next_line(self):
        v = PW11 + "1"
        for code in ('if kind != "SECRET":\n    ' + v, "class Secret:\n    " + v, "def secret():\n    " + v,
                     "if value is not secret:\n    " + v, "if n >= min_secret:\n    " + v,
                     "while pwd <= secret:\n    " + v, 'elif mode == "secret":\n    ' + v):
            with self.subTest(code=code[:24]):
                self.assertEqual(kinds(code), [])
        for text in ("for the db, password:\n" + v, "if needed, passwort:\n" + v, "while you wait, secret:\n" + v,
                     "is it the password:\n" + v, "class notes, secret:\n" + v):
            with self.subTest(text=text[:24]):
                self.assertEqual(kinds(text), [("ds-keyword-colon", v)])

    def test_german_labels(self):
        v = PW12
        for label in ("passwort", "Passwort", "KENNWORT", "geheimnis", "Schlüssel", "schluessel", "Zugangsdaten",
                      "db_passwort"):
            for sep in (": ", " = ", ":\n"):
                with self.subTest(label=label, sep=sep):
                    self.assertIn(v, [val for _, val in kinds(label + sep + v)])
        # the product's own name holds "secret" and is never a detect-secrets label
        self.assertEqual([k for k, _ in kinds("maisecrets: " + v) if k.startswith("ds-")], [])
        self.assertEqual(kinds("/maisecrets:shortcut"), [])


# ------------------------------------------------------------ keyword window --
class KeywordWindowTests(unittest.TestCase):
    """_windowed must find exactly what the regex finds over the whole text."""

    rule = next(r for r in detect.rules() if r.id == "generic-api-key")
    kw = detect._WINDOWED["generic-api-key"]
    WORDS = ["the", "api", "key", "token", "password", "secret", "auth", "access", "credential", "value", "=", ":",
             "=>", ",", "'", '"', "\n", "\r\n", "\n\n", "\r\n\r\n", "   ", "\t", "x" * 45, "a.b-c_d" * 8, "keyboard",
             "monkey", "api_version", "==", ";"]

    def _text(self, r: random.Random, target: int) -> str:
        out, n = [], 0
        while n < target:
            if r.random() < 0.15:
                # a keyword, up to 3 whitespace, a separator, up to 5 whitespace, a value
                ws = [" ", "\t", "\n", "\r\n", "'"]
                sep = "".join(r.choice(ws) for _ in range(r.randint(0, 3))) + r.choice(["=", ":", "=>", ","])
                sep += "".join(r.choice(ws) for _ in range(r.randint(0, 5)))
                t = r.choice(["password", "token", "api_key", "secret"]) + sep + rnd(r.randint(10, 40), AN, r)
            elif r.random() < 0.2:
                t = rnd(r.randint(8, 40), "abcdefXYZ0123456789+/=-_.", r)
            else:
                t = r.choice(self.WORDS)
            out.append(t + r.choice([" ", "", "\n", "-"]))
            n += len(out[-1])
        return "".join(out)[:target]

    def _spans(self, it):
        return [(m.start(), m.end(), m.start(1), m.end(1)) for m in it]

    def test_the_window_finds_what_the_whole_text_regex_finds(self):
        r = random.Random(9)
        for i in range(120):
            text = self._text(r, r.choice([300, 4095, 4096, 4097, 4600]))
            with self.subTest(i=i):
                self.assertEqual(self._spans(detect._windowed(self.rule, self.kw, text)),
                                 self._spans(self.rule.regex.finditer(text)))

    def test_a_value_up_to_eight_line_breaks_after_its_keyword(self):
        value = PW18
        filler = "filler text. " * 400
        for before in range(4):
            for after in range(6):
                sep = "\n" * before + ":" + "\n" * after
                text = filler + "password" + sep + value + "\n" + "y" * 50
                with self.subTest(before=before, after=after):
                    self.assertEqual(self._spans(detect._windowed(self.rule, self.kw, text)),
                                     self._spans(self.rule.regex.finditer(text)))

    def test_scan_gives_the_same_hits_with_and_without_the_window(self):
        r = random.Random(10)
        for i in range(25):
            text = self._text(r, r.choice([4097, 5000]))
            windowed = kinds(text, enabled={"generic-api-key"})
            with mock.patch.dict(detect._WINDOWED, clear=True):
                whole = kinds(text, enabled={"generic-api-key"})
            with self.subTest(i=i):
                self.assertEqual(windowed, whole)


# --------------------------------------------------------- label value ends --
class LabelValueTests(unittest.TestCase):
    """What a detect-secrets keyword rule takes as the value after `password:` / `api_key=`."""

    MAIL = "anna.berg@acme.de"

    def test_an_unquoted_value_ends_at_the_first_whitespace(self):
        pw = "wwdwewrw" + "rwrwrwwr"   # assembled: a literal after pw = is a password to the repo scan
        for text, expected in [
            (f"password:{pw} and {self.MAIL}", [("SECRET", pw), ("EMAIL", self.MAIL)]),
            (f"password:{pw} {self.MAIL}", [("SECRET", pw), ("EMAIL", self.MAIL)]),
            ("pass§wort: Sommer2026! bitte", [("SECRET", "Sommer2026!")]),
            ("api§_key=abc§123XYZdef extra words", [("SECRET", "abc" + "123XYZdef")]),
            ("pass§word = " + PW11 + ", user = bob", [("SECRET", PW11)]),
            ("pass§wort:\nSommer2026! bitte schnell", [("SECRET", "Sommer2026!")]),
        ]:
            with self.subTest(text=text):
                self.assertEqual([(m.type, m.value) for m in scan(text)], expected)

    def test_a_quoted_value_keeps_its_spaces(self):
        self.assertEqual(kinds('pass§word: "correct horse9"'), [("ds-keyword-colon", "correct horse9")])
        self.assertEqual(kinds("pass§word = 'correct horse9'"), [("ds-keyword-equal-signs", "correct horse9")])
        # the unquoted form ends at the space ("correct" alone is then too short for a value)
        self.assertFalse([v for _, v in kinds("pass§word: correct horse9") if " " in v])
        # a quoted phrase is judged whole, never cut at its first space
        cut = [v for _, v in kinds('pass§word: "correct horse battery"') if v in ("correct", "correct horse")]
        self.assertFalse(cut)

    def test_a_short_value_glued_to_its_label_counts(self):
        # field report, 2026-09-27: a 7-letter password glued to "pass:" passed; 8 characters were the floor
        for text, value in (("pass§:" + PW11[:7], PW11[:7]), ("pass§word=" + PW11[:6], PW11[:6]),
                            ("a@b.c pass§:" + PW11[:7].lower(), PW11[:7].lower())):
            with self.subTest(text=text):
                self.assertEqual([v for _, v in kinds(text)], [value])
        # with a space between them the floor of the keyword rules stays 8: "password: string" is prose in API docs.
        # A value that is no word is a password at 4 characters and more (label-pw-literal, 0.6.16)
        self.assertEqual(kinds("pass§word: string"), [])
        self.assertEqual([k for k, _ in kinds("pass§word: " + PW11[:7])], ["label-pw-literal"])
        self.assertEqual([x for x in kinds("pass§:" + PW11[:5]) if x[0] != "label-pw-literal"], [],
                         "5 characters are too few for a keyword rule in any case")
        # a colon inside our own placeholder is no label
        self.assertEqual(kinds("api§_key: ⟦SECRET_c5:ab•••⟧"), [])
        # a type, a keyword or a camelCase name glued to a label is code, not a value (final review, 2026-09-28)
        for text in ("pass§word:string", "{pass§word:string, tok§en:number}", "pass§word:boolean", "sec§ret=config",
                     "api§_key=apiKey", "auth§_token=Bearer"):
            with self.subTest(text=text):
                self.assertEqual(kinds(text), [])

    def test_prose_after_a_label_is_still_not_a_value(self):
        for text in ("secret: very important", "api_key: Add API key", '"api_key_label": "Add API key"',
                     "the token expired yesterday"):
            with self.subTest(text=text):
                self.assertEqual(kinds(text), [])

    def test_a_capitalised_word_that_starts_a_sentence_is_not_a_value(self):
        # both lines are in this repository (harness/run.py, the rotation reference)
        for text in ("# the model reads a file that holds a sec§ret: PostToolUse must redact it",
                     "- Webhook signing sec§ret: Developers, Webhooks, the endpoint, Roll sec§ret."):
            with self.subTest(text=text):
                self.assertEqual(kinds(text), [])
        # at the end of the line nothing was cut: one word is still the value
        self.assertEqual(kinds("pass§wort: Sommerwiese"), [("ds-keyword-colon", "Sommerwiese")])

    def test_code_after_a_colon_is_not_a_value(self):
        # `if not token: continue` stored the statement word, and every later text with it was redacted,
        # this repository's own code included (field report, 2026-09-29)
        for text in ("        if not tok§en: continue", "            if not sec§ret: continue",
                     "    if tok§en is None: return", "while not pass§word: break", "if not api§_key: raise",
                     "except Error as sec§ret: pass", "pass§word: continue"):
            with self.subTest(text=text):
                self.assertEqual(kinds(text), [])

    def test_a_line_that_starts_like_code_still_carries_its_value(self):
        # a check of the whole line ("it opens a block") skipped every one of these (review, 2026-09-29)
        v = "Xk9" + "mQ2vLp8r"
        for text in ("with pass§word: {v}", "for staging use pass§word: {v}", "if you need it, pass§word: {v}",
                     "try pass§word: {v}", "else pass§word: {v}", "while testing, api§_key: {v}",
                     "if env == 'prod': pass§word = '{v}'", "        if not tok§en: {v}"):
            with self.subTest(text=text):
                self.assertIn(v, [m.value for m in scan(text.format(v=v))])

    def test_one_lowercase_word_before_more_prose_stays_a_value(self):
        # "Sec§rets: connectors and plugins" is prose, but a lowercase value can be a random password
        # ("To§ken: abbabaabab, thanks", tests/detection_matrix.py) and a real word ("password:<word> and
        # <address>" leaked once as prose, 2026-09-27). Without a dictionary the two cannot be told apart:
        # the false positive is the cheaper error (decision, 2026-09-29)
        self.assertEqual(kinds("Sec§rets: connectors and plugins"), [("ds-keyword-colon", "connectors")])
        self.assertEqual(kinds("pass§word: hunter2hunter2 please"), [("ds-keyword-colon", "hunter2hunter2")])

    def test_two_distinct_characters_are_a_value(self):
        for text, value in [("pass§word:asasasasasasaasasasa", "asasasasasasaasasasa"),
                            ("pass§wort: abababab12", "abababab12")]:
            with self.subTest(text=text):
                self.assertEqual([m.value for m in scan(text)], [value])

    def test_one_repeated_character_is_filler(self):
        for text in ("password: ********", "password: xxxxxxxx", "secret: ........", "password: aaaaaaaaaa",
                     "pass§wort: ZZZZZZZZZZZZ"):
            with self.subTest(text=text):
                self.assertEqual(kinds(text), [])


class OwnRuleAllowlistTests(unittest.TestCase):
    """In the own secret rules, as in gitleaks, regexTarget "match" means the whole match; the default is the secret."""

    V = PW16

    def test_a_match_allowlist_sees_the_label(self):
        for label in ("keyboard = ", "public_key: ", "api_version = ", "csrf_token: ", "key_alias: ", "access_id: ",
                      "author = "):
            with self.subTest(label=label):
                self.assertEqual(kinds(label + self.V), [])

    def test_the_same_value_after_a_credential_label_is_still_a_hit(self):
        for label in ("api_token = ", "access_token: ", "auth_key = "):
            with self.subTest(label=label):
                self.assertEqual([v for _, v in kinds(label + self.V)], [self.V])

    def test_a_secret_allowlist_still_sees_only_the_secret(self):
        self.assertEqual(kinds("api§_key = abcdefghijKLMNOPq"), [])       # letters only: `^[a-zA-Z_.-]+$`


# ----------------------------------------------------------------- corpora --
def _provider_tokens() -> dict[str, str]:
    r = random.Random(3)
    begin, end = "-----BEGIN " + "RSA PRIVATE KEY-----", "-----END " + "RSA PRIVATE KEY-----"
    return {
        "github-pat": "ghp_" + rnd(36, AN, r),
        "github-fine-grained-pat": "github_pat_" + rnd(82, AN + "_", r),
        "gitlab-pat": "glpat-" + rnd(20, AN, r),
        "slack-bot-token": "xoxb-" + rnd(11, string.digits, r) + "-" + rnd(12, string.digits, r) + "-" + rnd(24, AN, r),
        "stripe-access-token": "sk_" + "live_" + rnd(24, AN, r),
        "anthropic-api-key": "sk-ant-" + "api03-" + rnd(93, AN + "_-", r) + "AA",
        "gcp-api-key": "AI" + "za" + rnd(35, AN + "_-", r),
        "npm-access-token": "npm_" + rnd(36, string.ascii_lowercase + string.digits, r),
        "sendgrid-api-token": "SG." + rnd(22, AN, r) + "." + rnd(43, AN, r),
        "digitalocean-pat": "dop_" + "v1_" + rnd(64, HEX, r),
        "shopify-access-token": "shpat_" + rnd(32, HEX, r),
        "pypi-upload-token": "pypi-" + base64.b64encode(b"\x02\x01\x08pypi.org")[:15].decode() + rnd(60, AN + "_-", r),
        "openai-api-key": "sk-" + "proj-" + rnd(58, AN + "_-", r) + "T3Blbk" + "FJ" + rnd(58, AN + "_-", r),
        "huggingface-access-token": "hf_" + rnd(34, string.ascii_letters, r),
        "gitlab-runner-token": "glrt-" + rnd(26, AN, r),
        "gitlab-deploy-token-any": "gldt-" + rnd(24, AN, r),
        "webhook-signing-secret": "whsec_" + rnd(32, AN, r),
        "cloudflare-user-api-token": "cfut_" + rnd(40, AN, r),
        "private-key": begin + "\n" + rnd(64, AN + "+/", r) + "\n" + rnd(64, AN + "+/", r) + "\n" + end,
        "aws-access-token": "AKIA" + rnd(16, string.ascii_uppercase + "234567", r),
    }


class TruePositiveCorpusTests(unittest.TestCase):
    def test_every_provider_shape_is_found_with_its_exact_value(self):
        for kind, token in _provider_tokens().items():
            for text in (f"here: {token} done", f"{token}\n", f'"{token}"'):
                with self.subTest(kind=kind, text=text[:20]):
                    self.assertEqual(kinds(text), [(kind, token)])

    def test_positional_credentials(self):
        v = PW12
        akid = "AKIA" + rnd(16, string.ascii_uppercase + "234567")
        aws_secret = rnd(40, AN + "/+")
        for text, expected in [
            (f"curl https://deploy:{v}@example.org/x", [("ds-basic-auth", v)]),
            (f"GET https://example.org/cb?api_key={v}&x=1", [("url-query-secret", v)]),
            (f"Authorization: Bearer {v}{v}", [("auth-scheme", v + v)]),
            (f"password = {v}", [("ds-keyword-equal-signs", v)]),
            (f'"api_key": "{v}"', [("ds-keyword-colon", v)]),
            (f"id {akid}\nsecret {aws_secret}\n",
             [("aws-access-token", akid), ("aws-secret-after-access-key", aws_secret)]),
        ]:
            with self.subTest(text=text[:30]):
                got = kinds(text)
                self.assertEqual(sorted(got), sorted(expected))

    def test_pii_shapes(self):
        card = luhn_complete("492918440817223")   # synthetic, not in rules/public_test_values.txt
        iban = iban_complete("DE", "370400440532013000")
        for text, expected in [("mail anna.berg@acme.de now", [("email", "anna.berg@acme.de")]),
                               ("call +49 170 1234567", [("phone", "+49 170 1234567")]),
                               (f"card {card}", [("credit-card", card)]), (f"IBAN {iban}", [("iban", iban)]),
                               ("from 93.184.216.34", [("ip#2", "93.184.216.34")])]:
            with self.subTest(text=text):
                self.assertEqual(kinds(text), expected)


class FalsePositiveCorpusTests(unittest.TestCase):
    CODE = [
        "def check_password(password: str) -> bool:\n    return len(password) >= 12\n",
        "if kind != \"SECRET\":\n    continue\n",
        "password = getpass.getpass()\n",
        "secret = load_secret(name)\n",
        "token = request.headers.get(\"Authorization\")\n",
        "password: ${DB_PASSWORD}\n",
        "password: {{ vault_db_password }}\n",
        "password = \"<your password here>\"\n",
        "PASSWORD_MIN_LENGTH = 12\n",
        "class PasswordResetForm(forms.Form):\n    pass\n",
        "    if not password:\n        raise ValueError(\"password required\")\n",
        "self.pass§word = pass§word\n",
        "def login(user, password=None):\n",
        "token = token.strip()\n",
        "secret_key = os.getenv(\"SECRET_KEY\")\n",
        "password: str = Field(default=None)\n",
        "\"password\": \"\",\n",
        "export PASSWORD=$PASSWORD\n",
        "password = args.password or prompt_password()\n",
        "api_key = request.args.get('api_key')\n",
        "api_key = kwargs['api_key']\n",
        "secret = secrets.token_hex(32)\n",
        "if api_key is None:\n    return\n",
        "assert to" "ken == other_token\n",   # split: as a source literal the \\n reads as part of the value
        "| password | the account password |\n",
        "password_hash = bcrypt.hashpw(password, salt)\n",
        "PASSWORD = env.str(\"PASSWORD\")\n",
        "api§_key = API§_KEY\n",
        "api§_key = abcdefghijKLMNOPq\n",
        "password=\"$DB_PASS\"\n",
    ]
    # dotted references and identifiers that end in `:`, `;` or `[` (found by this corpus, 2026-09-27)
    REFERENCES = [
        "if pass§word == confirm_pass§word:\n    save(user)\n",
        "while pass§word != expected_pass§word:\n    retry()\n",
        "pass§word = os.environ[\"DB_PASS§WORD\"]\n",
        "api§_key = settings.API§_KEY\n",
        "pass§word = self._pass§word\n",
        "const api§Key = process.env.API§_KEY;\n",
        "db_pass§word = config.database.pass§word\n",
        "pass§wort = eingabe.pass§wort\n",
    ]
    PROSE = [
        "The API key goes into the settings page; the password is never stored.",
        "Das Passwort wird nie gespeichert, der Schlüssel liegt im Tresor.",
        "Run `/maisecrets:report` | then send",
        "The /maisecrets:shortcut command installs /ms.",
        "localhost 127.0.0.1 and 10.0.0.1 and 192.168.1.10 and fe80::1",
        "Order 1234 5678 costs 12.50 EUR, room 101 at 3pm",
        "Version lodash@4.17.21 and actions/checkout@v4.1.1 and python@3.14",
        "Mail git@github.com or noreply@example.org",
    ]

    # lines of the Python standard library that the detector took for secrets, IP addresses of a person or phone
    # numbers (measured over 36.6 MB, 2026-09-29): a name on the right side, a message word, a format string, a
    # time zone, a mask, a documentation anchor, a number in code, documentation and multicast addresses
    STANDARD_LIBRARY = [
        "            proxy = ProxyType(to§ken, serializer, manager=manager, auth§key=auth§key,\n",
        "                    self.to§ken = nextchar\n",
        "        self.username, self.pass§word = credentials\n",
        "TOK§EN_ENDS = TSPECIALS | WSP\n",
        "            raise TypeError(\"pw§d: expected bytes, got %s\" % type(pw§d).__name__)\n",
        "        expected_msg = \"pw§d: expected bytes, got str\"\n",
        "log.error(\"to§ken: invalid signature for %s\", user)\n",
        "        token_range = \"%d,%d-%d,%d:\" % (to§ken.start + to§ken.end)\n",
        "        k§ey = \"Europe/Dublin\"\n",
        "        self.assertEqual('Pass§word: *******\\x08 \\x08', mock_output.getvalue())\n",
        "    'pw§d': 'pw§d#module-pw§d',\n",
        "            a = +4294967296  # 1 << 32\n",
        "        testcommon(\"%+34d\", big, \"  +123456789012345678901234567890\")\n",
        "        self.assertEqual(format(1234, \"+b\"), \"+10011010010\")\n",
        ">>> ExtendedContext.quantize(Decimal('+35236450.6'), Decimal('1e-2'))\n",
        "        testcommon(\"%0+34d\", big, \"+000123456789012345678901234567890\")\n",
        "    >>> ipaddress.ip_address('192.0.2.1')\n",
        "    >>> ipaddress.ip_address('2001:db8::1')\n",
        "    nameserver 8.8.8.8\n    nameserver 1.1.1.1\n",
        "    mcast = ('224.0.0.251', 5353)\n",
        "    BROADCAST = '255.255.255.255'\n",
        "    width = \"+0123 4567 89\"\n",                                       # no country code starts with 0
    ]

    def test_each_value_shape_of_normal_work_is_refused_on_its_own(self):
        # one shape per check of _ds_value_ok, so that no check hides behind another (mutation probes, 2026-09-29)
        for v in ("Option<String>", "testpass1", "Passw0rd!", "0.20.3", "mcp_{user}",
                  "{body['transfer_id']}", "_cleanup", "max.muster@firma-xyz.de", "list[str]", "1_234_567",
                  "session_key:*", "logs/*.txt", "no-check}", "settings", "tokenValue", "redacted;",
                  "Configuration["):
            with self.subTest(v=v):
                self.assertFalse(detect._ds_value_ok(v), v)
        for v in ("Kx7Qp2Zr9Lm4Wn", "4CX!DkQ1ya*UT-Ci$", "*-n65R!DzNSnrLY%T$", "Sommerwiese", "Sommer2026!"):
            with self.subTest(v=v):
                self.assertTrue(detect._ds_value_ok(v), v)

    def test_the_label_decides_only_right_before_the_value(self):
        tok = "Kx7Qp2" + "Zr9Lm4Wn"
        # a derived label earlier on the line does not hide the password after it
        self.assertEqual([m.value for m in scan(f"secret_name: prod, pass§word: {tok}")], [tok])
        self.assertEqual(kinds("secret_name: \"prod/db/password\""), [])
        # a default equal to its label, also at the end of a sentence
        self.assertEqual(kinds("the compose file sets POSTGRES_PASS§WORD: postgres."), [])
        # an address after a label is personal data, not a secret
        self.assertEqual([m.type for m in scan("GET user_tok§ens:max.muster@firma-xyz.de")], ["EMAIL"])
        # a prefix and one repeated character is a placeholder, a random tail is not
        self.assertEqual(kinds("tok§en: glpat-" + "A" * 20), [])
        self.assertEqual(kinds("glrt-" + "A" * 40), [])          # a prefix rule without an entropy floor
        self.assertEqual(kinds("cfut_" + "x" * 40), [])
        self.assertEqual([m.type for m in scan("glpat-" + "Q7w8E9r0T1y2U3i4O5p6")], ["SECRET"])

    def test_lines_of_the_standard_library_are_not_a_hit(self):
        self._check(self.STANDARD_LIBRARY)

    def test_the_code_rules_keep_every_value_a_person_types(self):
        # each rule of the standard-library group has a neighbour that must stay a hit, whichever rule finds it
        tok = "Q7w8E9r0T1y2U3i4"
        for text, expected in [
                (f"self.pass§word = \"{tok}\"", [("SECRET", tok)]),           # quoted: a value
                (f"spring.datasource.pass§word={tok}", [("SECRET", tok)]),    # not an object attribute
                (f"db.pass§word = {tok}", [("SECRET", tok)]),
                (f"pass§word: {tok} | then log in", [("SECRET", tok)]),            # a pipe in prose
                ("pass§word: Sommerwiese", [("SECRET", "Sommerwiese")]),           # a word, not a message word
                ("call +49 170 1234567", [("PHONE", "+49 170 1234567")]),
                ("my number is +4915112345678", [("PHONE", "+4915112345678")]),              # no separators, prose
                ("from 93.184.216.34", [("IP", "93.184.216.34")])]:
            with self.subTest(text=text):
                self.assertEqual([(m.type, m.value) for m in scan(text)], expected)
        # generic-api-key takes a random value after a label too and hid a broken keyword rule: the keyword rules alone
        keyword = {r.id for r in detect.rules() if r.id.startswith("ds-keyword")}
        for text in (f"self.pass§word = \"{tok}\"", f"spring.datasource.pass§word={tok}", f"db.pass§word = {tok}",
                     f"pass§word: {tok} | then log in"):
            with self.subTest(text=text, rules="keyword"):
                self.assertEqual([m.value for m in scan(text, enabled=keyword)], [tok])

    def _generated(self) -> list[str]:
        r = random.Random(6)
        out = []
        for i in range(20):
            out.append("commit " + hashlib.sha1(str(i).encode()).hexdigest() + " fixes the parser")
            out.append("git show " + hashlib.sha1(str(i).encode()).hexdigest()[:12])
            out.append("sha256: " + hashlib.sha256(str(i).encode()).hexdigest())
            out.append("request id " + str(uuid.UUID(int=r.getrandbits(128))))
            words = " ".join(r.choice(["the", "report", "is", "ready", "and", "plain", "text"]) for _ in range(12))
            out.append("data: " + base64.b64encode(words.encode()).decode())
            out.append(f"see https://docs.example.org/guide/{r.randint(1, 99)}?lang=de&page={r.randint(1, 9)}#setup")
        return out

    def _notices(self) -> list[str]:
        entries = [SimpleNamespace(type="SECRET", ref="⟦SECRET_c1⟧"),
                   SimpleNamespace(type="EMAIL", ref="⟦EMAIL_c1:ma•••@•••.de⟧"),
                   SimpleNamespace(type="PHONE", ref="⟦PHONE_c2:+49••••••67⟧")]
        vault = SimpleNamespace(backend=SimpleNamespace())
        out = []
        for copied in (True, False):
            for codex in (True, False):
                for cfg in ({}, {"report_url": "https://example.org/report", "renew_on_use": False,
                                 "ttl_seconds": {"default": 3600, "EMAIL": 600}}):
                    out.append("\n".join(hooks.block_notice(entries, "use ⟦SECRET_c1⟧ and ⟦EMAIL_c1:ma•••@•••.de⟧",
                                                            copied, codex, cfg, vault)))
        return out

    def _check(self, texts):
        for text in texts:
            with self.subTest(text=text[:60]):
                self.assertEqual(kinds(text), [])

    def test_code_with_credential_names_is_not_a_hit(self):
        self._check(self.CODE)

    def test_references_to_a_credential_are_not_a_hit(self):
        self._check(self.REFERENCES)

    def test_prose_and_non_personal_addresses_are_not_a_hit(self):
        self._check(self.PROSE)

    def test_hashes_uuids_base64_and_urls_are_not_a_hit(self):
        self._check(self._generated())

    def test_the_plugins_own_notices_are_not_a_hit(self):
        notices = self._notices()
        # the first line of every notice since 0.4.2; the check guards the notices themselves
        self.assertTrue(all("found and kept from the AI" in n for n in notices), notices[:1])
        self._check(notices)


if __name__ == "__main__":
    unittest.main()


class BetterleaksJsonTests(unittest.TestCase):
    """The detector reads betterleaks.json, because tomllib is Python 3.11+ and the stock python3 of
    macOS is 3.9. The JSON must hold exactly the rules of the vendored betterleaks.toml."""

    @unittest.skipIf(sys.version_info < (3, 11), "tomllib is Python 3.11+")
    def test_the_json_rules_equal_the_vendored_toml(self):
        import tomllib
        rules = Path(__file__).resolve().parent.parent / "maisecrets" / "detection" / "rules"
        self.assertEqual(json.loads((rules / "betterleaks.json").read_text(encoding="utf-8")),
                         tomllib.loads((rules / "betterleaks.toml").read_text(encoding="utf-8")),
                         "run scripts/sync_betterleaks.py: it writes both")
