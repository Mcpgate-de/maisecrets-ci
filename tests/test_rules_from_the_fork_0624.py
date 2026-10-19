"""The rest of a contributor's fork list (danszymkowiak/maisecrets, Apache-2.0, docs/UPSTREAM-DETECTION.md), ported in
0.6.24 and measured again here: Presidio's own check digits for four recognizers and no UK postcode alone; an IBAN
after an MT940 subfield code; four checks on the password-label rules; one entropy floor per alphabet for
generic-api-key.

Run: python3 -m unittest tests.test_rules_from_the_fork_0624 -v
Every value is built at run time from parts.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import checksums, detect, regions  # noqa: E402

J = "".join


def found(text: str, region: tuple = (), channel: str = "tool") -> list:
    active = regions.Active(regions=("generic", *region), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return [(m.kind, text[m.start:m.end]) for m in detect.scan(text, channel=channel)]


def kinds(text: str, region: tuple = (), channel: str = "tool") -> set:
    return {k for k, _ in found(text, region, channel)}


def npi(body: str) -> str:
    for d in "0123456789":
        if checksums.us_npi_ok(body + d):
            return body + d
    raise AssertionError("no check digit")


def luhn10(body: str) -> str:
    for d in "0123456789":
        if checksums._luhn_sum(body + d) == 0:
            return body + d
    raise AssertionError("no check digit")


class PresidioChecksTests(unittest.TestCase):
    def test_a_uk_postcode_alone_is_no_hit(self):
        text = "Delivery postcode: " + J(["SW1A", " 2AA"])
        self.assertFalse({k for k in kinds(text, ("uk",)) if k.startswith("uk-postcode")})

    def test_an_npi_needs_its_check_digit_and_its_word(self):
        good = npi("192837465")
        bad = good[:-1] + str((int(good[-1]) + 1) % 10)
        self.assertIn(("us-npi", good), [(k.split("#")[0], v) for k, v in found("NPI: " + good, ("us",))])
        self.assertFalse({k for k in kinds("NPI: " + bad, ("us",)) if k.startswith("us-npi")})
        self.assertFalse({k for k in kinds("order " + good, ("us",)) if k.startswith("us-npi")})

    def test_a_swedish_organisation_number_needs_its_check_digit(self):
        good = luhn10("556036079")
        bad = good[:-1] + str((int(good[-1]) + 1) % 10)
        for v, want in ((good[:6] + "-" + good[6:], True), (bad[:6] + "-" + bad[6:], False)):
            with self.subTest(want=want):
                hit = any(k.startswith("se-organisationsnummer") for k in kinds("orgnr " + v, ("se",)))
                self.assertEqual(hit, want)

    def test_a_uk_number_plate_needs_a_real_age_identifier(self):
        for plate, want in ((J(["AB", "51", "XYZ"]), True), (J(["AB", "99", "XYZ"]), False)):
            with self.subTest(plate=plate):
                hit = any(k.startswith("uk-vehicle-registration")
                          for k in kinds("vehicle registration " + plate, ("uk",)))
                self.assertEqual(hit, want)


class Mt940Tests(unittest.TestCase):
    IBAN = J(["DE89", "3704", "0044", "0532", "0130", "00"])

    def statement(self, iban: str) -> str:
        return J([":61:2610151015CR1250,00NTRFNONREF\n:86:166?00GUTSCHRIFT?20SVWZ+Miete Oktober",
                  "?30COBADEFFXXX?31", iban, "?32Mieter Muster"])

    def test_the_counterparty_iban_of_a_bank_statement_export_is_found(self):
        for iban in (self.IBAN, self.IBAN.lower()):
            with self.subTest(case=iban[:2]):
                self.assertIn(iban, [v for _, v in found(self.statement(iban), ("de",))])

    def test_a_digit_run_before_a_country_code_is_still_no_iban(self):
        # only `?` and two digits open the subfield: a longer digit run before the IBAN letters keeps the boundary
        text = "ref 1234" + self.IBAN
        self.assertNotIn(self.IBAN, [v for _, v in found(text, ("de",))])



class PasswordLabelChecksTests(unittest.TestCase):
    NO_VALUE = [
        "password = " + J(["PROD", "-DB-", "PASS_7"]),                 # a constant's name with a dash and an underscore
        "password = " + J(["MY_", "SECRET_", "VALUE_1"]),              # an UPPER_SNAKE name with a counter
        "secret: " + J(["0", ":default"]),                             # a time or a ratio
        'secret: "' + J(["12", ":minutes"]) + '"',
        "the test passed: everything works fine",                     # passed, passes, passing: no label
        "In the second round the passes: several were skipped",
        "TOKEN_TTL = " + J(["36", "00"]) + ".",                        # seconds before the full stop of a sentence
        "| secret: " + J(["rota", "tion"]) + " of keys in the vault |",  # a table cell of prose
    ]
    VALUE = [
        "password = " + J(["Xk9", "_Qz7-", "Lm2"]),
        "password = " + J(["PRD", "_X7K9", "_QW2Z"]),                  # random capitals stay a value
        "secret: " + J(["4", ":f9Kq2", "Lm7"]),
        "db_pass: " + J(["hunter", "2", "!x"]),
        "password = " + J(["XK-", "QZ_", "7R9W2"]),                    # capitals without a vowel and a long suffix
        "secret: " + J(["rota", "tion"]),                             # one word after a label in plain text stays
    ]

    def test_a_name_a_time_a_word_after_passed_and_a_table_cell_are_no_value(self):
        for text in self.NO_VALUE:
            for channel in ("prompt", "tool"):
                with self.subTest(text=text, channel=channel):
                    self.assertEqual([k for k, _ in found(text, channel=channel) if k.startswith("ds-keyword")], [])

    def test_a_value_after_the_label_stays_a_hit(self):
        for text in self.VALUE:
            with self.subTest(text=text):
                self.assertTrue(found(text, channel="tool"))



class GenericKeyFloorTests(unittest.TestCase):
    def key(self) -> set:
        return {s.key for s, _ in detect.rule_specs() if s.id == "generic-api-key"}

    def generic(self, value: str) -> list:
        text = "const apiKey = '" + value + "';"
        return [m.kind for m in detect.scan(text, channel="tool", enabled=self.key())]

    def test_each_alphabet_has_its_own_floor(self):
        self.assertEqual(detect.alphabet_of("0a1b2c"), "hex")
        self.assertEqual(detect.alphabet_of("ABCDEF234567"), "hex")
        self.assertEqual(detect.alphabet_of("ABCXYZ234567"), "base32")
        self.assertEqual(detect.alphabet_of("Kq7Lp2"), "base62")
        self.assertEqual(detect.alphabet_of("Kq7+p2/="), "base64")
        self.assertEqual(detect.alphabet_of("Kq7-p2_"), "base64url")
        self.assertEqual(detect.alphabet_of("Kq7!p2"), "printable")

    def test_a_base62_key_under_the_old_floor_is_a_hit(self):
        v = J(["Kq7Lp2", "Kq7Rt4", "Wq9z"])
        self.assertTrue(3.322 <= detect.shannon_entropy(v) < 3.5)
        self.assertEqual(self.generic(v), ["generic-api-key"])

    def test_a_hex_value_keeps_the_floor_of_3_5(self):
        import hashlib
        v = hashlib.md5(b"14").hexdigest()
        self.assertTrue(3.4 < detect.shannon_entropy(v) < 3.5)
        self.assertEqual(self.generic(v), [])

    def test_base64_of_a_word_under_the_old_floor_is_no_key(self):
        import base64
        v = base64.b64encode(J(["staging", "-user"]).encode()).decode()
        self.assertTrue(detect.shannon_entropy(v) < 3.5)
        self.assertEqual(self.generic(v), [])

    def test_unpadded_base64_of_a_word_is_no_key(self):
        import base64
        v = base64.b64encode(J(["hello", "-world"]).encode()).decode().rstrip("=")
        self.assertEqual(self.generic(v), [])

    def test_a_kebab_case_name_keeps_the_floor_of_3_5(self):
        self.assertEqual(detect.ENTROPY_BY_ALPHABET["base64url"], 3.5)
        self.assertEqual(self.generic(J(["deploy-", "worker-", "eu2-prod"])), [])

    def test_the_login_challenge_of_a_mail_server_is_no_key(self):
        import base64
        challenge = base64.b64encode(J(["Pass", "word:"]).encode()).decode()
        text = "535 5.7.8 Error: authentication failed: " + challenge
        for channel in ("prompt", "tool"):
            with self.subTest(channel=channel):
                self.assertEqual(found(text, channel=channel), [])



class CardWithoutWordTests(unittest.TestCase):
    CARD = luhn10("453201511283036"[:15])

    def test_a_card_number_without_a_card_word_is_masked_in_a_tool_result(self):
        text = "row 17: " + self.CARD[:4] + " " + self.CARD[4:8] + " " + self.CARD[8:12] + " " + self.CARD[12:]
        self.assertIn("credit-card", kinds(text, channel="tool"))

    def test_a_card_number_after_a_card_word_stays_a_hit_in_any_form(self):
        for text in ("credit card " + self.CARD, "card: " + self.CARD + "."):
            for channel in ("tool", "prompt"):
                with self.subTest(channel=channel):
                    self.assertIn("credit-card", kinds(text, channel=channel))

    def test_a_typed_prompt_keeps_the_card_word(self):
        text = "row 17: " + self.CARD
        self.assertNotIn("credit-card", kinds(text, channel="prompt"))
        self.assertIn("credit-card", kinds("my credit card " + self.CARD, channel="prompt"))

    def test_a_number_after_a_plus_a_test_card_and_a_wrong_check_digit_stay_text(self):
        bad = self.CARD[:-1] + str((int(self.CARD[-1]) + 1) % 10)
        test_card = J(["4111", "1111", "1111", "1111"])
        for text in ("call +" + self.CARD, "row 17: " + bad, "row 17: " + test_card):
            with self.subTest(text=len(text)):
                self.assertNotIn("credit-card", kinds(text, channel="tool"))


class CardAsOneRunTests(unittest.TestCase):
    """A card number written as one run of digits is masked alone in a tool result when it has the prefix and the
    length of a card network (Benchmark V1: Gretel cards 299 to 431); a timestamp, an IMEI, an order id, a decimal
    and a longer run stay text."""
    VISA = luhn10(J(["4532", "0151", "1283", "036"]))
    MC = luhn10(J(["5425", "2334", "3010", "910"]))
    IMEI = luhn10(J(["3567", "0702", "3456", "78"]))      # 15 digits, the type code of a phone

    def test_an_ungrouped_card_number_is_masked_alone_in_a_tool_result(self):
        for text in ("row 17: " + self.VISA, "paid with " + self.MC + " today"):
            with self.subTest(text=text[:8]):
                self.assertIn("credit-card", kinds(text, channel="tool"))

    def test_a_run_that_is_no_card_stays_text(self):
        for text in ("device " + self.IMEI + " registered", "ts=" + J(["1760", "9123", "4567", "8901"]),
                     "order_id: " + self.VISA, "value 0." + self.VISA, "id " + self.VISA + "12"):
            with self.subTest(text=text[:6]):
                self.assertNotIn("credit-card", kinds(text, channel="tool"))

    def test_a_typed_prompt_still_needs_the_card_word(self):
        self.assertNotIn("credit-card", kinds("row 17: " + self.VISA, channel="prompt"))


class CardRangesPresidioMissedTests(unittest.TestCase):
    """Presidio's card pattern knew the first digits 1, 3, 4, 5 and 6: a Mastercard of the 2-series and a 15-digit JCB
    never reached the Luhn check (Benchmark V1, Mendeley, 681 card numbers, 2026-10-19)."""
    MC2 = luhn10(J(["2221", "0012", "3456", "789"]))        # 16 digits, the first BIN of the 2-series
    MC2_TOP = luhn10(J(["2720", "9912", "3456", "789"]))
    JCB15 = luhn10(J(["2131", "0012", "3456", "78"]))       # 15 digits
    PAST = luhn10(J(["2721", "0012", "3456", "789"]))       # above the 2-series: no card network

    def test_a_mastercard_of_the_2_series_after_its_word_is_a_hit(self):
        for card in (self.MC2, self.MC2_TOP):
            for channel in ("tool", "prompt"):
                with self.subTest(card=card[:4], channel=channel):
                    self.assertIn("credit-card", kinds("Mastercard " + card, channel=channel))

    def test_a_15_digit_jcb_after_its_word_is_a_hit(self):
        for channel in ("tool", "prompt"):
            with self.subTest(channel=channel):
                self.assertIn("credit-card", kinds("JCB card " + self.JCB15, channel=channel))

    def test_a_grouped_mastercard_of_the_2_series_is_masked_alone_in_a_tool_result(self):
        c = self.MC2
        self.assertIn("credit-card", kinds("row 17: " + " ".join((c[:4], c[4:8], c[8:12], c[12:])), channel="tool"))

    def test_a_grouped_15_digit_jcb_is_masked_alone_in_a_tool_result(self):
        c = self.JCB15                                       # written 4-6-5, as a 15-digit card is printed
        self.assertIn("credit-card", kinds("row 17: " + " ".join((c[:4], c[4:10], c[10:])), channel="tool"))

    def test_a_number_above_the_2_series_stays_text(self):
        self.assertNotIn("credit-card", kinds("Mastercard " + self.PAST, channel="tool"))


if __name__ == "__main__":
    unittest.main()
