"""Three gaps that a public benchmark found (Mcpgate-de/maisecrets#17, 2026-10-11): documented test values that were
false alarms, an email address with its @ percent-encoded, and SSNs that Presidio itself rejects.

Run: python3 -m unittest tests.test_public_benchmark_gaps -v
Every value is built at run time from parts, so no literal sits in the tree and the tree scan stays clean.
"""
from __future__ import annotations

import os
import random
import re
import string
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "maisecrets" / "detection" / "rules"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, pii_display, regions  # noqa: E402

J = "".join
RNG = random.Random(17)


def found(text: str, region: tuple[str, ...] = ()) -> list[tuple[str, str]]:
    active = regions.Active(regions=("generic", *region), languages=("en",), source="test")
    with detect.Detector(regions=active).activate():
        return [(m.type, m.value) for m in detect.scan(text)]


def luhn_complete(prefix: str, length: int) -> str:
    """A card number with a valid check digit that no vendor publishes for tests."""
    body = prefix + J(RNG.choice(string.digits) for _ in range(length - len(prefix) - 1))
    for d in string.digits:
        if detect._luhn_ok(body + d):
            return body + d
    raise AssertionError("no check digit")


JWT_IO = J(["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", ".",
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", ".",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"])


class PublicTestValueTests(unittest.TestCase):
    def test_the_rule_file_holds_digests_and_never_a_value(self):
        lines = [ln.split("#", 1)[0].strip()
                 for ln in (RULES / "public_test_values.txt").read_text().splitlines()]
        entries = [ln for ln in lines if ln]
        self.assertGreaterEqual(len(entries), 30)
        for e in entries:
            self.assertRegex(e, r"^[0-9a-f]{64}  (?:CARD|SECRET|PHONE)$")

    def test_a_documented_test_card_is_no_hit_and_a_card_beside_it_is(self):
        stripe_visa = " ".join(["4242"] * 4)
        mastercard = J(["5" * 12, "4" * 4])
        other = luhn_complete("4", 16)
        self.assertEqual(found(f"Stripe test cards (docs): Visa {stripe_visa} | MC {mastercard}"), [])
        self.assertEqual(found(f"card: {other}"), [("CARD", other)])

    def test_the_stripe_reference_key_is_no_hit_and_a_key_of_its_shape_is(self):
        reference = J(["sk", "_test_", "4eC39HqLyjWDarjtT1zdp7dc"])
        other = J(["sk", "_test_", *(RNG.choice(string.ascii_letters + string.digits) for _ in range(24))])
        self.assertEqual(found(f"The Stripe API reference shows {reference}"), [])
        self.assertEqual(found(f"STRIPE_KEY={other}"), [("SECRET", other)])

    def test_the_jwt_io_example_is_no_hit(self):
        self.assertEqual(found(f"Example JWT from jwt.io docs: {JWT_IO}"), [])

    def test_a_test_card_number_under_another_type_stays_a_hit(self):
        digits = "4242" * 4
        self.assertEqual(found(f"customer bank account {digits}", ("us",)), [("US_BANK_NUMBER", digits)])

    def test_a_test_value_does_not_hide_a_value_of_another_type_around_it(self):
        bban = "4242" * 4 + "00"
        iban = "DE" + f"{98 - int(bban + '131400') % 97:02d}" + bban   # DE = 13 14, mod 97
        grouped = " ".join(iban[i:i + 4] for i in range(0, len(iban), 4))   # DExx 4242 4242 4242 4242 00
        self.assertTrue(detect._iban_ok(grouped))
        self.assertEqual(found(f"card on file, IBAN {grouped}"), [("IBAN", grouped)])

    def test_a_malformed_line_in_the_rules_file_is_skipped(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "public_test_values.txt").write_text("# a comment\nonlyonefield\n" + "0" * 64 + "  CARD\n")
            with mock.patch.object(detect, "RULES_DIR", Path(tmp)), \
                    mock.patch.object(detect, "_PUBLIC_TEST_VALUES", []):
                self.assertFalse(detect.is_public_test_value("4242" * 4, "CARD"))

    def test_a_published_key_that_a_label_assigns_is_a_credential_use(self):
        # being public does not make the same bytes no secret where something uses them as one (review of 0.6.12)
        key = J(["sk", "_test_", "4eC39HqLyjWDarjtT1zdp7dc"])
        self.assertEqual(found(f"The Stripe API reference shows {key}"), [])
        self.assertEqual(found(f"PROD_PASSWORD={key}"), [("SECRET", key)])
        self.assertEqual(found(f"api_key: {key}"), [("SECRET", key)])
        # a token in a URL parameter is used as a credential too; the value stays exact, never `<token>&x=1`
        self.assertEqual(found(f"GET /callback?token={JWT_IO}&x=1"), [("SECRET", JWT_IO)])

    def test_a_twilio_test_number_is_no_phone_and_a_number_beside_it_is(self):
        magic = J(["+1", "500", "555", "0006"])
        other = J(["+1", "415", "555", "0177"])
        self.assertEqual(found(f"From: {magic}"), [])
        self.assertEqual(found(f"From: {other}"), [("PHONE", other)])


class PercentEncodedEmailTests(unittest.TestCase):
    def test_an_address_with_its_at_percent_encoded_is_an_email(self):
        address = J(["jane.doe", "%40", "firma-xyz", ".de"])
        self.assertEqual(found(f"GET /login?email={address}&next=/ HTTP/1.1"), [("EMAIL", address)])
        self.assertEqual(found(f"bounce: {address} -- retry"), [("EMAIL", address)])

    def test_after_an_encoded_mailto_the_address_starts_at_its_name(self):
        address = J(["jane", "%40", "firma-xyz", ".de"])
        self.assertEqual(found(J(["href=mailto%3A", address])), [("EMAIL", address)])

    def test_a_reserved_domain_stays_no_hit_encoded_too(self):
        self.assertEqual(found(J(["?email=jane", "%40", "firma-xyz", ".com"])),
                         [("EMAIL", J(["jane", "%40", "firma-xyz", ".com"]))])
        self.assertEqual(found(J(["?email=jane", "%40", "example", ".com"])), [])

    def test_an_encoded_at_outside_an_address_context_is_no_hit(self):
        for text in (J(["dependency name", "%40", "version.com"]), J(["git ref refs/tags/name", "%40", "version.dev"]),
                     J(["GET /asset/name", "%40", "version.js HTTP/1.1"]), J(["foo%20bar", "%40", "firma.de"]),
                     J(["path/to/pkg", "%40", "version.com"]), J(["import x from pkg", "%40", "version.dev"]),
                     J(["email sent; pkg x", "%40", "version.com"]), J(["email=\n", "jane", "%40", "firma-xyz.de"])):
            with self.subTest(text=text):
                self.assertEqual(found(text), [])

    def test_the_contexts_an_encoded_address_comes_in(self):
        address = J(["jane", "%40", "firma-xyz", ".de"])
        for text in (J(["href=MAILTO%3A", address]), J(['href="mailto:', address, '"']),
                     J(["GET /v1.0/users/", address, "/messages"]), J(["?return_to=%2Flogin%3Femail%3D", address]),
                     J(["To: ", address]), J(["bounce: ", address])):
            with self.subTest(text=text):
                self.assertEqual(found(text), [("EMAIL", address)])

    def test_the_display_masks_an_encoded_address_like_a_plain_one(self):
        shown = pii_display.display(J(["jane.doe", "%40", "firma-xyz", ".de"]), "email")
        self.assertIn(pii_display.BULLET, shown)
        self.assertNotIn("jane.doe", shown)
        self.assertNotIn("firma-xyz", shown)


class SsnValidatorTests(unittest.TestCase):
    def test_numbers_presidio_rejects_are_no_ssn(self):
        for v in ("000-00-0000", J(["078", "-05-", "1120"]), J(["123", "-45-", "6789"]), "666-12-3456",
                  "000-12-3456", "123-00-4567", "123-45-0000", "111-11-1111"):
            with self.subTest(shape=re.sub(r"\d", "9", v)):
                self.assertFalse(detect.VALIDATORS["us_ssn"](v))
                self.assertEqual(found(f"SSN {v}", ("us",)), [])

    def test_the_descending_sample_is_no_ssn(self):
        # only the validator: an area of 9 is the shape of an ITIN, and the us-itin rule claims it on its own
        self.assertFalse(detect.VALIDATORS["us_ssn"](J(["987", "-65-", "4320"])))

    def test_mixed_delimiters_are_no_ssn(self):
        self.assertFalse(detect.VALIDATORS["us_ssn"](J(["536", "-22 ", "8147"])))

    def test_a_number_beside_a_sample_stays_a_hit(self):
        self.assertTrue(detect.VALIDATORS["us_ssn"](J(["987", "-65-", "4322"])))

    def test_a_plausible_number_stays_a_hit(self):
        v = J(["536", "-22-", "8147"])
        self.assertTrue(detect.VALIDATORS["us_ssn"](v))
        self.assertEqual(found(f"SSN {v}", ("us",)), [("US_SSN", v)])


if __name__ == "__main__":
    unittest.main()
