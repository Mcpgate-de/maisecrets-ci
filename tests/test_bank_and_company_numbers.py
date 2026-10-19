"""Card numbers after a card word in another language, IBANs with hyphens or in lower case, and two German numbers that
are no personal data on their own: a bare VAT ID without a VAT word and a company register number.

Adapted from a public fork of maisecrets (Apache-2.0, see NOTICE).

Run: python3 -m unittest tests.test_bank_and_company_numbers -v
Every value is built at run time from parts, so no literal sits in the tree and the tree scan stays clean.
"""
from __future__ import annotations

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

from maisecrets import detect, regions  # noqa: E402

RNG = random.Random(618)


def found(text: str, channel: str = "prompt") -> list[tuple[str, str]]:
    """(type, value) of each hit with the German region on."""
    active = regions.Active(regions=("generic", "de"), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return [(m.type, m.value) for m in detect.scan(text, channel=channel)]


def both(text: str) -> list[tuple[str, str]]:
    """The hits of a text, which must be the same in both channels."""
    prompt, tool = found(text, "prompt"), found(text, "tool")
    assert prompt == tool, (prompt, tool)
    return prompt


def luhn_complete(body: str) -> str:
    """Append the Luhn check digit (independent of detect._luhn_ok)."""
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return body + str((10 - total % 10) % 10)


def iban_complete(cc: str, bban: str) -> str:
    """The ISO 13616 check digits (independent of detect._iban_ok)."""
    num = "".join(str(int(c, 36)) for c in bban + cc + "00")
    return f"{cc}{98 - int(num) % 97:02d}{bban}"


def vat_complete(eight: str) -> str:
    """A German VAT ID: DE, eight digits and the ISO 7064 MOD 11,10 check digit (independent of the validator)."""
    p = 10
    for ch in eight:
        s = (int(ch) + p) % 10
        p = ((s if s else 10) * 2) % 11
    return "DE" + eight + str((11 - p) % 10)


CARD = luhn_complete("4929" + "".join(RNG.choice(string.digits) for _ in range(11)))
GROUPED = " ".join(CARD[i:i + 4] for i in range(0, 16, 4))
BAD_CARD = CARD[:-1] + str((int(CARD[-1]) + 1) % 10)
IBAN = iban_complete("DE", "".join(RNG.choice(string.digits) for _ in range(18)))
IBAN_GROUPS = [IBAN[i:i + 4] for i in range(0, len(IBAN), 4)]
VAT = vat_complete("".join(RNG.choice(string.digits) for _ in range(8)))


class CardWordTests(unittest.TestCase):
    def test_a_card_word_in_another_language_counts(self):
        for text in (f"Karte {GROUPED} Bezug", f"Kreditkarte: {CARD}", f"Kartennummer {GROUPED}",
                     f"Debitkarte {GROUPED}", f"numéro de carte {GROUPED}", f"carte bancaire {CARD}",
                     f"carta di credito {GROUPED}", f"número de tarjeta {GROUPED}", f"creditcard {CARD}"):
            with self.subTest(text=text):
                self.assertEqual(both(text), [("CARD", CARD if CARD in text else GROUPED)])

    def test_luhn_still_decides(self):
        self.assertEqual(both(f"Karte {BAD_CARD} Bezug"), [])

    def test_without_a_card_word_the_number_stays_text_in_a_typed_prompt(self):
        # a tool result masks a card number written in groups without the word (0.6.24, test_rules_from_the_fork_0624)
        self.assertEqual(found(f"Referenz {GROUPED} vom Konto", "prompt"), [])
        self.assertEqual(found(f"Kartoffel {GROUPED}", "prompt"), [], "a whole word only: Kartoffel is no Karte")
        self.assertEqual(found(f"Kartoffel {GROUPED}", "tool"), [("CARD", GROUPED)])


class IbanFormTests(unittest.TestCase):
    def test_an_iban_with_hyphens_between_its_groups_is_found(self):
        hyphened = "-".join(IBAN_GROUPS)
        self.assertEqual(both(f"IBAN {hyphened}"), [("IBAN", hyphened)])
        self.assertEqual(both(f"Konto: {hyphened}."), [("IBAN", hyphened)])

    def test_a_hyphen_does_not_rescue_a_wrong_checksum(self):
        broken = IBAN[:2] + f"{(int(IBAN[2:4]) + 1) % 100:02d}" + IBAN[4:]
        groups = "-".join(broken[i:i + 4] for i in range(0, len(broken), 4))
        self.assertEqual(both(f"IBAN {groups}"), [])

    def test_an_iban_in_lower_case_is_found_plain_and_in_groups(self):
        for value in (IBAN.lower(), " ".join(IBAN_GROUPS).lower(), "-".join(IBAN_GROUPS).lower()):
            with self.subTest(value=value):
                self.assertEqual(both(f"iban {value} bitte"), [("IBAN", value)])

    def test_a_lower_case_iban_needs_its_countrys_length(self):
        # mod 97 passes, but DE has 22 characters: a lower-case run of another length is a digest or an id
        short = iban_complete("DE", "".join(RNG.choice(string.digits) for _ in range(16))).lower()
        self.assertTrue(detect._iban_ok(short.upper()))
        self.assertFalse(detect._iban_ok(short))
        self.assertEqual(both(f"id {short}"), [])

    def test_a_hex_digest_in_lower_case_stays_text(self):
        digest = "".join(RNG.choice("0123456789abcdef") for _ in range(64))
        self.assertEqual(both(f"sha256 de12{digest[:18]} and {digest}"), [])


class GermanCompanyNumberTests(unittest.TestCase):
    def test_a_bare_vat_id_without_a_vat_word_stays_text(self):
        for text in (f"PartyID {VAT}", f"<49={VAT}>", f"id: {VAT}"):
            with self.subTest(text=text):
                self.assertEqual(both(text), [])

    def test_a_vat_id_next_to_its_word_is_still_found(self):
        for text in (f"USt-IdNr. {VAT}", f"VAT {VAT}", f"Rechnung, USt-ID: {VAT}"):
            with self.subTest(text=text):
                self.assertEqual(both(text), [("DE_VAT_ID", VAT)])

    def test_a_company_register_number_is_no_personal_data(self):
        number = "HR" + "B" + " " + "".join(RNG.choice(string.digits) for _ in range(5))
        for text in (f"Amtsgericht Hamburg {number}", f"Handelsregister: {number}, GmbH"):
            with self.subTest(text=text):
                self.assertEqual(both(text), [])


class UsBankLabelWindowTests(unittest.TestCase):
    """A us-bank number (8 to 17 digits) is a hit when its label stands before it on its own line, within 60
    characters (core.PRESIDIO_LABEL_BEFORE). Benchmark V1: Gretel lost 1,920 false alarms, Nemotron 73 of 9,051
    account numbers."""
    NUMBER = "".join(["4071", "8653", "29"])               # 10 digits, no date and no card shape

    def us(self, text: str) -> set:
        active = regions.Active(regions=("generic", "us"), languages=("en",), source="test")
        with detect.Detector(regions=active).activate():
            return {m.kind for m in detect.scan(text, channel="tool")}

    def test_a_label_within_60_characters_before_the_number_is_a_hit(self):
        for text in ("account number: " + self.NUMBER,
                     "The account number associated with this agreement is " + self.NUMBER + "."):
            with self.subTest(text=text[:30]):
                self.assertIn("us-bank", self.us(text))

    def test_a_number_whose_line_names_no_account_is_no_hit(self):
        for text in ("order " + self.NUMBER + " shipped, see the bank holiday notice",
                     "The account was opened in March.\nreference " + self.NUMBER,
                     "account " + "x" * 70 + " " + self.NUMBER):
            with self.subTest(text=text[:30]):
                self.assertNotIn("us-bank", self.us(text))


class AccountNumberWholeTests(unittest.TestCase):
    """An account number is masked whole: written with a hyphen after its label (us-bank took only the digits after
    the hyphen and won the overlap), and in a table column named account number (Benchmark V1, Nemotron: account
    numbers found whole 8,978 to 11,266)."""
    HYPHEN = "".join(["482", "-", "3917", "265", "104"])
    PLAIN = "".join(["7305", "1928", "4461"])
    AWS = "".join(["1234", "5678", "9012"])

    def hits(self, text: str) -> list:
        active = regions.Active(regions=("generic", "de", "us"), languages=("en", "de"), source="test")
        with detect.Detector(regions=active).activate():
            return [(m.kind, m.value) for m in detect.scan(text, channel="tool")]

    def test_a_hyphenated_account_number_after_its_label_is_masked_whole(self):
        for text in ("Account Number: " + self.HYPHEN, "Your account number is " + self.HYPHEN + ".",
                     "account_number=" + self.HYPHEN, '{"accountNumber": "' + self.HYPHEN + '"}'):
            with self.subTest(text=text[:16]):
                self.assertIn(self.HYPHEN, [v for _, v in self.hits(text)])

    def test_us_bank_takes_no_part_of_a_hyphenated_number(self):
        self.assertNotIn("us-bank", [k for k, _ in self.hits("account ref " + self.HYPHEN)])

    def test_code_that_names_an_account_number_stays_text(self):
        self.assertEqual(self.hits("account_number = get_account(row)"), [])

    def test_a_number_in_a_column_named_account_number_is_masked(self):
        for head in ("Account Number", "**Account Number**", "Mortgage Account Number", "Acct No"):
            text = f"| Name | {head} | Balance |\n|---|---|---|\n| Cap | {self.PLAIN} | $10.00 |"
            with self.subTest(head=head):
                self.assertIn((("md-table-personal-column"), self.PLAIN), self.hits(text))

    def test_other_columns_and_cells_that_are_no_account_number_stay_text(self):
        for head, cell in (("Account ID", self.AWS), ("Account", self.AWS), ("Policy Number", self.PLAIN),
                           ("Account Number", "0" * 12), ("Account Number", "2024-01-02"),
                           ("Account Number", "".join(["407", "1865"])), ("Account Number", "see contract")):
            text = f"| {head} | Region |\n|---|---|\n| {cell} | eu-west-1 |"
            with self.subTest(head=head, cell=cell[:4]):
                self.assertNotIn("md-table-personal-column", [k for k, _ in self.hits(text)])


if __name__ == "__main__":
    unittest.main()
