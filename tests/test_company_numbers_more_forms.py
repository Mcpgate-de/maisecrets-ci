"""Three forms of a company's address where 0.6.26 masked the postcode or the VAT ID and left the street as text.

0.6.26 frees the postcode and the German VAT ID of an address that an address rule left as text for a company (a
legal form ends the company's name right before the address). Its review left three forms out, and each kept a half
mask: a department between the company's name and its address, a `Kunde:` or `Customer:` label before the company,
and the street and the postcode on two lines. The decision follows the company only: without a legal form, or with a
person between the company and the address, the values stay masked.

Every value here is invented. The VAT ID is computed with its check digit (ISO 7064, MOD 11,10).

Run: python3 -m unittest tests.test_company_numbers_more_forms -v
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

from maisecrets import detect, regions  # noqa: E402


def vat_id(body: str) -> str:
    p = 10
    for ch in body:
        s = (int(ch) + p) % 10 or 10
        p = 2 * s % 11
    return "DE" + body + str((11 - p) % 10)


VAT = vat_id("27391846")
CO = "Lindner Logistik GmbH"
STREET = "Hafenstra" + "ße 17"
PLZ = "2819" + "5"
PLACE = PLZ + " Bremen"
PERSON = "Lena " + "Brückner"


def redact(text: str, channel: str = "tool") -> str:
    active = regions.Active(regions=("generic", "de"), languages=("de", "en"), source="test")
    with detect.Detector(regions=active).activate():
        found = detect.scan(text, channel=channel)
    for m in sorted(found, key=lambda m: -m.start):
        text = text[:m.start] + "•" + text[m.end:]
    return text


class CompanyFormTests(unittest.TestCase):
    def assertFree(self, text: str) -> None:
        out = redact(text)
        self.assertIn(STREET, out)
        self.assertIn(PLZ, out)
        self.assertIn(VAT, out)

    def assertMasked(self, text: str, plz: bool = True) -> None:
        # the heading lets de-plz mask the postcode of a two-line address, as it does in an invoice; the values
        # masked without this change must stay masked
        out = redact("Rechnungsadresse\n" + text)
        if plz:   # plz=False: de-plz leaves this postcode as text with and without this change
            self.assertNotIn(PLZ, out)
        self.assertNotIn(VAT, out)

    def test_street_and_postcode_on_two_lines(self):
        self.assertFree("Rechnungsadresse\n" + CO + "\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT + "\n")
        self.assertFree(CO + "\r\n" + STREET + "\r\n" + PLACE + "\r\nUSt-IdNr. " + VAT + "\r\n")

    def test_a_department_between_the_company_and_its_address(self):
        self.assertFree(CO + "\nAbteilung Einkauf\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT + "\n")
        self.assertFree(CO + "\nDept. Accounts Payable\n" + STREET + "\n" + PLACE + "\nVAT ID: " + VAT + "\n")
        self.assertFree(CO + "\nAbteilung Finanzen und Controlling\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT)
        self.assertFree(CO + ", Abteilung Einkauf, " + STREET + ", " + PLACE + ", USt-IdNr. " + VAT + "\n")

    def test_a_customer_label_before_the_company(self):
        self.assertFree("Kunde: " + CO + "\n" + STREET + ", " + PLACE + "\nUSt-IdNr.: " + VAT + "\n")
        self.assertFree("Customer: " + CO + ", " + STREET + ", " + PLACE + ", VAT ID " + VAT + "\n")
        self.assertFree("Kunde: " + CO + "\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT + "\n")

    def test_without_a_legal_form_the_values_stay_masked(self):
        self.assertMasked("Rechnungsadresse\n" + PERSON + "\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT + "\n")
        self.assertMasked("Lindner Logistik\nAbteilung Einkauf\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT)
        self.assertMasked("Kunde: " + PERSON + "\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT + "\n")

    def test_a_person_between_the_company_and_the_address_keeps_the_mask(self):
        self.assertMasked(CO + "\n" + PERSON + "\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT + "\n")
        self.assertMasked(CO + "\nAbteilung Einkauf, z. Hd. " + PERSON + "\n" + STREET + "\n" + PLACE
                          + "\nUSt-IdNr.: " + VAT + "\n", plz=False)
        self.assertMasked(CO + ", Abteilung Einkauf, " + PERSON + ", " + STREET + ", " + PLACE + ", USt-IdNr. " + VAT,
                          plz=False)

    def test_a_persons_name_before_the_company_keeps_the_mask(self):
        self.assertMasked(PERSON + " <lena@example.com>\n" + CO + "\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT,
                          plz=False)
        self.assertMasked(CO + "\nAbteilung Einkauf " + PERSON + "\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT,
                          plz=False)
        # a department is a word of a closed list: a person's name in the slot is no department (Gate A)
        for dept in ("Abteilung Mara Winter", "Abteilung Winter", "Dept. Mara Winter", "Abteilung Einkauf Winter"):
            with self.subTest(dept=dept):
                self.assertMasked(CO + "\n" + dept + "\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT)
                self.assertMasked(CO + ", " + dept + ", " + STREET + ", " + PLACE + ", USt-IdNr. " + VAT, plz=False)

    def test_a_person_on_or_above_the_company_line_keeps_the_mask(self):
        # Gate B: a name without a label gets no NAME hit, so the line itself decides in the two-line form
        two = "\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT
        self.assertMasked(PERSON + ", " + CO + two)
        self.assertMasked(PERSON + " - " + CO + two)
        self.assertMasked("Frau " + PERSON + "\n" + CO + two)
        self.assertMasked(PERSON + "\n" + CO + two)
        self.assertFree("Rechnungsempfänger:\n" + CO + two)
        self.assertFree("Bill to\n" + CO + two)

    def test_a_salutation_or_a_longer_key_before_the_company_keeps_the_mask(self):
        for key in ("Kunde: Frau ", "Customer: Mr ", "customer_name: "):
            with self.subTest(key=key):
                self.assertMasked(key + PERSON + " Lindner GmbH\n" + STREET + ", " + PLACE + "\nUSt-IdNr.: " + VAT,
                                  plz=False)

    def test_a_person_glued_to_the_company_name_keeps_the_mask(self):
        # round 2 of both gates: without a separator a person and a company read as one name. The new forms take a
        # company's name of at most two words, so a longer name keeps the mask, as on origin/next
        rest = "\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT
        self.assertMasked(PERSON + " Lindner GmbH" + rest)
        self.assertMasked(PERSON + " Lindner Logistik GmbH" + rest)
        self.assertMasked("Kunde: " + PERSON + " Lindner GmbH" + rest)
        self.assertMasked("Kunde: " + PERSON + " Lindner GmbH, " + STREET + ", " + PLACE + "\nUSt-IdNr.: " + VAT,
                          plz=False)
        self.assertMasked("Customer: " + PERSON + " Lindner GmbH, " + STREET + ", " + PLACE + ", VAT ID " + VAT,
                          plz=False)
        self.assertFree("Kunde: Lindner & Partner GmbH" + rest)

    def test_each_guard_alone_keeps_the_mask(self):
        # one layer each: the name rule does not read a name in lower case, and Inhaber: is no key of a person's
        # record, so the key check and the name check cannot cover for each other
        self.assertMasked("customer_name: lena Lindner GmbH\n" + STREET + ", " + PLACE + "\nUSt-IdNr.: " + VAT)
        self.assertMasked("Inhaber: " + PERSON + " Lindner GmbH\n" + STREET + ", " + PLACE + "\nUSt-IdNr.: " + VAT)

    def test_a_customer_who_is_a_person_keeps_the_mask(self):
        self.assertMasked("Kunde: " + PERSON + "\n" + CO + "\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT)
        self.assertMasked("Customer: " + PERSON + ", " + CO + ", " + STREET + ", " + PLACE + ", VAT ID " + VAT,
                          plz=False)
        self.assertMasked("Name: " + PERSON + "\nKunde: " + CO + "\n" + STREET + ", " + PLACE
                          + "\nUSt-IdNr.: " + VAT, plz=False)

    def test_an_employer_or_a_blank_line_keeps_the_mask(self):
        self.assertMasked("Arbeitgeber: " + CO + "\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT + "\n")
        self.assertMasked(CO + "\n\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT + "\n")
        self.assertMasked(CO + "\nIrgendwas anderes hier\n" + STREET + "\n" + PLACE + "\nUSt-IdNr.: " + VAT + "\n")

    def test_a_persons_two_line_address_after_the_company_keeps_its_postcode(self):
        other = "70173"
        out = redact(CO + "\n" + STREET + "\n" + PLACE + "\n\nLieferadresse\n" + PERSON + "\nGartenweg 3\n" + other
                     + " Stuttgart\n")
        self.assertIn(PLZ, out)
        self.assertNotIn(other, out)


if __name__ == "__main__":
    unittest.main()
