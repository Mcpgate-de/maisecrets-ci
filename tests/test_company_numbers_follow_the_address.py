"""The postcode and the German VAT ID follow the company decision of the address rules.

Field report, 2026-10-16: a cloud provider's invoice to a GmbH, read from a PDF (tool channel). The address rule left
the recipient's address as text, because a legal form stood before it, but de-plz masked the postcode and de-vat-id
masked the VAT ID. The street stayed in the clear, so the half mask protected nothing. Now a postcode inside such an
address and a VAT ID next to it stay text too. Without a legal form (a sole trader: the VAT ID names a person) both
stay masked, and a person's record that names an employer keeps its postcode masked (test_company_address_window.py).

Every value here is invented. The VAT ID is computed with its check digit (ISO 7064, MOD 11,10), as a real one has it.

Run: python3 -m unittest tests.test_company_numbers_follow_the_address -v
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, regions  # noqa: E402


def vat_id(body: str) -> str:
    """DE, the eight digits of `body` and their check digit (ISO 7064, MOD 11,10, as the BZSt computes it)."""
    p = 10
    for ch in body:
        s = (int(ch) + p) % 10 or 10
        p = 2 * s % 11
    return "DE" + body + str((11 - p) % 10)


VAT = vat_id("27391846")
STREET = "Lindenstraße 42"
PLZ = "10827"
CONTACT = "Erika " + "Musterfrau"

# the shape of the invoice of the field report: the recipient's block under a heading, one line per part
INVOICE = ("Rechnung\nRechnungsnummer: 5123456789\nRechnungsdatum: 30.09.2026\n\n"
           "Rechnungsadresse\nBeispiel GmbH\n" + STREET + ", " + PLZ + " Berlin\nDeutschland\n"
           "USt-IdNr.: " + VAT + "\n\nAnsprechpartner: " + CONTACT + "\nBetrag: 123,45 EUR\n")


def redact(text: str, channel: str = "tool") -> str:
    active = regions.Active(regions=("generic", "de"), languages=("de", "en"), source="test")
    with detect.Detector(regions=active).activate():
        found = detect.scan(text, channel=channel)
    for m in sorted(found, key=lambda m: -m.start):
        text = text[:m.start] + "•" + text[m.end:]
    return text


class CompanyNumberTests(unittest.TestCase):
    def test_the_vat_id_of_the_test_has_a_valid_check_digit(self):
        self.assertTrue(detect.VALIDATORS["de_vat_id"](VAT))
        # ISO 7064 MOD 11,10 check over all nine digits: the last step ends at 1
        p = 10
        for ch in VAT[2:]:
            last = (int(ch) + p) % 10 or 10
            p = 2 * last % 11
        self.assertEqual(last, 1)

    def test_an_invoice_to_a_company_keeps_its_postcode_and_vat_id_with_its_street(self):
        out = redact(INVOICE)
        self.assertIn(STREET, out)
        self.assertIn(PLZ, out)
        self.assertIn(VAT, out)
        self.assertNotIn(CONTACT, out)   # the contact person stays masked

    def test_a_company_on_one_line_keeps_its_postcode_and_vat_id(self):
        out = redact("Rechnungsadresse: Beispiel GmbH, " + STREET + ", " + PLZ + " Berlin, USt-IdNr. " + VAT + "\n")
        self.assertIn(PLZ, out)
        self.assertIn(VAT, out)

    def test_a_company_record_after_an_address_label_keeps_its_postcode_and_vat_id(self):
        # no street word: the address label rule decides here, not the street rule
        out = redact('{"firma":"Beispiel GmbH","adresse":"Am Lindenhof 3, ' + PLZ + ' Berlin","ust-idnr":"' + VAT
                     + '"}')
        self.assertIn(PLZ, out)
        self.assertIn(VAT, out)

    def test_a_sole_traders_invoice_keeps_its_postcode_and_vat_id_masked(self):
        out = redact(INVOICE.replace("Beispiel GmbH", CONTACT))
        self.assertNotIn(PLZ, out)
        self.assertNotIn(VAT, out)
        self.assertNotIn(STREET, out)

    def test_a_sole_traders_postcode_alone_stays_masked(self):
        out = redact("Rechnungsadresse\n" + CONTACT + "\nAm Lindenhof 3\n" + PLZ + " Berlin\nUSt-IdNr.: " + VAT + "\n")
        self.assertNotIn(PLZ, out)
        self.assertNotIn(VAT, out)

    def test_a_hotel_or_an_office_names_no_holder(self):
        out = redact("Rechnungsadresse\nHotel am Park\n" + STREET + ", " + PLZ + " Berlin\nUSt-IdNr.: " + VAT + "\n")
        self.assertIn(STREET, out)        # the address rule leaves a hotel's address as text, as before
        self.assertNotIn(PLZ, out)
        self.assertNotIn(VAT, out)

    def test_a_vat_id_after_a_blank_line_is_not_the_companys(self):
        out = redact("Rechnungsadresse\nBeispiel GmbH\n" + STREET + ", " + PLZ + " Berlin\n\nUSt-IdNr.: " + VAT + "\n")
        self.assertIn(PLZ, out)
        self.assertNotIn(VAT, out)

    def test_a_second_vat_id_after_the_address_is_not_the_companys(self):
        own = vat_id("58104273")
        out = redact("Rechnungsadresse\nBeispiel GmbH\n" + STREET + ", " + PLZ + " Berlin\nIhre USt-IdNr.: " + VAT
                     + "\nUnsere USt-IdNr.: " + own + "\n")
        self.assertIn(VAT, out)
        self.assertNotIn(own, out)

    def test_a_vat_id_far_after_the_address_is_not_the_companys(self):
        fill = "\n".join("Position %d: Rechenzeit, 1 Stunde" % i for i in range(8))
        out = redact("Rechnungsadresse\nBeispiel GmbH\n" + STREET + ", " + PLZ + " Berlin\n" + fill
                     + "\nUSt-IdNr.: " + VAT + "\n")
        self.assertNotIn(VAT, out)

    def test_a_persons_postcode_next_to_the_companys_address_stays_masked(self):
        other = "70173"
        out = redact(INVOICE + "\nLieferadresse\n" + CONTACT + "\nAm Lindenhof 3\n" + other + " Stuttgart\n")
        self.assertIn(PLZ, out)
        self.assertNotIn(other, out)

    def test_a_sole_traders_vat_id_before_the_customers_address_stays_masked(self):
        out = redact("Rechnung von Erika Beispiel, USt-IdNr. " + VAT + "\nan: Beispiel GmbH\n" + STREET + ", " + PLZ
                     + " Berlin\n")
        self.assertIn(PLZ, out)
        self.assertNotIn(VAT, out)

    def test_a_persons_record_with_an_employer_keeps_its_postcode_masked(self):
        # the address itself stays text, as test_company_address_window.py documents; the name in the window keeps
        # the postcode masked, so the change does not make that record worse
        person = ('{"name":"' + CONTACT + '","arbeitgeber":"Beispiel GmbH","adresse":"' + STREET + ", " + PLZ
                  + ' Berlin","ust-idnr":"' + VAT + '"}')
        out = redact(person)
        self.assertNotIn(PLZ, out)
        self.assertNotIn(VAT, out)

    # the shapes of the two review gates of this change: a person's postcode or VAT ID near a legal form
    def test_a_persons_address_after_the_companys_address_keeps_its_vat_id_masked(self):
        other = "Max Muster, Gartenweg 3, 80331 München"
        for text in ("Rechnungsadresse\nBeispiel GmbH, " + STREET + ", " + PLZ + " Berlin\n" + other + "\nUSt-IdNr.: "
                     + VAT,
                     "Rechnung an Beispiel GmbH, " + STREET + ", " + PLZ + " Berlin, von " + other + ", USt-IdNr. "
                     + VAT):
            with self.subTest(text=text[:30]):
                self.assertNotIn(VAT, redact(text))

    def test_a_vat_id_after_a_page_break_is_not_the_companys(self):
        for sep in ("\n\f\n", "\r\r\n", " "):
            with self.subTest(sep=repr(sep)):
                out = redact("Rechnungsadresse\nBeispiel GmbH\n" + STREET + ", " + PLZ + " Berlin" + sep
                             + "USt-IdNr. " + VAT)
                self.assertNotIn(VAT, out)

    def test_a_short_legal_form_in_lower_or_mixed_case_is_no_company(self):
        out = redact("Sa résidence privée: Gartenweg 3, " + PLZ + " München;\nUSt-IdNr. " + VAT)
        self.assertNotIn(VAT, out)

    def test_a_short_legal_form_after_a_word_still_needs_its_case(self):
        out = redact("Lieferung Sa, Gartenweg 3, " + PLZ + " München, USt-IdNr. " + VAT)
        self.assertNotIn(VAT, out)

    def test_a_court_and_a_place_before_the_address_are_no_company(self):
        out = redact("Verfahren AG Teststadt: Gartenweg 3, " + PLZ + " München, USt-IdNr. " + VAT)
        self.assertNotIn(VAT, out)

    def test_a_persons_name_before_the_company_keeps_the_mask(self):
        out = redact("Erika Beispiel <erika@beispiel.test>\nBeispiel GmbH\n" + STREET + ", " + PLZ
                     + " Berlin\nUSt-IdNr.: " + VAT)
        self.assertNotIn(VAT, out)

    def test_a_legal_form_before_a_place_is_a_court(self):
        out = redact("Aktenzeichen beim AG Teststadt: Mietsache;\nWohnung Gartenweg 3, " + PLZ + " München; USt-IdNr. "
                     + VAT)
        self.assertNotIn(VAT, out)

    def test_a_legal_form_after_no_word_is_no_companys_name(self):
        out = redact("Az. 12 C 345/26, AG\nGartenweg 3, " + PLZ + " München\nUSt-IdNr.: " + VAT)
        self.assertNotIn(VAT, out)

    def test_a_home_label_between_the_company_and_the_address_keeps_the_mask(self):
        out = redact('{"firma":"Beispiel GmbH","home_address":"Gartenweg 3, ' + PLZ + ' München","ust-idnr":"' + VAT
                     + '"}')
        self.assertNotIn(VAT, out)

    def test_an_employer_label_makes_the_address_the_employees(self):
        out = redact('{"id":7,"employer":"Beispiel GmbH","adresse":"Gartenweg 3, ' + PLZ + ' München","ust-idnr":"'
                     + VAT + '"}')
        self.assertNotIn(PLZ, out)
        self.assertNotIn(VAT, out)

    def test_a_persons_key_before_the_company_keeps_the_mask(self):
        out = redact('{"person":"max muster","firma":"Beispiel GmbH","adresse":"Gartenweg 3, ' + PLZ
                     + ' München","ust-idnr":"' + VAT + '"}')
        self.assertNotIn(PLZ, out)
        self.assertNotIn(VAT, out)

    def test_a_company_in_parentheses_after_a_person_keeps_the_mask(self):
        out = redact("Adresse: Max Muster (Beispiel GmbH), Gartenweg 3, " + PLZ + " München, USt-IdNr. " + VAT)
        self.assertNotIn(VAT, out)

    def test_the_next_record_after_a_company_keeps_its_postcode_masked(self):
        out = redact('[{"firma":"Beispiel GmbH","adresse":"' + STREET + ', 10115 Berlin"},{"kunde":"Max Muster",'
                     '"adresse":"Gartenweg 3, ' + PLZ + ' München"}]')
        self.assertNotIn(PLZ, out)

    def test_an_address_rule_that_is_off_decides_nothing(self):
        for key, value in (("presidio:de-vat-id#0", VAT), ("presidio:de-plz", PLZ)):
            with self.subTest(key=key):
                active = regions.Active(regions=("generic", "de"), languages=("de", "en"), source="test")
                with detect.Detector(regions=active).activate():
                    found = detect.scan(INVOICE, channel="tool", enabled={key})
                self.assertIn(value, [INVOICE[m.start:m.end] for m in found])

    def test_a_name_or_the_senders_label_before_the_vat_id_keeps_it_masked(self):
        for label in ("Max Muster USt-IdNr.: ", "Unsere USt-IdNr.: ", "meine USt-IdNr. "):
            with self.subTest(label=label):
                out = redact("Rechnungsadresse\nBeispiel GmbH\n" + STREET + ", " + PLZ + " Berlin\n" + label + VAT)
                self.assertNotIn(VAT, out)

    def test_the_recipients_vat_label_frees_the_vat_id(self):
        for label in ("Ihre USt-IdNr.: ", "VAT ID: ", "Kunden-USt-IdNr. ", "Germany, VAT No. "):
            with self.subTest(label=label):
                out = redact("Rechnungsadresse\nBeispiel GmbH\n" + STREET + ", " + PLZ + " Berlin\n" + label + VAT)
                self.assertIn(VAT, out)

    def test_a_name_before_a_colon_between_the_company_and_the_address_is_no_label(self):
        out = redact("Lieferadresse: Beispiel GmbH, Lieferung an Max Muster: Gartenweg 3, " + PLZ
                     + " München, USt-IdNr. " + VAT)
        self.assertNotIn(VAT, out)

    def test_a_short_legal_form_after_a_preposition_is_a_floor(self):
        out = redact("Max Muster wohnt im UG, Gartenweg 3, " + PLZ + " München, USt-IdNr. " + VAT)
        self.assertNotIn(VAT, out)

    def test_a_member_of_a_club_keeps_the_mask(self):
        out = redact("Mitglied seit 2019 im Turnverein Beispiel e.V., Adresse: Gartenweg 3, " + PLZ
                     + " München, USt-IdNr. " + VAT)
        self.assertNotIn(VAT, out)

    def test_a_user_or_staff_record_keeps_the_mask(self):
        for key in ("user", "mitarbeiter"):
            with self.subTest(key=key):
                out = redact('{"' + key + '":"mmuster","firma":"Beispiel GmbH","adresse":"Gartenweg 3, ' + PLZ
                             + ' München","ust-idnr":"' + VAT + '"}')
                self.assertNotIn(VAT, out)

    def test_an_address_label_of_another_party_keeps_the_mask(self):
        for label in ("recipient_address", "Lieferadresse", "ship_to"):
            with self.subTest(label=label):
                out = redact('{"supplier":"Beispiel GmbH","' + label + '":"Gartenweg 3, ' + PLZ
                             + ' München","ust-idnr":"' + VAT + '"}')
                self.assertNotIn(VAT, out)

    def test_a_legal_form_in_a_job_field_keeps_the_mask(self):
        out = redact('{"job_title":"Beispiel Ltd","adresse":"Gartenweg 3, ' + PLZ + ' München","ust-idnr":"' + VAT
                     + '"}')
        self.assertNotIn(VAT, out)

    def test_an_address_rule_on_the_allow_list_decides_nothing(self):
        active = regions.Active(regions=("generic", "de"), languages=("de", "en"), source="test")
        with detect.Detector(regions=active).activate(), \
                    mock.patch.object(detect, "allow_list", return_value=(frozenset(), frozenset({"street-address"}))):
            found = detect.scan(INVOICE, channel="tool")
        self.assertIn(VAT, [INVOICE[m.start:m.end] for m in found])

    def test_a_typed_prompt_keeps_its_vat_id_hit(self):
        out = redact("Rechnungsadresse: Beispiel GmbH, " + STREET + ", " + PLZ + " Berlin, USt-IdNr. " + VAT,
                     channel="prompt")
        self.assertNotIn(VAT, out)


if __name__ == "__main__":
    unittest.main()
