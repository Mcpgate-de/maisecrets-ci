"""Personal data after a label in six more forms (the gap analysis of the dev split, Nemotron-PII, Gretel, Mendeley).

Each class is one change: a two-column Markdown row read as label and value (T1), a birth date after a comma or a bold
label (B1), a user id label with an account name (U2), the US national phone form after a call cue (P1), the user name
in an apposition (U1), a street line after "located at", "situated at", "property at" (A2), a home address label over a
company word (A1), the street forms of more EU languages (A3) and compound and EU id labels (N3). Each positive is an
invented value; each negative is the developer text or business text of the same shape.

Run: python3 -m unittest tests.test_pii_gaps_labels_tables_phones -v
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

ALL = ("us", "uk", "in", "de", "fr", "es", "it", "pt", "ca", "au", "nl", "se")

# invented values, split so that no literal in this file has a value's whole shape
BIRTH = "1984-03-" + "12"
PHONE = "(312) " + "846-2291"
PHONE_555 = "(312) " + "555-0147"
USER = "synthetic.person" + "42"
STREET = "4821 " + "Synthetic Ridge Drive"


def scan(text: str, channel: str = "tool") -> list:
    active = regions.Active(regions=("generic", *ALL), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return detect.scan(text, channel=channel)


def masked(text: str, channel: str = "tool") -> str:
    for m in sorted(scan(text, channel), key=lambda m: -m.start):
        text = text[:m.start] + "•" + text[m.end:]
    return text


class Base(unittest.TestCase):
    def assertMasked(self, text: str, value: str, channel: str = "tool") -> None:
        self.assertIn(value, text)
        self.assertNotIn(value, masked(text, channel), text)

    def assertText(self, text: str, channel: str = "tool") -> None:
        self.assertEqual(text, masked(text, channel))


class MarkdownKeyValueRowTests(Base):
    """T1: | Date of Birth | value | in a table without a header row is the label and its value."""

    def test_a_headerless_key_value_table_is_masked(self):
        self.assertMasked("| Patient | record 7 |\n| Date of Birth | " + BIRTH + " |\n| Ward | 3 |\n", BIRTH)
        self.assertMasked("| **Date of Birth** | " + BIRTH + " |\n", BIRTH)

    def test_a_docs_table_stays_text(self):
        self.assertText("| Option | Meaning |\n|---|---|\n| --timeout | seconds to wait |\n"
                        "| Date of birth | a date |\n")
        self.assertText("| Field | Type |\n| Date of Birth | date |\n| Phone | string |\n")

    def test_a_lone_first_name_stays_text(self):
        self.assertText("| First name | Dana |\n| Plan | basic |\n")


class BirthAfterCommaOrBoldTests(Base):
    """B1: Date of birth, value and **DOB:** value."""

    def test_a_date_after_date_of_birth_and_a_comma_is_masked(self):
        self.assertMasked("Date of birth, " + BIRTH + ", place of birth unknown", BIRTH)

    def test_a_date_after_a_bold_dob_label_is_masked(self):
        self.assertMasked("**DOB:** " + BIRTH, BIRTH)


class UserIdLabelTests(Base):
    """U2: user_id: an account name; a number, a UUID, code or a service account stays text."""

    def test_an_account_name_after_a_user_id_label_is_masked(self):
        self.assertMasked("user_id: " + USER + "\n", USER)
        self.assertMasked('{"userId": "' + USER + '"}', USER)

    def test_a_number_a_uuid_code_and_a_service_account_stay_text(self):
        self.assertText("user_id: 48213\n")
        self.assertText("user_id: 3f2b8c1e-" + "9d4a-4b7e-8c21-5a6f0e9d1b37\n")
        self.assertText("user_id = request.user.id\n")
        self.assertText("user_id: svc_backup\n")


class PhoneAfterCallCueTests(Base):
    """P1: (ddd) ddd-dddd after a cue of a person (reached at, me at)."""

    def test_the_us_national_form_after_a_call_cue_is_masked(self):
        self.assertMasked("Dana can be reached at " + PHONE + " after five.", PHONE)

    def test_a_555_number_and_a_number_after_us_at_stay_text(self):
        self.assertText("Dana can be reached at " + PHONE_555 + " after five.")
        self.assertText("Write to us at " + PHONE + " for support.")

    def test_no_double_hit_with_phone_us_national(self):
        # a phone word and a call cue before the number: phone-us-national masks it, this rule adds nothing
        hits = scan("You can reach me by phone at " + PHONE + " after five.")
        self.assertEqual(["phone-us-national"], [m.kind for m in hits])


class UserNameApposedTests(Base):
    """U1: the user name, value, and the user name (value)."""

    def test_a_user_name_in_an_apposition_is_masked(self):
        self.assertMasked("Her user name, " + USER + ", was locked.", USER)
        self.assertMasked("the user name (" + USER + ") was locked", USER)

    def test_a_relative_clause_a_plain_word_and_code_stay_text(self):
        self.assertText("Enter the user name, which is case sensitive.")
        self.assertText("Enter the user name, password and code.")
        self.assertText("login(user_name, api_key2)\n")
        self.assertText("* user name (e.g. a nickname)\n")


class StreetAfterPlaceWordTests(Base):
    """A2: the property located at a street line; a company's office stays text."""

    def test_a_street_after_located_at_situated_at_and_property_at_is_masked(self):
        self.assertMasked("Whereas the borrower owns the property located at " + STREET + ", Anytown", STREET)
        self.assertMasked("the house situated at " + STREET + " passes to her son", STREET)
        self.assertMasked("the property at " + STREET + " is held in trust", STREET)

    def test_our_office_located_at_stays_text(self):
        self.assertText("Our office is located at " + STREET + ", Anytown.")
        self.assertText("a licensed insurance provider located at " + STREET + ", Anytown")


class HomeAddressOverCompanyWordTests(Base):
    """A1: a home or residential address label right before a US address wins over a company word on the line."""

    US_ADDRESS = STREET + "\nSpringfield, IL " + "62704"

    def test_a_labelled_home_address_after_a_company_word_is_masked(self):
        self.assertMasked("Acme Insurance Inc. registered your details, including your home address ("
                          + self.US_ADDRESS + "), contact number", self.US_ADDRESS)

    def test_the_company_check_holds_for_an_address_without_the_label(self):
        self.assertText("Acme Insurance Inc. registered your details, including your address ("
                        + self.US_ADDRESS + "), contact number")
        self.assertText("Home address on file. Acme Insurance Inc.\n" + self.US_ADDRESS)


class EuStreetFormTests(Base):
    """A3: Dutch, Swedish, Romance and French street forms after an address label or a verb of residence."""

    def test_an_eu_street_after_its_label_is_masked(self):
        for text, value in (
                ("Adres: Synthetischestraat 12\nPostcode: 1234 AB\nPlaats: Utrecht", "Synthetischestraat 12"),
                ("Adress: Syntetiskgatan 5\nPostnummer: 123 45\nOrt: Uppsala", "Syntetiskgatan 5"),
                ("Indirizzo: Via Sintetica, 12\nCittà: Torino", "Via Sintetica, 12"),
                ("Adresse : 12 rue Synthétique\n75002 Paris", "12 rue Synthétique"),
                ("Adres: Synthetischestraat 12", "Synthetischestraat 12"),
                ("She lives at Via Sintetica, 12, in Torino.", "Via Sintetica, 12")):
            self.assertMasked(text, value)

    def test_a_business_record_a_template_and_no_label_stay_text(self):
        self.assertText("Exempel AB\nAdress: Syntetiskgatan 5\nPostnummer: 123 45")
        self.assertText("Fornitore: Esempio S.p.A.\nIndirizzo: Via Sintetica, 12\nCittà: Torino")
        self.assertText("Indirizzo: Via Sintetica, 12, [città]")
        self.assertText("Synthetischestraat 12\n1234 AB Utrecht")


class IdContextWordTests(Base):
    """N3: compound and EU labels as context words of the US licence and passport rules; the value shape decides."""

    LICENCE = "D1234" + "567"

    def test_a_licence_after_a_compound_or_german_label_is_masked(self):
        self.assertMasked('{"driverLicense": "' + self.LICENCE + '"}', self.LICENCE)
        self.assertMasked("Führerschein: " + self.LICENCE, self.LICENCE)

    def test_a_label_alone_a_patent_number_and_a_phone_after_its_plus_stay_out(self):
        self.assertText('{"driverLicense": "required"}')
        self.assertText("Führerschein: ja")
        self.assertText("Patente: " + "12345678")
        phone = "+4917" + "01234567"
        hits = scan("Permiso de conducir en trámite.\nNúmero de teléfono: " + phone)
        self.assertEqual([("phone", phone)], [(m.kind, m.value) for m in hits])

    def test_a_passport_number_after_an_edifact_separator_is_masked(self):
        # the + after a letter separates segments: the number after it is no phone number's digits
        passport = "4" + "87512963"
        self.assertMasked("DOC+P+" + passport + ":110:111+passport'", passport)

    def test_a_phone_number_after_its_word_takes_a_licence_hit_in_its_digits(self):
        phone = "312 " + "8462291"
        hits = scan("Phone: " + phone + ", driver license on file")
        self.assertEqual([("PHONE", phone)], [(m.type, m.value) for m in hits])


if __name__ == "__main__":
    unittest.main()
