"""Personal data after its label in more forms (the gap analysis of 2026-10-16 on Nemotron-PII and Gretel).

Each class here is one change: a label in Markdown bold, a phone number after a phone word, an ID number after a
health, tax or national label, one name word after a first or last name label, a street line after an address label,
the person columns of a Markdown table, and the passport and driving licence labels of the EU languages. Each
positive is an invented value in the shape of the datasets; each negative is developer text in the same shape.

Run: python3 -m unittest tests.test_personal_after_its_label -v
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

from maisecrets import detect, normalise, regions  # noqa: E402

ALL = ("us", "uk", "in", "de", "fr", "es", "it", "pt", "ca", "au", "nl", "se")


def scan(text: str, channel: str = "tool", region: tuple = ALL) -> list:
    active = regions.Active(regions=("generic", *region), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return detect.scan(text, channel=channel)


def masked(text: str, channel: str = "tool", region: tuple = ALL) -> str:
    for m in sorted(scan(text, channel, region), key=lambda m: -m.start):
        text = text[:m.start] + "•" + text[m.end:]
    return text


class Base(unittest.TestCase):
    def assertMasked(self, text: str, value: str, channel: str = "tool", region: tuple = ALL) -> None:
        self.assertIn(value, text)
        self.assertNotIn(value, masked(text, channel, region), text)

    def assertText(self, text: str, channel: str = "tool", region: tuple = ALL) -> None:
        self.assertEqual(text, masked(text, channel, region))


# ------------------------------------------------------------------------------------------------- Markdown bold --
BIRTH = "1984-03-" + "12"
NAME = "Dana " + "Okafor"
PASSWORD = "Qz8k" + "Lm2pR7xw"


class BoldLabelTests(Base):
    def test_a_value_after_a_bold_label_is_masked_like_after_the_plain_label(self):
        for text, value in (
                ("**Date of birth:** " + BIRTH, BIRTH),
                ("**Date of birth**: " + BIRTH, BIRTH),
                ("- **Full name:** " + NAME + "\n- **Role:** reviewer", NAME),
                ("__Date of birth:__ " + BIRTH, BIRTH),
                ("**Password:** " + PASSWORD, PASSWORD),
                ("| **Password:** " + PASSWORD + " |", PASSWORD)):
            with self.subTest(text=text):
                self.assertMasked(text, value)

    def test_the_offsets_of_the_value_stay_those_of_the_original(self):
        text = "**Date of birth:** " + BIRTH + " and more"
        hits = [m for m in scan(text) if m.type == "BIRTH_DATE"]
        self.assertEqual([(text[m.start:m.end]) for m in hits], [BIRTH])
        # a hit never takes the stars of the next bold label with it
        text = "**Full name:** " + NAME + " **Role:** reviewer"
        self.assertEqual([text[m.start:m.end] for m in scan(text) if m.type == "NAME"], [NAME])

    def test_the_emphasis_stage_drops_only_the_stars_around_a_label(self):
        self.assertEqual(normalise.normalise("**Date of birth:** x").text, "Date of birth: x")
        self.assertEqual(normalise.normalise("**Date of birth**: x").text, "Date of birth: x")
        self.assertEqual(normalise.normalise("__Name:__ x").text, "Name: x")
        for text in ("a **bold** word", "__version__ = 1", "__all__: list = []", "f(**kwargs)", "**Note**",
                     "x ** 2: y", "__init__ : x"):
            with self.subTest(text=text):
                self.assertIs(normalise.normalise(text).text, text)

    def test_a_typed_prompt_keeps_its_decisions(self):
        self.assertText("**Date of birth:** " + BIRTH, "prompt")

    def test_a_bold_label_without_a_value_stays_text(self):
        for text in ("**Note:** see below", "**Password:** must be 12 characters", "**First name:** String, required",
                     "**Date of birth**: required, format YYYY-MM-DD", "**Version:** 1.2.3"):
            with self.subTest(text=text):
                self.assertText(text)

    def test_a_long_line_of_bold_labels_stays_linear(self):
        import time
        line = ("**Note:** x " * 20000) + ("**" * 40000)
        t0 = time.process_time()
        scan(line)
        self.assertLess(time.process_time() - t0, 20)


# ---------------------------------------------------------------------------------- phone after a phone word --
US = "415-382-" + "9174"


class PhoneAfterWordTests(Base):
    def test_a_national_number_after_a_phone_word_is_masked(self):
        for text, value in (
                ("Phone number: " + US, US),
                ("You can reach me at " + US + " or by mail.", US),
                ("Please call " + US.replace("-", ".") + " tomorrow.", US.replace("-", ".")),
                ('{"phone": "' + US + '", "name": "x"}', US),
                ("Telefoonnummer: 06 " + "4829 1735", "06 " + "4829 1735"),
                ("Telefon: 030 " + "4829" + "1735", "030 " + "4829" + "1735"),
                ("contact number is 07700 " + "900123", "07700 " + "900123"),
                ("Handy: 0151/" + "4829" + "1735", "0151/" + "4829" + "1735"),
                ("Phone (work): " + US, US),
                ("Tel.: 030 482917-" + "0", "030 482917-" + "0"), ("Tel: 030 482917 " + "0", "030 482917 " + "0")):
            with self.subTest(text=text):
                self.assertMasked(text, value)
                self.assertIn("phone-after-phone-word", {m.kind for m in scan(text)})

    def test_a_number_that_is_no_phone_number_stays_text(self):
        for text in ("Fax: (212) 555-" + "0147", "Phone: 415-555-" + "0123", "phone: 123-456-" + "7890",
                     "mobile: 1.2.3", "Mobile build 2024.10.16.1 shipped", "phone_verified_at: 1712345678",
                     "Phone: 2019-2024", "call took 1712345678 ms", "contact: 2024-10-16", "cell [2]: 3.14159",
                     "phone_number = models.CharField(max_length=20)", "Called 3 times in 2024-10-16 12:00:01",
                     "Mobile: 0151 1111111", "text 1234567 bytes", "Phone: 12:30 to 14:00",
                     "Phone: 2024-10-16 14:30", "mobile 2024-10-16 14:30:01 INFO app started",
                     "mobile: 3 412 908 users", "Fax: 1 500 000", "phone 4 8 15 16 23 42",
                     "Mobile build artifact: 938-274-" + "6157 completed",
                     "Mobile build artifact = 938-274-" + "6157", "Mobile build artifact - 938-274-" + "6157"):
            with self.subTest(text=text):
                self.assertNotIn("phone-after-phone-word", {m.kind for m in scan(text)})

    def test_a_typed_prompt_is_not_blocked_by_it(self):
        self.assertNotIn("phone-after-phone-word", {m.kind for m in scan("Phone number: " + US, "prompt")})

    def test_a_north_american_number_needs_region_us_or_ca(self):
        self.assertNotIn("phone-after-phone-word", {m.kind for m in scan("Phone number: " + US, region=("de",))})
        self.assertIn("phone-after-phone-word", {m.kind for m in scan("Phone number: " + US, region=("ca",))})
        self.assertMasked("Telefon: 030 " + "4829" + "1735", "030 " + "4829" + "1735", region=("de",))
        # the (312) form stays with phone-us-national
        self.assertEqual({m.kind for m in scan("Tel: (312) 846-" + "2291", region=("us",))}, {"phone-us-national"})


# ------------------------------------------------------------------- one name word after a first or last name --
GIVEN, FAMILY = "Da" + "na", "Oka" + "for"


class SingleNameTests(Base):
    def test_one_name_word_after_a_first_or_last_name_label_is_masked(self):
        for text, value in (
                ("First name: " + GIVEN, GIVEN),
                ("last name: " + FAMILY, FAMILY),
                ('{"first_name": "' + GIVEN + '", "last_name": "' + FAMILY + '"}', FAMILY),
                ("Vorname: Jürgen\nNachname: " + FAMILY, FAMILY),
                ("Prénom : Amélie", "Amélie"),
                ("Last name: Nguy" + "ễn", "Nguy" + "ễn"),
                ("First name: Nguye\u0302" + "n", "Nguye\u0302" + "n"),
                ("First name: \u1ea0" + "nh", "\u1ea0" + "nh"),
                ("First name: Mark", "Mark")):
            with self.subTest(text=text):
                self.assertMasked(text, value)
                self.assertIn("name-single-after-label", {m.kind for m in scan(text)})

    def test_a_word_a_type_a_state_or_a_documentation_name_stays_text(self):
        for text in ("first_name: String", "last name: Required", 'first_name = "John"', "last_name: Doe",
                     "surname: Text", "last name: Baker", "first_name: Optional[str] = None", "first name: <name>",
                     "given_name: Unknown", "first_name = models.CharField(max_length=30)", "lastName: Mustermann",
                     "first name: Max Mustermann", "last_name: Nullable", "first_name: Hashed",
                     '{"first_name": "Vorname", "last_name": "Nachname", "surname": "Familienname"}',
                     "first_name: Prénom\nlast_name: Nom", "first_name=Imię\nlast_name=Nazwisko",
                     '"firstName": "Firstname"', "last_name: Deprecated", "first_name: Unicode",
                     '{"first_name":"Texte"}', '{"first_name":"Zeichenfolge"}', "first_name: Prenume\nlast_name: Nume",
                     '{"first_name": "Vardas", "last_name": "Pavard\u0117"}', "first_name: Input"):
            with self.subTest(text=text):
                self.assertNotIn("name-single-after-label", {m.kind for m in scan(text)})

    def test_two_words_are_left_to_the_name_rule(self):
        kinds = {m.kind for m in scan("Last name: " + FAMILY + " Smith")}
        self.assertEqual(kinds, {"name-after-label"})


# ------------------------------------------------------------------- a street line after an address label --
STREET = "4821 Maple " + "Ridge Drive"


class StreetLineTests(Base):
    def test_a_street_line_after_an_address_label_or_a_verb_of_residence_is_masked(self):
        for text, value in (
                ("Street address: " + STREET, STREET),
                ("The tenant resides at 77 Harbour " + "Lane, Apt 4B.", "77 Harbour " + "Lane, Apt 4B"),
                ('{"address": "' + STREET + '", "city": "Springfield"}', STREET),
                ("Anschrift: Linden" + "straße 42", "Linden" + "straße 42"),
                ("Frau Okafor wohnt in der Garten" + "straße 3a.", "Garten" + "straße 3a"),
                ("Indirizzo: Via Roma " + "12", "Via Roma " + "12"),
                ("Street address: 123 5th " + "Avenue", "123 5th " + "Avenue"),
                ("Bank account status: active\nAddress: 100 Harbour " + "Lane", "100 Harbour " + "Lane"),
                ("The patient lives at " + STREET + " with her son.", STREET),
                ("Dana, our office manager, lives at 12 Oak " + "Street", "12 Oak " + "Street"),
                ("Her daughter works at the store and lives at 12 Oak " + "Street", "12 Oak " + "Street"),
                ("Return address: 12 Oak " + "Street", "12 Oak " + "Street")):
            with self.subTest(text=text):
                self.assertMasked(text, value)
                self.assertIn("address-street-after-label", {m.kind for m in scan(text)})

    def test_a_company_or_public_address_and_a_street_shape_in_code_stay_text(self):
        for text in ("Our office address: 100 Main Street", "Beispiel GmbH, Address: 100 Main Street",
                     "The Empire State Building is located at 350 Fifth Avenue", "Listen address: 8080 Rack Row",
                     "address: 0x7fff Main Street", "Hotel address: 1 Harbour Lane",
                     "address: see the 2 Main Street docs", "lives at: the 3 Root Path",
                     "IP address: 10 Network " + "Drive", "address: 0 Main " + "Street",
                     "The server lives at 10 Downing " + "Street", "Our store lives on 5 Market " + "Street",
                     "Warehouse address: 9 Industrial " + "Road", "The API lives at 10 Data " + "Drive"):
            with self.subTest(text=text):
                self.assertNotIn("address-street-after-label", {m.kind for m in scan(text)})

    def test_a_company_on_the_line_before_keeps_the_address_text_and_a_home_label_keeps_it_masked(self):
        for text in ("Acme Inc.\nAddress: 100 Harbour Lane", "Employer address: 100 Harbour Lane",
                     "Northwind Industries\nStreet Address: " + STREET,
                     "First Harbour Bank\nAddress: 100 Harbour Lane"):
            with self.subTest(text=text):
                self.assertNotIn("address-street-after-label", {m.kind for m in scan(text)})
        self.assertMasked("Employer: Acme Inc.\nHome address: 12 Harbour Lane", "12 Harbour Lane")
        self.assertMasked("Name: " + NAME + "\nAddress: " + STREET, STREET)

    def test_a_companys_address_takes_the_company_decision(self):
        company: list = []
        from maisecrets import personal
        personal.hits("Beispiel GmbH, Address: 100 Main Street", "tool", ("us",), company)
        self.assertIn("address-street-after-label", {c[4] for c in company})


# ----------------------------------------------------------------------- person columns of a Markdown table --
class MarkdownTableTests(Base):
    TABLE = ("| Name | Date of Birth | Phone Number |\n|------|---------------|--------------|\n"
             "| " + NAME + " | " + BIRTH + " | " + US + " |\n")

    def test_the_person_columns_of_a_markdown_table_mask_their_cells(self):
        for value in (NAME, BIRTH, US):
            self.assertMasked(self.TABLE, value)
        self.assertIn("md-table-personal-column", {m.kind for m in scan(self.TABLE)})
        # a table without the outer bars
        self.assertMasked("Name | Phone\n--- | ---\n" + NAME + " | 030 846 " + "2291 |", NAME)
        self.assertMasked("| Patient Name | MRN |\n|:---|---:|\n| " + NAME + " | " + "4821" + "3977 |", "4821" + "3977")

    def test_a_table_without_a_person_stays_text(self):
        for text in ("| Name | Version | Phone |\n|---|---|---|\n| maisecrets | 0.6.31 | n/a |",
                     "| Depot | Address | Phone |\n|---|---|---|\n| North | 12 Harbour Lane, Dunmore | " + US + " |",
                     "| Field | Type | Description |\n|---|---|---|\n| name | string | Full Name |",
                     "| Name | Phone |\n|---|---|\n| Front Desk | " + US + " |",
                     "| Name | Address |\n|---|---|\n| Zorvia Quent | 127.0.0.1:8080 |",
                     "| Name | Address | DOB |\n|---|---|---|\n| Zorvia Quent | db.internal:5432 | n/a |",
                     "| Name | Date of Birth |\n|---|---|\n| Release Candidate | 2024-05-01 |",
                     "| Name | Address | DOB |\n| --- | --- | --- |\n| Orion Vega | node1.acme.dev | n/a |"):
            with self.subTest(text=text):
                self.assertText(text)
        self.assertText("name,address\nZorvia Quent,127.0.0.1:8080\n")

    def test_a_long_separator_line_stays_linear(self):
        import time
        for sep in ("|---|---" + " " * 1990 + "x", "|" + "---|" * 490 + "x", " " * 1990 + "x"):
            t0 = time.process_time()
            scan("| Name | DOB |\n" + sep + "\n| " + NAME + " | " + BIRTH + " |")
            self.assertLess(time.process_time() - t0, 5)


# ------------------------------------------------------------------------------- health, tax and national IDs --
class HealthIdLabelTests(Base):
    def test_an_id_after_a_health_tax_or_national_label_is_masked(self):
        for text, value in (
                ("Health plan beneficiary number: " + "4821" + "39771", "4821" + "39771"),
                ("The patient's medical record number is MRX-" + "4821" + "3977.", "MRX-" + "4821" + "3977"),
                ("National ID: " + "7741 2290 " + "5531", "7741 2290 " + "5531"),
                ("Tax ID number: " + "48-21" + "39771", "48-21" + "39771"),
                ('beneficiary_id = "BNF-' + "4821" + '397"', "BNF-" + "4821" + "397")):
            with self.subTest(text=text):
                self.assertMasked(text, value)
                self.assertIn("id-number-after-label", {m.kind for m in scan(text)})

    def test_the_label_without_a_number_stays_text(self):
        for text in ("Medical record: see the chart (no number yet)", "national_id: str = Field(..., max_length=12)",
                     "TIN format: 9 digits", "Tax ID: ${TAX_ID}", "national id card 123456789",
                     "beneficiary: the person who receives the payout", "Beneficiary: VENDOR " + "00042",
                     "Social Security: 2024 COLA " + "3.2"):
            with self.subTest(text=text):
                self.assertText(text)


# --------------------------------------------------------------- passport and driving licence, EU languages --
class TravelIdLabelTests(Base):
    def test_a_passport_or_licence_number_after_its_label_in_an_eu_language_is_masked(self):
        for label in ("Führerscheinnummer:", "Pass-Nr.", "permis de conduire n°", "Número de pasaporte:",
                      "carnet de conducir:", "numero di passaporto", "patente di guida:", "Paspoortnummer:",
                      "rijbewijsnummer", "Passaporte n.º", "körkortsnummer", "numer paszportu:", "Numer prawa jazdy:",
                      "driving licence number:"):
            value = "XC" + "4821" + "3977"
            with self.subTest(label=label):
                self.assertMasked(label + " " + value, value)
                self.assertIn("id-number-after-label", {m.kind for m in scan(label + " " + value)})

    def test_a_patent_a_password_and_a_label_without_a_number_stay_text(self):
        for text in ("Patente: EP" + "1234567", "pass: " + "48213977", "Reisepass: abgelaufen, neu beantragen",
                     "permis de conduire: catégorie B", "numero di passaporto: vedi allegato"):
            with self.subTest(text=text):
                self.assertNotIn("id-number-after-label", {m.kind for m in scan(text)})


if __name__ == "__main__":
    unittest.main()


class ReviewOfTheDatasetRulesTests(Base):
    """The Opus review of 2026-10-17: developer text that the first version masked."""

    def test_placeholder_streets_stay_text(self):
        for text in ("address: 123 Main Street", "Shipping address: 123 Main St", "Adresse: Musterstraße 1",
                     "Anschrift: Beispielweg 12", "server:\n  address: 25 Main Street",
                     "The default address is 1 Infinite Loop for the test fixture."):
            with self.subTest(text):
                self.assertText(text)

    def test_a_sentence_after_a_name_label_stays_text(self):
        for text in ("first_name: Too long (maximum is 50 characters)", "first_name: May not be null",
                     "first_name: Was", "surname: Renamed to family_name in v2",
                     "- **first_name:** Renamed to given_name"):
            with self.subTest(text):
                self.assertText(text)

    def test_a_type_word_in_one_field_keeps_the_other_names_masked(self):
        for text in ("first_name: Dana\nlast_name: Okafor\nmiddle_name: Unknown",
                     '{"first_name": "Dana", "surname": "Okafor", "middle_name": "Default"}'):
            with self.subTest(text):
                out = masked(text)
                self.assertNotIn("Dana", out)
                self.assertNotIn("Okafor", out)

    def test_four_digit_groups_after_a_phone_word_stay_text(self):
        for text in ("Telefon 2024 2025 2026", "Cell 1024 2048 4096 overflow", "Fax: 8080 9090 7070"):
            with self.subTest(text):
                self.assertText(text)

    def test_a_thing_that_resides_at_a_place_stays_text(self):
        for text in ("Each shard resides at 2 Primary Road", "The handler lives in 4 Core Lane module."):
            with self.subTest(text):
                self.assertText(text)
