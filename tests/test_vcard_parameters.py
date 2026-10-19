"""A vCard property with parameters is the same field as without them: `ADR;TYPE=home:`, `FN;CHARSET=UTF-8:`,
`BDAY;VALUE=date:` and the bare type of vCard 2.1 (`ADR;HOME;PREF:`) mask what `ADR:`, `FN:` and `BDAY:` mask.
Before 0.6.25 the parameters stood between the label and its colon, and the address, the name and the birth date
of a contact export passed (TEL and EMAIL were found by their shape already).

Run: python3 -m unittest tests.test_vcard_parameters -v
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

ADDRESS = "7 Rosemount Gardens, Dunmore, Wexford " + "4471"
NAME = "Lena " + "Brückner"
CYRILLIC = "Ирина" + " Соколова"
BIRTH = "1980-" + "04-12"
MAIL = "lena.brueckner" + "@" + "mailbox-test.net"
PHONE = "+49 151 " + "2345 6789"

# (property, value, the parameter forms); each form must mask what the plain `PROPERTY:` masks
CASES = [
    ("ADR", ";;" + ADDRESS, ["ADR;TYPE=home", "ADR;TYPE=HOME,PREF", "ADR;HOME;PREF", "item1.ADR;type=HOME;type=pref",
                             'ADR;TYPE=home;LABEL="Rosemount Gardens"']),
    ("FN", NAME, ["FN;CHARSET=UTF-8", "FN;LANGUAGE=de", "FN;TYPE=work"]),
    ("FN", CYRILLIC, ["FN;CHARSET=UTF-8", "FN;LANGUAGE=ru"]),
    ("BDAY", BIRTH, ["BDAY;VALUE=date", "BDAY;VALUE=DATE"]),
    ("EMAIL", MAIL, ["EMAIL;TYPE=INTERNET", "EMAIL;TYPE=INTERNET,HOME;PREF=1"]),
    ("TEL", PHONE, ["TEL;TYPE=CELL", "TEL;CELL", "TEL;TYPE=cell;PREF=1"]),
]


def scan(text: str, channel: str = "tool") -> list:
    active = regions.Active(regions=("generic", "us", "uk", "de"), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return detect.scan(text, channel=channel)


def card(line: str) -> str:
    return "BEGIN:VCARD\nVERSION:3.0\n" + line + "\nEND:VCARD\n"


def masked(text: str, channel: str = "tool") -> set:
    return {(m.type, text[m.start:m.end]) for m in scan(text, channel)}


class VcardParameterTests(unittest.TestCase):
    def test_a_property_with_parameters_masks_what_the_plain_property_masks(self):
        for prop, value, forms in CASES:
            plain = masked(card(prop + ":" + value))
            self.assertTrue(plain, f"{prop}: the plain form must mask its value")
            for form in forms:
                with self.subTest(form=form):
                    self.assertEqual(masked(card(form + ":" + value)), plain)

    def test_the_value_itself_is_masked(self):
        self.assertIn(("ADDRESS", ADDRESS), masked(card("ADR;TYPE=home:;;" + ADDRESS)))
        self.assertIn(("NAME", NAME), masked(card("FN;CHARSET=UTF-8:" + NAME)))
        self.assertIn(("NAME", CYRILLIC), masked(card("FN;CHARSET=UTF-8:" + CYRILLIC)))
        self.assertIn(("BIRTH_DATE", BIRTH), masked(card("BDAY;VALUE=date:" + BIRTH)))

    def test_a_label_that_starts_with_adr_is_no_vcard_field(self):
        # Adresse is a German address label: it needs no `;;` before its value (a check of the first three letters
        # took it for ADR and lost four holdout addresses)
        text = "Adresse: " + ADDRESS
        self.assertIn(("ADDRESS", ADDRESS), masked(text))

    def test_an_architecture_decision_record_stays_text(self):
        # ADR without the empty fields of a vCard address is a decision record, with parameters too
        for text in ("ADR: 0007 Use Postgres, Accepted", "ADR;status=accepted: 0007 Use Postgres, Accepted",
                     "ADR;TYPE=home: 12 Harbour Lane, Springfield"):
            with self.subTest(text=text):
                self.assertEqual([m for m in scan(text) if m.type == "ADDRESS"], [])


STREET = "7 Rosemount Gardens;Dunmore;Wexford;" + "4471;Ireland"


class VcardFieldTests(unittest.TestCase):
    """ADR and N write their value in fields (RFC 6350): box;extended;street;locality;region;code;country and
    family;given;additional;prefix;suffix. Contact exports of Apple, Google and Outlook write them so, and a BDAY of
    eight digits is the form of the RFC's own examples. The labels of 0.6.24 saw none of them (review of 0.6.25)."""

    def test_an_address_in_its_fields_is_masked_with_and_without_parameters(self):
        for prop in ("ADR", "ADR;TYPE=home", "item1.ADR;type=HOME;type=pref", "ADR;HOME"):
            with self.subTest(prop=prop):
                self.assertIn(("ADDRESS", STREET), masked(card(prop + ":;;" + STREET)))

    def test_a_name_in_its_fields_is_masked(self):
        family_given = "Brückner;" + "Lena"
        for prop in ("N", "N;CHARSET=UTF-8"):
            with self.subTest(prop=prop):
                self.assertIn(("NAME", family_given), masked(card(prop + ":" + family_given + ";;;")))
        self.assertIn(("NAME", family_given + ";Marie"), masked(card("N:" + family_given + ";Marie;Dr.;")))

    def test_a_birth_date_of_eight_digits_is_masked(self):
        for prop in ("BDAY", "BDAY;VALUE=date"):
            with self.subTest(prop=prop):
                self.assertIn(("BIRTH_DATE", "19850412"), masked(card(prop + ":19850412")))

    def test_shapes_that_are_no_vcard_field_stay_text(self):
        for text in ("GET /api/users/bday;from=2020-01-01;to=2020-12-31", "/api/report;bday;since=2021-03-04",
                     card("ADR: 0007 Use Postgres; Accepted"), card("ADR:;;;;;;"), card("ADR;TYPE=work:;;Suite 4;;;;"),
                     card("N:Roe;Jane;;;"), card("N:Total;Count;;;"), card("BDAY:19700101"), card("BDAY:20990412")):
            with self.subTest(text=text):
                self.assertEqual({t for t, _ in masked(text)} & {"ADDRESS", "NAME", "BIRTH_DATE"}, set())


class VcardContextTests(unittest.TestCase):
    """The field forms count only inside a vCard (BEGIN:VCARD before the line), in any group, also indented or in a
    JSON string (review round 2 of 0.6.25)."""

    def test_a_line_outside_a_vcard_stays_text(self):
        for text in ("ADR: 0012;Accepted;Use Postgres 16;2026-01-01;platform;db;x",
                     "adr:1;Shop;12 Market Street;Leeds;LS1;UK;x", "N:Europe;Asia;Africa;America;Oceania",
                     "[grid]\nN:Smallville;Metropolis;Gotham;Central;Star", "BDAY:20240101",
                     card("ADR:0007;Accepted;123 Use Postgres;platform;2024;yes"),
                     card("VERSION:3.0") + "N:Europe;Asia;Africa;America;Oceania\n" + "BDAY:19991231"):
            with self.subTest(text=text):
                self.assertEqual({t for t, _ in masked(text)} & {"ADDRESS", "NAME", "BIRTH_DATE"}, set())

    def test_a_vcard_in_a_json_string_an_indented_vcard_and_any_group(self):
        import json
        family_given = "Brückner;" + "Lena"
        inner = "BEGIN:VCARD\nADR;TYPE=home:;;" + STREET + "\nN:" + family_given + ";;;\nBDAY:19850412\nEND:VCARD"
        text = json.dumps({"vcard": inner}, ensure_ascii=False)
        self.assertEqual(masked(text) & {("ADDRESS", STREET), ("NAME", family_given), ("BIRTH_DATE", "19850412")},
                         {("ADDRESS", STREET), ("NAME", family_given), ("BIRTH_DATE", "19850412")})
        indented = "contacts:\n  - |\n    BEGIN:VCARD\n    ADR:;;" + STREET + "\n    END:VCARD"
        self.assertIn(("ADDRESS", STREET), masked(indented))
        grouped = "BEGIN:VCARD\nhome.ADR:;;" + STREET + "\nprivate.BDAY:19850412\nEND:VCARD"
        self.assertTrue({("ADDRESS", STREET), ("BIRTH_DATE", "19850412")} <= masked(grouped))

    def test_the_shorter_forms_of_older_exports(self):
        cottage = "Rose Cottage;Dunmore;Wexford;Y35 X2K;Ireland"
        self.assertIn(("ADDRESS", cottage), masked(card("ADR;TYPE=home:;;" + cottage)))
        self.assertIn(("NAME", "Brückner;" + "Lena"), masked(card("N:Brückner;" + "Lena")))
        self.assertIn(("BIRTH_DATE", "19850412"), masked(card("BDAY:19850412T000000Z")))


if __name__ == "__main__":
    unittest.main()
