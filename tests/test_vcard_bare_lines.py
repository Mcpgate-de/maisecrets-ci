"""A vCard line without its BEGIN:VCARD is a vCard line when nothing else writes its shape.

grep over a contact export prints single lines (`contacts.vcf:12:ADR;TYPE=home:;;…`), and a person copies one line
of a card into a ticket. Before this change ADR, N and BDAY counted only inside BEGIN:VCARD to END:VCARD, so the
address, the name and the birth date of such a line passed (TEL, EMAIL and FN are found by their shape or label
already). After a .vcf file name a line is a vCard line. Without one it needs the structure of the property:
ADR in capitals with a parameter of a card, an empty box and extended field and seven fields, N in capitals with
five fields and a title or nothing as the prefix, BDAY with a parameter of a card. The lines of
tests/test_vcard_parameters.py that stay text outside a vCard stay text.

Every value here is invented.

Run: python3 -m unittest tests.test_vcard_bare_lines -v
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

FIELDS = "Hafenstra" + "ße 17;Bremen;;" + "28195;Germany"
FAMILY_GIVEN = "Brück" + "ner;Lena"
BIRTH = "1980" + "0412"
PHONE = "+49 151 " + "2345 6789"
MAIL = "lena.brueckner" + "@" + "mailbox-test.net"
NAME = "Lena " + "Brückner"


def masked(text: str, channel: str = "tool") -> set:
    active = regions.Active(regions=("generic", "us", "uk", "de"), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        found = detect.scan(text, channel=channel)
    return {(m.type, text[m.start:m.end]) for m in found}


PERSONAL = {"ADDRESS", "NAME", "BIRTH_DATE"}


class BareLineTests(unittest.TestCase):
    def test_grep_output_of_a_contact_export(self):
        for prefix in ("contacts.vcf:", "contacts.vcf:12:", "export/Kontakte.VCF:3:", "C:\\Users\\x\\contacts.vcf:12:"):
            with self.subTest(prefix=prefix):
                self.assertIn(("ADDRESS", FIELDS), masked(prefix + "ADR;TYPE=home:;;" + FIELDS))
                self.assertIn(("NAME", FAMILY_GIVEN), masked(prefix + "N:" + FAMILY_GIVEN + ";;;"))
                self.assertIn(("BIRTH_DATE", BIRTH), masked(prefix + "BDAY:" + BIRTH))
                self.assertIn(("ADDRESS", FIELDS), masked(prefix + "adr;type=home:;;" + FIELDS))

    def test_a_line_of_a_card_without_a_file_name(self):
        self.assertIn(("ADDRESS", FIELDS), masked("ADR;TYPE=home:;;" + FIELDS))
        self.assertIn(("ADDRESS", FIELDS), masked("item1.ADR;type=HOME;type=pref:;;" + FIELDS))
        self.assertIn(("ADDRESS", FIELDS), masked("ADR;HOME:;;" + FIELDS))
        self.assertIn(("NAME", FAMILY_GIVEN), masked("N:" + FAMILY_GIVEN + ";;;"))
        self.assertIn(("NAME", FAMILY_GIVEN + ";Marie"), masked("N:" + FAMILY_GIVEN + ";Marie;Dr.;"))
        self.assertIn(("BIRTH_DATE", BIRTH), masked("BDAY;VALUE=date:" + BIRTH))
        self.assertIn(("NAME", FAMILY_GIVEN), masked("12:N;CHARSET=UTF-8:" + FAMILY_GIVEN + ";;;"))

    def test_tel_email_and_fn_lines_are_found_as_before(self):
        self.assertIn(("PHONE", PHONE), masked("contacts.vcf:7:TEL;TYPE=cell:" + PHONE))
        self.assertIn(("EMAIL", MAIL), masked("EMAIL;TYPE=INTERNET:" + MAIL))
        self.assertIn(("NAME", NAME), masked("FN;CHARSET=UTF-8:" + NAME))

    def test_the_prompt_channel_does_not_change(self):
        for text in ("ADR;TYPE=home:;;" + FIELDS, "contacts.vcf:N:" + FAMILY_GIVEN + ";;;"):
            with self.subTest(text=text[:12]):
                self.assertEqual({t for t, _ in masked(text, "prompt")} & PERSONAL, set())

    def test_shapes_that_are_no_vcard_line_stay_text(self):
        for text in ("ADR: 0012;Accepted;Use Postgres 16;2026-01-01;platform;db;x",
                     "adr:1;Shop;12 Market Street;Leeds;LS1;UK;x", "adr:;;" + FIELDS, "Adr:;;" + FIELDS,
                     "ADR:;;" + FIELDS + ";extra", "ADR:;;Hafenstraße;Bremen;;28195;Germany",
                     "ADR:;;Step 1;Init;;;", "ADR:;;12;34;;56;78",
                     "ADR:0007;Accepted;12 Use Postgres;platform;db;2024;yes", "ADR:;;" + FIELDS,
                     "ADR:;;Cache 2;Primary;;8080;prod", "ADR:;;0012 Accepted;Use Postgres;;16;x",
                     "ADR;TYPE=work:0007;Accepted;12 Use Postgres;platform;db;2024;yes",
                     "ADR;TYPE=home:;;Step 1;Init;;;", "ADR:;;Node 3;Cluster;;8080;prod",
                     "ADR;shard=2:;;Node 3;Cluster;;8080;prod", "ADR;TYPE=cache:;;Cache 2;Primary;;8080;prod",
                     "Supported markers are BEGIN:VCARD and END:VCARD.\nBDAY:" + BIRTH,
                     "Use `BEGIN:VCARD` to start.\nN:" + FAMILY_GIVEN + ";;;;", "BDAY;since=1:" + BIRTH,
                     "N:Europe;Asia;Africa;America;Oceania", "n:" + FAMILY_GIVEN + ";;;",
                     "N:" + FAMILY_GIVEN + ";;;;", "N:" + FAMILY_GIVEN + ";;Admin;", "N:" + FAMILY_GIVEN + ";;;Team",
                     "N:Total;Count;;;", "N:5;3;1;;", "[grid]\nN:Polaris;Central;Star", "BDAY:" + BIRTH,
                     "BDAY:20240101", "notes.txt:BDAY:" + BIRTH,
                     "read contacts.vcf\nBDAY:" + BIRTH, "N:" + FAMILY_GIVEN + ";2nd;;",
                     "DTSTART;TZID=Europe/Berlin:20261020T090000", "RRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=10",
                     "GET /api/users/bday;from=2020-01-01;to=2020-12-31"):
            with self.subTest(text=text):
                self.assertEqual({t for t, _ in masked(text)} & PERSONAL, set())


if __name__ == "__main__":
    unittest.main()
