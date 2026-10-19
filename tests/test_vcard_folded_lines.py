"""A vCard property folded over two lines is read whole (RFC 6350, 3.2: a line break and one space or tab continue
the line before it). Exports fold a line after 75 octets, so a long address or a name with parameters often stands
on two lines. Before this change the vCard rules read the first part only: the address had too few fields, the
name or the phone number was cut, and the rest reached the model. The cleaned copy of a tool result now joins the
parts inside a vCard, and the mask covers both parts in the true text.

Every value here is invented.

Run: python3 -m unittest tests.test_vcard_folded_lines -v
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

STREET = "Hafenstra" + "ße 17"
CITY = "Bremen"
PLZ = "2819" + "5"
FAMILY, GIVEN = "Brück" + "ner", "Lena"
PHONE = "+49 151 " + "2345 6789"
MAIL = "lena.brueckner" + "@" + "mailbox-test.net"
BIRTH = "1980" + "0412"


def redact(text: str, channel: str = "tool") -> str:
    active = regions.Active(regions=("generic", "us", "uk", "de"), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        found = detect.scan(text, channel=channel)
    for m in sorted(found, key=lambda m: -m.start):
        text = text[:m.start] + "•" + text[m.end:]
    return text


def card(*lines: str, nl: str = "\n") -> str:
    return nl.join(("BEGIN:VCARD", "VERSION:3.0") + lines + ("END:VCARD", ""))


class FoldedLineTests(unittest.TestCase):
    def test_a_folded_address_is_masked_in_both_parts(self):
        for fold in ("\n ", "\n\t", "\r\n "):
            with self.subTest(fold=repr(fold)):
                nl = "\r\n" if fold.startswith("\r") else "\n"
                text = card("ADR;TYPE=home:;;" + STREET + ";Bre" + fold + "men;;" + PLZ + ";Germany", nl=nl)
                out = redact(text)
                self.assertNotIn(STREET, out)
                self.assertNotIn("men;;" + PLZ, out)
                self.assertNotIn(PLZ, out)

    def test_a_fold_between_two_fields_masks_the_whole_address(self):
        out = redact(card("ADR;TYPE=home:;;" + STREET + ";" + CITY + ";;", " " + PLZ + ";Germany"))
        self.assertNotIn(STREET, out)
        self.assertNotIn(PLZ, out)

    def test_a_folded_name_phone_mail_and_birth_date_are_masked_in_both_parts(self):
        text = card("FN:" + GIVEN + " Brü", " ckner",
                    "N:" + FAMILY[:3], " " + FAMILY[3:] + ";" + GIVEN + ";;;",
                    "TEL;TYPE=cell:" + PHONE[:7], " " + PHONE[7:],
                    "EMAIL;TYPE=INTERNET:" + MAIL[:9], " " + MAIL[9:],
                    "BDAY:" + BIRTH[:4], " " + BIRTH[4:])
        out = redact(text)
        for part in ("ckner", FAMILY[3:], PHONE[7:], MAIL[9:], BIRTH[4:]):
            with self.subTest(part=part):
                self.assertNotIn(part, out)

    def test_a_folded_line_that_starts_with_end_vcard_does_not_end_the_card(self):
        for cont in (" END:VCARD reminder", " END:VCARD"):
            with self.subTest(cont=cont):
                out = redact(card("NOTE:x", cont, "BDAY:" + BIRTH[:4], " " + BIRTH[4:]))
                self.assertNotIn(BIRTH[4:], out)

    def test_an_indented_vcard_with_a_folded_line(self):
        text = ("contacts:\n  - |\n    BEGIN:VCARD\n    ADR:;;" + STREET + ";" + CITY + ";;\n     " + PLZ
                + ";Germany\n    END:VCARD\n")
        out = redact(text)
        self.assertNotIn(STREET, out)
        self.assertNotIn(PLZ, out)

    def test_the_lines_of_an_indented_vcard_are_not_joined(self):
        # each line of a vCard in YAML starts with the indent of BEGIN:VCARD: that is no fold
        text = "  BEGIN:VCARD\n  VERSION:3.0\n  FN:" + GIVEN + " " + FAMILY + "\n  END:VCARD\n"
        self.assertIs(normalise.normalise(text, stages=("unfold",)).text, text)

    def test_a_folded_line_outside_a_vcard_is_not_joined(self):
        for text in ("description: a long line\n  that YAML folds\n", "DTSTART:20261020T090000Z\nDESCRIPTION:a\n b\n",
                     "BEGIN:VCALENDAR\nATTACH;FMTTYPE=text/vcard:https://example.com/c.vcf\nDESCRIPTION:Termin mit\n "
                     + GIVEN + "\nEND:VCALENDAR\n",
                     card("FN:" + GIVEN) + "notes: after the card\n  an indented line\n"):
            with self.subTest(text=text[:20]):
                self.assertIs(normalise.normalise(text, stages=("unfold",)).text, text)

    def test_a_binary_property_stays_folded(self):
        photo = "PHOTO;ENCODING=b;TYPE=JPEG:" + "QUJD" * 18 + "\n " + "REVG" * 18
        text = card(photo, "N:" + FAMILY + ";" + GIVEN + ";;;")
        self.assertIs(normalise.normalise(text, stages=("unfold",)).text, text)
        key = card("KEY;TYPE=PGP:" + "QUJD" * 18, " " + "REVG" * 18, "FN:" + GIVEN, " " + FAMILY)
        joined = normalise.normalise(key, stages=("unfold",)).text
        self.assertIn("\n " + "REVG", joined)                # the key keeps its fold
        self.assertIn("FN:" + GIVEN + FAMILY, joined)        # the name after it is joined

    def test_the_prompt_channel_does_not_change(self):
        text = card("ADR;TYPE=home:;;" + STREET + ";Bre", " men;;" + PLZ + ";Germany")
        self.assertEqual(redact(text, "prompt"), redact(text.replace("Bre\n men", "Bremen"), "prompt")
                         .replace("Bremen", "Bre\n men"))


if __name__ == "__main__":
    unittest.main()
