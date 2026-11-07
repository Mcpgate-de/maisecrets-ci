"""The gaps that ai-gateway #1764 (comment 112503) found when the gateway made maisecrets its only detector: a value
that only its field names, a phone number in front of a series of numbers, a middle name that is also a word, a
surname after Mr or Ms, and two forms of an e-mail address. Synthetic values only; each is built from parts, so the
repository scan reads no literal.

Run: python3 -m unittest tests.test_gateway_field_gaps -v
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

from maisecrets import detect  # noqa: E402
from maisecrets.detection import NO_REFERENCES, NO_SOURCES, Active, Detector, Host, personal  # noqa: E402

D = Detector(regions=Active(regions=("generic", "de", "us"), languages=("en", "de"), source="gaps-test"),
             sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="", year=2026))
PHONE = "0170 " + "4829173"
PHONE2 = "030 " + "4829176"
SERIES = " ".join(f"{i:04d}" for i in range(60))


def leaf(value: str, *path) -> list:
    return [m.type for m in D.findings(value, channel="tool", fields=[(0, len(value), path)])]


def hits(text: str) -> list:
    return [(m.type, text[m.start:m.end]) for m in detect.scan(text, channel="tool")]


class FieldNameTests(unittest.TestCase):
    def test_a_value_in_a_nested_object_takes_the_name_of_the_object_above_it(self):
        self.assertEqual(leaf(PHONE, "x"), [], "premise: the bare number under a word gives nothing")
        for path in (("phone", 0, "value"), ("phoneNumbers", 0, "value"), ("contact", "phone", "number")):
            with self.subTest(path=path):
                self.assertEqual(leaf(PHONE, *path), ["PHONE"])
        tax = next(f"86095742{a}{b}{c}" for a in range(10) for b in range(10) for c in range(10)
                   if detect._de_tax_id_ok(f"86095742{a}{b}{c}"))
        self.assertEqual(leaf(tax, "customer", "steuer_id", "value"), ["DE_TAX_ID"])
        # a wrapper under a word that names nothing, or under cell or mobile alone, stays without evidence
        self.assertEqual(leaf(PHONE, "order", "number"), [])
        self.assertEqual(leaf(PHONE, "headers", 0, "value"), [])
        self.assertEqual(leaf("0815 " + "4711 0815", "cell", "value"), [], "a spreadsheet cell")
        self.assertEqual(leaf("0480 " + "0768 1024", "mobile", "value"), [], "a layout breakpoint")

    def test_a_phone_word_with_qualifiers_is_a_phone_field_and_with_another_word_it_is_not(self):
        for name in ("phone_home", "phone_work", "tel_privat", "telefon_privat", "handy_geschaeftlich",
                     "mobileBusiness", "phone_cell", "mobile_cellular", "telefon_mobil", "home_phone"):
            with self.subTest(name=name):
                self.assertEqual(leaf(PHONE, name), ["PHONE"])
        for name in ("phone_verified", "phone_country_code", "mobile_app_version", "phone_type", "mobile_sessions",
                     "mobile_order_reference", "order_id"):
            with self.subTest(name=name):
                self.assertEqual(leaf(PHONE, name), [])


class LeafRecordTests(unittest.TestCase):
    """The record scan of leaves.py (findings_by_leaf, the gateway's main path) reads a key as `fields=` does."""

    def found(self, obj) -> list:
        from maisecrets.detection.leaves import findings_by_leaf
        return [(leaf.path, m.type) for leaf, m in findings_by_leaf(D, obj) if leaf is not None]

    def test_a_wrapped_value_and_a_qualified_phone_key_are_found_in_a_record(self):
        for obj, path in (({"phone": [{"value": PHONE, "label": "mobile"}]}, ("phone", 0, "value")),
                          ({"phoneNumbers": [{"value": PHONE, "type": "mobile"}]}, ("phoneNumbers", 0, "value")),
                          ({"contact": {"phone": {"number": PHONE}}}, ("contact", "phone", "number")),
                          ({"phone_cell": PHONE}, ("phone_cell",)), ({"telefon_privat": PHONE}, ("telefon_privat",))):
            with self.subTest(path=path):
                self.assertIn((path, "PHONE"), self.found(obj))
        for obj in ({"phone_type": PHONE}, {"cell": {"value": "0815 " + "4711 0815"}}, {"order": {"number": PHONE}}):
            with self.subTest(obj=list(obj)):
                self.assertEqual([t for _p, t in self.found(obj) if t == "PHONE"], [])


class PhoneSeriesTests(unittest.TestCase):
    def test_a_number_before_a_series_and_two_numbers_before_it_are_found(self):
        self.assertEqual(hits("Tel " + PHONE + " " + SERIES), [("PHONE", PHONE)])
        self.assertEqual(hits("Tel 0170 482 91 73 " + PHONE2 + " " + SERIES),
                         [("PHONE", "0170 482 91 73"), ("PHONE", PHONE2)])
        # the last number of a list ends the run, and a list of four is found whole
        self.assertEqual(hits("Tel " + PHONE + " " + PHONE2), [("PHONE", PHONE), ("PHONE", PHONE2)])
        four = [PHONE, PHONE2, "0221 " + "4710385", "089 " + "4829175"]
        self.assertEqual([v for _t, v in hits("Tel " + " ".join(four))], four)

    def test_a_series_alone_and_a_test_number_before_it_stay_text(self):
        for text in ("Mobile sessions per week: " + SERIES, "Tel: " + SERIES, "Telefon 2024 2025 2026",
                     "Tel 0170 " + "1234567 " + SERIES):
            with self.subTest(text=text[:30]):
                self.assertEqual([h for h in hits(text) if h[0] == "PHONE"], [])
        # dates with blanks and a list of postcodes after a phone word are no numbers
        for text in ("Tel 01 11 2026 02 11 2026 03 11 2026", "Telefon 01067 01069 01097 01099 01108",
                     "Tel 01 4829 1736 " + SERIES):      # no area code is 0 and one digit
            with self.subTest(text=text):
                self.assertEqual(hits(text), [])
        # after a number, a group of zeros starts no second one: no area code starts with 00
        self.assertEqual(hits("Tel " + PHONE + " 0000 " + "4829 1736 0001 0002"), [("PHONE", PHONE)])


class CsvNameTests(unittest.TestCase):
    def test_a_middle_name_that_is_a_word_keeps_its_row(self):
        text = ("Name,E-Mail,Telefon\nLena " + "Maria Koch,lena.koch@probe-mail.de," + PHONE2 + "\n")
        self.assertEqual([t for t, _v in hits(text)], ["NAME", "EMAIL", "PHONE"])
        self.assertTrue(personal._reads_as_words("Customer Portal"), "premise: words stay words")

    def test_a_given_name_that_is_a_word_alone_is_still_a_name(self):
        for name in ("Grace", "Rose", "Mark", "Victor"):
            with self.subTest(name=name):
                self.assertEqual(hits(f"first_name: {name}"), [("NAME", name)])


class TitleSurnameTests(unittest.TestCase):
    def test_one_capital_word_after_mr_or_ms_is_a_surname_in_a_tool_result(self):
        surname = "Oka" + "for"
        for text in (f"Dear Mr. {surname},", f"Ms {surname} wrote", f"Mrs. {surname} called"):
            with self.subTest(text=text):
                self.assertEqual(hits(text), [("NAME", surname)])
                self.assertEqual(detect.scan(text, channel="prompt"), [], "a typed prompt keeps its words")
        for text in ("Dear Mr. Customer,", "Mrs. Applicant", "Mr. X said", "Cache Miss Ratio", "Ms Word export",
                     "Mx Linux 23", "Mr. Lastname", "Mr. President", "Salutation options: Mr Mrs Ms Mx",
                     "Mr. Potato Head", "Mr Product Owner will decide.", "Mr. Smith", "Mr. Ok", "Mr. Mister"):
            with self.subTest(text=text):
                self.assertEqual(hits(text), [])


class MailFormTests(unittest.TestCase):
    def test_a_quoted_local_part_and_a_public_ip_literal_are_addresses(self):
        quoted = '"jonas ' + 'weber"@probe-mail.de'
        public = "jonas@[" + "93.184." + "216.34]"
        v6 = "jonas@[IPv6:" + "2a01:4f8:c17:1a2b::7]"
        for addr in (quoted, public, v6, "admin@[" + "93.184." + "216.34]"):
            with self.subTest(addr=addr[:8]):
                self.assertEqual(hits(f"Mail an {addr} heute"), [("EMAIL", addr)])

    def test_a_public_ip_after_another_at_bracket_keeps_the_ip_rule(self):
        ip = "93.184." + "216.34"
        for text in (f"peer=@[{ip}]", f"bob@[{ip}:22]", f'"quoted"@[{ip}]', f"x@[{ip} ]"):
            with self.subTest(text=text):
                self.assertEqual(hits(text), [("IP", ip)])

    def test_a_string_before_an_at_in_code_or_json_is_no_quoted_address(self):
        for text in ('{"handle": "@jane.smith"}', '{"a":"b","c":"@app.route"}', '"x"@media.print',
                     'v = "ab\\"c"@probe-mail.de'):
            with self.subTest(text=text):
                self.assertEqual([h for h in hits(text) if h[0] == "EMAIL"], [])

    def test_a_private_or_documentation_ip_literal_stays_text(self):
        for addr in ("x@[10.0.0.1]", "jonas@[203.0.113.9]", '"a"@example.com'):
            with self.subTest(addr=addr):
                self.assertEqual(hits(addr), [])
        self.assertEqual(hits("ip " + "93.184." + "216.34 up")[0][0], "IP", "a bare IP is the IP rule's")


if __name__ == "__main__":
    unittest.main()
