"""The gaps that ai-gateway #1764 (comment 112503) found when the gateway made maisecrets its only detector: a value
that only its field names, a phone number in front of a series of numbers, a middle name that is also a word, a
surname after Mr or Ms, and two forms of an e-mail address. Synthetic values only; each is built from parts, so the
repository scan reads no literal.

Run: python3 -m unittest tests.test_gateway_field_gaps -v
"""
from __future__ import annotations

import hashlib
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


class InternationalWithoutPlusTests(unittest.TestCase):
    """A number in its international form without its +, as an API keeps it in a JSON number (ai-gateway #1763)."""

    def test_it_is_a_phone_under_a_phone_field_or_after_a_phone_word(self):
        intl = "49151" + "48291736"
        for path in (("phone",), ("phone_cell",), ("phone", 0, "value")):
            with self.subTest(path=path):
                self.assertEqual(leaf(intl, *path), ["PHONE"])
        self.assertEqual(hits("Telefon: " + intl), [("PHONE", intl)])
        self.assertEqual(leaf("1415" + "8462291", "phone"), ["PHONE"], "the North American plan: 11 digits")

    def test_a_timestamp_an_id_and_a_lost_trunk_zero_stay_text(self):
        for value, path in (("15148" + "29173", ("phone",)),            # seconds, or a number without its 0
                            ("17625" + "14829173", ("phone",)),         # milliseconds: 13 digits from 1
                            ("49151" + "48291736", ("order_id",)),
                            ("49111" + "11111111", ("phone",)),          # a specimen
                            ("20261021" + "120000", ("fax",))):          # a timestamp from 20, a country code
            with self.subTest(value=value, path=path):
                self.assertEqual(leaf(value, *path), [])
        self.assertEqual(hits("order 49151" + "48291736"), [])


class GermanCallCueTests(unittest.TestCase):
    """A phone field that holds a sentence (ai-gateway #1764): the number after a German call cue and `unter`."""

    def test_a_number_after_a_call_cue_and_unter_is_found(self):
        number = "030 " + "48291736"
        for text in (f"erreichbar ab Montag unter {number}", f"Sie erreichen mich unter {number}.",
                     f"Rufen Sie uns an unter {number}", f"bitte zurückrufen unter {number}"):
            with self.subTest(text=text):
                self.assertEqual(hits(text), [("PHONE", number)])
        from maisecrets.detection.leaves import findings_by_leaf
        found = [(leaf.path, m.type) for leaf, m in findings_by_leaf(D, {"notiz": f"erreichbar unter {number}"})]
        self.assertEqual(found, [(("notiz",), "PHONE")], "a free-text field, not only a phone field")

    def test_two_numbers_after_unter_are_two_hits(self):
        # one span over both numbers left the subscriber digits of the second in the clear
        second = "0171 " + "5829174"
        self.assertEqual(hits("erreichbar unter 030 " + "48291736 " + second),
                         [("PHONE", "030 " + "48291736"), ("PHONE", second)])

    def test_unter_alone_a_date_or_a_number_that_is_no_phone_is_no_cue(self):
        for text in ("Bestellung unter 030 " + "48291736 abholen", "erreichbar unter 2026 11 07",
                     "erreichbar unter 0815-4711", "erreichbar unter 0 8080 8443"):
            with self.subTest(text=text):
                self.assertEqual([h for h in hits(text) if h[0] == "PHONE"], [])

    def test_the_cue_needs_a_german_speaking_region_and_tool_output(self):
        text = "erreichbar unter 030 " + "48291736"
        us = Detector(regions=Active(regions=("generic", "us"), languages=("en", "de"), source="gaps-test"),
                      sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="", year=2026))
        self.assertEqual([m.type for m in D.findings(text, channel="tool")], ["PHONE"])
        self.assertEqual([m.type for m in us.findings(text, channel="tool")], [])
        # a typed prompt takes only a number after a phone label (Wir erreichen das Limit unter …)
        self.assertEqual([m.type for m in D.findings(text, channel="prompt")], [])


class CardAfterUuidTests(unittest.TestCase):
    def test_a_card_right_after_a_uuid_is_found_whole(self):
        # the card pattern started in the UUID's last group, Luhn refused that span, and the card stayed in the clear
        card = "4508 " + "7194 0132 6529"
        for uuid in ("550E8400-E29B-41D4-A716-" + "446655440000", "550e8400-e29b-41d4-a716-" + "446655440000"):
            with self.subTest(uuid=uuid[:8]):
                text = uuid + " " + card
                self.assertEqual(hits(text), [("CARD", card)])
                self.assertEqual(hits(uuid), [], "a UUID alone is no card")


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



class FileNameLabelTests(unittest.TestCase):
    """#28: the sha256 after a file name that holds the word secret is no secret; a credential label still is."""

    DIGEST = hashlib.sha256(b"synthetic-test-file").hexdigest()

    def test_a_digest_after_an_archive_name_is_no_secret(self):
        for text in (f"('maisecrets-0.8.27.tar.gz', '{self.DIGEST}')", f"('secrets.tar.gz', '{self.DIGEST}')",
                     f"secrets.zip: {self.DIGEST}"):
            with self.subTest(text=text[:20]):
                self.assertEqual(hits(text), [])

    def test_a_digest_after_a_credential_label_stays_a_secret(self):
        self.assertEqual([t for t, _v in hits(f"('client_secret', '{self.DIGEST}')")], ["SECRET"])

    def test_the_password_of_an_archive_stays_a_secret(self):
        # only a digest is dropped: a password after the archive's name is the value people write there
        value = "Kq7" + "mZt4wPx9Lc2Rv"
        for text in (f"The password for backup.zip: {value}", f"secret_key backup.tar.gz = {value}"):
            with self.subTest(text=text[:24]):
                self.assertEqual([t for t, _v in hits(text)], ["SECRET"])


if __name__ == "__main__":
    unittest.main()
