"""The optional `fields` of Detector.scan and Detector.findings (maisecrets/detection/fields.py).

A field name is evidence as the same label in text is, and nothing more: it adds a hit inside its span, takes none
away, gives nothing for a weak or unknown name, and parses nothing. Without fields a scan is the one of before.
The shapes are the gateway's (src/security/detector_shadow.py walks a JSON response and scans each string leaf
with its field path; a list item keeps its list's path).

Run: python3 -m unittest tests.test_detection_fields -v
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets.detection import NO_REFERENCES, NO_SOURCES, Active, Detector, Host  # noqa: E402

D = Detector(regions=Active(regions=("generic", "de", "us"), languages=("en", "de"), source="fields-test"),
             sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="", year=2026))
PHONE = "0171 4829173"
PASSWORD = "Mauve-" + "Otter-4821"   # built from parts: the repository scan reads literals
OPAQUE = "X1234567"
CURSOR = "CiAKGjBpNDd2Nmp2Zml2cXRwYjBpOXAzMhIDCJgBGgA"


def spans(ms) -> list:
    return [(m.kind, m.type, m.start, m.end) for m in ms]


def leaf(value: str, *name) -> list:
    """The hits of one string leaf under its field path, as the gateway scans it."""
    return D.findings(value, channel="tool", fields=[(0, len(value), name)])


class FieldEvidenceTests(unittest.TestCase):
    def test_a_phone_under_a_phone_field_is_found_and_bare_it_is_not(self):
        self.assertEqual(spans(D.findings(PHONE, channel="tool")), [], "the premise: bare it is no finding")
        self.assertEqual([(m.type, m.start, m.end) for m in leaf(PHONE, "customer", "telefon")],
                         [("PHONE", 0, len(PHONE))])

    def test_a_list_index_in_the_path_is_skipped_for_the_label(self):
        self.assertEqual([m.type for m in leaf(PHONE, "contacts", 0, "phone")], ["PHONE"])
        self.assertEqual([m.type for m in leaf(PHONE, "telefon", 0)], ["PHONE"])
        self.assertEqual([m.type for m in leaf(PHONE, "telefon", "3")], ["PHONE"])

    def test_a_password_field_marks_its_value(self):
        self.assertEqual(spans(D.findings(PASSWORD, channel="tool")), [], "the premise")
        self.assertEqual([(m.type, m.start, m.end) for m in leaf(PASSWORD, "password")],
                         [("SECRET", 0, len(PASSWORD))])

    def test_a_build_number_stays_text(self):
        self.assertEqual(leaf("20261021", "build_number"), [])
        self.assertEqual(leaf("20261021", "pipeline", "build_number"), [])

    def test_weak_and_unknown_names_add_nothing(self):
        for name in ("id", "value", "data", "key", "title", "status", "description", "flux_capacitor", "customer_id"):
            for v in (OPAQUE, PHONE, PASSWORD):
                with self.subTest(name=name, value=v[:3]):
                    self.assertEqual(spans(leaf(v, name)), spans(D.findings(v, channel="tool")))

    def test_a_page_cursor_is_no_key_though_an_access_token_is(self):
        self.assertEqual([m.type for m in leaf(CURSOR, "access_token")], ["SECRET"], "the premise: the label rules")
        for name in ("nextPageToken", "next_page_token", "pageToken", "syncToken", "nextSyncToken",
                     "continuationToken", "prev-page-token"):
            with self.subTest(name=name):
                self.assertEqual(leaf(CURSOR, name), [])

    def test_key_and_token_alone_are_no_label_but_with_a_word_before_they_are(self):
        # in text `token: <identifier>` is a SECRET; in API data a field `key` or `token` names an identifier as often
        for value in ("PBE-3697", "img_7f3a9c21b4", "onboarding_step_3_title", PASSWORD):
            for name in ("key", "token", "Token", " key "):
                with self.subTest(name=name, value=value[:3]):
                    self.assertEqual(spans(leaf(value, name)), spans(D.findings(value, channel="tool")))
        for name in ("api_key", "apiKey", "access_token", "auth-token", "secret_key"):
            with self.subTest(name=name):
                self.assertEqual([m.type for m in leaf(PASSWORD, "config", name)], ["SECRET"])

    def test_a_name_that_cannot_be_a_label_adds_nothing(self):
        for name in ("pass:word", "x\npassword", 'pass"word', "p" * 65 + "password", " ", "12"):
            with self.subTest(n=len(name)):
                self.assertEqual(leaf(PASSWORD, name), [])
        self.assertEqual(leaf(PASSWORD, 0), [])

    def test_a_field_takes_no_hit_away(self):
        text = "mail erika.musterfrau@firma-beispiel.de now"
        base = spans(D.findings(text, channel="tool"))
        self.assertTrue(base, "the premise")
        for name in ("build_number", "id", "example", "telefon"):
            with self.subTest(name=name):
                self.assertEqual(spans(D.findings(text, channel="tool", fields=[(5, 39, (name,))])), base)

    def test_a_field_does_not_bring_back_a_hit_the_text_took_away(self):
        # the bare value is a phone, and the text around it decided it is none: the field gives no evidence for it
        value = "+49 171 4829173"
        text = "test_" + value
        self.assertEqual([m.type for m in D.scan(value, channel="tool")], ["PHONE"], "the premise: bare a phone")
        self.assertEqual(D.scan(text, channel="tool"), [], "the premise: the text took it away")
        self.assertEqual(D.scan(text, channel="tool", fields=[(5, len(text), ("telefon",))]), [])

    def test_a_hit_stays_inside_its_field(self):
        text = "call " + PHONE + " today"
        hits = D.findings(text, channel="tool", fields=[(5, 5 + len(PHONE), ("telefon",))])
        self.assertEqual([(m.start, m.end, m.value) for m in hits], [(5, 5 + len(PHONE), PHONE)])

    def test_overlapping_fields_give_one_hit(self):
        hits = D.findings(PHONE, channel="tool", fields=[(0, len(PHONE), ("telefon",)), (0, len(PHONE), ("phone",))])
        self.assertEqual(len(hits), 1)


class NoFieldsIsTheOldScanTests(unittest.TestCase):
    TEXTS = ("telefon: " + PHONE, "password: " + PASSWORD, json.dumps({"customer": {"telefon": PHONE}}), PHONE, "")

    def test_none_and_an_empty_list_give_the_scan_of_before(self):
        for text in self.TEXTS:
            with self.subTest(n=len(text)):
                for ch in ("prompt", "tool"):
                    before = spans(D.scan(text, channel=ch))
                    self.assertEqual(spans(D.scan(text, channel=ch, fields=None)), before)
                    self.assertEqual(spans(D.scan(text, channel=ch, fields=[])), before)
                    self.assertEqual(spans(D.findings(text, channel=ch, fields=())),
                                     spans(D.findings(text, channel=ch)))

    def test_the_module_functions_and_detector_scan_take_fields_too(self):
        from maisecrets.detection import core
        self.assertEqual([m.type for m in D.scan(PHONE, channel="tool", fields=[(0, 12, ("telefon",))])], ["PHONE"])
        with D.activate():
            self.assertEqual([m.type for m in core.findings(PHONE, channel="tool", fields=[(0, 12, ("telefon",))])],
                             ["PHONE"])
            self.assertEqual([m.type for m in core.scan(PHONE, channel="tool", fields=[(0, 12, ("telefon",))])],
                             ["PHONE"])

    def test_fields_is_keyword_only(self):
        with self.assertRaises(TypeError):
            D.findings(PHONE, "tool", "", [(0, 12, ("telefon",))])
        with self.assertRaises(TypeError):
            D.scan(PHONE, None, "tool", "", None, [(0, 12, ("telefon",))])


class JsonTextTests(unittest.TestCase):
    """The core parses a JSON line itself; fields that name what it read give the same hits, never a second one."""

    def test_fields_of_the_cores_own_parse_change_nothing(self):
        record = {"customer": {"telefon": PHONE, "build_number": "20261021", "password": PASSWORD, "id": OPAQUE,
                               "name": "Erika Musterfrau", "note": "call back"}}
        text = json.dumps(record)
        fields = []
        for key, value in record["customer"].items():
            at = text.index(json.dumps(key) + ": " + json.dumps(value)) + len(json.dumps(key)) + 3
            self.assertEqual(text[at:at + len(value)], value)
            fields.append((at, at + len(value), ("customer", key)))
        for ch in ("tool", "prompt"):
            with self.subTest(channel=ch):
                plain = spans(D.findings(text, channel=ch))
                if ch == "tool":
                    self.assertIn("PHONE", [s[1] for s in plain], "the premise: the core reads the JSON itself")
                self.assertEqual(spans(D.findings(text, channel=ch, fields=fields)), plain)
                self.assertEqual(spans(D.scan(text, channel=ch, fields=fields)), spans(D.scan(text, channel=ch)))


class ValidationTests(unittest.TestCase):
    SECRET_TEXT = "token " + PASSWORD
    SECRET_NAME = "Ozelot-Fjord-91"

    def assert_refused(self, exc, fields):
        with self.assertRaises(exc) as cm:
            D.findings(self.SECRET_TEXT, channel="tool", fields=fields)
        msg = str(cm.exception)
        self.assertNotIn(PASSWORD, msg)
        self.assertNotIn("token", msg)
        self.assertNotIn(self.SECRET_NAME, msg)
        return msg

    def test_a_wrong_shape_is_a_type_error_that_names_no_text(self):
        n = len(self.SECRET_TEXT)
        for bad in ("telefon", b"x", {"start": 0}, 7, iter([(0, 1, ("a",))]), [(0, 1)], [[0, 1, ("a",), "x"]],
                    [(0.0, 1, ("a",))], [(True, 1, ("a",))], [(0, "1", ("a",))], [(0, n, self.SECRET_NAME)],
                    [(0, n, ())], [(0, n, (self.SECRET_NAME, None))], [(0, n, (False,))], [(0, n, None)]):
            with self.subTest(bad=type(bad).__name__):
                self.assert_refused(TypeError, bad)

    def test_an_offset_outside_the_text_is_a_value_error(self):
        n = len(self.SECRET_TEXT)
        for bad in ([(-1, 3, ("a",))], [(0, n + 1, ("a",))], [(3, 3, ("a",))], [(4, 2, ("a",))]):
            with self.subTest(bad=bad[0][:2]):
                msg = self.assert_refused(ValueError, bad)
                self.assertIn("fields[0]", msg)

    def test_the_position_of_the_bad_field_is_named(self):
        msg = self.assert_refused(TypeError, [(0, 3, ("a",)), (0, 3, "b")])
        self.assertIn("fields[1]", msg)

    def test_a_text_that_is_no_str_is_the_type_error_of_scan_also_with_fields(self):
        for bad in (None, b"0171 4829173"):
            for call in (D.findings, D.scan):
                with self.subTest(text=type(bad).__name__, call=call.__name__):
                    with self.assertRaises(TypeError) as cm:
                        call(bad, channel="tool", fields=[(0, 3, ("telefon",))])
                    self.assertEqual(str(cm.exception), f"text must be a str, not {type(bad).__name__}")

    def test_a_list_for_a_tuple_is_taken(self):
        self.assertEqual([m.type for m in D.findings(PHONE, channel="tool", fields=[[0, 12, ["telefon"]]])],
                         ["PHONE"])


if __name__ == "__main__":
    unittest.main()
