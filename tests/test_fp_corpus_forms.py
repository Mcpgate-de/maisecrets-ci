"""The forms of 0.6.24 (maisecrets/detection/personal.py, FORMS): each finds its synthetic value, and none of them
fires on the
developer text of tests/fp_corpus_forms.py, which holds exactly their shapes without a value.

Run: python3 -m unittest tests.test_fp_corpus_forms -v
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

import fp_corpus_forms as corpus  # noqa: E402
from maisecrets import detect, personal, regions  # noqa: E402

ALL = ("us", "uk", "in", "de", "fr", "es", "it", "pt", "ca", "au", "nl", "se", "jp")
# hits of older rules on this corpus, measured on 0.6.23: the bar is that 0.6.24 adds none
KNOWN = {
    "account aws id": {"us-bank"},           # a 12-digit run in the us region (BENCHMARKS, "Regions")
    "account arn": {"us-bank"},
    "fhir type coding": {"ip#2"},            # an OID that reads as an IPv4 address
    "digest after key word": {"generic-api-key"},
    "key fingerprint": {"generic-api-key"},
    "owner team": {"name-after-label"},
    "base64 of a name after a key": {"ds-keyword-equal-signs"},   # the password-label rule, not generic-api-key
    # ::add-mask:: declares its value a secret: in a tool result even a doc example is masked; a typed prompt is not
    # blocked (every form is tool-only)
    "add-mask question": {"secret-add-mask"},
}
# the rule that must take each positive (the corpus id → the rule id)
OWNER = {
    "add-mask literal": "secret-add-mask", "sas key": "secret-shared-access-key",
    "postman secret": "secret-postman-variable", "har header": "secret-hex48-after-token-word",
    "hex48 token prose": "secret-hex48-after-token-word", "redis auth": "secret-in-login-code",
    "login call": "secret-in-login-code", "user slash": "secret-after-user-slash",
    "fhir mrn": "id-number-fhir-identifier", "insurance member": "id-number-after-record-label",
    "member id letters": "id-letters-after-label", "member parentheses": "id-number-in-member-parentheses",
    "sql alias tax": "id-number-under-sql-alias", "sql alias address": "address-under-sql-alias",
    "address after label": "address-after-label", "jp postcode": "address-jp-postcode",
    "indian address": "address-in-form", "name cyrillic": "name-non-latin-after-label",
    "name cjk": "name-non-latin-after-label", "name latin ext": "name-after-label",
    "phone encoded": "phone-url-encoded", "phone wrapped": "phone-wrapped-line",
    "encoded mail sent to": "email-percent-encoded", "encoded mail csv cell": "email-percent-encoded",
    "card in groups": "credit-card", "card after pan": "credit-card", "card after a swedish word": "credit-card",
    "postman password counter": "secret-postman-variable", "user slash with words": "secret-after-user-slash",
    "fhir pretty passport": "id-number-fhir-identifier", "name patient_name": "name-non-latin-after-label",
    "dl in json": "id-number-after-record-label", "address level": "address-after-label",
    "encoded mail after a line": "email-percent-encoded",
    "card in a csv row": "credit-card", "encoded mail quoted cell": "email-percent-encoded",
    "postman password of words": "secret-postman-variable", "add-mask of words": "secret-add-mask",
    "vcard adr fields": "address-vcard-fields", "vcard n fields": "name-vcard-n",
    "vcard bday digits": "birth-date-vcard-compact", "encoded mail contact column": "email-percent-encoded",
    "phone after a phone word": "phone-after-phone-word", "phone national after a label": "phone-after-phone-word",
    "one first name": "name-single-after-label", "street line after a label": "address-street-after-label",
    "markdown table of persons": "md-table-personal-column",
}


def scan(text: str, channel: str, region: tuple = ALL) -> list:
    active = regions.Active(regions=("generic", *region), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return detect.scan(text, channel=channel)


def masked(text: str, found: list) -> str:
    for m in sorted(found, key=lambda m: -m.start):
        text = text[:m.start] + "#" + text[m.end:]
    return text


class FormsCorpusTests(unittest.TestCase):
    def test_no_rule_fires_on_the_developer_text_in_the_shapes_of_the_forms(self):
        for name, text in corpus.FORMS_NO_HIT:
            for channel in ("tool", "prompt"):
                with self.subTest(name=name, channel=channel):
                    kinds = {m.kind for m in scan(text, channel)}
                    known = KNOWN.get(name, set()) if channel == "tool" or name != "add-mask question" else set()
                    self.assertLessEqual(kinds, known)

    def test_each_form_masks_its_value_in_the_tool_channel(self):
        for name, text, values in corpus.FORMS_HIT:
            with self.subTest(name=name):
                found = scan(text, "tool")
                out = masked(text, found)
                for v in values:
                    self.assertNotIn(v, out)
                self.assertIn(OWNER[name], {m.kind for m in found})

    def test_every_form_has_a_positive(self):
        self.assertLessEqual(set(personal.FORMS), set(OWNER.values()))


class FormsChannelTests(unittest.TestCase):
    def test_a_form_never_blocks_a_typed_prompt(self):
        for name, text, values in corpus.FORMS_HIT:
            rule = OWNER[name]
            if rule in personal.FORMS:
                with self.subTest(name=name):
                    self.assertNotIn(rule, {m.kind for m in scan(text, "prompt")})

    def test_every_form_runs_in_the_tool_channel_only(self):
        # a typed question about a form (`How does ::add-mask::x work?`) is no secret, and a hit blocks the prompt
        self.assertEqual({v[1] for v in personal.FORMS.values()}, {"tool"})

    def test_the_indian_address_form_runs_only_in_its_region(self):
        name, text, values = next(x for x in corpus.FORMS_HIT if x[0] == "indian address")
        self.assertIn("address-in-form", {m.kind for m in scan(text, "tool", ("in",))})
        self.assertNotIn("address-in-form", {m.kind for m in scan(text, "tool", ("us", "de"))})


class FormsRegistryTests(unittest.TestCase):
    def test_each_form_has_its_channel_region_and_label_requirement_in_the_registry(self):
        specs = {s.id: s for s in detect.pass_specs() if s.source == "personal"}
        for rid, (typ, channel, region, needs) in personal.FORMS.items():
            with self.subTest(rule=rid):
                spec = specs[rid]
                self.assertEqual((spec.type, spec.channel, spec.region, spec.needs), (typ, channel, region, needs))
                self.assertTrue(spec.rule_class.startswith("form:" if typ == "SECRET" else "pii:"))


if __name__ == "__main__":
    unittest.main()
