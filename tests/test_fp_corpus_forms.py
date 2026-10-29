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
    "name in a declaration": "name-next-to-a-person-cue", "name before born on": "name-next-to-a-person-cue",
    "name after my name is": "name-next-to-a-person-cue", "us address on two lines": "address-us-two-lines",
    "us address on one line": "address-us-one-line",
    "phone encoded": "phone-url-encoded", "phone wrapped": "phone-wrapped-line",
    "encoded mail sent to": "email-percent-encoded", "encoded mail csv cell": "email-percent-encoded",
    "card in groups": "credit-card", "card after pan": "credit-card", "card after a swedish word": "credit-card",
    "postman password counter": "secret-postman-variable", "user slash with words": "secret-after-user-slash",
    # passportNumber in the FHIR system URL is a context word of us-passport, which takes the same value first
    "fhir pretty passport": "us-passport" + "#1", "name patient_name": "name-non-latin-after-label",
    "dl in json": "id-number-after-record-label", "address level": "address-after-label",
    "encoded mail after a line": "email-percent-encoded",
    "card in a csv row": "credit-card", "encoded mail quoted cell": "email-percent-encoded",
    "postman password of words": "secret-postman-variable", "add-mask of words": "secret-add-mask",
    "vcard adr fields": "address-vcard-fields", "vcard n fields": "name-vcard-n",
    "vcard bday digits": "birth-date-vcard-compact", "encoded mail contact column": "email-percent-encoded",
    "phone after a phone word": "phone-after-phone-word", "phone national after a label": "phone-after-phone-word",
    "one first name": "name-single-after-label", "street line after a label": "address-street-after-label",
    "markdown table of persons": "md-table-personal-column",
    "yaml record of a person": "kv-personal-field",
    "password column in a table": "secret-under-password-column",
    "street postcode city": "address-street-postcode-city",
    "sql insert of persons": "sql-insert-personal-column", "html table of persons": "html-table-personal-column",
    "json record of a person": "json-personal-field", "xml record of a person": "xml-personal-field",
    "username in json": "username-after-label", "user_name in yaml": "username-after-label",
    "userName in a log": "username-after-label", "benutzername": "username-after-label",
    "csv with a german social insurance column": "csv-personal-column",
    "tax id under a steuer_id key": "de-tax-id", "username with a year": "username-after-label",
    "username with a team suffix": "username-after-label", "username with a bot-like start": "username-after-label",
    "username service word first": "username-after-label", "username svc first": "username-after-label",
    "username bot first": "username-after-label",
    "username long name worker": "username-after-label", "username long name agent": "username-after-label",
    "username long name svc": "username-after-label",
    "username long name bot": "username-after-label",
    "username with a path part": "username-after-label", "username with a realm": "username-after-label",
    "username with an umlaut": "username-after-label", "username short with digits": "username-after-label",
    "username after an unrelated example key": "username-after-label",
    "username of two dictionary words": "username-after-label", "us bank account number": "us-bank",
    "compact birth date after its label": "birth-date-after-label",
    "password after use the": "secret-password-with-sign", "password after such as": "secret-password-with-sign",
    "password after and password": "secret-password-with-sign",
    "password that ends with a bang": "secret-password-with-sign",
    "password that starts with a hash": "secret-password-with-sign",
    "user name after the label in a sentence": "username-after-label",
    "user name after the label and is": "username-after-label",
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

    def test_many_username_fields_on_one_line_take_linear_time(self):
        # codex Gate A, 2026-10-19: the example check copied the whole line head for each field (8,000 fields: 10 s)
        from _timing import assert_linear
        assert_linear(self, lambda t: scan(t, "tool"),
                      lambda n: ", ".join('"username": "u%dxq"' % i for i in range(n)), 2000)

    def test_a_username_form_masks_its_whole_value_by_its_own_rule(self):
        # codex Gate A, 2026-10-19: a prefix masked by the rule and the rest by another passed the test above
        for name, text, values in corpus.FORMS_HIT:
            if OWNER.get(name) != "username-after-label":
                continue
            spans = {(m.start, m.end) for m in scan(text, "tool") if m.kind == "username-after-label"}
            for v in values:
                with self.subTest(name=name):
                    self.assertIn((text.index(v), text.index(v) + len(v)), spans)

    def test_every_form_has_a_positive(self):
        # from the positives themselves (codex Gate A, 2026-10-19): a name in OWNER without its entry proves nothing
        names = {name for name, _t, _v in corpus.FORMS_HIT}
        self.assertLessEqual(set(OWNER) - names, set(), "an OWNER entry without its positive")
        self.assertLessEqual(set(personal.FORMS), {OWNER[n] for n in names if n in OWNER})


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
