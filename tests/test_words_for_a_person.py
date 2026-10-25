"""The words a person reads for what maisecrets found: one noun per class of the type vocabulary (notices.TYPE_WORDS,
CLASS_WORDS), and the form of a personal-data rule that finds a value only by the words around it.

Run: python3 -m unittest tests.test_words_for_a_person -v
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

from maisecrets import detect, notices  # noqa: E402
from maisecrets.detection.vocabulary import TYPES  # noqa: E402


class NounTests(unittest.TestCase):
    def test_every_class_of_the_vocabulary_has_one_noun(self):
        classes = {v["class"] for v in TYPES.values()}
        self.assertEqual(classes, set(notices.CLASS_WORDS))
        for type_ in TYPES:
            with self.subTest(type_):
                self.assertNotIn("value of the type", notices.type_word(type_))

    def test_the_article_follows_the_sound(self):
        self.assertEqual(notices.type_word("SECRET"), "a secret")
        self.assertEqual(notices.type_word("EMAIL"), "an e-mail address")
        self.assertEqual(notices.type_word("IBAN"), "an IBAN")
        self.assertEqual(notices.type_word("IP"), "an IP address")
        self.assertEqual(notices.type_word("US_SSN"), "an official ID number")
        self.assertEqual(notices.type_word("MY_OWN_TYPE"), "a value of the type MY_OWN_TYPE")

    def test_a_postal_code_and_a_licence_plate_are_no_official_id(self):
        # pii.national_id holds a postal code and licence plates: the class noun would call them an ID of a person
        self.assertEqual(notices.type_word("DE_PLZ"), "a postal code")
        for plate in ("DE_KFZ", "UK_VEHICLE_REGISTRATION", "TR_LICENSE_PLATE", "IN_VEHICLE_REGISTRATION",
                      "NG_VEHICLE_REGISTRATION"):
            self.assertEqual(notices.type_word(plate), "a licence plate", plate)
        self.assertEqual(notices.type_word("DE_VAT_ID"), "a VAT number")


class PersonalFormTests(unittest.TestCase):
    def test_a_personal_rule_that_needs_the_words_around_it_is_a_label_rule(self):
        # name-after-label, phone-after-phone-word, the vCard rules: each finds a value only by the words around it,
        # so its spec must not say shape (a shape is found alone)
        personal = [s for s in detect.pass_specs() if s.source == "personal"]
        self.assertTrue(personal)
        for s in personal:
            with self.subTest(s.id):
                self.assertEqual(s.form, "label" if s.needs else "shape")
        ids = {s.id: s.form for s in personal}
        for rid in ("name-after-label", "phone-after-phone-word", "name-vcard-n", "address-in-form"):
            self.assertEqual(ids[rid], "label", rid)
        self.assertEqual(ids["phone-one-digit-groups"], "shape")

    def test_the_rule_list_keeps_the_form_of_its_ids(self):
        # the form of a rule of the rule list decides the fixture check: it must not move with the words for a person
        for spec, rule in detect.rule_specs():
            self.assertEqual(spec.form, rule.form, spec.key)


class HowFoundTests(unittest.TestCase):
    def test_the_form_sentence_follows_the_rule(self):
        from maisecrets import verdict
        self.assertEqual(verdict.how_found("email"), "format")
        self.assertEqual(verdict.how_found("ds-keyword-colon"), "label")
        self.assertEqual(verdict.how_found("name-after-label"), "label")
        self.assertEqual(verdict.how_found("phone-after-phone-word"), "label")
        self.assertEqual(verdict.how_found("address-in-form"), "words")
        self.assertEqual(verdict.how_found("name-vcard-n"), "words")
        # a rule that fires only with a context word near it is no format found alone
        self.assertEqual(verdict.how_found("de-plz"), "words")

    def test_the_label_shown_never_touches_a_value(self):
        from maisecrets import verdict
        text = "password: abcdefgh"
        self.assertEqual(verdict.label_before(text, 10, [(10, 18)]), "password:")
        self.assertEqual(verdict.label_before("token=abc", 6, [(6, 9)]), "token=")
        self.assertEqual(verdict.label_before("Authorization: Bearer abc", 22, [(22, 25)]), "Bearer")
        # the word before the value is a value itself: no label is shown
        self.assertEqual(verdict.label_before("abcdefgh: xyz", 10, [(0, 8), (10, 13)]), "")

    def test_each_source_has_its_own_sentence_and_no_rule_id(self):
        from types import SimpleNamespace as NS

        from maisecrets import verdict
        cases = {"term:ent-1": "It is on your term list, so it is masked. The AI sees a placeholder that is never put "
                               "back.",
                 "import:abc123:v1": "It is in your imported values (import:abc123). It is masked and never put back "
                                     "into a command.",
                 "user:acme-token": "Your own rule acme-token found it.",
                 "label-password-export": "It is in the password column of a password export, so the whole cell is "
                                          "masked."}
        for kind, want in cases.items():
            m = NS(kind=kind, type="SECRET", value="x" * 12, start=0, end=12)
            self.assertEqual(verdict.hit_sentences("x" * 12, m, None, [(0, 12)])[0], want, kind)
        stored = NS(type="SECRET", ref="REF")
        self.assertEqual(verdict.stored_sentences(stored)[0],
                         "This value is already stored as REF. maisecrets masks it wherever it appears exactly.")


if __name__ == "__main__":
    unittest.main()
