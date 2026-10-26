"""A date of birth after its label in the other label languages and in Greek, Romanian, Ukrainian and Arabic (nym dev,
2026-10-25): the label, an optional copula (ist, est, è, on, jest) and the date. A verb of birth counts only with its
preposition (geboren op, född den), as `born on` does; a date that lies ahead is no birth date.

Run: python3 -m unittest tests.test_birth_date_labels -v
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

BIRTH = "1984-03-" + "12"


def kinds_of(text: str, channel: str = "tool") -> list:
    active = regions.Active(regions=("generic", "de", "us"), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return [(m.kind, text[m.start:m.end]) for m in detect.scan(text, channel=channel)]


class BirthLabelTests(unittest.TestCase):
    LABELS = ("Geboortedatum: {d}", "geboren op {d}", "Födelsedatum: {d}", "född den {d}", "Fødselsdato: {d}",
              "Syntymäaikani on {d}", "Data urodzenia: {d}", "urodzona dnia {d}", "Datum narození: {d}",
              "Doğum tarihim {d}", "Дата рождения: {d}", "дату рождения {d}", "Дата народження {d}",
              "Data nașterii: {d}", "Ημερομηνία γέννησης: {d}", "تاريخ الميلاد {d}", "生年月日：{d}",
              "出生日期: {d}", "생년월일은 {d}", "Mein Geburtsdatum ist {d}", "la mia data di nascita è {d}",
              "nata il {d}", "nascido em {d}")

    def test_a_birth_date_after_its_label_is_masked(self):
        for label in self.LABELS:
            text = "Kundendaten. " + label.format(d=BIRTH) + ", bitte prüfen."
            with self.subTest(label.split()[0]):
                self.assertIn(("birth-date-after-label", BIRTH), kinds_of(text))

    def test_a_typed_prompt_keeps_its_decision(self):
        # the label rules of personal data run on tool output; a typed prompt is the person's own
        self.assertNotIn("birth-date-after-label", [k for k, _ in kinds_of("Geboortedatum: " + BIRTH, "prompt")])

    def test_a_verb_of_birth_alone_and_a_date_ahead_stay_text(self):
        for text in ("Syntynyt 1912-06-23 Helsingissä, hän oli säveltäjä.", "urodzony 1912-06-23 w Krakowie",
                     "född 1912-06-23 i Uppsala", "Doğum tarihi 2099-01-01 olarak girilmiş bir test kaydı",
                     "Geboortedatum: 9999-12-31 (placeholder)", "Datum narození: YYYY-MM-DD"):
            with self.subTest(text[:12]):
                self.assertNotIn("birth-date-after-label", [k for k, _ in kinds_of(text)])


if __name__ == "__main__":
    unittest.main()
