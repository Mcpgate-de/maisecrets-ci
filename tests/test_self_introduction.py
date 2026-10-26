"""A full name after a self-introduction in the other label languages (mein Name ist, je m'appelle, me llamo, mijn naam
is, jag heter, nazywam się, meu nome é, …), as after `my name is` (nym dev, 2026-10-25). The same name check: two name
words at least, which do not read as words. Tool output only.

Run: python3 -m unittest tests.test_self_introduction -v
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

NAME = "Dana " + "Okafor"


def kinds_of(text: str, channel: str = "tool") -> list:
    active = regions.Active(regions=("generic", "de", "us"), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return [(m.kind, text[m.start:m.end]) for m in detect.scan(text, channel=channel)]


class SelfIntroductionTests(unittest.TestCase):
    CUES = ("Mein Name ist {n}", "Je m'appelle {n}", "Mon nom est {n}", "Mi nombre es {n}", "Me llamo {n}",
            "Il mio nome è {n}", "Mi chiamo {n}", "Mijn naam is {n}", "Ik heet {n}", "Jag heter {n}",
            "Mitt namn är {n}", "Jeg heter {n}", "Mit navn er {n}", "Nazywam się {n}", "O meu nome é {n}",
            "Eu me chamo {n}", "Jmenuji se {n}", "Nimeni on {n}", "Numele meu este {n}", "Mă numesc {n}")

    def test_a_full_name_after_a_self_introduction_is_masked(self):
        for cue in self.CUES:
            text = "Hallo, " + cue.format(n=NAME) + " und ich habe eine Frage."
            with self.subTest(cue.split()[0]):
                self.assertIn(("name-next-to-a-person-cue", NAME), kinds_of(text))

    def test_a_typed_prompt_keeps_its_decision(self):
        self.assertNotIn("name-next-to-a-person-cue", [k for k, _ in kinds_of("Je m'appelle " + NAME, "prompt")])

    def test_one_word_a_welcome_and_words_stay_text(self):
        for text in ("Je m'appelle Dana.", "Ich heiße Neue Kollegen herzlich willkommen.",
                     "Mi nombre es Secret Agent", "Mijn naam is Haas", "Jag heter Anna och bor i Lund."):
            with self.subTest(text[:12]):
                self.assertNotIn("name-next-to-a-person-cue", [k for k, _ in kinds_of(text)])


if __name__ == "__main__":
    unittest.main()
