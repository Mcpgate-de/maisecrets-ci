"""The keyword test of a line rule: one finder per keyword tuple, the same answer as a test of each word.

The keyword rules skip each line that holds none of their keywords. With the label words of 19 languages, each rule
tested each word in each line, and that cost a fifth of a 1 MB scan (release gate of 0.8.2). The lines are now tested
once per text with one regex, and these tests hold that the answer is the one of `any(k in line for k in keywords)`,
also for keywords that overlap (pass, passe, passwort) and for a regex character in a keyword.

Run: python3 -m unittest tests.test_keyword_lines -v
"""
from __future__ import annotations

import os
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets.detection import core  # noqa: E402

KEYWORDS = ("contrase", "key", "pass", "passe", "passwort", "pwd", "secret", "mot de passe", "a.b", "пароль")
PIECES = ("pass", "passw", "ort", "key", "ke", "y", "a.b", "axb", "mot de", " passe", "пар", "оль", "x", " ", "=")


class KeywordLinesTests(unittest.TestCase):
    def test_the_same_answer_as_a_test_of_each_word(self):
        rnd = random.Random(7)
        lines = ["".join(rnd.choice(PIECES) for _ in range(rnd.randint(0, 6))) for _ in range(3000)]
        text = "\n".join(lines)
        low = core._lower(text).split("\n")
        got = core._keyword_lines(text, low, KEYWORDS)
        want = [any(k in line for k in KEYWORDS) for line in low]
        self.assertEqual(sum(want) > 0 and sum(want) < len(want), True)   # both kinds of line are there
        self.assertEqual(got, want)

    def test_a_regex_character_is_a_literal(self):
        text = "axb\na.b"
        self.assertEqual(core._keyword_lines(text, text.split("\n"), ("a.b",)), [False, True])

    def test_computed_once_per_text_and_tuple(self):
        text = "the password is here\nnothing\nkey = 1"
        low = text.split("\n")
        first = core._keyword_lines(text, low, KEYWORDS)
        self.assertIs(core._keyword_lines(text, low, KEYWORDS), first)
        self.assertEqual(core._keyword_lines(text, low, ("nothing",)), [False, True, False])


if __name__ == "__main__":
    unittest.main()
