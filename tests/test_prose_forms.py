"""Secrets in typed sentences that Benchmark V3 found in the clear (aparte dev, 2026-10): a key that the sentence owns
and names ("my stripe key is <value>"), a password with words between its word and the copula ("the wifi password
here is <value>"), and a password that ends with "!".

Run: python3 -m unittest tests.test_prose_forms -v
Every value is built at run time from a seeded random source, so no literal sits in the tree and the tree scan stays
clean. The prose these rules must leave alone is in tests/fp_corpus.py too.
"""
from __future__ import annotations

import os
import random
import string
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402

RNG = random.Random(2310)
ALNUM = string.ascii_letters + string.digits


def key(n: int = 32) -> str:
    while True:
        v = "".join(RNG.choice(ALNUM) for _ in range(n))
        if any(c.isupper() for c in v) and any(c.islower() for c in v) and any(c.isdigit() for c in v):
            return v


def password() -> str:
    """No word and a number: a capital, small letters that make no word, digits and a sign."""
    return (RNG.choice("QXZJ") + "".join(RNG.choice("qxzjkvw") for _ in range(5)) + str(RNG.randint(10, 99))
            + RNG.choice("#%&"))


def hits(text: str) -> list[tuple[str, str]]:
    return [(m.kind, m.value) for m in detect.scan(text)]


def values(text: str) -> list[str]:
    return [v for _, v in hits(text)]


class OwnedKeyTests(unittest.TestCase):
    def test_a_key_that_the_sentence_owns_and_names_is_a_hit(self):
        k = key(32)
        for text in (f"Also my stripe key is {k}, can you check it?",
                     f"Our google api key for the map widget is {k}.",
                     f"my token for the study app is {k} , can you explain it?",
                     f"The session JWT is {k} and it expires soon."):
            self.assertIn(("label-prose-key-owned", k), hits(text), text)

    def test_a_public_key_a_word_and_a_short_value_stay_text(self):
        for text in (f"my Stripe public key for the page is {key(28)}.",
                     "and the shop key on the landing page is pk_" + "live_" + key(24) + ".",
                     "The key is important for the whole team.",
                     "My key for the locker is 4711.",
                     "The token is TokenizerPieceVersionTwo here."):
            self.assertEqual([], [k for k, _ in hits(text) if k == "label-prose-key-owned"], text)


class PasswordWordsIsTests(unittest.TestCase):
    def test_a_password_with_words_before_the_copula_is_a_hit(self):
        pw = password()
        for text in (f"Oh and the wifi password here is {pw} in case you need it.",
                     f"The VPN password we share now is {pw}."):
            self.assertIn(("label-password-words-is", pw), hits(text), text)

    def test_prose_after_the_words_stays_text(self):
        for text in ("The password reset link is valid for one day.",
                     "The password policy here is strict.",
                     "The password you typed is wrong."):
            self.assertEqual([], values(text), text)

    def test_an_exclamation_mark_after_a_prose_password_is_part_of_it(self):
        pw = password()[:-1]
        self.assertIn(pw + "!", values(f"My mail password is {pw}! (don't judge)"))
        # the example of a weak password stays an example with its "!"
        self.assertEqual([], values("The password is " + "Hunter" + "2! Never use it."))


if __name__ == "__main__":
    unittest.main()
