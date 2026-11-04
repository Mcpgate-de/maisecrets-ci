"""An English word after a token or key label is prose or code in a tool result: no secret (maisecrets#25: 24 of 61
ds-keyword-colon hits over the ai-gateway repository were words). After a password or secret label it stays a hit (a
weak password: DB_PASSWORD in a .env), and in a typed prompt a word after a label stays a hit too."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets.detection import Active, Detector  # noqa: E402

D = Detector(regions=Active(regions=("generic", "de", "us"), languages=("en", "de"), source="keyword words"))
WORDS = ("resp" + "onse", "resol" + "ver", "encry" + "ption", "sun" + "shine")
RANDOM = "Kx9v" + "Q2mLp"


def kinds(text: str, channel: str) -> list:
    return [m.kind for m in D.findings(text, channel=channel)]


class KeywordValueWordTests(unittest.TestCase):
    def test_a_word_after_a_keyword_label_in_a_tool_result_is_no_secret(self):
        for word in WORDS:
            for label in ("token", "api_key", "access_key"):
                with self.subTest(label=label, n=len(word)):
                    self.assertEqual(kinds(f"{label}: {word}", "tool"), [])

    def test_the_same_word_typed_in_a_prompt_stays_a_hit(self):
        for word in WORDS:
            with self.subTest(n=len(word)):
                self.assertTrue(kinds(f"token: {word}", "prompt"))

    def test_a_word_after_a_password_or_secret_label_stays_a_hit_in_a_tool_result(self):
        for word in WORDS:
            for label in ("password", "DB_PASSWORD", "secret", "client_secret"):
                with self.subTest(label=label, n=len(word)):
                    self.assertTrue(kinds(f"{label}: {word}", "tool"))
                    self.assertTrue(kinds(f"{label}:\n  {word}", "tool"))   # the label ends the line before

    def test_a_value_that_is_no_word_stays_a_hit_in_a_tool_result(self):
        self.assertTrue(kinds(f"password: {RANDOM}", "tool"))
        self.assertTrue(kinds("token: " + "sun" + "shine" + "42", "tool"))
        # letters only, but no word: the filter reads it and keeps it
        self.assertIn("ds-keyword-colon", kinds("token: " + "xqzv" + "bnmkwp", "tool"))


if __name__ == "__main__":
    unittest.main()
