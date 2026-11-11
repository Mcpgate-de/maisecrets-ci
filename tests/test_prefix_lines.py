"""The short form of rules/prefixes.txt (`id  PREFIX  REST`, detect.prefix_line): one line is the whole contribution.

Run: python3 -m unittest tests.test_prefix_lines -v
For each short line a token is generated at run time from PREFIX and REST, seeded by the rule id; no value sits in the
tree. A line whose REST no token can satisfy, or whose rule does not find its own token whole, turns this red.
"""
from __future__ import annotations

import os
import random
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

import measure_catalog_coverage as mcc  # noqa: E402
from maisecrets import detect  # noqa: E402

FRAME = r"(?:(?<![A-Za-z0-9_-]{p})|(?<=\\[nrt]{p}))"


def short_lines() -> list[tuple[str, str, str]]:
    out = []
    for line in (detect.RULES_DIR / "prefixes.txt").read_text(encoding="utf-8").splitlines():
        parts = line.split(None, 2)
        if not line.startswith("#") and len(parts) == 3 and re.fullmatch(r"[A-Za-z0-9_.:/-]{4,}", parts[1]):
            out.append((parts[0], parts[1], parts[2]))
    return out


class PrefixLineTests(unittest.TestCase):
    def test_the_short_form_is_the_long_form_with_its_edges(self):
        p = re.escape("acme.tok_")
        self.assertEqual(detect.prefix_line("acme-token  acme.tok_  [a-z0-9]{32}"),
                         ("acme-token", p + FRAME.format(p=p) + "[a-z0-9]{32}(?![A-Za-z0-9_-])"))

    def test_a_long_line_stays_as_written(self):
        self.assertEqual(detect.prefix_line("x-token   (?:ab|cd)_[0-9]{20} [x]?"),
                         ("x-token", "(?:ab|cd)_[0-9]{20} [x]?"))
        # a prefix of 3 characters is too short to anchor: the line is read in the long form
        self.assertEqual(detect.prefix_line("x-token  abc  [0-9]{20}"), ("x-token", "abc  [0-9]{20}"))
        self.assertIsNone(detect.prefix_line("# a comment"))
        self.assertIsNone(detect.prefix_line("   "))

    def test_most_rules_use_the_short_form(self):
        self.assertGreater(len(short_lines()), 290)

    def test_each_short_rule_finds_its_own_token_whole(self):
        for rule_id, prefix, rest in short_lines():
            tok = mcc.new_secret(re.escape(prefix) + rest, random.Random(rule_id))
            with self.subTest(rule=rule_id):
                self.assertTrue(tok, "no token satisfies PREFIX and REST")
                for text in (tok, f"here it is: {tok} thanks", f'{{"k": "a\\n{tok}"}}'):
                    self.assertIn((rule_id, tok), [(m.kind, m.value) for m in detect.scan(text, channel="tool")])
                # a token character right before the prefix: no token of this rule starts there
                self.assertNotIn(rule_id, [m.kind for m in detect.scan("x" + tok, channel="tool")])
                # and after the token: the rule does not stop in the middle of a longer word
                self.assertNotIn((rule_id, tok), [(m.kind, m.value) for m in detect.scan(tok + "Z", channel="tool")])


if __name__ == "__main__":
    unittest.main()
