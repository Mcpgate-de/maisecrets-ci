"""The leading literals worked out ahead (maisecrets/detection/rules/leading_literals.json) are those the parser gives,
for every built-in pattern of every region and language, and a pattern the file lacks is parsed as before."""
from __future__ import annotations

import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT / "scripts"))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

import gen_leading_literals as gen  # noqa: E402
from maisecrets.detection import core, prefilter, registry  # noqa: E402


class LeadingLiteralTests(unittest.TestCase):
    def test_the_file_is_the_parser_s_answer_for_every_pattern(self):
        want = gen.wanted()
        self.assertGreater(len(want), 400, "premise: the built-in patterns are there")
        self.assertEqual(prefilter._known(), want, "stale: run scripts/gen_leading_literals.py")

    def test_each_rule_gets_the_same_literal_from_the_file_as_from_the_parser(self):
        n = 0
        for source, rules in core._rule_sources(gen.every_region()):
            for r in rules:
                m = registry.matcher_of(r.id, source)
                if r.keywords or source == "user" or m not in ("", "regex"):
                    continue
                n += 1
                self.assertEqual(prefilter.leading_literal(r.regex, m, r.keywords, source),
                                 prefilter.parsed_literal(r.regex), r.id)
        self.assertGreater(n, 400)

    def test_a_pattern_the_file_lacks_is_parsed(self):
        rx = re.compile("zq_" + "[a-z]{20}" + "_not_in_the_file")
        self.assertNotIn(prefilter.literal_key(rx.pattern, rx.flags), prefilter._known())
        self.assertEqual(prefilter.leading_literal(rx, "", (), "betterleaks"), ("zq_", False))

    def test_a_changed_flag_is_another_key(self):
        rx, ri = re.compile("ghx_[a-z]{9}"), re.compile("ghx_[a-z]{9}", re.IGNORECASE)
        self.assertNotEqual(prefilter.literal_key(rx.pattern, rx.flags), prefilter.literal_key(ri.pattern, ri.flags))
        self.assertEqual(prefilter.leading_literal(ri, "", (), "betterleaks"), ("ghx_", True))


if __name__ == "__main__":
    unittest.main()
