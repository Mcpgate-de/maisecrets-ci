"""The literal pre-check of the scan (maisecrets/detection/prefilter.py): a built-in rule without keywords whose
leading literal is not in the text is skipped. It must never change a finding: the scan with and without it gives the
same findings on the texts of the repository's own cases.

Run: python3 -m unittest tests.test_rule_prefilter -v
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

from maisecrets.detection import NO_REFERENCES, NO_SOURCES, Active, Detector, Host, prefilter  # noqa: E402


def _detector() -> Detector:
    return Detector(regions=Active(regions=("generic", "de", "us"), languages=("en", "de"), source="prefilter-test"),
                    sources=NO_SOURCES, references=NO_REFERENCES, host=Host(user="", year=2026))


class PrefilterTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(setattr, prefilter, "MIN", prefilter.MIN)

    def test_most_built_in_rules_without_keywords_get_a_literal_and_no_rule_of_your_own_does(self):
        rules = [r for r in _detector().rules() if not r.keywords]
        with_literal = [r for r in rules if r.prefix[0]]
        self.assertGreater(len(with_literal), len(rules) // 2, "the premise: the pre-check applies at all")
        self.assertFalse([r.id for r in with_literal if r.key.startswith("user:")])

    def test_the_findings_are_the_same_with_and_without_it(self):
        from bench import sources
        texts = []
        for name in ("bank", "traces"):
            texts += [(c["text"], c.get("channel", "tool")) for c in list(sources.load(name))[:300]]
        self.assertGreater(len(texts), 300, "the premise: texts to compare")

        def run():
            d = _detector()
            d.reset()
            return [[(m.start, m.end, m.type, m.kind) for m in d.findings(t, channel=ch)] for t, ch in texts]
        prefilter.MIN = 3
        on = run()
        prefilter.MIN = 10 ** 9
        off = run()
        self.assertEqual(on, off)
        self.assertTrue(any(on), "the premise: something is found")


if __name__ == "__main__":
    unittest.main()
