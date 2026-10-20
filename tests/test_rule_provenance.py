"""scripts/rule_provenance.py: one row per rule, and docs/rule-limits.json names only rules that exist.

Run: python3 -m unittest tests.test_rule_provenance -v
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

import rule_provenance  # noqa: E402


class RuleProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        known = rule_provenance.limits()
        cls.rows = [rule_provenance.row(s, r, known) for s, r in rule_provenance.specs()]

    def test_every_rule_has_one_row_with_its_source_class_and_licence(self):
        keys = [r["key"] for r in self.rows]
        self.assertGreater(len(keys), 600, "the premise: every region is on")
        self.assertEqual(len(keys), len(set(keys)))
        for r in self.rows:
            with self.subTest(key=r["key"]):
                self.assertTrue(r["source"] and r["class"] and r["type"] and r["licence"])
                self.assertEqual(r["upstream"] is not None, r["origin"] in ("vendored", "patched"))

    def test_every_limit_names_a_rule_or_a_family(self):
        ids = {r["id"].split("#")[0] for r in self.rows}
        families = {r["class"] for r in self.rows}
        for key in rule_provenance.limits():
            with self.subTest(key=key):
                if key.startswith("class:"):
                    self.assertIn(key[len("class:"):], families)
                else:
                    self.assertIn(key, ids)

    def test_a_row_holds_no_regex_and_no_value(self):
        text = json.dumps(self.rows)
        self.assertNotIn("(?", text)
        self.assertNotIn("\\\\d", text)


if __name__ == "__main__":
    unittest.main()
