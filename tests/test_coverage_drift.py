"""scripts/coverage_drift.py: the weekly drift of the catalog coverage (no network, no catalog here).

Run: python3 -m unittest tests.test_coverage_drift -v
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import coverage_drift as cd  # noqa: E402


class CoverageDriftTests(unittest.TestCase):
    def test_the_rule_list_reads_back_as_written(self):
        rows = [("gitleaks", "a-rule", True, True), ("kingfisher", "k.1", False, True)]
        self.assertEqual(cd.load_rules(cd.dump_rules(rows)),
                         {("gitleaks", "a-rule"): (True, True), ("kingfisher", "k.1"): (False, True)})

    def test_a_new_rule_missed_after_a_label_is_a_gap_and_one_found_only_after_a_label_a_candidate(self):
        before = {("g", "old"): (False, False)}
        rows = [("g", "old", False, False), ("g", "new-gap", False, False), ("g", "new-label", False, True),
                ("g", "new-bare", True, True)]
        self.assertEqual(cd.drift(before, rows), ([("g", "new-gap")], [("g", "new-label")]))

    def test_the_baseline_holds_every_catalog(self):
        rules = cd.load_rules((ROOT / "docs" / "coverage-rules.txt").read_text(encoding="utf-8"))
        self.assertEqual({c for c, _r in rules}, set(cd.CATALOGS))
        self.assertGreater(len(rules), 2000)


if __name__ == "__main__":
    unittest.main()
