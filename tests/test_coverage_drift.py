"""scripts/coverage_drift.py: the weekly drift of the catalog coverage (no network, no catalog here).

Run: python3 -m unittest tests.test_coverage_drift -v
"""
from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT / "scripts"))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

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

    def test_a_catalog_that_reads_0_rules_turns_the_job_red_by_name_and_the_result_is_written(self):
        try:
            import tomllib  # noqa: F401
        except ImportError:
            self.skipTest("tomllib is Python 3.11+")
        root = Path(tempfile.mkdtemp(prefix="catalogs-"))
        (root / "betterleaks" / "rules").mkdir(parents=True)   # a layout that no reader of the script knows
        (root / "betterleaks" / "rules" / "x.go").write_text("package rules\n", encoding="utf-8")
        out, buf = root / "drift.json", io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cd.main([str(root), "--out", str(out)])
        self.assertEqual(code, 1)
        self.assertIn("UNREAD     betterleaks\t0 rules read at", buf.getvalue())
        self.assertTrue(out.is_file())    # scripts/draft_format_rules.py reads it next


if __name__ == "__main__":
    unittest.main()
