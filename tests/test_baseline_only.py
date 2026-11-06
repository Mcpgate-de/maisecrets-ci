"""The guard of a baseline merge request (scripts/baseline_only.py): it passes measurement results only, so the
branch name chore/baseline-X cannot carry code past the test jobs it skips.

Run: python3 -m unittest tests.test_baseline_only -v
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import baseline_only  # noqa: E402


class BaselineOnlyTests(unittest.TestCase):
    def test_the_files_a_release_gate_keeps_pass(self):
        self.assertEqual(baseline_only.outside([
            "bench/results/2026-11-05-v3-0.8.24/measured.json",
            "bench/results/2026-11-05-v3-0.8.24/holdout-v2/summary.json",
            "bench/HOLDOUT-LOG.md", "docs/coverage.json"]), [])

    def test_any_other_path_is_named(self):
        for path in ("maisecrets/hooks.py", "tests/test_x.py", ".gitlab-ci.yml", "scripts/baseline_only.py",
                     "bench/run.py", "bench/results/README.md", "docs/DETECTION.md", "bench/HOLDOUT-LOG.md.bak",
                     "bench/results/../maisecrets/core.py"):
            with self.subTest(path=path):
                self.assertEqual(baseline_only.outside(["docs/coverage.json", path]), [path])

    def test_the_ci_job_and_the_skips_name_the_same_branch(self):
        ci = (ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
        rule = '$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME =~ /^chore\\/baseline-/'
        self.assertEqual(ci.count(rule), 3)     # the skip of the test jobs, the skip of the matrix, baseline_only
        self.assertIn("python scripts/baseline_only.py", ci)


if __name__ == "__main__":
    unittest.main()
