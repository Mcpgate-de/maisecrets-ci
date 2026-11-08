"""The repository stays well under the 200 MB that the claude.ai organisation sync takes (0.9.0 reached 202 MB and
its sync failed), and the pruning of old baselines keeps what the docs, tests and scripts name.

Run: python3 -m unittest tests.test_tree_size -v
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import prune_baselines as P  # noqa: E402

TREE_MAX_MB = 150


class TreeSizeTests(unittest.TestCase):
    def test_the_tracked_files_stay_under_the_limit(self):
        names = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True).stdout.split("\0")
        total = sum((ROOT / n).stat().st_size for n in names if n and (ROOT / n).is_file())
        self.assertLess(total / 2 ** 20, TREE_MAX_MB, "run scripts/prune_baselines.py")

    def test_the_pruning_keeps_the_newest_baselines_and_every_named_one(self):
        gone = {p.name for p in P.to_remove()}
        releases = sorted((p.name for p in (ROOT / "bench" / "results").iterdir() if P._RELEASE.fullmatch(p.name)),
                          key=lambda n: tuple(int(g) for g in P._RELEASE.fullmatch(n).groups()))
        self.assertFalse(gone & set(releases[-P.KEEP:]), "the newest baselines stay")
        self.assertFalse(gone & P.named(), "a folder that a doc, a test or a script names stays")
        self.assertIn("2026-11-01-v3-0.8.7", P.named(), "a run named after a folder keeps that folder")


if __name__ == "__main__":
    unittest.main()
