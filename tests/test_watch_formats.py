"""scripts/watch_formats.py: the daily watch of the public token-format lists (no network here).

Run: python3 -m unittest tests.test_watch_formats -v
"""
from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import watch_formats as wf  # noqa: E402


class WatchFormatsTests(unittest.TestCase):
    def test_a_new_entry_is_news_and_a_removed_one_is_not(self):
        snap = {"github": ["a", "b"], "veles": ["x"]}
        cur = {"github": ["b", "c"], "veles": ["x"], "trufflehog": ["t"]}
        self.assertEqual(wf.new_entries(snap, cur), {"github": ["c"], "trufflehog": ["t"]})
        self.assertEqual(wf.new_entries(cur, cur), {})

    def test_the_parsers_read_the_ids_of_their_formats(self):
        yml = "- provider: Acme\n  supportedSecret: Acme Key\n  secretType: acme_api_key\n  isPublic: true\n"
        self.assertEqual(wf.github_types(yml + yml.replace("acme_api_key", "acme_pat")), ["acme_api_key", "acme_pat"])
        toml = '[[rules]]\nid = "acme-key"\nregex = "x"\n[[rules]]\n  id = "acme-pat"\n'
        self.assertEqual(wf.betterleaks_ids(toml), ["acme-key", "acme-pat"])

    def test_a_source_that_gives_nothing_stops_the_watch(self):
        # a moved file or folder must turn the job red, not read as "no new entry"
        with mock.patch.dict(wf.SOURCES, {"github": lambda: ["a"], "veles": lambda: []}, clear=True):
            with self.assertRaises(SystemExit):
                wf.fetch_all()

    def test_check_exits_1_and_names_each_new_entry(self):
        snap = {"github": ["a"]}
        with mock.patch.object(wf, "fetch_all", return_value={"github": ["a", "b"]}), \
                mock.patch.object(wf, "SNAPSHOT", mock.Mock(read_text=lambda **_k: wf.dump(snap))):
            out = io.StringIO()
            with redirect_stdout(out):
                code = wf.main(["check"])
        self.assertEqual(code, 1)
        self.assertIn("github: 1 new: b", out.getvalue())

    def test_the_snapshot_text_reads_back_as_written(self):
        lists = {"github": ["b_type", "a_type"], "veles": ["x"]}
        self.assertEqual(wf.load(wf.dump(lists)), {"github": ["a_type", "b_type"], "veles": ["x"]})

    def test_the_snapshot_holds_every_source(self):
        snap = wf.load((ROOT / "docs" / "format-watch.txt").read_text(encoding="utf-8"))
        self.assertEqual(set(snap), set(wf.SOURCES))
        self.assertTrue(all(len(v) > 40 for v in snap.values()))


if __name__ == "__main__":
    unittest.main()
