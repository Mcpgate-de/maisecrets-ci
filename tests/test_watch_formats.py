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
        self.assertEqual(sorted(wf.github_entries(yml + yml.replace("acme_api_key", "acme_pat"))),
                         ["acme_api_key", "acme_pat"])
        toml = '[[rules]]\nid = "acme-key"\nregex = "x"\n[[rules]]\n  id = "acme-pat"\n'
        self.assertEqual(sorted(wf.toml_rules(toml)), ["acme-key", "acme-pat"])
        go = 'var rules = []Rule{\n\t{\n\t\tID:              "acme-key",\n\t\tCategory: CategoryAcme,\n\t},\n'
        self.assertEqual(sorted(wf.trivy_rules(go + go.replace("acme-key", "acme-pat"))), ["acme-key", "acme-pat"])
        np_yml = "rules:\n- name: Acme Key\n  id: np.acme.1\n  pattern: x\n- name: Acme PAT\n  id: np.acme.2\n"
        self.assertEqual(sorted(wf.yaml_rules(np_yml)), ["np.acme.1", "np.acme.2"])

    def test_a_changed_rule_text_changes_only_its_own_fingerprint(self):
        toml = '[[rules]]\nid = "acme-key"\nregex = "acme_[a-z]{32}"\n[[rules]]\nid = "acme-pat"\nregex = "x"\n'
        before = wf.toml_rules(toml)
        after = wf.toml_rules(toml.replace("{32}", "{40}"))
        self.assertNotEqual(before["acme-key"], after["acme-key"])
        self.assertEqual(before["acme-pat"], after["acme-pat"])

    def test_a_changed_fingerprint_is_news_and_a_new_id_or_a_bare_list_is_no_change(self):
        snap_fp = {"betterleaks": {"a": "111", "b": "222"}}
        cur = {"betterleaks": {"a": "111", "b": "999", "c": "333"}, "trufflehog": ["t"]}
        self.assertEqual(wf.changed_entries(snap_fp, cur), {"betterleaks": ["b"]})
        self.assertEqual(wf.load_fp(wf.dump_fp(cur)), {"betterleaks": {"a": "111", "b": "999", "c": "333"},
                                                       "trufflehog": {}})

    def test_every_source_has_a_section_in_the_snapshot(self):
        # a source without a section reports its whole list as new on the first run
        self.assertEqual(set(wf.SOURCES) - set(wf.load(wf.SNAPSHOT.read_text(encoding="utf-8"))), set())

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
