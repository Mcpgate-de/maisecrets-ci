"""scripts/draft_researched_rules.py: prefix rules drafted from researched token formats (loop 6).

Run: python3 -m unittest tests.test_draft_researched_rules -v
The formats are made up for the test; no token is written to the tree.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

import draft_researched_rules as drr  # noqa: E402

SRC = {"source": "https://example.com/docs/tokens", "evidence": "code"}
ROWS = [
    {"provider": "Qzv Cloud", "variant": "API key", "regex": "qzvx_[A-Za-z0-9]{32}", **SRC},
    {"provider": "Qzv Cloud", "variant": "test key", "regex": "test_[A-Za-z0-9]{32}", **SRC},
    {"provider": "Qzv Cloud", "variant": "publishable key", "regex": "qzvp_[A-Za-z0-9]{32}", **SRC},
    {"provider": "Qzv Cloud", "variant": "scanner rule", "regex": "qzvs_[A-Za-z0-9]{32}",
     "source": "https://example.com/scanner", "evidence": "scanner"},
    {"provider": "Qzv Cloud", "variant": "dotted", "regex": "qzvd_[A-Za-z0-9.]{30,40}", **SRC},
    {"provider": "GitHub", "variant": "classic PAT", "regex": "gh" + "p_[A-Za-z0-9]{36}", **SRC},
    {"provider": "Qzv Cloud", "variant": "short start", "regex": "qz_[A-Za-z0-9]{32}", **SRC},
]


class DraftResearchedRulesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.det = drr.detector()
        cls.kept, cls.dropped = drr.draft(ROWS, cls.det, {r.id for r in cls.det.rules()})

    def test_a_new_prefixed_format_with_a_first_party_source_is_drafted(self):
        self.assertEqual([k["id"] for k in self.kept], ["qzv-cloud-api-key"])
        self.assertEqual(self.kept[0]["source"], "qzvx_[A-Za-z0-9]{32}")
        self.assertTrue(self.kept[0]["line"].startswith("qzv-cloud-api-key "))

    def test_each_left_out_format_names_its_reason(self):
        self.assertEqual(self.dropped["Qzv Cloud test key"], "generic start 'test_'")
        self.assertEqual(self.dropped["Qzv Cloud publishable key"], "a public id")
        self.assertEqual(self.dropped["Qzv Cloud scanner rule"], "no first-party source")
        self.assertIn("does not take every token whole", self.dropped["Qzv Cloud dotted"])
        self.assertTrue(self.dropped["GitHub classic PAT"].startswith("found already by "))
        self.assertEqual(self.dropped["Qzv Cloud short start"], "no literal start of four characters")

    def test_the_drafted_rule_loads_and_finds_its_tokens_before_punctuation(self):
        import random
        import re
        import measure_catalog_coverage as mcc
        rx = re.compile(self.kept[0]["line"].split(None, 1)[1])
        drafted = mcc.new_secret(ROWS[0]["regex"], random.Random(1))
        self.assertTrue(drr.takes_whole(rx, drafted))

    def test_the_command_writes_three_files_and_no_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            fmt = Path(tmp) / "formats.jsonl"
            fmt.write_text("".join(json.dumps(r) + "\n" for r in ROWS), encoding="utf-8")
            out = Path(tmp) / "drafts"
            self.assertEqual(drr.main([str(fmt), "--out", str(out)]), 0)
            self.assertEqual(sorted(p.name for p in out.iterdir()),
                             ["dropped.txt", "prefixes-draft.txt", "sources-draft.txt"])
            self.assertIn("('qzv-cloud-api-key',", (out / "sources-draft.txt").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
