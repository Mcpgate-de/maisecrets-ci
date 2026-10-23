"""scripts/draft_format_rules.py: draft prefix rules from catalog rules that maisecrets misses without a label.

Run: python3 -m unittest tests.test_draft_format_rules -v
The catalog rules here are synthetic; every example is built at run time.
"""
from __future__ import annotations

import random
import re
import string
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import draft_format_rules as dfr  # noqa: E402

RNG = random.Random(7)


def tok(prefix: str, n: int) -> str:
    return prefix + "".join(RNG.choice(string.ascii_letters + string.digits) for _ in range(n))


def rule(name: str, rx: str, secrets: list, group=None) -> dict:
    return {"catalog": "cat", "rule": name, "rx": rx, "group": group,
            "pos": [{"text": f"key {s} here", "secret": s} for s in secrets]}


class DraftTests(unittest.TestCase):
    def test_a_prefixed_rule_is_drafted_in_the_form_of_prefixes_txt(self):
        r = rule("acme.token", r"\b(acme_tok_[A-Za-z0-9]{32})\b", [tok("acme_tok_", 32), tok("acme_tok_", 32)])
        kept, dropped = dfr.draft([r], {})
        self.assertEqual(dropped, {})
        line = kept[0]["line"]
        self.assertTrue(line.split(None, 1)[1].startswith(r"acme_tok_(?:(?<![A-Za-z0-9_-]acme_tok_)|"))
        crx = re.compile(line.split(None, 1)[1])
        value = tok("acme_tok_", 32)
        self.assertEqual([m.group(0) for m in crx.finditer(f"use {value} now")], [value])
        self.assertEqual(kept[0]["template"].replace("a", "").replace("A", "").replace("9", ""), "")

    def test_found_short_public_and_unmatched_rules_are_left_out(self):
        found_rule = rule("found", r"(fnd_[a-z0-9]{20})", [tok("fnd_", 20)])
        short = rule("short", r"(ab_[A-Za-z0-9]{30})", [tok("ab_", 30)])
        public = rule("acme client id", r"(acmecid_[A-Za-z0-9]{30})", [tok("acmecid_", 30)])
        wrong = rule("wrong", r"(wrng_[0-9]{30})", [tok("wrng_", 30)])   # its example has letters: the rule misses it
        kept, dropped = dfr.draft([found_rule, short, public, wrong], {("cat", "found"): (True, True)})
        self.assertEqual(kept, [])
        self.assertEqual(sorted(dropped.values()), sorted(["no literal start of four characters",
                                                           "public id, connection string or URL",
                                                           "misses an example of its catalog rule"]))


if __name__ == "__main__":
    unittest.main()
