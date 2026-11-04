"""A response scan of findings_by_leaf walks only the rules that can fire somewhere in the response
(prefilter.rules_for): the findings are the same as with every rule, on records built from the corpus texts."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets.detection import Active, Detector, leaves, prefilter  # noqa: E402
from test_required_literals import _texts  # noqa: E402

D = Detector(regions=Active(regions=("generic", "de", "us"), languages=("en", "de"), source="response rules"))
KEYS = ("note", "password", "email", "address", "description", "token", "name", "phone", "comment", "body")


def _records() -> list:
    texts = _texts()
    out = []
    for i in range(0, len(texts), 5):
        chunk = texts[i:i + 5]
        out.append({"items": [{KEYS[(i + j) % len(KEYS)]: t for j, t in enumerate(chunk)},
                              {KEYS[(i + j + 3) % len(KEYS)]: t for j, t in enumerate(reversed(chunk))}]})
    return out


def _spans(obj) -> list:
    return [(leaf.path if leaf else None, m.start, m.end, m.kind) for leaf, m in leaves.findings_by_leaf(D, obj)]


class ResponseRulesTests(unittest.TestCase):
    def test_the_findings_are_the_same_with_every_rule(self):
        records = _records()
        self.assertGreater(len(records), 100, "premise: the corpora are there")
        used = []
        real = leaves._response_order

        def counting(*a, **k):
            got = real(*a, **k)
            used.append(got)
            return got
        with mock.patch.object(leaves, "_response_order", counting):
            subset = [_spans(r) for r in records]
        self.assertTrue(any(u for u in used), "premise: a subset was used")
        every = len(D._run(lambda: __import__("maisecrets.detection.core", fromlist=["x"]).rules()))
        self.assertTrue(any(u and len(u) < every / 2 for u in used), "premise: the subset is small")
        with mock.patch.object(leaves, "_response_order", lambda *a, **k: None):
            full = [_spans(r) for r in records]
        self.assertEqual(subset, full)

    def test_the_three_letter_filter_picks_the_rules_the_plain_checks_pick(self):
        # rules_for answers `word in low` first by the three-letter pieces of the text: a word with a piece the text
        # lacks cannot be in it. The plain checks of the scan must pick the same rules, in the same order
        from maisecrets.detection import core
        order = D._run(lambda: core._in_scan_order(core.rules()))
        texts = _texts() + ["\u015e\u0130FRE: x", "\u0130stanbul password: y", "\u017fecret \u0131",
                            "\u03a3 token \u03a3\u03a3", "ab", "", "x" * 3]
        checked = 0
        for t in texts:
            low = core._lower(t)
            known: dict = {}
            plain = tuple(r for r in order if not hasattr(r, "keywords") or (
                not (r.keywords and not prefilter.any_keyword(r.keywords, low, known))
                and not prefilter.lacks_prefix(r.prefix, t, low) and not prefilter.lacks_required(r.need, t, low)))
            self.assertEqual(prefilter.rules_for(order, t, low), plain)
            checked += 1
        self.assertGreater(checked, 100, "premise: the corpora are there")

    def test_only_the_exact_text_takes_the_subset(self):
        text = "password: x"
        with prefilter.with_response_rules(text, ("only",)):
            self.assertEqual(prefilter.response_rules(text), ("only",))
            same_letters = "".join(["password: ", "x"])          # built at run time: another object, equal text
            self.assertEqual(same_letters, text)
            self.assertIsNone(prefilter.response_rules(same_letters))
        self.assertIsNone(prefilter.response_rules(text))


if __name__ == "__main__":
    unittest.main()
