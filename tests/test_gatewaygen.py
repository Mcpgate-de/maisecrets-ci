"""The gateway corpus (bench/gatewaygen.py) and its leaf report (bench/gateway_report.py): the same cases on every run,
each span on its value in the JSON text and in the leaf, mail domains under .internal only, and the gateway's leaf
and prefix rules. The tests never print a value."""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from bench import gateway_report as R  # noqa: E402
from bench import gatewaygen as G  # noqa: E402
from bench import sources  # noqa: E402

SAMPLE = 60


class GatewayCorpusTests(unittest.TestCase):
    def setUp(self):
        self.items = list(G.objects(SAMPLE))

    def test_same_cases_each_run(self):
        self.assertEqual([c["text"] for c in G.generate(SAMPLE)], [c["text"] for c, _, _ in self.items])

    def test_text_is_json_and_spans_sit_on_their_values(self):
        n = 0
        for case, o, obj in self.items:
            json.loads(case["text"])
            values = {v for v, cls, _ in o.values if cls}
            for sp in case["spans"]:
                self.assertIn(case["text"][sp["start"]:sp["end"]], values)
                n += 1
        self.assertGreater(n, 500)

    def test_leaf_spans_sit_on_their_values(self):
        n = 0
        for _, o, obj in self.items:
            values = {v for v, cls, _ in o.values if cls}
            for _, raw in R.leaves(obj):
                text, spans, _ = o.leaf(raw)
                self.assertNotIn("", text)
                for sp in spans:
                    self.assertIn(text[sp["start"]:sp["end"]], values)
                    n += 1
        self.assertGreater(n, 500)

    def test_every_mail_domain_is_internal(self):
        for _, o, _ in self.items:
            for v, cls, kind in o.values:
                if "@" in v and (cls == "pii.email" or kind.endswith("mailbox")):
                    self.assertTrue(v.endswith(".internal"))

    def test_all_classes_and_lookalikes_occur(self):
        classes = {s["class"] for c, _, _ in self.items for s in c["spans"]}
        kinds = {x["kind"] for c, _, _ in self.items for x in c["lookalikes"]}
        self.assertEqual(classes, {"pii.name", "pii.username", "pii.email"})
        self.assertEqual(kinds, {"bot", "project", "product", "branch", "system mailbox", "team mailbox"})

    def test_no_sealed_split(self):
        self.assertEqual({c["split"] for c in G.generate()}, {"dev", "val"})

    def test_registered_source(self):
        self.assertIn("gateway", sources.SOURCES)


class GatewayRulesTests(unittest.TestCase):
    def test_a_list_item_keeps_its_lists_path(self):
        obj = {"reviewers": [{"name": "a"}, {"name": "b"}], "x": {"y": "c"}}
        self.assertEqual(list(R.leaves(obj)), [("reviewers.name", "a"), ("reviewers.name", "b"), ("x.y", "c")])

    def test_prefix_is_the_last_key(self):
        self.assertEqual(R.prefix("author.username"), "username: ")
        self.assertEqual(R.prefix("items.0"), "")
        self.assertEqual(R.prefix("next_page_token"), "")
        self.assertEqual(R.prefix("cursor"), "")
        self.assertEqual(R.prefix("token"), "token: ")

    def test_label_keeps_the_parent_of_a_person_key(self):
        self.assertEqual(R.label("merge_user.username"), "merge_user.username")
        self.assertEqual(R.label("fields.comment.comments.body"), "body")


if __name__ == "__main__":
    unittest.main()
