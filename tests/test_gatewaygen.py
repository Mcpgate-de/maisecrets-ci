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

    def test_text_is_json_and_each_span_sits_on_its_own_value(self):
        n = 0
        for case, o, obj in self.items:
            json.loads(case["text"])
            own = [(s, e) for i, s, e in o.placed if o.values[i][1]]
            self.assertEqual([(sp["start"], sp["end"]) for sp in case["spans"]], own)
            for i, s, e in o.placed:
                self.assertEqual(json.loads('"' + case["text"][s:e] + '"'), o.values[i][0])
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


class _Match:
    def __init__(self, start, end, typ):
        self.start, self.end, self.type = start, end, typ


class ReportMetricTests(unittest.TestCase):
    """bench/gateway_report.run and summary with a detector that answers what the test says, and a clock that ticks
    what the test says: precision counts findings, and a response takes the fastest whole pass."""

    def _one(self):
        o = G.Out()
        obj = [{"author": {"name": o.put("x" * 8, "pii.name")}, "title": o.put("Release", kind="project")}]
        case = {"tags": ["service:gitlab"], "lang": "en"}
        return [(case, o, obj)]

    def test_two_findings_on_one_span_are_two_right_findings_and_one_elsewhere_is_a_false_positive(self):
        class Det:
            def findings(self, text, channel, fields=None):
                if text.startswith("name: "):
                    return [_Match(6, 10, "NAME"), _Match(10, 14, "NAME")]
                if text.startswith("title: "):
                    return [_Match(7, 14, "NAME")]
                return []
        r = R.run(Det(), self._one(), repeat=1)
        rep = R.summary(r)
        self.assertEqual((sum(r["hits"].values()), rep["fp"]), (2, 1))
        self.assertEqual(rep["precision"], round(2 / 3, 4))
        self.assertEqual(rep["precision_by_label"]["author.name"]["precision"], 1.0)
        self.assertEqual(rep["precision_by_label"]["title"]["precision"], 0.0)

    def test_a_response_takes_the_fastest_whole_pass_not_a_sum_of_leaf_minima(self):
        class Det:
            def findings(self, text, channel, fields=None):
                return []
        # two leaves, two passes: pass 1 takes 1 + 9 ticks, pass 2 takes 9 + 1; the leaf minima would sum to 2
        ticks = iter([0, 1, 1, 10, 10, 19, 19, 20])
        real = R.time.perf_counter
        R.time.perf_counter = lambda: next(ticks)
        try:
            r = R.run(Det(), self._one(), repeat=2)
        finally:
            R.time.perf_counter = real
        self.assertEqual(r["resp_ms"]["gitlab"], [10 * 1000])


if __name__ == "__main__":
    unittest.main()
