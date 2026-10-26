"""bench/ghissues.py: the split by issue, the core of a candidate, the cases of a record and the metrics. Synthetic
values only."""
import collections
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import ghissues, score  # noqa: E402


class GhIssuesTests(unittest.TestCase):
    def test_the_split_is_by_issue_and_fixed(self):
        self.assertEqual(ghissues.issue_of("https://github.com/Owner/Repo/issues/12"), "owner/repo#12")
        got = collections.Counter(ghissues.split_of(f"o/r#{n}") for n in range(2000))
        self.assertEqual(set(got), {"dev", "holdout"})
        self.assertGreater(min(got.values()), 900)
        self.assertEqual(ghissues.split_of("o/r#7"), ghissues.split_of("o/r#7"))

    def test_the_core_is_the_secret_inside_the_match(self):
        tok = "Ab3" * 8
        for cand, core in ((tok, tok), (f'api_key = "{tok}"', tok), (f"password: {tok}", tok),
                           (f"key={tok}==", f"{tok}=="), (f"https://u:{tok}@host.test/x", tok),
                           (f"?token={tok}&page=2", tok), (f"'{tok}'", tok)):
            a, b = ghissues.core_of(cand)
            self.assertEqual(cand[a:b], core, cand.replace(tok, "<tok>"))

    def test_a_record_gives_spans_negatives_and_neutral_values(self):
        tok, neg, both = "Zx9" * 8, "Qw7" * 8, "Er5" * 8
        body = f"token: {tok}\nother {neg} and {both} and {tok}"
        rec = {"issue": "o/r#1", "texts": [{"body": body, "candidates": [
            {"value": f"token: {tok}", "label": 1, "secret_type": "Generic Pattern"},
            {"value": tok, "label": 1, "secret_type": "Alibaba API"},
            {"value": neg, "label": 0, "secret_type": "Anypoint API"},
            {"value": both, "label": 1, "secret_type": "Alibaba API"},
            {"value": both, "label": 0, "secret_type": "Alibaba API"},
            {"value": "absent" * 4, "label": 1, "secret_type": "Alibaba API"}]}]}
        stats = collections.Counter()
        (case,) = ghissues.cases_of(rec, "dev", stats)
        true = [s for s in case["spans"] if not s.get("neutral")]
        self.assertEqual(len(true), 2, "the keyed match and the bare value share one core; the second place counts")
        self.assertEqual(len([s for s in case["spans"] if s.get("neutral")]), 1)
        self.assertEqual(len(case["negatives"]), 1)
        self.assertEqual(stats["true values not in the body (left out)"], 1)
        # a finding on the first core and one on the false candidate; one on free text is out of scope
        at, ng = body.index(tok), body.index(neg)
        fr = body.index("other")
        found = [(at, at + len(tok), "secret"), (ng, ng + 3, "secret"), (fr, fr + 5, "secret")]
        sc = score.score_case(case, found, ("secret.",))
        sc["found"] = [(s, e) for s, e, _ in found]
        m = ghissues.metrics([(case, sc)])
        self.assertEqual((m["spans"], m["full"], m["on_target"], m["fp"], m["findings_out_of_scope"]),
                         (2, 1, 1, 1, 1))
        self.assertEqual((m["recall_strict"], m["precision"]), (0.5, 0.5))

    def test_a_half_is_refused_when_it_differs_from_the_seal_or_both_are_asked_for(self):
        with self.assertRaises(ghissues.DataError):
            list(ghissues.records(Path("/nonexistent"), "all"))
        with self.assertRaises(ghissues.DataError):
            list(ghissues.records(Path("/nonexistent"), "dev"))


if __name__ == "__main__":
    unittest.main()
