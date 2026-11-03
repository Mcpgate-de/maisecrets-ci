"""A rule with no other gate runs its regex only when an ASCII text holds one of the literals every match of it holds
(prefilter.required_literals): a text that holds none cannot hold a match, and any other text runs the rule."""
from __future__ import annotations

import os
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

import fp_corpus  # noqa: E402
import fp_corpus_forms  # noqa: E402
import fp_corpus_pii  # noqa: E402
from bench import cases as bench_cases  # noqa: E402
from maisecrets.detection import Active, Detector, core, prefilter  # noqa: E402
from maisecrets.detection.regions import REGION_LANGUAGE, label_languages_available  # noqa: E402


def _detector() -> Detector:
    d = Detector(regions=Active(regions=("generic", *sorted(REGION_LANGUAGE)),
                                languages=tuple(label_languages_available()), source="required literals"))
    d.findings("x", channel="tool")
    return d


def _texts() -> list:
    """The texts of the repository's corpora: the conformance inputs, the hits and the developer text of the three
    corpora, and the dev and val cases of the bank (never its holdout)."""
    import json
    out = [c["input"] for c in json.loads((ROOT / "tests" / "conformance" / "cases.json").read_text())["cases"]]
    for rows in (fp_corpus.HIT, fp_corpus.NO_HIT, fp_corpus_pii.POSITIVE, fp_corpus_pii.PII_NO_HIT,
                 fp_corpus_forms.FORMS_HIT, fp_corpus_forms.FORMS_NO_HIT):
        out += [r[1] for r in rows if isinstance(r[1], str)]
    for split in ("dev", "val"):
        out += [c["text"] for c in bench_cases.load_bank(ROOT / "bench" / "bank", split)]
    return [t.replace("§", "") for t in out]


class RequiredLiteralTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.det = _detector()
        cls.gated = [r for r in cls.det.rules() if r.need]

    def test_rules_without_another_gate_get_their_literals(self):
        self.assertGreater(len(self.gated), 30, "premise: most ungated rules get a gate")
        by_id = {r.id: r.need for r in self.gated}
        self.assertEqual(by_id.get("email-percent-encoded"), ("%40",))
        for r in self.gated:
            self.assertFalse(r.keywords or r.prefix[0], f"{r.id} has another gate already")

    def test_every_match_in_an_ascii_text_holds_one_of_the_literals(self):
        texts = [t for t in _texts() if t.isascii()]
        self.assertGreater(len(texts), 500, "premise: the corpora are there")
        matched = 0
        for r in self.gated:
            rx = re.compile(r.regex.pattern, r.regex.flags)
            for t in texts:
                if rx.search(t):
                    matched += 1
                    self.assertTrue(any(x in t.lower() for x in r.need), f"{r.id} matches a text without {r.need}")
        self.assertGreater(matched, 20, "premise: the gated rules match some corpus texts")

    def test_the_findings_are_the_same_with_and_without_the_gate(self):
        texts = _texts()
        skipped = [0]
        real = prefilter.lacks_required

        def counting(need, text, low):
            out = real(need, text, low)
            skipped[0] += out
            return out
        with mock.patch.object(core, "_lacks_required", counting):
            with_gate = [[(m.start, m.end, m.kind) for m in self.det.findings(t, channel="tool")] for t in texts]
        self.assertGreater(skipped[0], 1000, "premise: the gate skips rules on these texts")
        with mock.patch.object(core, "_lacks_required", lambda *a: False):
            without = [[(m.start, m.end, m.kind) for m in self.det.findings(t, channel="tool")] for t in texts]
        self.assertEqual(with_gate, without)

    def test_a_text_that_is_not_ascii_always_runs_the_rule(self):
        self.assertFalse(prefilter.lacks_required(("%40",), "café no literal", "café no literal"))
        self.assertTrue(prefilter.lacks_required(("%40",), "no literal here", "no literal here"))
        self.assertFalse(prefilter.lacks_required(("%40",), "a%40b", "a%40b"))
        self.assertFalse(prefilter.lacks_required((), "anything", "anything"))

    def test_a_folded_letter_still_reaches_the_rule(self):
        # re.IGNORECASE matches dotless i and long s against i and s; str.lower() does not, so such a text must run
        # the rule (second-model review, 2026-11-03)
        tail = "Zq7x" * 6
        for rid, text in (("url-query-secret", "https://x.example.com/cb?ſecret=" + tail),
                          ("label-prose-key", "the apı key is " + tail)):
            with self.subTest(rule=rid):
                r = next(x for x in self.gated if x.id == rid)
                self.assertTrue(re.compile(r.regex.pattern, r.regex.flags).search(text), "premise: the rule matches")
                with_gate = [(m.start, m.end, m.kind) for m in self.det.findings(text, channel="tool")]
                with mock.patch.object(core, "_lacks_required", lambda *a: False):
                    without = [(m.start, m.end, m.kind) for m in self.det.findings(text, channel="tool")]
                self.assertTrue(without, "premise: something is found")
                self.assertEqual(with_gate, without)

    def test_no_literal_holds_a_letter_that_folds_to_ascii(self):
        for r in self.gated:
            for x in r.need:
                self.assertFalse(any(prefilter._folds_to_ascii(ch) for ch in x if not ch.isascii()), r.id)
        self.assertTrue(prefilter._folds_to_ascii("ſ") and prefilter._folds_to_ascii("K"))
        self.assertFalse(prefilter._folds_to_ascii("密"))

    def test_the_file_holds_the_parser_s_literals(self):
        for r in self.gated:
            self.assertEqual(r.need, prefilter.parsed_required(r.regex), r.id)


if __name__ == "__main__":
    unittest.main()
