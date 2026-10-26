"""The structured corpus, template set A (bench/structgen.py, docs/BENCHMARK-STRUCTURED.md): the same cases on every
run, each span on its value, the grid of formats, languages and styles complete, and every value synthetic.

The tests read a sample of the cases and never print a value."""
from __future__ import annotations

import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from bench import cases, score, sources, structgen  # noqa: E402
from bench import structvalues as V  # noqa: E402
from bench.structvocab import STYLES  # noqa: E402
from maisecrets.detection import checksums  # noqa: E402

SAMPLE = 26 * 9 * 3     # every format in every language, three times


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _iban_ok(v: str) -> bool:
    v = v.replace(" ", "")
    return int("".join(str(int(c, 36)) for c in v[4:] + v[:4])) % 97 == 1


class StructuredCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = list(structgen.generate(count=SAMPLE))

    def test_the_cases_are_the_same_on_every_run(self):
        self.assertEqual(self.cases[:200], list(structgen.generate(count=200)))
        self.assertIn("structured", sources.SOURCES)
        self.assertEqual(list(sources.load("structured"))[:5], self.cases[:5])

    def test_each_span_lies_on_its_value_and_no_two_overlap(self):
        n = 0
        for c in self.cases:
            text = c["text"]
            marks = sorted([(s["start"], s["end"]) for s in c["spans"]]
                           + [(lk["start"], lk["end"]) for lk in c["lookalikes"]])
            for (a, b), (a2, _) in zip(marks, marks[1:]):
                self.assertLessEqual(b, a2, c["id"])
            for s in c["spans"]:
                n += 1
                v = text[s["start"]:s["end"]]
                self.assertIn(s["class"], cases.CLASSES, c["id"])
                self.assertTrue(v and v == v.strip(), c["id"])
                if "core" in s:
                    a, b = s["core"]
                    self.assertTrue(s["start"] <= a < b <= s["end"], c["id"])
            self.assertIn(c["split"], ("dev", "val"))
            self.assertIn(c["context"], cases.CONTEXTS)
            self.assertTrue(cases.safe_path(c["path"]))
        self.assertGreater(n, 3000, "the premise: the sample has spans")

    def test_the_grid_is_complete(self):
        tags = {t for c in self.cases for t in c["tags"]}
        for name in structgen.FORMAT_NAMES:
            self.assertIn(f"format:{name}", tags)
        for lang in V.LANGS:
            self.assertIn(f"lang:{lang}", tags)
        for style in STYLES:
            self.assertIn(f"style:{style}", tags)
        for kind in structgen.NEG_KINDS:
            self.assertIn(f"neg:{kind}", tags)
        classes = {s["class"] for c in self.cases for s in c["spans"]}
        want = {"pii.name", "pii.email", "pii.phone", "pii.address", "pii.birth_date", "pii.national_id",
                "pii.tax_id", "pii.iban", "pii.card", "pii.bank_account", "pii.username", "pii.ip",
                "secret.password", "secret.token", "secret.private_key", "secret.connection_string"}
        self.assertEqual(want - classes, set())
        neg = sum("kind:negative" in c["tags"] for c in self.cases) / len(self.cases)
        self.assertTrue(0.18 < neg < 0.32, neg)

    def test_every_value_is_synthetic_and_checksum_valid(self):
        """E-mail addresses only under example.com/.org, hosts only under reserved names; each number with a check
        digit passes it. The national checks are the detector's own (an independent second reading of the
        definitions written in bench/structvalues.py)."""
        checks = 0
        for c in self.cases:
            text = c["text"]
            for dom in re.findall(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", text):
                self.assertTrue(dom.endswith(("example.com", "example.org", ".internal")), c["id"])
            for host in re.findall(r"Host: (\S+)", text):
                self.assertTrue(host.endswith((".example.org", ".internal")), c["id"])
            for s in c["spans"]:
                v = text[s["start"]:s["end"]]
                if s["class"] == "pii.iban":
                    self.assertTrue(_iban_ok(v), c["id"])
                elif s["class"] == "pii.card":
                    self.assertTrue(_luhn_ok(re.sub(r"\D", "", v)), c["id"])
                elif s.get("concept") == "national_id" and c["lang"] == "pl":
                    self.assertTrue(checksums.pl_pesel_ok(v), c["id"])
                elif s.get("concept") == "national_id" and c["lang"] == "es":
                    self.assertTrue(checksums.es_nif_ok(v), c["id"])
                elif s.get("concept") == "tax_id" and c["lang"] == "it":
                    self.assertTrue(checksums.it_fiscal_code_ok(v), c["id"])
                elif s.get("concept") == "routing_number":
                    self.assertTrue(checksums.us_aba_ok(v), c["id"])
                else:
                    continue
                checks += 1
        self.assertGreater(checks, 300, "the premise: the sample has checksum numbers")

    def test_a_scanner_that_finds_each_span_scores_full_and_one_that_finds_nothing_scores_zero(self):
        for c in self.cases[:300]:
            perfect = [(s["start"], s["end"], s["class"]) for s in c["spans"]]
            sc = score.score_case(c, perfect, ("secret.", "pii."))
            self.assertEqual({o["outcome"] for o in sc["spans"]} - {"full"}, set(), c["id"])
            self.assertEqual(sc["fp"], 0, c["id"])
            none = score.score_case(c, [], ("secret.", "pii."))
            self.assertEqual({o["outcome"] for o in none["spans"]} - {"missed"}, set(), c["id"])

    def test_a_finding_on_a_lookalike_is_a_false_positive(self):
        c = next(c for c in self.cases if "kind:negative" in c["tags"] and c["lookalikes"])
        lk = c["lookalikes"][0]
        sc = score.score_case(c, [(lk["start"], lk["end"], "pii.phone")], ("secret.", "pii."))
        self.assertEqual(sc["fp"], 1)


if __name__ == "__main__":
    unittest.main()
