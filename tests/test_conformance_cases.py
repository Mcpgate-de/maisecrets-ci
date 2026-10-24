"""The normative conformance cases (tests/conformance/cases.json, format of docs/DETECTION-SPEC-DRAFT.md).

Each case names the spans that must be masked whole (start, end, type) and the spans that must stay text. A second
implementation would run the same file; here it holds the boundary decisions of the detection core. A case is judged
on start, end and type only, not on the rule id. A case may give `context.fields` (start, end and the field path
`name` of a value, docs/DETECTION-CONTRACT-PROPOSAL.md); the scan then takes them as `fields`.

Run: python3 -m unittest tests.test_conformance_cases -v
"""
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

from maisecrets import detect, regions  # noqa: E402

CASES = json.loads((ROOT / "tests" / "conformance" / "cases.json").read_text(encoding="utf-8"))["cases"]


def hits(case: dict) -> list:
    active = regions.Active(regions=tuple(case["regions"]), languages=tuple(case["languages"]), source="conformance")
    with detect.Detector(regions=active).activate():
        return detect.scan(case["input"], channel=case["channel"], fields=fields_of(case))


def fields_of(case: dict):
    """The optional context.fields of a case as the API takes them: (start, end, name path), or None."""
    given = case.get("context", {}).get("fields")
    return None if given is None else [(f["start"], f["end"], tuple(f["name"])) for f in given]


class ConformanceCaseTests(unittest.TestCase):
    def test_the_file_holds_normative_cases_with_offsets_inside_their_text(self):
        self.assertGreaterEqual(len(CASES), 10, "the premise: the file has cases")
        for c in CASES:
            with self.subTest(case=c["id"]):
                self.assertEqual(c["kind"], "normative")
                for s in c["expected"] + c["not_expected"]:
                    self.assertTrue(0 <= s["start"] < s["end"] <= len(c["input"]))
                for f in c.get("context", {}).get("fields", []):
                    self.assertTrue(0 <= f["start"] < f["end"] <= len(c["input"]) and f["name"])

    def test_each_expected_span_is_masked_whole_with_its_type(self):
        for c in CASES:
            found = {(m.start, m.end, m.type) for m in hits(c)}
            for s in c["expected"]:
                with self.subTest(case=c["id"], span=(s["start"], s["end"])):
                    self.assertIn((s["start"], s["end"], s["type"]), found)

    def test_no_hit_of_the_type_touches_a_span_that_must_stay_text(self):
        for c in CASES:
            ms = hits(c)
            for s in c["not_expected"]:
                with self.subTest(case=c["id"], span=(s["start"], s["end"])):
                    touching = [m for m in ms if m.type == s["type"] and m.start < s["end"] and s["start"] < m.end]
                    self.assertEqual([], [(m.kind, m.start, m.end) for m in touching])


if __name__ == "__main__":
    unittest.main()
