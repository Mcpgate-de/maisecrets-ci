"""The check for a company before an address label reads at most 120 characters of the line (`_line_back`).

In minified JSON a company record can hold its company word farther back than that, and its address is then masked
in a tool result: a false hit. Measured for 0.6.25: reading back to the start of the JSON object removes that false
hit, but the same reach finds an employer or a hotel in a person's record and lets the home address pass. The window
stays at 120 characters (docs/BENCHMARKS.md, "Left out after measuring", 0.6.25). These tests hold the side of the
trade-off that protects a person.

Run: python3 -m unittest tests.test_company_address_window -v
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

ADDRESS = "7 Rosemount Gardens, Dunmore, Wexford " + "4471"
FILL = {"industry": "freight and storage", "employees": 250, "founded": 1998, "tier": "gold",
        "since": "2019-04-01", "notes": "prefers e-invoices, net 30"}


def masked(obj: dict) -> bool:
    text = json.dumps(obj, separators=(",", ":"))
    active = regions.Active(regions=("generic", "us", "uk"), languages=("en",), source="test")
    with detect.Detector(regions=active).activate():
        return any(text[m.start:m.end] == ADDRESS for m in detect.scan(text, channel="tool"))


class CompanyWindowTests(unittest.TestCase):
    def test_a_home_address_far_after_an_employer_stays_masked(self):
        person = {"name": "Dana " + "Okafor", "employer": "Acme Logistics Ltd", **FILL, "home_address": ADDRESS}
        self.assertTrue(masked(person))

    def test_a_home_address_far_after_a_hotel_in_a_note_stays_masked(self):
        person = {"customer": "Dana " + "Okafor", "note": "met at the hotel bar", **FILL, "address": ADDRESS}
        self.assertTrue(masked(person))

    def test_a_company_word_within_the_window_keeps_the_address_text(self):
        self.assertFalse(masked({"company": "Acme Logistics Ltd", "address": ADDRESS}))


if __name__ == "__main__":
    unittest.main()
