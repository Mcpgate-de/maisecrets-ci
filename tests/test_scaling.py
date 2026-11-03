"""The time of a scan grows at most linearly with the number of hits in one text.

The release gate times 1 MB of ordinary text, which holds few hits, so a step that is quadratic in the hits passes it:
personal._address_with_its_place compared each address hit with every other one (16,000 addresses in one text took
129 s on the reference host, 2026-11-03), and the hook's watchdog then withheld the whole tool result. Each test here
scans a hit-dense text with N and 4N hits and compares the CPU time: linear gives about 4, quadratic about 16, and
the limit 8 lies between them. A ratio in one process holds under the load of a CI runner, where a time would not.
"""
from __future__ import annotations

import itertools
import os
import random
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets.detection import Active, Detector, leaves, personal  # noqa: E402

LIMIT = 8.0
DOMAIN = "nord" + "werk.internal"
STREETS = ("Harbor", "Maple", "Oak", "Cedar", "Pine", "Lake", "Hill", "River")


def _detector() -> Detector:
    d = Detector(regions=Active(regions=("generic", "de", "us"), languages=("en", "de"), source="test"))
    d.findings("warm up", channel="tool")
    return d


def _cpu(fn) -> float:
    """The CPU time of one call, best of 3; each trial repeats the call until 0.1 s have passed, so a clock that ticks
    every 15.6 ms (Windows) measures a short call too (a 0 there made the ratio 15,625)."""
    best = float("inf")
    for _ in range(3):
        n, t0 = 0, time.process_time()
        while True:
            fn()
            n += 1
            spent = time.process_time() - t0
            if spent >= 0.1:
                break
        best = min(best, spent / n)
    return best


class ScalingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.det = _detector()

    def ratio(self, make, n: int, channel: str = "tool", want: str | None = None) -> float:
        small, large = make(n), make(4 * n)
        if want is not None:
            # the premise: the text really holds the hits of the family it stands for
            kinds = [m.kind for m in self.det.findings(small, channel=channel)]
            self.assertGreaterEqual(kinds.count(want), n, f"premise: {n} hits of {want}")
        return _cpu(lambda: self.det.findings(large, channel=channel)) / \
            _cpu(lambda: self.det.findings(small, channel=channel))

    def test_address_hits(self):
        def make(n):
            return "\n".join(f"Address: {100 + i} {STREETS[i % 8]} Street, Springfield, IL {62000 + i % 900}"
                             for i in range(n))
        self.assertLess(self.ratio(make, 400, want="street-address"), LIMIT)

    def test_the_address_place_step_alone(self):
        # the whole scan dilutes a quadratic step until about 2,000 addresses (its other steps are linear and larger),
        # so the step is timed alone: 1,000 and 4,000 address hits of a street rule, each followed by its place
        def args(n):
            lines = [f"{100 + i} {STREETS[i % 8]} Street, 12345 Berlin" for i in range(n)]
            text, out, at = "\n".join(lines), [], 0
            for line in lines:
                out.append((at, at + line.index(","), "street-address", personal.ADDRESS))
                at += len(line) + 1
            return text, out
        small, large = args(1000), args(4000)
        got = personal._address_with_its_place(*small)
        self.assertGreater(sum(e > s0[1] for (_s, e, _k, _t), s0 in zip(got, small[1])), 900,
                           "premise: the step widens the hits")
        r = _cpu(lambda: personal._address_with_its_place(*large)) / \
            _cpu(lambda: personal._address_with_its_place(*small))
        self.assertLess(r, LIMIT)

    def test_email_hits(self):
        def make(n):
            return "\n".join(f"contact u{i}.x@{DOMAIN} for build {i}" for i in range(n))
        self.assertLess(self.ratio(make, 500, want="email"), LIMIT)

    def test_phone_hits_after_a_phone_word(self):
        def make(n):
            return "\n".join(f"Telefon: 0{30 + i % 60} {4000000 + i * 7}" for i in range(n))
        self.assertLess(self.ratio(make, 400, want="phone-after-phone-word"), LIMIT)

    def test_password_hits_after_a_label(self):
        def make(n):
            rng = random.Random(n)
            return "\n".join("password: " + "".join(rng.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(14))
                             for _ in range(n))
        self.assertLess(self.ratio(make, 400, want="ds-keyword-colon"), LIMIT)

    def test_names_after_a_german_title(self):
        ends = ("bach", "berg", "feld", "hof", "mann", "dorf", "brink", "kamp")

        def make(n):
            return "\n".join(f"Bitte an Frau {STREETS[i % 8]}{ends[(i // 8) % 8]} weiterleiten." for i in range(n))
        self.assertLess(self.ratio(make, 400, want="name-after-german-title"), LIMIT)

    def test_records_of_a_json_response(self):
        def make(n):
            return {"items": [{"id": i, "name": f"build {i}", "email": f"u{i}.x@{DOMAIN}",
                               "address": f"{100 + i} {STREETS[i % 8]} Street, Springfield, IL 62704"}
                              for i in range(n)]}
        small, large = make(100), make(400)
        r = _cpu(lambda: leaves.findings_by_leaf(self.det, large)) / \
            _cpu(lambda: leaves.findings_by_leaf(self.det, small))
        self.assertLess(r, LIMIT)


def _address_with_its_place_all_pairs(text: str, out: list) -> list:
    """The version before 2026-11-03: each hit against every other one. The reference of the equivalence test."""
    if not any(k in personal._ADDRESS_RULES_WITH_PLACE for _s, _e, k, _t in out):
        return out
    res = []
    wider = [(s, e) for s, e, _k, typ in out if typ == personal.ADDRESS]
    for s, e, k, typ in out:
        if typ == personal.ADDRESS and k in personal._ADDRESS_RULES_WITH_PLACE \
                and not any(s2 <= s and e2 > e for s2, e2 in wider):
            m = personal._PLACE_AFTER_RE.match(text, e)
            if m:
                e = m.end()
        res.append((s, e, k, typ))
    return res


class AddressPlaceEquivalenceTests(unittest.TestCase):
    def test_the_sorted_lookup_gives_what_each_pair_gave(self):
        rng = random.Random(3)
        kinds = sorted(personal._ADDRESS_RULES_WITH_PLACE) + ["de-plz", "email"]
        text = ", 12345 Berlin, 54321 Hamburg-Nord, " * 40
        for _ in range(3000):
            out = []
            for _ in range(rng.randint(0, 9)):
                s = rng.randrange(0, 120)
                e = s + rng.randrange(0, 40)
                k = rng.choice(kinds)
                out.append((s, e, k, rng.choice((personal.ADDRESS, personal.ADDRESS, "EMAIL"))))
            # ties: equal starts and equal spans are the cases the lookup must get right
            if out and rng.random() < 0.5:
                out.append(out[0][:2] + (rng.choice(kinds), personal.ADDRESS))
                out.append((out[0][0], out[0][1] + 5, rng.choice(kinds), personal.ADDRESS))
            self.assertEqual(personal._address_with_its_place(text, list(out)),
                             _address_with_its_place_all_pairs(text, list(out)), out)

    def test_the_premise_some_hits_are_held_and_some_widened(self):
        text = "12 Harbor Street, 12345 Berlin"
        out = [(0, 16, "street-address", personal.ADDRESS), (0, 30, "address-after-label", personal.ADDRESS)]
        got = personal._address_with_its_place(text, out)
        self.assertEqual(got[0], out[0], "held by the wider hit: stays as it was")
        self.assertEqual([x[1] for x in itertools.islice(got, 1, 2)], [30])


if __name__ == "__main__":
    unittest.main()
