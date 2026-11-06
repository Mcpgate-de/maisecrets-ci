"""A scan with a deadline stops between rules and raises ScanIncomplete with what it found so far, at the offsets of
the text it was given (findings) or of each string (findings_by_leaf). Without a deadline, and with one far ahead,
the results are those of before (#1759 of the gateway: a per-response budget, and a running scan cannot be cut off).

Run: python3 -m unittest tests.test_scan_deadline -v
Every value is generated at run time, so no literal sits in the tree.
"""
from __future__ import annotations

import os
import random
import string
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets.detection import Active, Detector, ScanIncomplete, core, leaves  # noqa: E402

D = Detector(regions=Active(regions=("generic", "de", "us"), languages=("en", "de"), source="deadline"))
R = random.Random(1759)


def rnd(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(R.choice(alphabet) for _ in range(n))


def text() -> str:
    lines = []
    for i in range(40):
        lines += [f"token: {'gh' + 'p_' + rnd(36)}", f"mail {rnd(7, string.ascii_lowercase)}@corp-{i}.de",
                  f"password: {rnd(10)}!{rnd(2, string.digits)}", "the build failed again on runner " + rnd(5)]
    return "\n".join(lines)


def spans(found) -> list:
    return sorted((m.start, m.end, m.type) for m in found)


class FakeClock:
    """time.monotonic that moves one second per call: the deadline passes after `calls` checks."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self) -> float:
        self.now += 1.0
        return self.now


class DeadlineTests(unittest.TestCase):
    def setUp(self):
        self.t = text()
        self.full = spans(D.findings(self.t, channel="tool"))
        self.assertGreater(len(self.full), 40)   # the text holds values for many rules

    def test_a_deadline_far_ahead_changes_nothing(self):
        self.assertEqual(spans(D.findings(self.t, channel="tool", deadline=time.monotonic() + 3600)), self.full)

    def test_a_passed_deadline_raises_at_once(self):
        with self.assertRaises(ScanIncomplete) as cm:
            D.findings(self.t, channel="tool", deadline=time.monotonic() - 1)
        self.assertEqual(cm.exception.reason, "deadline")
        self.assertEqual(cm.exception.findings, [])

    def test_a_deadline_in_the_middle_gives_a_part_of_the_findings_at_their_offsets(self):
        partial_seen = False
        for budget in (5, 20, 60, 200, 600):
            clock = FakeClock()
            with mock.patch.object(core.time, "monotonic", clock), self.subTest(budget=budget):
                try:
                    got = D.findings(self.t, channel="tool", deadline=1000.0 + budget)
                    self.assertEqual(spans(got), self.full)
                    continue
                except ScanIncomplete as e:
                    part = e.findings
            for m in part:
                self.assertEqual(self.t[m.start:m.end], m.value)
            self.assertLessEqual(set(spans(part)), set(self.full))
            partial_seen = partial_seen or 0 < len(part) < len(self.full)
        self.assertTrue(partial_seen)   # some budget stopped the scan after it had found something

    def test_the_deadline_ends_with_the_call(self):
        with self.assertRaises(ScanIncomplete):
            D.findings(self.t, channel="tool", deadline=time.monotonic() - 1)
        self.assertEqual(spans(D.findings(self.t, channel="tool")), self.full)   # no deadline left behind


class SlowCallbackTests(unittest.TestCase):
    """A References callback the caller gives runs once per hit. A slow one carried a scan far past its deadline,
    because the deadline was checked between rules only (a gateway callback: 185 s against a 10 s deadline)."""

    def test_the_scan_stops_within_one_hit_after_the_deadline(self):
        from maisecrets.detection import References
        clock = {"now": 1000.0}
        late = []

        class Slow(References):
            def hit_is_a_reference(self, text, start, secret):
                clock["now"] += 1.0                  # each call takes a second
                if clock["now"] > 1003.0:
                    late.append(start)
                return False

        det = Detector(regions=Active(regions=("generic", "de", "us"), languages=("en", "de"), source="slow"),
                       references=Slow())
        with mock.patch.object(core.time, "monotonic", lambda: clock["now"]), self.assertRaises(ScanIncomplete):
            det.findings(text(), channel="tool", deadline=1003.0)
        self.assertLessEqual(len(late), 1, "calls after the deadline")


class LeafDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.obj = {"messages": [{"user": "U" + rnd(8, string.digits), "text": line}
                                 for line in text().split("\n")]}
        self.full = sorted((id(leaf), m.start, m.end, m.type) for leaf, m in leaves.findings_by_leaf(D, self.obj))
        self.assertGreater(len(self.full), 40)

    def test_a_deadline_far_ahead_changes_nothing(self):
        got = leaves.findings_by_leaf(D, self.obj, deadline=time.monotonic() + 3600)
        self.assertEqual(len(got), len(self.full))

    def test_a_deadline_in_the_middle_keeps_the_segments_before_and_places_each_finding(self):
        partial_seen = False
        for budget in (50, 400, 2000):
            clock = FakeClock()
            with mock.patch.object(core.time, "monotonic", clock), self.subTest(budget=budget):
                try:
                    leaves.findings_by_leaf(D, self.obj, deadline=1000.0 + budget)
                    continue
                except ScanIncomplete as e:
                    part = e.findings
            for leaf, m in part:
                self.assertIsNotNone(leaf)
                self.assertEqual(leaf.value[m.start:m.end], m.value)
            partial_seen = partial_seen or 0 < len(part) < len(self.full)
        self.assertTrue(partial_seen)

    def test_a_read_leaf_has_every_finding_of_the_whole_scan(self):
        # the gateway withholds the leaves outside `read` and shows the others with their masks: a read leaf must
        # carry what the whole scan gives it, also in a record that holds its text twice (text and blocks)
        def block(line: str) -> list:
            section = {"type": "rich_text_section", "elements": [{"type": "text", "text": line}]}
            return [{"type": "rich_text", "elements": [section]}]
        obj = {"messages": [{"user": "U" + rnd(8, string.digits), "text": line, "blocks": block(line)}
                            for line in text().split("\n")]}
        whole: dict = {}
        for leaf, m in leaves.findings_by_leaf(D, obj):
            if leaf is not None:
                whole.setdefault(leaf.path, set()).add((m.start, m.end, m.type))
        cut_seen = False
        for budget in range(20, 4000, 41):     # many cut points: some fall inside a segment that finds more later
            clock = FakeClock()
            with mock.patch.object(core.time, "monotonic", clock), self.subTest(budget=budget):
                try:
                    leaves.findings_by_leaf(D, obj, deadline=1000.0 + budget)
                    continue
                except ScanIncomplete as e:
                    cut = e
            got: dict = {}
            for leaf, m in cut.findings:
                if leaf is not None:
                    got.setdefault(leaf.path, set()).add((m.start, m.end, m.type))
            for leaf in cut.read:
                self.assertEqual(got.get(leaf.path, set()), whole.get(leaf.path, set()), leaf.path)
            cut_seen = cut_seen or (0 < len(cut.read))
        self.assertTrue(cut_seen)   # a budget cut the scan after some leaves were read

    def test_the_json_layout_places_the_findings_so_far(self):
        clock = FakeClock()
        with mock.patch.object(core.time, "monotonic", clock):
            try:
                leaves.findings_by_leaf(D, self.obj, layout="json", deadline=1000.0 + 400)
                return
            except ScanIncomplete as e:
                part = e.findings
        for leaf, m in part:
            if leaf is not None:
                self.assertEqual(leaf.value[m.start:m.end], m.value)


if __name__ == "__main__":
    unittest.main()
