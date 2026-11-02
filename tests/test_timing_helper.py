"""tests/_timing.py measures what it claims: a quadratic call fails assert_linear, a linear call passes, and a call
that is fast only on the same text object a second time (a cache by identity, as the text index of the scan) is
measured as a first call, at both sizes.

Run: python3 -m unittest tests.test_timing_helper -v
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _timing import assert_linear  # noqa: E402


def linear(text: str) -> int:
    return sum(1 for ch in text if ch == "a")


def quadratic(text: str) -> int:
    n = 0
    for i in range(0, len(text), 8):
        n += text.count("a", i)
    return n


class _Last:
    """Does the work of `fn` the first time it sees a text object, nothing when it sees the same object again: a cache
    by identity, as the index of the last text in maisecrets/detection/text_index.py."""

    def __init__(self, fn):
        self.fn, self.last = fn, None

    def __call__(self, text: str) -> int:
        if text is self.last:
            return 0
        self.last = text
        return self.fn(text)


class AssertLinearTests(unittest.TestCase):
    def test_a_linear_call_passes(self):
        assert_linear(self, linear, lambda n: "ab" * (n // 2), 400_000)

    def test_a_quadratic_call_fails(self):
        with self.assertRaises(AssertionError):
            assert_linear(self, quadratic, lambda n: "ab" * (n // 2), 160_000)

    def test_a_cache_of_the_last_text_does_not_hide_a_quadratic_first_call(self):
        with self.assertRaises(AssertionError):
            assert_linear(self, _Last(quadratic), lambda n: "ab" * (n // 2), 160_000)

    def test_a_cache_of_the_last_text_does_not_fail_a_linear_call(self):
        # the small size called again and again in a batch hit the cache and read about nothing, the large size did
        # not: a linear scan then read 80 times for 8 times the text (test_scan_bounds, 2026-11-02)
        assert_linear(self, _Last(linear), lambda n: "ab" * (n // 2), 12_000_000)


if __name__ == "__main__":
    unittest.main()
