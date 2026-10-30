"""A BitLocker recovery key in a tool result (Microsoft Graph bitlockerRecoveryKey, manage-bde): 48 digits in 8 groups
of 6, each group a 16-bit number times 11. Before this rule it reached the model in clear, bare and after `key: `
(gateway field report, 2026-10-30).

Run: python3 -m unittest tests.test_bitlocker_recovery_key -v
Every key is generated at run time from a seeded generator, so no literal sits in the tree.
"""
from __future__ import annotations

import os
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402

RNG = random.Random(48)


def key(bad_group: int | None = None) -> str:
    groups = [f"{RNG.randrange(65536) * 11:06d}" for _ in range(8)]
    if bad_group is not None:
        groups[bad_group] = f"{int(groups[bad_group]) + 1:06d}"   # no longer divisible by 11
    return "-".join(groups)


def kinds(text: str, channel: str = "tool") -> list:
    return [(m.kind, text[m.start:m.end]) for m in detect.scan(text, channel=channel)]


class BitLockerRecoveryKeyTests(unittest.TestCase):
    def test_a_recovery_key_is_found_bare_after_a_label_and_in_json(self):
        for channel in ("tool", "prompt"):
            k = key()
            for text in (k, f"key: {k}", f'{{"id": "b465e4e8", "key": "{k}"}}', f"Recovery Password: {k}."):
                with self.subTest(channel=channel, form=text[:6]):
                    self.assertIn(("bitlocker-recovery-key", k), kinds(text, channel))

    def test_a_group_that_fails_the_check_is_no_key(self):
        for i in range(8):
            k = key(bad_group=i)
            with self.subTest(group=i):
                self.assertNotIn("bitlocker-recovery-key", [kind for kind, _ in kinds(k)])

    def test_a_group_above_the_16_bit_range_is_no_key(self):
        groups = key().split("-")
        groups[3] = f"{65536 * 11:06d}"
        self.assertNotIn("bitlocker-recovery-key", [kind for kind, _ in kinds("-".join(groups))])

    def test_a_hyphen_or_a_line_break_after_it_ends_the_key(self):
        for tail in ("-", " - see the console", "\r\n", "."):
            k = key()
            with self.subTest(tail=tail):
                hits = kinds(k + tail)
                self.assertTrue(any(kind == "bitlocker-recovery-key" and v.startswith(k) for kind, v in hits))

    def test_a_longer_digit_run_or_arabic_indic_digits_are_no_key(self):
        k = key()
        arabic = k.translate({ord(d): 0x0660 + int(d) for d in "0123456789"})
        for text in ("7" + k, k + "7", arabic):
            with self.subTest(form=text[:2]):
                self.assertNotIn("bitlocker-recovery-key", [kind for kind, _ in kinds(text)])

    def test_fullwidth_digits_are_the_key_after_the_normaliser(self):
        k = key()
        fullwidth = k.translate({ord(d): 0xFF10 + int(d) for d in "0123456789"})
        self.assertIn("bitlocker-recovery-key", [kind for kind, _ in kinds(fullwidth)])

    def test_seven_or_nine_groups_are_no_key(self):
        k = key()
        for text in (k.rsplit("-", 1)[0], k + "-" + f"{11 * 7:06d}"):
            with self.subTest(n=text.count("-") + 1):
                self.assertNotIn("bitlocker-recovery-key", [kind for kind, _ in kinds(text)])


if __name__ == "__main__":
    unittest.main()
