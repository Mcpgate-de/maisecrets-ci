"""A password and a US address in the sentence forms that benchmark V3 found in the clear: a password in an
apposition, after "for <account> is", before "as the password"; a US home address on one line.

Run: python3 -m unittest tests.test_sentence_forms -v
The passwords are built at run time from a seeded random source, so no literal sits in the tree and the tree scan
stays clean. The addresses are synthetic, as in tests/fp_corpus_forms.py.
"""
from __future__ import annotations

import os
import random
import string
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402
from maisecrets.detection import regions  # noqa: E402

RNG = random.Random(22)


def password() -> str:
    """Five letters, two digits and a sign: the shape the password sentences take, and no word of a list."""
    return ("".join(RNG.choice(string.ascii_letters) for _ in range(5)) + "".join(RNG.choice(string.digits)
            for _ in range(2)) + RNG.choice("!#%&"))


def kinds(text: str, channel: str = "tool") -> list[tuple[str, str]]:
    active = regions.Active(regions=("generic", "de", "us"), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return [(m.kind, m.value) for m in detect.scan(text, channel=channel)]


class PasswordSentenceTests(unittest.TestCase):
    def test_each_new_form_masks_the_password(self):
        for form, kind in (("Reset the password, {v}, before Friday.", "label-password-apposition"),
                           ("The new password for the admin account is {v}.", "label-password-for-is"),
                           ("Use {v} as the password.", "label-password-use-as"),
                           ("Set {v} as your new password today.", "label-password-use-as")):
            v = password()
            with self.subTest(form=form):
                self.assertEqual(kinds(form.format(v=v), channel="prompt"), [(kind, v)])

    def test_words_and_examples_in_the_new_forms_stay_text(self):
        for text in ("The password, username1, and the email go in the form.",
                     "The password for the account is incorrect.",
                     "The password for the admin account is Hunter2!",
                     "Use SHA256-hashing as the password storage.",
                     "Use PBE-3403 as the password ticket.",
                     "The password, as noted in PBE-3403, expires."):
            with self.subTest(text=text[:30]):
                self.assertEqual(kinds(text, channel="prompt"), [])


class UsAddressOneLineTests(unittest.TestCase):
    def test_a_home_address_on_one_line_is_masked(self):
        for addr in ("4821 Harbor " + "Mission Apt. 5 Springfield, IL 62704",
                     "77 Quiet " + "Spurs Riverton, OR 97301",
                     "PSC 1234, Box 5678, APO AE 09876"):
            with self.subTest(addr=addr[:12]):
                self.assertEqual(kinds(f"Please send it to {addr} by Friday."), [("address-us-one-line", addr)])

    def test_a_company_a_venue_or_a_heading_keeps_it_text(self):
        addr = "4821 Harbor " + "Mission Springfield, IL 62704"
        for text in (f"Acme Inc, {addr}", f"We met at the Harbor View Inn, {addr} last week.",
                     "Release 2 Notes, CA 90210"):
            with self.subTest(text=text[:20]):
                self.assertNotIn("address-us-one-line", [k for k, _ in kinds(text)])

    def test_the_rule_runs_only_with_the_us_region(self):
        text = "Please send it to 4821 Harbor " + "Mission Springfield, IL 62704 by Friday."
        for region, expected in ((("us",), True), (("de",), False)):
            active = regions.Active(regions=("generic", *region), languages=("en",), source="test")
            with detect.Detector(regions=active).activate():
                found = "address-us-one-line" in [m.kind for m in detect.scan(text, channel="tool")]
            with self.subTest(region=region):
                self.assertEqual(found, expected)


if __name__ == "__main__":
    unittest.main()
