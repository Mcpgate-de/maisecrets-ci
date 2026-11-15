"""#49 step 1: after a strong address label (street, home, residential, mailing, billing, postal, property address) on
the line of the address label, the street before its number, as Eastern and Central Europe write it. `Address:` alone
keeps its stricter value check; product, tool and filler names, a year as the number and words in capitals alone stay
text. Invented street names."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, regions  # noqa: E402

L_STROKE = "Łąkowa"     # a street name with Latin Extended-A letters


def scan(text: str) -> list:
    active = regions.Active(regions=("generic", "de", "us"), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return detect.scan(text, channel="tool")


def masked(text: str) -> str:
    for m in sorted(scan(text), key=lambda m: -m.start):
        text = text[:m.start] + "*" + text[m.end:]
    return text


class StreetNumberLastTests(unittest.TestCase):
    def test_each_form_after_each_strong_label(self):
        for text, value in (("- **Street Address:** Lindenweg Kalinova, 17\n- **City:** x", "Lindenweg Kalinova, 17"),
                            ("Street Address: Kalinova Ulica 17\nPostcode: 4000", "Kalinova Ulica 17"),
                            ("Street Address: ul. Kalinova 17\n", "ul. Kalinova 17"),
                            ("Property Address: Kalinova-Ostrov Ulica 9\n", "Kalinova-Ostrov Ulica 9"),
                            ("Home address: Rivne Prospekt, 42\n", "Rivne Prospekt, 42"),
                            ("Billing Address: Kalinova Ulica 17/3\n", "Kalinova Ulica 17/3"),
                            ("Street Address: Kalinova ulica 17\n", "Kalinova ulica 17"),
                            (f"Street Address: ul. {L_STROKE} 5\n", f"ul. {L_STROKE} 5"),
                            ("Street Address: ulica Kalinova 17\n", "ulica Kalinova 17")):
            with self.subTest(text=text):
                hits = [(m.kind, text[m.start:m.end]) for m in scan(text)]
                self.assertIn(("address-after-label", value), hits)

    def test_a_plain_label_and_a_thing_stay_text(self):
        for text in ("Address: Kalinova Ulica 17\n", "Street Address: Version 17\n", "Street Address: Port 8080\n",
                     "Billing address: Plan Basic 2\n", "Property Address: See Section 4\n",
                     "Billing address: Same As Shipping 1\n", "Postal address: Room 101\n",
                     "IP address: Kalinova Ulica 17\n", "Home Address\nAddress: Kalinova Ulica 17\n",
                     "Mailing address: Kubernetes Ingress 2\n", "Street Address: Windows Server 2019\n",
                     "Billing address: Invoice INV 20481\n", "Mailing Address: Firefox Nightly 128\n",
                     "Street Address: Grafana_Dash 12\n", "Street Address: https://x.example/a 17\n",
                     "Billing Address: ABCD EFGH 12\n"):
            with self.subTest(text=text):
                self.assertEqual(text, masked(text))

    def test_without_the_word_list_the_form_is_refused(self):
        from unittest import mock
        from maisecrets.detection import value_checks
        with mock.patch.object(value_checks, "_WORDS_OK", [False]):
            self.assertEqual("Street Address: Kalinova Ulica 17\n", masked("Street Address: Kalinova Ulica 17\n"))


if __name__ == "__main__":
    unittest.main()
