"""#50: a phone number in any country's grouping after a call cue (tool channel), and after a phone label a local number
of 4 and 4 digits and the North American shape with an area code no plan has. The regions are those of the benchmark
(de, us): the numbers of other countries must not depend on a region rule. Invented values, split so that no literal
has a value's whole shape."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, regions  # noqa: E402

UK = "0161 874 " + "2093"
FR = "06 47 83 " + "92 15"
AU = "0412 873 " + "516"
GROUPS = "61-3412-" + "7788"
FAX = "977-" + "639211"
LOCAL = "7182-" + "4630"
NO_PLAN = "(187) 642-" + "9035"


def scan(text: str, channel: str = "tool", where: tuple = ("de", "us")) -> list:
    active = regions.Active(regions=("generic", *where), languages=("en", "de"), source="test")
    with detect.Detector(regions=active).activate():
        return detect.scan(text, channel=channel)


def masked(text: str, channel: str = "tool") -> str:
    for m in sorted(scan(text, channel), key=lambda m: -m.start):
        text = text[:m.start] + "•" + text[m.end:]
    return text


class PhoneAfterACallCueTests(unittest.TestCase):
    def test_each_country_grouping_after_a_call_cue(self):
        for text, value in ((f"contact us at {UK} or email", UK), (f"or by phone at {FR}.", FR),
                            (f"can be reached at {AU}. Timely", AU), (f"please contact us at {GROUPS}.", GROUPS),
                            (f"fax us at {FAX}.", FAX), (f"call {AU} today", AU),
                            (f"contact our team on {AU}.", AU),
                            ("reach me at 98765 " + "43219 today", "98765 43219")):
            with self.subTest(text=text):
                self.assertNotIn(value, masked(text))
        # the area code's parenthesis is a part of the value
        self.assertEqual("contact us at \u2022.", masked("contact us at (02) 9374 " + "4518."))

    def test_a_label_alone_keeps_its_rules(self):
        # Gate A of #50: 4 and 4 digits after a phone word are years, screen sizes, hours and ports too
        for text in ("Mobile: 2023-2024", "mobile 1920 1080 layout", "Phone 0900-1700", "Tel 8080 8443",
                     "- Phone Number: " + LOCAL + "\n", "- Phone Number: " + NO_PLAN + "\n"):
            with self.subTest(text=text):
                self.assertEqual(text, masked(text))
                self.assertEqual(text, masked(text, "prompt"))

    def test_a_date_a_time_round_numbers_a_series_and_an_example_stay_text(self):
        for text in ("call 2024 08 15 the release", "contact us at 10:30 tomorrow", "call the function at line 1234",
                     "dial 1-2-3", "call 1234 5678 9012 3456", "Order Number: " + LOCAL + "\n",
                     "contact us at 555-0142", "contact us at 312 555 " + "0142", "reach us at 2023-07-15",
                     "contact us at 100 200 300 400",
                     "Phone Number: 1111-" + "1111\n", "fax us at 12345678", "call 15 08 2024 the release",
                     # Gate A: an IP, a date with a time, lists of numbers, a bare `the number`
                     "contact the API at 10.20.30." + "40", "reach the host at 172.16.10." + "20",
                     "call 31 12 2024 23 59", "contacted at 2024 11 14 09 30", "call 64 128 256 512 1024",
                     "call 65535 65536", "call 33 44 55 66", "text 42 17 13 99 88", "call 01 02 03 04 05",
                     "call 00 11 22 33 44", "contact us at 06 06 06 06 06", "telemetry: the number 0123 4567 8901",
                     # round 2: four equal groups, runs and doublings, one-digit groups, a date and a time
                     "call 404 500 502 503", "call 128 256 512 1024", "dial 250 500 750 1000",
                     "contact redis at 6379 16379 26379", "call 05 10 15 20 25", "call 02 04 08 16 32",
                     "contact us at 06 06 07 07 08", "call 0 4 8 15 16 23 42", "call 31 12 2024 2359",
                     "call 11 14 2024 0930", "call 65535 65536", "contact us at 0300 1200 4500"):
            with self.subTest(text=text):
                self.assertEqual(text, masked(text))

    def test_a_north_american_number_needs_us_or_ca(self):
        text = "contact us at 312-846-" + "2291 today"
        self.assertEqual([], [m.kind for m in scan(text, where=("de",))])

    def test_a_typed_prompt_keeps_its_rules(self):
        # a call cue in a prompt blocked developer prompts (review, 2026-11-02): the prompt channel takes labels only
        text = f"contact us at {AU}."
        self.assertEqual(text, masked(text, "prompt"))


if __name__ == "__main__":
    unittest.main()
