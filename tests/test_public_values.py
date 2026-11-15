"""Values with the shape of personal data that name no person (detection/public_values.py, ideas from Cloakroom 1.4.0):
a bank number that is a run or one repeated digit, and a North American toll-free number in its NANP form. Invented
values."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, regions  # noqa: E402
from maisecrets.detection import public_values  # noqa: E402


def types(text: str, regs: tuple = ("generic", "de", "us")) -> list:
    act = regions.Active(regions=regs, languages=("en", "de"), source="test")
    with detect.Detector(regions=act).activate():
        return [m.type for m in detect.scan(text, channel="tool")]


class PublicValueTests(unittest.TestCase):
    def test_a_run_or_a_repeated_digit_is_no_bank_number(self):
        for text in ("account number: 12345678", "account number: 98765432", "account number: 0000000000"):
            with self.subTest(text=text):
                self.assertNotIn("US_BANK_NUMBER", types(text))
        self.assertIn("US_BANK_NUMBER", types("account number: 48172930"))

    def test_a_toll_free_number_is_no_persons_phone(self):
        for text in ("phone: 1-800-555-7788", "Call us: (888) 412-7790", "phone: +1 866 412 7790"):
            with self.subTest(text=text):
                self.assertNotIn("PHONE", types(text))
        for text in ("phone: (415) 820-4471", "Tel.: 0800 123 4567", "phone: (812) 412-7790", "phone: (880) 412-7790"):
            with self.subTest(text=text):
                self.assertIn("PHONE", types(text), "a geographic number, and a German 0800 number by its region")

    def test_an_indian_mobile_that_starts_like_a_toll_free_number_stays_a_phone(self):
        # Gate A: Indian mobiles start with 8 too; their 5-5 form and any form under region in stay a hit
        self.assertIn("PHONE", types("Mobile: 88823 45671", ("generic", "in")))
        self.assertIn("PHONE", types("Mobile: 888 234 5671", ("generic", "us", "in")))
        self.assertIn("PHONE", types("customer phone 1 888 234 5671", ("generic", "us", "in")))

    def test_a_birthday_label_and_an_ordinal_day_give_a_birth_date(self):
        # Cloakroom 1.4.0 rules.py:131 finds these; maisecrets 0.9.10 did not
        for text in ("birthday: 1987-03-14", "Birthday: March 14, 1987", "b-day: 14.03.1987",
                     '{"birthday": "1987-03-14"}',
                     "born on 14th March 1987", "born on March 14th, 1987", "DOB: 14th Mar 1987"):
            with self.subTest(text=text):
                self.assertIn("BIRTH_DATE", types(text))
        for text in ("birthday: tomorrow", "birthday party on 2026-11-20", "the 4th quarter 2020 report",
                     "birthday_reminder_at: 2026-03-14", "birthdays: 3", '{"birthday": "0001-01-01T00:00:00Z"}',
                     "nobirthday: 1987-03-14"):
            with self.subTest(text=text):
                self.assertNotIn("BIRTH_DATE", types(text))

    def test_the_bounds_of_the_checks(self):
        nv = public_values.no_person_value
        self.assertFalse(nv("12345", "US_BANK_NUMBER"), "too short to be a placeholder run")
        self.assertFalse(nv("12345678", "PHONE"), "a run is no toll-free number")
        self.assertFalse(nv("+44 800 412 7790", "PHONE"), "toll-free is a North American rule")
        self.assertFalse(nv("8004127790", "PHONE"), "ten digits without the NANP grouping")


if __name__ == "__main__":
    unittest.main()
