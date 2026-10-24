"""`start` and `end` of a Match count the Unicode code points of the str that was scanned, and
text[m.start:m.end] == m.value for every hit (docs/DETECTION.md, "The API"). A UTF-16 caller (JavaScript, Java,
.NET) counts an astral character such as an emoji as two units: it must convert, and these tests pin what it
converts from.

Run: python3 -m unittest tests.test_code_point_offsets -v
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detection  # noqa: E402

EMOJI = "\U0001F600"                                      # outside the BMP: one code point, two UTF-16 units
FAMILY = "\U0001F468‍\U0001F469‍\U0001F467"     # five code points, eight UTF-16 units
FLAG = "\U0001F1E9\U0001F1EA"
ACUTE = "é"                                         # a combining character: two code points, one glyph
TOKEN = "glpat-" + "AbCdEfGhIjKlMnOpQrSt"
MAIL = "jane.roe" + "@" + "mailbox-sample.de"
IBAN = "DE89 3704 0044 " + "0532 0130 00"
PHONE = "+49 30 " + "12345678"
LABEL = "pass" + "word"                                   # split, so the tree scan sees no pair
VALUE = "Xq7vowel" + "Plum93"

# (name, text, the value whose span is pinned, its rule id, the channels that find it)
CASES = [
    ("a secret rule after two emoji", f"{EMOJI}{EMOJI} token {TOKEN} done", TOKEN, "gitlab-pat", ("prompt", "tool")),
    ("an e-mail after a family emoji", f"{FAMILY} mail {MAIL}", MAIL, "email", ("prompt", "tool")),
    ("an IBAN after a flag", f"{FLAG} IBAN {IBAN}", IBAN, "iban", ("prompt", "tool")),
    ("a phone between emoji", f"{EMOJI} call me at {PHONE} {EMOJI}", PHONE, "phone", ("prompt", "tool")),
    ("a label value with an emoji before the label", f"{EMOJI} {LABEL}: {VALUE} {EMOJI}", VALUE,
     "ds-keyword-colon", ("prompt", "tool")),
    ("a JSON line with an emoji before the value", '{"note": "' + EMOJI + '", "email": "' + MAIL + '", "token": "'
     + TOKEN + '"}', MAIL, "email", ("prompt", "tool")),
    ("a JSON line with an emoji in a key", '{"' + EMOJI + '": 1, "' + LABEL + '": "' + VALUE + '"}', VALUE,
     "ds-keyword-colon", ("prompt", "tool")),
    ("combining characters before the values", f"Caf{ACUTE} {ACUTE}{ACUTE} {MAIL} and {TOKEN}", TOKEN,
     "gitlab-pat", ("prompt", "tool")),
    ("an emoji inside a password", f"{LABEL}: Xq7{EMOJI}" + "Plum93", f"Xq7{EMOJI}" + "Plum93", "ds-keyword-colon",
     ("prompt", "tool")),
    ("a name after its label", f"{EMOJI} Name: Jörg Müller{EMOJI}", "Jörg Müller",
     "name-after-label", ("tool",)),
    # the tool channel's cleaned copy (maisecrets/detection/normalise.py): the span is the original one, hidden
    # characters inside the value included
    ("a token with a zero-width space, after an emoji", f"{EMOJI} token glpat-AbCdEfGhIj​KlMnOpQrSt {EMOJI}",
     "glpat-AbCdEfGhIj​KlMnOpQrSt", "gitlab-pat", ("tool",)),
    ("a token split by ANSI codes, after two emoji", f"{EMOJI}{EMOJI} \x1b[31mglpat-AbCdEfGhIj\x1b[0mKlMnOpQrSt",
     "glpat-AbCdEfGhIj\x1b[0mKlMnOpQrSt", "gitlab-pat", ("tool",)),
]


def detector() -> detection.Detector:
    return detection.Detector(regions=detection.Active(regions=("generic", "de"), languages=("en", "de"), source="t"),
                              sources=detection.NO_SOURCES, references=detection.NO_REFERENCES,
                              host=detection.Host(user="t", year=2026))


class CodePointOffsetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = detector()

    def test_each_hit_is_the_slice_of_its_code_points(self):
        for name, text, value, kind, channels in CASES:
            for channel in channels:
                with self.subTest(name, channel=channel):
                    hits = self.d.findings(text, channel=channel)
                    for m in hits:
                        self.assertEqual(text[m.start:m.end], m.value, m.kind)
                    start = text.index(value)
                    self.assertIn((kind, start, start + len(value)), [(m.kind, m.start, m.end) for m in hits])

    def test_a_prefix_of_astral_or_combining_characters_shifts_the_hits_by_its_code_points(self):
        for prefix in (EMOJI + EMOJI + " ", FAMILY + " ", ACUTE + ACUTE + " "):
            for name, text, _value, _kind, channels in CASES:
                for channel in channels:
                    with self.subTest(name, prefix=prefix, channel=channel):
                        plain = text.replace(EMOJI, "x").replace(FAMILY, "x").replace(FLAG, "x")
                        want = [(m.kind, m.start + len(prefix), m.end + len(prefix))
                                for m in self.d.findings(plain, channel=channel)]
                        got = [(m.kind, m.start, m.end) for m in self.d.findings(prefix + plain, channel=channel)]
                        self.assertTrue(want, "the premise: the text without emoji has a hit")
                        self.assertEqual(got, want)

    def test_the_offsets_are_not_utf16_units(self):
        text = f"{EMOJI}{EMOJI} token {TOKEN}"
        (m,) = self.d.findings(text)
        self.assertEqual(m.start, 9)
        self.assertEqual(len(text[:m.start].encode("utf-16-le")) // 2, 11, "a UTF-16 caller adds one per emoji")


if __name__ == "__main__":
    unittest.main()
