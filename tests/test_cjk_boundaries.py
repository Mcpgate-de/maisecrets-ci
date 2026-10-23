"""An e-mail address or a phone number right next to Chinese, Japanese or Korean text is a hit, and its span is the
value alone. Python's \\w includes the CJK letters, and these scripts put no space between words, so the boundaries of
the two rules never held there (holdout analysis, 2026-10-15).

Run: python3 -m unittest tests.test_cjk_boundaries -v
Every value is built at run time from parts.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect  # noqa: E402

J = "".join
MAIL = J(["taro.test", "@", "shop-sample", ".co.jp"])
PHONE = J(["+81", " 3 ", "4521", " 7788"])


def spans(text: str, channel: str) -> list:
    return [(m.type, text[m.start:m.end]) for m in detect.scan(text, channel=channel)]


class CjkBoundaryTests(unittest.TestCase):
    CASES = [
        ("Japanese on both sides", "メールは" + MAIL + "まで。", ("EMAIL", MAIL)),
        ("Japanese before", "メールは" + MAIL + "。", ("EMAIL", MAIL)),
        ("Japanese after", "メール: " + MAIL + "まで", ("EMAIL", MAIL)),
        ("Chinese after", "请发邮件到 " + MAIL + "谢谢", ("EMAIL", MAIL)),
        ("Hangul after", "메일 " + MAIL + "으로 보내주세요", ("EMAIL", MAIL)),
        ("fullwidth colon before", "メール：" + MAIL, ("EMAIL", MAIL)),
        ("phone, Japanese on both sides", "電話番号は" + PHONE + "です。", ("PHONE", PHONE)),
        ("phone, Japanese after", "電話番号: " + PHONE + "です。", ("PHONE", PHONE)),
        ("phone, Hangul after", "전화 " + PHONE + "으로", ("PHONE", PHONE)),
    ]

    def test_an_address_or_number_next_to_cjk_text_is_found_alone_in_both_channels(self):
        for channel in ("prompt", "tool"):
            for name, text, want in self.CASES:
                with self.subTest(channel=channel, case=name):
                    self.assertIn(want, spans(text, channel))

    def test_a_latin_letter_still_bounds_the_value(self):
        # the boundary skips CJK letters only: a Latin or Cyrillic letter glued to the value still ends a match
        for text in ("x" + PHONE[1:].replace(" ", ""), PHONE.replace(" ", "") + "abc",
                     MAIL + "é", MAIL + "ж"):
            with self.subTest(text=len(text)):
                self.assertNotIn(PHONE, [v for _, v in spans(text, "tool")])
                self.assertNotIn(MAIL, [v for _, v in spans(text, "tool")])

    def test_a_cjk_local_part_is_left_to_the_text(self):
        # the local part takes no CJK letter: a Japanese word before an address is not part of it
        text = "担当者" + MAIL
        self.assertEqual([("EMAIL", MAIL)], [s for s in spans(text, "tool") if s[0] == "EMAIL"])


class CjkFreeFormTests(unittest.TestCase):
    """A rule with the class of CJK letters also has a form without it (detect._Lazy), for a text with no CJK letter:
    the class made the compilation of four rules cost 26 ms in each hook process. Both forms must find the same."""
    RULES = {"email", "phone", "label-password-after-word", "label-password-after-space", "label-password-apposition",
             "label-password-for-is", "label-password-words-is"}

    def rules(self) -> list:
        return [r for r in detect.rules() if isinstance(r.regex, detect._Lazy) and r.regex._plain is not None]

    def test_each_rule_with_the_cjk_class_has_a_form_without_it(self):
        self.assertEqual({r.id for r in self.rules()}, self.RULES)
        for r in self.rules():
            self.assertNotIn(detect._CJK, r.regex._plain, r.id)

    def test_both_forms_find_the_same_in_a_text_without_a_cjk_letter(self):
        import re
        import fp_corpus
        import fp_corpus_pii
        texts = [t[1].replace("\u00a7", "") for t in fp_corpus.NO_HIT + fp_corpus.HIT + fp_corpus_pii.PII_NO_HIT
                 + fp_corpus_pii.POSITIVE]
        texts += ["Mail an " + MAIL + ", Telefon " + PHONE + ".", MAIL + "-x", "x" + PHONE, "Gr\u00fc\u00dfe " + MAIL,
                  "Das Passwort ist " + J(["Test", "pass", "45!"]) + " und " + PHONE.replace(" ", "") + "\u00e9",
                  "my password is '" + J(["test", "pass", "2024"]) + "' and the WLAN-Passwort ist \u201e"
                  + J(["Test", "77"]) + "\u201c."]
        texts = [t for t in texts if not detect._has_cjk(t)]
        found = 0
        for r in self.rules():
            full = re.compile(r.regex.pattern, r.regex.flags)
            plain = re.compile(r.regex._plain, r.regex.flags)
            for text in texts:
                want = [(m.span(), m.groups()) for m in full.finditer(text)]
                with self.subTest(rule=r.id, text=text[:40]):
                    self.assertEqual([(m.span(), m.groups()) for m in r.regex.finditer(text)], want)
                    self.assertEqual([(m.span(), m.groups()) for m in plain.finditer(text)], want)
                found += len(want)
        self.assertGreater(found, 50, "the texts give the rules hits to compare")


if __name__ == "__main__":
    unittest.main()
