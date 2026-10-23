"""The vendored rules end a token at sentence punctuation too (0.7.11).

Run: python3 -m unittest tests.test_vendored_sentence_end -v
336 vendored rules end with a terminator for an assignment (a quote, a space, ";" or a line end). Before 0.7.11 a
token before ". , : ) ! ?" in a sentence lost the whole hit. Values are built at run time from pieces.
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

R = random.Random(711)
LOW = string.ascii_lowercase + string.digits
ALNUM = string.ascii_letters + string.digits
TOKENS = {
    "npm-access-token": "np" + "m_" + "".join(R.choice(LOW) for _ in range(36)),
    "notion-api-token": "nt" + "n_" + "".join(R.choice(string.digits) for _ in range(11))
                        + "".join(R.choice(ALNUM) for _ in range(35)),
}


def hits(text: str, channel: str = "prompt") -> list[tuple[str, str]]:
    return [(m.kind, m.value) for m in detect.scan(text, channel=channel)]


class SentenceEndTests(unittest.TestCase):
    def test_a_token_before_sentence_punctuation_is_found_whole(self):
        for rule_id, tok in TOKENS.items():
            for end in (".", ",", ":", ")", "!", "?"):
                for tail in (" thanks", ""):
                    with self.subTest(rule=rule_id, end=end, tail=tail):
                        self.assertIn((rule_id, tok), hits(f"my key is ({tok}{end}{tail}"))

    def test_an_azure_client_secret_before_a_full_stop_or_colon_is_found(self):
        # this rule has a terminator of its own, which refused "." and ":"; the 336 rules above share another
        r = random.Random(713)
        body = string.ascii_letters + string.digits + "_~."
        value = ("".join(r.choice(ALNUM) for _ in range(3)) + "8" + "Q~"
                 + "".join(r.choice(body) for _ in range(33)) + r.choice(ALNUM))
        for end in (".", ":", ".\n"):
            with self.subTest(end=repr(end)):
                self.assertIn(("azure-ad-client-secret", value), hits(f"the client secret is {value}{end} thanks"))
        self.assertNotIn("azure-ad-client-secret", [k for k, _v in hits(f"see {value}.example there")])

    def test_a_dot_before_a_letter_is_no_end(self):
        # a host name or a file name: the vendored terminator never took it, and still does not
        for rule_id, tok in TOKENS.items():
            with self.subTest(rule=rule_id):
                self.assertNotIn(rule_id, [k for k, _v in hits(f"see {tok}.example there")])

    def test_punctuation_next_to_a_quote_is_code_not_a_sentence(self):
        # a map key `<value>: "x"` and a list item `<value>, "y"` are no sentence end (two FP bank alarms)
        for rule_id, tok in TOKENS.items():
            for text in (f'm := map[string]string{{{tok}: "x"}}\n', f"names = [{tok}, 'y']\n"):
                with self.subTest(rule=rule_id, text=text[:4]):
                    self.assertNotIn(rule_id, [k for k, _v in hits(text, "tool")])


if __name__ == "__main__":
    unittest.main()
