"""A short text walks only the rules its alphabet allows (prefilter.alphabet_order): the findings stay the same.

Run: python3 -m unittest tests.test_alphabet_order -v
A gateway scans each number of a metric series apart, as `values: 1794412212320`: 2,680 points walked all rules each
and passed the gateway's 10 s budget (ai-gateway, 2026-11-11). The list of an alphabet is used from its second text on,
so each text here is scanned twice: once with every rule, once with the list of its alphabet.
"""
from __future__ import annotations

import os
import random
import sys
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

import fp_corpus  # noqa: E402
import fp_corpus_forms  # noqa: E402
import fp_corpus_pii  # noqa: E402
from maisecrets import detect  # noqa: E402
from maisecrets.detection import core, prefilter  # noqa: E402


def luhn_card(rng: random.Random, head: str = "4") -> str:
    """A 16-digit number with a valid Luhn check digit: the shape of a card, not a documented test card."""
    body = head + "".join(rng.choice("0123456789") for _ in range(14 - len(head) + 1))
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            d -= 9 if d > 9 else 0
        total += d
    return body + str((10 - total % 10) % 10)


def corpus() -> list[str]:
    texts = []
    for rows in (fp_corpus.NO_HIT, fp_corpus.HIT, fp_corpus_pii.PII_NO_HIT, fp_corpus_pii.POSITIVE,
                 fp_corpus_forms.FORMS_NO_HIT, fp_corpus_forms.FORMS_HIT):
        texts += [row[1].replace("§", "") for row in rows if isinstance(row[1], str)]
    rng = random.Random(1822)
    ts = 1794412200000
    texts += [f"values: {ts + 15000 * i}" for i in range(5)] + [str(ts + 7 * i) for i in range(5)]
    texts += [luhn_card(rng), f"values: {luhn_card(rng)}", f"card {luhn_card(rng, '5')}", luhn_card(rng, "37")[:15]]
    return [t for t in texts if len(t) <= prefilter.ALPHABET_TEXT_MAX]


def found(text: str, channel: str) -> list:
    return [(m.kind, m.type, m.start, m.end, m.value) for m in detect.findings(text, channel=channel)]


class AlphabetOrderTests(unittest.TestCase):
    def setUp(self):
        detect.reset_rules()

    def test_the_rules_of_an_alphabet_find_what_every_rule_finds(self):
        texts = corpus()
        self.assertGreater(len(texts), 1000)
        for channel in ("tool", "prompt"):
            with unittest.mock.patch.object(prefilter, "ALPHABET_TEXT_MAX", -1):
                every = [found(t, channel) for t in texts]
            detect.reset_rules()
            for t in texts:
                found(t, channel)           # the first text of an alphabet notes it
            for t, want in zip(texts, every):
                with self.subTest(channel=channel, text=t[:40]):
                    self.assertEqual(found(t, channel), want)
        self.assertTrue(any(every), "the corpus has findings to compare")

    def test_a_card_stored_as_a_number_is_still_found(self):
        card = luhn_card(random.Random(7))
        for _ in range(3):              # the second and third scan take the list of the alphabet
            self.assertEqual([m.value for m in detect.findings(card, channel="tool")], [card])
            got = detect.findings(f"values: {card}", channel="tool", fields=[(8, 24, ("data", "values", 0))])
            self.assertIn(card, [m.value for m in got])

    def test_a_series_of_timestamps_walks_few_rules_and_finds_nothing(self):
        texts = [f"values: {1794412200000 + 15000 * i}" for i in range(50)]
        self.assertEqual([found(t, "tool") for t in texts], [[]] * 50)
        order = core._in_scan_order(core.rules())
        short = prefilter.alphabet_order(core._det(), order, texts[0], texts[0].lower())
        self.assertLess(len(short) * 5, len(order), "the alphabet of a number leaves a fifth of the rules or less")

    def test_an_alphabet_is_listed_from_its_second_text_on(self):
        order = core._in_scan_order(core.rules())
        det = core._det()
        self.assertIs(prefilter.alphabet_order(det, order, "values: 1", "values: 1"), order)
        self.assertIsNot(prefilter.alphabet_order(det, order, "values: 2", "values: 2"), order)
        long = "x" * (prefilter.ALPHABET_TEXT_MAX + 1)
        self.assertIs(prefilter.alphabet_order(det, order, long, long), order)
        self.assertIs(prefilter.alphabet_order(det, order, long, long), order)


if __name__ == "__main__":
    unittest.main()
