"""Detector.label_names_a_number (maisecrets/detection/label_number.py, ai-gateway #1795).

The method answers from samples: one synthetic value per rule that reads a digit-only number of 7 to 19 digits only
after a label (label_number.SAMPLES). CompletenessTests finds those rules from the rules' own data, without the
recipes, and fails on a rule that has no recipe:

- each built-in rule: values from its own regex (label_number.digit_runs) that pass its own check (core.VALIDATORS),
  under the words of its own context and keywords, scanned with that rule alone, bare and after each word;
- the keyword and label rules and the personal passes, which have no digit shape of their own: plain digit runs, a
  national phone number and a date, under every word of the rules' context and keywords, the label files
  (rules/labels/*.txt) and the word tables of personal.py.

A rule id that gives a finding after a word and not bare must have a recipe. Each recipe must give its own rule after
one of those words. Each rule of a number type (national id, tax id, phone, bank account, card) whose regex can match
digits alone must have a recipe or a reason in NEVER_LABEL_ONLY.

Run: python3 -m unittest tests.test_label_number -v
"""
from __future__ import annotations

import os
import random
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets.detection import (NO_REFERENCES, NO_SOURCES, TYPES, Active, Detector, Host, Sources,  # noqa: E402
                                  user_rule)
from maisecrets.detection import core, label_number, leaves, personal, regions  # noqa: E402
from maisecrets.detection.contract import known_regions  # noqa: E402


def detector(regs=("generic", "de", "us"), langs=("en", "de"), sources=NO_SOURCES) -> Detector:
    return Detector(regions=Active(regions=regs, languages=langs, source="label-number-test"), sources=sources,
                    references=NO_REFERENCES, host=Host(user="", year=2026))


ALL = detector(("generic", *sorted(known_regions() - {"generic"})), tuple(regions.label_languages_available()))

# "Steuer ID": a column's display name as Metabase gives it (ai-gateway #1795, live check 2026-11-08)
TRUE = ("steuer_id", "steuerid", "tax_id", "taxId", "phone", "phone_home", "telefon", "Steuer ID")
FALSE = ("id", "customer_id", "order_id", "deal_id", "kundennummer", "nextPageToken", "Kunden ID", "Order ID")

# the types whose value can be a number: their classes in types.json
NUMBER_CLASSES = frozenset({"pii.national_id", "pii.tax_id", "pii.phone", "pii.bank_account", "pii.card"})
# rules of a number type whose regex can match digits alone (by label_number.digit_samples) and that need no recipe,
# with the reason. The test checks that none of them gives a label-only finding
NEVER_LABEL_ONLY = {
    "in-pan#2": "two lookaheads ask for a letter: a value of digits alone never matches",
}

_SEP = "\n\n"


def _words() -> tuple:
    """The label words of the rules' own data: context and keywords of every rule, the examples of the label files,
    and the word tables of personal.py."""
    out = {}
    for r in ALL.rules():
        for w in r.context + r.keywords:
            out[w] = None
    for lang in regions.label_languages_available():
        for lb in regions.load_labels(lang):
            for w in lb.examples:
                out[w] = None
    for name in dir(personal):
        table = getattr(personal, name)
        if name.isupper() and isinstance(table, (tuple, frozenset)) and all(isinstance(w, str) for w in table):
            for w in table:
                out[w] = None
    return tuple(w for w in out if w.strip() and len(w) <= 64 and leaves.label((w,)) == w)


def _label_only(det, enabled, value: str, words, fields: bool = True) -> set:
    """The rule ids that give a finding in the value after one of the words and not in the bare value."""
    out = set()
    for channel in ("tool", "prompt"):
        bare = {(m.start, m.end, m.type) for m in det.scan(value, enabled=enabled, channel=channel)}
        if fields:
            for w in words:
                found = det.scan(value, enabled=enabled, channel=channel, fields=[(0, len(value), (w,))])
                out |= {m.kind for m in found if (m.start, m.end, m.type) not in bare}
        # the text form, all words in one text: each value on a line after its word
        lines, starts, pos = [], [], 0
        for w in words:
            lead = f"{w}: "
            lines.append(lead + value)
            starts.append(pos + len(lead))
            pos += len(lead) + len(value) + len(_SEP)
        found = det.scan(_SEP.join(lines), enabled=enabled, channel=channel)
        for m in found:
            for s in starts:
                if s <= m.start < s + len(value) or s < m.end <= s + len(value):
                    if (m.start - s, m.end - s, m.type) not in bare:
                        out.add(m.kind)
    return out


def _regex_samples(rule, per_rule: int = 6) -> list:
    """(string, start, end) from the rule's own regex (label_number.digit_samples) whose digit run passes the rule's
    own check: up to per_rule, runs of different lengths first."""
    check = core.VALIDATORS.get(rule.validator) if rule.validator else None
    pattern = getattr(rule.regex, "pattern", "") or ""
    out = []
    for s, a, b in label_number.digit_samples(pattern, rule.id, tries=40 if check else 4):
        try:
            ok = check(s[a:b]) if check else True
        except Exception:   # noqa: BLE001  a check that refuses the shape
            ok = False
        if ok and len(set(s[a:b])) >= 4:
            out.append((s, a, b))
    seen, picked = set(), []
    for x in out:
        if (x[2] - x[1], x[0] == x[0][x[1]:x[2]]) not in seen:
            seen.add((x[2] - x[1], x[0] == x[0][x[1]:x[2]]))
            picked.append(x)
    picked += [x for x in out if x not in picked]
    return picked[:per_rule]


def _reads_digits_alone(rule) -> bool:
    """Whether the rule's regex can match a run of 7 to 19 digits as a whole (no letter, sign or word around it)."""
    return any(s == s[a:b] for s, a, b in _regex_samples(rule, 1000))


def _plain_values() -> list:
    """Digit runs that no regex makes: random digits of each length, a national phone number and two dates."""
    rng = random.Random("label-number-plain")
    out = ["".join(rng.choice("0123456789") for _ in range(n)) for n in range(label_number.DIGITS_MIN,
                                                                             label_number.DIGITS_MAX + 1)]
    for first, n in (("01", 11), ("0", 10), ("0", 12)):
        while True:
            v = first + "".join(rng.choice("0123456789") for _ in range(n - len(first)))
            if personal._national_phone_ok(v):
                out.append(v)
                break
    out += ["1985" + "03" + "14", "14" + "03" + "1985"]
    # base32 digits only (2 to 7): an OTP seed after its label; random digits 0 to 9 never pass that rule (Opus review)
    out += ["".join(rng.choice("234567") for _ in range(n)) for n in (16, 19)]
    return out


_FOUND = {}


def _regex_labels(sample) -> tuple:
    """A label inside the regex (`rx: <digits>`): the last one to three words before the digit run in a string of the
    regex. Only a run that ends the string or a word, after a sign or a space, is a value after a label; a run glued to
    letters is part of a token (xoxb-…)."""
    s, a, b = sample
    if s == s[a:b] or a == 0 or s[a - 1].isalnum() or (b < len(s) and (s[b].isalnum() or s[b] == "_")):
        return ()
    words = re.findall(r"[^\W\d_][\w.-]*", s[:a])
    labels = {" ".join(words[-n:]) for n in (1, 2, 3) if len(words) >= n} | {"_".join(words[-2:])}
    return tuple(w for w in labels if w and len(w) <= 64 and leaves.label((w,)) == w)


def _regex_form(det, rule_id: str, sample) -> set:
    """The rule ids that read the run after a label of the regex itself, in the two forms of a caller."""
    labels = _regex_labels(sample)
    s, a, b = sample
    return _label_only(det, {rule_id}, s[a:b], labels) if labels else set()


def _own_words(rule, words) -> tuple:
    return tuple(dict.fromkeys(w for w in rule.context + rule.keywords if w in words or leaves.label((w,)) == w))


def discovered() -> dict:
    """rule id -> how it was found: the rules that give a finding on a digit-only value after a word only."""
    if _FOUND:
        return _FOUND
    words = _words()
    shapeless = set()
    for r in ALL.rules():
        samples = _regex_samples(r)
        if not samples:
            shapeless.add(r.id)
            continue
        own = _own_words(r, words)
        for sample in samples:
            for kind in _label_only(ALL, {r.id}, sample[0][sample[1]:sample[2]], own) | _regex_form(ALL, r.id, sample):
                _FOUND.setdefault(kind, f"its regex and words ({r.id})")
    passes = {r.id for r in ALL.rules() if r.form in ("keyword", "label")} | shapeless | set(personal.RULE_IDS)
    for v in _plain_values():
        for kind in _label_only(ALL, passes, v, words, fields=False):
            _FOUND.setdefault(kind, "plain digits under the word pool")
    return _FOUND


class PinnedTests(unittest.TestCase):
    def test_the_labels_of_a_number(self):
        d = detector()
        self.assertEqual({w: d.label_names_a_number(w) for w in TRUE}, dict.fromkeys(TRUE, True))
        self.assertEqual({w: d.label_names_a_number(w) for w in FALSE}, dict.fromkeys(FALSE, False))

    def test_the_label_of_a_leaf(self):
        # the label a caller holds is leaves.label(path): a wrapper key takes the name above it
        d = detector()
        self.assertTrue(d.label_names_a_number(leaves.label(("customer", "telefon"))))
        self.assertFalse(d.label_names_a_number(leaves.label(("items", 0, "order_id"))))
        self.assertFalse(d.label_names_a_number(""))

    def test_a_list_index_given_as_a_string_is_no_label(self):
        # the gateway splits phones.0 at the dots: "0" is the index, the key above it names the value (Opus review)
        d = detector()
        self.assertEqual(leaves.label(("phones", "0")), "phones")
        self.assertTrue(d.label_names_a_number(leaves.label(("phones", "0"))))
        self.assertTrue(d.label_names_a_number(leaves.label(("telefon", "2"))))
        self.assertTrue(detector(("generic", "us"), ("en",)).label_names_a_number(
            leaves.label(("data", "ssn", "1", "value"))))

    def test_an_otp_label(self):
        # an OTP seed of base32 digits (2 to 7) only, 16 or more of them (Opus review: no recipe, False before)
        d = detector()
        for w in ("otp", "totp"):
            with self.subTest(label=w):
                self.assertTrue(d.label_names_a_number(w))

    def test_the_answers_are_bounded(self):
        d = detector()
        with mock.patch.object(label_number, "ANSWERS_MAX", 3):
            for w in ("order_id", "deal_id", "customer_id", "kundennummer"):
                d.label_names_a_number(w)
            self.assertEqual(len(label_number._state(d).answers), 3)

    def test_the_text_form(self):
        # measured over the word pool: only `cc ` (a card context word with its space) gives a finding in the text
        # form `label: <value>` and none in the field form
        self.assertTrue(detector().label_names_a_number("cc "))

    def test_a_label_that_is_no_str(self):
        with self.assertRaises(TypeError):
            detector().label_names_a_number(None)

    def test_a_tax_id_after_the_spaced_label_in_prose(self):
        # the context words of the tax id rule hold the spaced form too: "Die Steuer ID ist <id>" in a sentence
        d = detector()
        tax = next(f"57549385{a}{b}{c}" for a in range(10) for b in range(10) for c in range(10)
                   if core.VALIDATORS["de_tax_id"](f"57549385{a}{b}{c}"))
        self.assertIn("DE_TAX_ID", [m.type for m in d.findings("Die Steuer ID ist " + tax + " laut Bescheid.",
                                                                 channel="tool")])

    def test_a_german_tax_label_needs_the_region(self):
        self.assertTrue(detector(("generic", "de")).label_names_a_number("steuer_id"))
        self.assertFalse(detector(("generic", "us"), ("en",)).label_names_a_number("steuer_id"))
        self.assertFalse(detector(("generic",), ("en",)).label_names_a_number("steuerid"))

    def test_a_rule_of_your_own_with_a_label(self):
        class Own(Sources):
            def user_rules(self):
                # ten digits from 77: no built-in sample has this shape, so only the samples of the rule's own regex
                # can show the label
                return [user_rule("member", "MEMBER_NO", r"(?i)mitglied(?:snummer|_nr)\W{1,3}(77\d{8})(?!\d)",
                                  secret_group=1)]
        plain = detector()
        own = detector(sources=Own())
        self.assertFalse(plain.label_names_a_number("mitgliedsnummer"))
        self.assertTrue(own.label_names_a_number("mitgliedsnummer"))
        self.assertTrue(own.label_names_a_number("mitglied_nr"))
        self.assertFalse(own.label_names_a_number("order_id"))

    def test_the_answer_is_cached_per_label(self):
        d = detector()
        d.label_names_a_number("customer_id")
        with mock.patch.object(Detector, "findings", side_effect=AssertionError("scanned")) as f, \
                mock.patch.object(Detector, "scan", side_effect=AssertionError("scanned")) as s:
            self.assertFalse(d.label_names_a_number("customer_id"))
        self.assertEqual((f.call_count, s.call_count), (0, 0))
        calls = []
        real = Detector.findings
        with mock.patch.object(Detector, "findings", autospec=True,
                               side_effect=lambda *a, **k: calls.append(1) or real(*a, **k)):
            d.label_names_a_number("deal_id")
            first = len(calls)
            d.label_names_a_number("deal_id")
        self.assertGreater(first, 0)
        self.assertEqual(len(calls), first)

    def test_reset_asks_again(self):
        d = detector()
        d.label_names_a_number("phone")
        d.reset()
        calls = []
        real = Detector.findings
        with mock.patch.object(Detector, "findings", autospec=True,
                               side_effect=lambda *a, **k: calls.append(1) or real(*a, **k)):
            self.assertTrue(d.label_names_a_number("phone"))
        self.assertGreater(len(calls), 0)

    def test_the_samples_are_digits_and_made_at_run_time(self):
        for rule_id in label_number.SAMPLES:
            v = label_number.sample(rule_id)
            self.assertTrue(v.isdigit() and label_number.DIGITS_MIN <= len(v) <= label_number.DIGITS_MAX, rule_id)
        self.assertEqual(label_number.sample("de-tax-id"), label_number.sample("de-tax-id"))
        self.assertTrue(core.VALIDATORS["de_tax_id"](label_number.sample("de-tax-id")))


class CompletenessTests(unittest.TestCase):
    def test_every_rule_that_reads_a_number_after_a_label_has_a_recipe(self):
        found = discovered()
        missing = {k: how for k, how in found.items() if k not in label_number.SAMPLES}
        self.assertEqual(missing, {}, "a rule reads a digit-only value after a label: add a recipe to "
                                      "label_number.SAMPLES")

    def test_each_recipe_gives_its_own_rule_after_a_word(self):
        # the recipe's value, scanned with its rule alone, after each word of the pool and the labels inside its regex
        words = _words()
        by_id = {r.id: r for r in ALL.rules()}
        dead = []
        for rule_id in label_number.SAMPLES:
            v = label_number.sample(rule_id)
            extra = tuple(w for x in _regex_samples(by_id[rule_id]) for w in _regex_labels(x)) if rule_id in by_id \
                else ()
            if rule_id not in _label_only(ALL, {rule_id}, v, words + extra, fields=False):
                dead.append(rule_id)
        self.assertEqual(dead, [], "a recipe whose value its rule does not read after any word")

    def test_each_rule_of_a_number_type_has_a_recipe_or_a_reason(self):
        found = discovered()
        open_ = []
        for r in ALL.rules():
            cls = TYPES.get(r.type, {}).get("class")
            if cls not in NUMBER_CLASSES or not _reads_digits_alone(r):
                continue
            if r.id not in label_number.SAMPLES and r.id not in NEVER_LABEL_ONLY:
                open_.append(r.id)
        self.assertEqual(open_, [], "a rule of a number type reads digits alone: a recipe or a reason")
        for rule_id in NEVER_LABEL_ONLY:
            self.assertNotIn(rule_id, found, "a rule named as never label-only gives a finding after a label")

    def test_the_personal_passes_of_a_number_type(self):
        number_passes = {k for k, t in personal.TYPES.items() if t in (personal.PHONE, personal.ID_NUMBER)
                         and personal.NEEDS.get(k) == "label"}
        found = discovered()
        self.assertEqual({k for k in number_passes if k in found} - set(label_number.SAMPLES), set())


if __name__ == "__main__":
    unittest.main()


class LabelChangesTests(unittest.TestCase):
    """label_changes_a_number: True when the label adds a finding to a digit run or takes one away (ai-gateway #1822:
    a host took the findings of one label for another, and a card under `id` stayed in clear)."""

    def test_an_id_label_takes_a_card_away_and_says_so(self):
        d = detector()
        for lab in ("id", "order_id", "uuid", "ref"):
            with self.subTest(label=lab):
                self.assertFalse(d.label_names_a_number(lab), "the label adds no finding")
                self.assertTrue(d.label_changes_a_number(lab), "but it takes the card of a bare number away")
        card = next(v for v in label_number.bare_samples() if d.findings(v, channel="tool"))
        self.assertEqual([m.value for m in d.findings("id: " + card, channel="tool")], [], "the premise: id drops it")

    def test_a_label_that_changes_nothing_is_false(self):
        d = detector()
        for lab in ("series", "values", "timestamp", "count", "", "   "):
            with self.subTest(label=lab):
                self.assertFalse(d.label_changes_a_number(lab))

    def test_a_label_that_names_a_number_changes_one(self):
        d = detector()
        for lab in ("card", "steuer_id", "phone", "series", "id", "iban", "tel", "account"):
            with self.subTest(label=lab):
                if d.label_names_a_number(lab):
                    self.assertTrue(d.label_changes_a_number(lab))
        self.assertTrue(d.label_changes_a_number("card"))
        with self.assertRaises(TypeError):
            d.label_changes_a_number(None)

    def test_the_bare_samples_are_card_numbers_found_without_a_label(self):
        d = detector()
        samples = label_number.bare_samples()
        self.assertEqual(len(samples), 35)
        self.assertEqual(samples, label_number.bare_samples(), "the same values in every call")
        self.assertTrue(any(d.findings(v, channel="tool") for v in samples))
