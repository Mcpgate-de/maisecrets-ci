"""The betterleaks rules and their filters (maisecrets/detection/rule_filter.py, Mcpgate-de/maisecrets#18).

betterleaks replaced the gitleaks ruleset: gitleaks takes security patches only since v8.30.1, and its maintainers
develop betterleaks. Its rules drop a finding when an Expr filter is true; rule_filter reads the subset the vendored
rules use and refuses the rest, so a rule never runs without its filter.

Run: python3 -m unittest tests.test_rule_filter -v
Every token is built at run time from a seeded alphabet, so no literal sits in the tree.
"""
from __future__ import annotations

import json
import os
import random
import string
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "maisecrets" / "detection" / "rules"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, rule_filter  # noqa: E402

RNG = random.Random(18)
VENDORED = json.loads((RULES / "betterleaks.json").read_text(encoding="utf-8"))


def tok(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(RNG.choice(alphabet) for _ in range(n))


def env(value: str, line: str = "") -> dict:
    return {"secret": value, "match": value, "line": line, "path": ""}


def kinds(text: str) -> list[tuple[str, str]]:
    return [(m.kind, m.value) for m in detect.scan(text)]


class FilterReaderTests(unittest.TestCase):
    def test_every_vendored_filter_compiles_except_the_four_programs(self):
        refused = []
        for r in VENDORED["rules"]:
            if r.get("filter"):
                try:
                    rule_filter.compile_filter(r["filter"])
                except rule_filter.Unsupported:
                    refused.append(r["id"])
        self.assertEqual(sorted(refused), ["generic-api-key", "generic-credential-uri", "generic-password",
                                           "generic-username"])
        rule_filter.compile_filter(VENDORED["filter"])

    def test_each_loaded_rule_drops_what_its_own_filter_and_the_global_one_drop(self):
        # rules() reads each filter text once and the rules with the same text share it: the shared one must judge
        # as the filter of the rule's own text, and a rule whose filter cannot be read stays out
        by_id = {r["id"]: r for r in VENDORED["rules"]}
        loaded = detect._load_betterleaks()
        ids = [r.id for r in loaded]
        self.assertTrue({"generic-api-key", "generic-password"}.isdisjoint(ids))
        self.assertEqual(len(ids), len([r for r in VENDORED["rules"] if "regex" in r and not r.get("skipReport")
                                        and r["id"] not in ("generic-api-key", "generic-credential-uri",
                                                            "generic-password", "generic-username")]))
        glob = rule_filter.compile_filter(VENDORED["filter"])
        samples = [env(v, line) for v in ("aaaaaaaaaaaaaaaa", tok(24), tok(40, string.hexdigits.lower()),
                                          "example-" + tok(12), "${API_TOKEN}", "true")
                   for line in ("", "token = x", "password: test")]
        differ = 0
        for rule in loaded:
            src = by_id[rule.id].get("filter")
            own = rule_filter.compile_filter(src) if src else None
            for e in samples:
                want = bool((own is not None and own(e)) or glob(e))
                self.assertEqual(bool(rule.drop(e)), want, rule.id)
            differ += own is not None and any(own(e) != glob(e) for e in samples)
        self.assertGreater(differ, 20, "the samples tell the filters apart")

    def test_the_operators_and_functions_read_like_expr(self):
        f = rule_filter.compile_filter('entropy(finding["secret"]) < 3.0 || '
                                       'matchesAny(finding["secret"], [`^x+$`, `(?i)^TEST`]) && '
                                       '!containsAny(finding["line"], ["keep"])')
        self.assertTrue(f(env("aaaa", "")))                      # entropy 0 < 3.0
        self.assertTrue(f(env("testQ7w8E9r0T1y2", "")))          # (?i)^TEST, no "keep" on the line
        self.assertFalse(f(env("testQ7w8E9r0T1y2", "keep it")))  # && binds tighter than ||
        self.assertFalse(f(env(tok(24), "")))
        self.assertTrue(f(env("aaaa", "keep it")))   # A || (B && C): A alone is enough; (A || B) && C would be False

    def test_a_string_with_an_escape_json_does_not_know_is_read_as_written(self):
        # json.loads raised on \\x41 and the ruleset load left every rule out (Gate A of 0.6.15)
        f = rule_filter.compile_filter('finding["secret"] == "a\\x41"')
        self.assertTrue(f(env("a\\x41", "")))
        self.assertFalse(f(env("aA", "")))

    def test_token_ratio_is_zero_as_betterleaks_answers_without_a_tokenizer(self):
        f = rule_filter.compile_filter('filter.entropy(finding["secret"]) < 3.0 || '
                                       'filter.tokenRatio(finding["secret"]) >= 2.5')
        self.assertFalse(f(env("the quick brown fox jumps over")))
        self.assertTrue(f(env("abababab")))

    def test_a_program_or_an_unknown_name_is_refused_not_run_without_it(self):
        for src in ('let x = finding["secret"]; x == "a"', 'filter.setConfidence("low")',
                    'unknownFn(finding["secret"])',
                    'finding["fragment_raw"] == ""', 'entropy(finding["secret"]) <',
                    'isExampleValue || entropy(finding["secret"]) < 3.0'):   # a let variable of a program
            with self.subTest(src):
                with self.assertRaises(rule_filter.Unsupported):
                    rule_filter.compile_filter(src)

    def test_entropy_counts_bytes_like_betterleaks(self):
        self.assertEqual(rule_filter.entropy(""), 0.0)
        self.assertEqual(rule_filter.entropy("aaaa"), 0.0)
        self.assertAlmostEqual(rule_filter.entropy("abcd"), 2.0)
        self.assertAlmostEqual(rule_filter.entropy("\u00e4\u00e4"), 1.0)   # two bytes each: c3 a4 c3 a4, not one rune

    def test_word_classes_are_ascii_as_in_re2(self):
        # a filter that drops a value made of word characters must not drop one with an umlaut: RE2's \\w is ASCII
        drop = rule_filter.compile_filter('matchesAny(finding["secret"], [`^\\w+$`])')
        self.assertTrue(drop(env("abc123")))
        self.assertFalse(drop(env("ab\u00e4c123")))

    def test_a_string_literal_keeps_non_ascii_text(self):
        drop = rule_filter.compile_filter('containsAny(finding["secret"], ["Schl\u00fcssel", "a\\"b"])')
        self.assertTrue(drop(env("mein Schl\u00fcssel")))
        self.assertTrue(drop(env('a"b')))

    def test_an_inline_case_flag_applies_from_its_place_as_in_re2(self):
        rx = rule_filter.to_python_regex("^/Users/(?i)[a-z0-9]+/x$")
        self.assertTrue(rx.search("/Users/AbC/x"))
        self.assertFalse(rx.search("/users/abc/x"))
        drop = rule_filter.compile_filter(VENDORED["filter"])            # the global filter holds ^/Users/(?i)…
        self.assertTrue(drop(env("/Users/" + tok(12, string.ascii_lowercase) + "/project")))
        self.assertFalse(drop(env("/users/" + tok(12, string.ascii_lowercase) + "/project")))
        with self.assertRaises(rule_filter.Unsupported):
            rule_filter.compile_filter('matchesAny(finding["secret"], [`a(?i)b|c`])')



class BetterleaksRuleTests(unittest.TestCase):
    def test_skip_report_components_and_unreadable_programs_are_not_loaded(self):
        ids = {r.id for r in detect._load_betterleaks()}
        skipped = {r["id"] for r in VENDORED["rules"] if r.get("skipReport")}
        self.assertTrue(skipped and not skipped & ids)
        self.assertFalse({"generic-password", "generic-username", "generic-credential-uri"} & ids)
        self.assertEqual(len([r for r in detect.rules() if r.id == "generic-api-key"]), 1,
                         "generic-api-key comes once, in its gitleaks form")

    def test_a_shape_gitleaks_did_not_know_is_found(self):
        value = "ddp_" + tok(36)                   # a Deno account token: no gitleaks v8.30.1 rule
        self.assertIn(("deno-account-token", value), kinds(f"DENO_DEPLOY={value}\n"))

    def test_the_shapes_betterleaks_lacks_stay_found_through_the_own_rules(self):
        lower = string.ascii_lowercase + string.digits
        for text, value in (("etsy: {v}", tok(24, lower)), ("artifactory: {v}", tok(73, lower)),
                            ("jfrog = {v}", tok(64, lower)), ("deploy with {v} now", "fo1_" + tok(43))):
            with self.subTest(text):
                self.assertIn(value, [v for _, v in kinds(text.format(v=value))])

    def test_each_own_secret_rule_finds_what_betterleaks_alone_misses(self):
        """The population of rules/own_secret_rules.json: each rule but generic-api-key stays only while betterleaks
        misses a realistic token of its shape. A later betterleaks that closes a gap turns this red: drop the rule."""
        low, hexd = string.ascii_lowercase + string.digits, "0123456789abcdef"
        samples = {
            "alibaba-access-key-id": "LTAI" + tok(20, low + string.ascii_uppercase),
            "etsy-access-token": "etsy: " + tok(24, low),
            "jfrog-api-key": "artifactory: " + tok(73, low),
            "jfrog-identity-token": "jfrog = " + tok(64, low),
            "flyio-access-token.legacy": "fo1_" + tok(43, string.ascii_letters + string.digits + "_-"),
            "atlassian-api-token.legacy": "confluence: " + tok(20, low) + tok(4, hexd),
            "vault-service-token.legacy": "s." + tok(24, low),
            "twilio-api-key.legacy": "SK" + tok(32, hexd),
            "codecov-access-token.legacy": "codecov: " + tok(32, low),
        }
        # the signature rules of the research (0.7.9) get a token from their researched pattern
        import test_researched_formats as researched
        own_ids = {r.id for r in detect._load_own_secret_rules()}
        samples.update({rid: researched.token(rid) for rid in researched.SOURCES if rid in own_ids})
        # the provider-word rules of 0.7.10 get the text of their kingfisher example, filled from its template
        import test_provider_context_rules as provider
        samples.update({rid: provider.sample(rid)[0] for rid in provider.EXAMPLES})
        kept = [r for r in detect._load_own_secret_rules() if r.id != "generic-api-key"]
        self.assertEqual(sorted(r.id for r in kept), sorted(samples), "the premise: one sample per kept rule")
        full = detect.rules()
        alone = [r for r in full if r.id not in samples]
        without = detect.Detector()
        without._rules = alone   # the default rule list without the samples' rules, as a detector of its own
        for rid, text in samples.items():
            with self.subTest(rid):
                self.assertEqual([m.kind for m in without.scan(text + "\n")], [], "betterleaks finds it alone")
                self.assertIn(rid, [m.kind for m in detect.scan(text + "\n")])

    def test_the_rule_filter_drops_a_low_entropy_value(self):
        value = "ddp_" + "ab" * 18                 # entropy 1.x: the rule's filter drops it
        self.assertNotIn("deno-account-token", [k for k, _ in kinds(f"x {value} y")])

    def test_the_global_filter_drops_a_template(self):
        rule = next(r for r in detect._load_betterleaks() if r.id == "deno-account-token")
        path = "/usr/" + tok(30)                  # high entropy: the rule's own filter keeps it, the global one not
        self.assertTrue(rule.drop(env(path)))
        self.assertFalse(rule.drop(env("ddp_" + tok(36))))


if __name__ == "__main__":
    unittest.main()
