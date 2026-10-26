"""The scan time stays linear for rules that look past a prefix: the AWS secret after its key id, and the two curl
rules of betterleaks. Each one scanned the rest of the line again from each prefix, so a line with many of them took
O(n^2) and ran past the hook's time limit, which lets the output through (0.6.15).

Run: python3 -m unittest tests.test_scan_bounds -v
Every token is generated at run time, so no literal sits in the tree.
"""
from __future__ import annotations

import os
import random
import re
import string
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402  first: a temp vault home, never the real one
from _timing import assert_linear  # noqa: E402
Path(_isolate.HOME).mkdir(parents=True, exist_ok=True)
Path(_isolate.HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import detect  # noqa: E402

AN = string.ascii_letters + string.digits
_R = random.Random(615)
AWS = "aws-secret-after-access-key"
CURL = ("curl-auth-header", "curl-auth-user")


def secret_span(m, ngroups: int) -> tuple:
    """The span of the first group that matched: the credential scan() takes when secret_group is 0."""
    g = next((i for i in range(1, ngroups + 1) if m.group(i)), 0)
    return m.start(g), m.end(g)


def rnd(n: int, alphabet: str = AN) -> str:
    return "".join(_R.choice(alphabet) for _ in range(n))


def akid() -> str:
    return "AK" + "IA" + rnd(16, string.ascii_uppercase + "234567")


def aws_secret() -> str:
    return rnd(40, AN + "/+")


def took(text: str, ids) -> float:
    t = time.process_time()
    detect.scan(text, enabled=set(ids))
    return time.process_time() - t


def linear(case: unittest.TestCase, make, ids, n: int) -> None:
    """tests/_timing.py: the scan of 8 times the text takes at most 16 times the CPU time. A fixed 1.0 s of wall time
    failed on a loaded machine (2026-10-16); the released code of each case took seconds at n (quadratic)."""
    assert_linear(case, lambda text: detect.scan(text, enabled=set(ids)), make, n)


class AwsSecretAfterKeyIdTests(unittest.TestCase):
    def values(self, text: str) -> list[str]:
        return [m.value for m in detect.scan(text) if m.kind == AWS]

    def test_the_console_form_on_two_lines_is_found(self):
        kid, sk = akid(), aws_secret()
        for text in (f"Access key ID: {kid}\nSecret access key: {sk}\n",
                     f"Access key\n{kid}\nSecret access key\n{sk}\n",
                     f'"AccessKeyId": "{kid}",\n        "Status": "Active",\n        "SecretAccessKey": "{sk}",\n'):
            with self.subTest(text[:12]):
                self.assertEqual(self.values(text), [sk])

    def test_a_credentials_csv_row_is_found(self):
        kid, sk = akid(), aws_secret()
        text = ("User name,Password,Access key ID,Secret access key,Console login link\n"
                f"deploy-bot,{rnd(16)},{kid},{sk},https://123456789012.signin.aws.amazon.com/console\n")
        self.assertEqual(self.values(text), [sk])

    def test_a_secret_more_than_400_characters_after_the_id_on_its_line_is_not_taken(self):
        # the bound that keeps the scan linear; a paste "within a few lines" is far inside it
        kid, sk = akid(), aws_secret()
        self.assertEqual(self.values(f"{kid} {'x ' * 150} {sk}"), [sk])
        self.assertEqual(self.values(f"{kid} {'x ' * 220} {sk}"), [])

    def test_a_line_of_64k_of_key_ids_scans_in_linear_time(self):
        # released code: 32K took 2.3 s, 256K took 97 s in the hook (client timeout 20 s, then the output passes)
        linear(self, lambda n: " ".join(akid() for _ in range(n // 21)), [AWS], 64000)


class CurlRuleTests(unittest.TestCase):
    def commands(self) -> list[str]:
        tok, b64, up = rnd(32), rnd(24, AN + "+/"), "deploy" + ":" + rnd(14)
        return [
            f"curl -H 'Authorization: Bearer {tok}' https://api.example.com/v1",
            f'curl https://api.example.com/v1 -H "Authorization: Basic {b64}"',
            f"curl -s \\\n  -X POST \\\n  --header 'X-Api-Key: {tok}' \\\n  https://api.example.com/x",
            f"curl -s https://api.example.com/x\\\n\n  -H 'Authorization: Token {tok}'",
            f"curl -u {up} https://example.com/a",
            f"curl --user '{up}' https://example.com/a",
            f'curl -s \\\n  --user="{up}" \\\n  https://example.com/a',
            f"curl -s\n1\n2\n3\n4\n5\n -u {up} https://example.com/a",        # 6 breaks: too far for the rule
            f"curl -s\n\n\n\n\n\n -u {up} https://example.com/a",              # blank lines: 3 breaks
            f"echo curl\n -H 'Authorization: Bearer {tok}'",
            f"curl https://example.com/a\n1\n2\n3\n4\n5\n6\n7\ncurl -u {up} https://example.com/b",  # near one
            f"wget --header 'Authorization: Bearer {tok}'",                         # no curl: no hit
        ]

    def test_the_curl_rules_take_the_linear_path(self):
        for rule in detect.rules():
            if rule.id in CURL:
                self.assertIsNotNone(detect._curl_parts(rule), f"{rule.id}: a sync changed the head of its regex")

    def test_the_linear_path_finds_what_the_regex_finds(self):
        rules = {r.id: r for r in detect.rules() if r.id in CURL}
        self.assertEqual(set(rules), set(CURL))
        for text in self.commands():
            for rid, rule in rules.items():
                with self.subTest(rule=rid, text=text[:30]):
                    rx = re.compile(rule.regex.pattern)
                    want = [(m.start(), secret_span(m, rx.groups), m.groups()) for m in rx.finditer(text)]
                    got = [(m.start(), secret_span(m, rx.groups), tuple(m.group(i) for i in range(1, rx.groups + 1)))
                           for m in detect._matches(rule, text)]
                    self.assertEqual(got, want)

    def test_a_second_credential_right_after_the_first_is_found(self):
        # the trailing space of the first -u was part of its match, and finditer went on after it (Gate B of 0.6.15)
        a, b = "admin" + ":" + rnd(14), "bob" + ":" + rnd(14)
        text = f"curl -u {a} --user {b} https://example.com/a"
        self.assertEqual([m.value for m in detect.scan(text) if m.kind == "curl-auth-user"], [a, b])

    def test_fuzz_the_linear_path_finds_every_credential_the_regex_finds(self):
        # every secret span the betterleaks regex finds is found by the linear path (it may find more: each -u)
        r = random.Random(1)
        tok = rnd(30)
        pieces = ["curl", "CURL", f" -H 'X-API-Key: {tok}'", f' -H "Authorization: Basic {tok}"', f" -u admin:{tok}",
                  " --user bob" + ":" + tok + " \\\n", "\n", "\n\n", "\r\n", " -X POST", " https://x", " echo",
                  " -d @f",
                  " && ", "curl -s", " -H 'Accept: */*'", "\r"]
        rules = [x for x in detect.rules() if x.id in CURL]
        misses = []
        for _ in range(3000):
            text = "".join(r.choice(pieces) for _ in range(r.randint(2, 14)))
            for rule in rules:
                rx = re.compile(rule.regex.pattern)
                want = {secret_span(m, rx.groups) for m in rx.finditer(text)}
                got = {secret_span(m, rx.groups) for m in detect._curl_matches(detect._curl_parts(rule), text)}
                if not want <= got:
                    misses.append((rule.id, len(text)))
        self.assertEqual(misses[:5], [])

    def test_a_line_of_many_curl_words_scans_in_linear_time(self):
        # released code: 32K characters of "curl " took 16.6 s for the two curl rules and the AWS rule
        for tok in ("curl ", "curl -u ", "curl -H 'Authorization: Bearer "):
            with self.subTest(tok):
                linear(self, lambda n, tok=tok: (tok * (n // 4))[:n], CURL, 32000)


class LabelRuleTests(unittest.TestCase):
    def test_a_long_line_of_a_command_word_scans_in_linear_time(self):
        # `mysql … -p` and `redis-cli … -a` looked for the option over the rest of the line from each command word:
        # 32K characters took 0.35 s, 256K about 22 s (Gate A of 0.6.15); bounded to 400 characters as the AWS rule
        for tok in ("mysql -u root ", "redis-cli -h cache "):
            with self.subTest(tok):
                linear(self, lambda n, tok=tok: (tok * (n // 10))[:n], ("label-mysql-p", "label-redis-cli-a"),
                              96000)

    def test_a_run_of_spaces_or_bangs_after_a_password_word_scans_in_linear_time(self):
        # `[ \t]*:?[ \t]+` tried every split of a run of spaces, and `!*` before a lookahead that also takes "!" every
        # length of a run of "!": 16K characters took 3.5 to 6.2 s of the whole scan (ReDoS probe of 0.7.12)
        cases = {
            "password is": ("label-prose-password", "label-password-after-word"),
            "password a is": ("label-password-words-is",),
            "password for the db is": ("label-password-for-is",),
            "password ": ("label-password-after-space", "label-password-after-word"),
            "Kennwort ist": ("label-password-after-word",),
        }
        for head, ids in cases.items():
            with self.subTest(head=head):
                linear(self, lambda n, head=head: head + " " * n, ids, 32000)
        linear(self, lambda n: "password is a" + "!" * n + "x", ("label-prose-password",), 32000)

    def test_a_password_after_spaces_a_colon_or_bangs_is_still_found(self):
        pw = rnd(10) + "#7"
        for text in (f"the password is {pw}", f"the password is:   {pw}", f"password was  :  {pw}",
                     f"the wifi password here is {pw}", f"password for the db is {pw}"):
            with self.subTest(text=text[:20]):
                self.assertIn(pw, [m.value for m in detect.scan(text)])
        self.assertIn(pw + "!!", [m.value for m in detect.scan(f"the password is {pw}!! thanks")])

    def test_the_option_400_characters_after_the_command_is_still_found(self):
        pw = rnd(10) + "#7"
        text = "mysql " + "--host db " * 39 + f"-p{pw} shop"
        self.assertEqual([m.value for m in detect.scan(text) if m.kind == "label-mysql-p"], [pw])


class KeywordLabelTailTests(unittest.TestCase):
    """The detect-secrets keyword rules read `<keyword>\\w*` as the label. On `password=` and a long run of letters with
    no space, each keyword inside the run (pwd, key) took the rest of the run: 320 KB took 10 s (0.6.15). They now run
    as detect._KeywordTail: the same matches as the vendored regex, in linear time."""

    def rules(self, languages=("en",)):
        return [r for r in detect._load_detect_secrets(languages) if r.id.startswith("ds-keyword")]

    def test_a_long_run_of_letters_after_a_label_scans_in_linear_time(self):
        run = "".join(_R.choice("bcdfghjkmnpqrstvwxz") for _ in range(320000))
        ids = [r.id for r in detect.rules() if r.id.startswith("ds-keyword")]
        linear(self, lambda n: "password=" + run[:n], ids, 320000)
        linear(self, lambda n: "password=" + "pwd" * (n // 3), ids, 300000)

    def test_a_megabyte_of_label_chains_scans_in_linear_time(self):
        # `pw=pw=…` started a label at each `pw` and each value ran 300 characters to fail at the line end: 1 MB took
        # 5.5 s (Gate B of 0.6.16, 0.6.15: 1.1 s). A label never starts after `=` now
        lit = [d["id"] for d in detect.LITERAL_RULES]
        linear(self, lambda n: "pw=" * (n // 3), lit, 1020000)
        linear(self, lambda n: "password: " * (n // 10), lit, 1000000)

    def test_one_long_word_does_not_slow_the_rest_of_the_text(self):
        # codex verification of 0.6.16: one unrelated word of 200 characters sent a whole 270 KB text of password
        # records through the slow loop (4.7 s against 0.7 s)
        rec = ["password: ${DB_PASSWORD}", "mot de passe : voir le coffre", 'api_key = os.environ["API_KEY"]',
               "secret: please rotate", "db_pass = config.get('db')"]
        plain = "\n".join(rec[i % len(rec)] for i in range(4000))
        mixed = plain + "\n" + "x" * 200

        def run(t):
            best = 9e9
            for _ in range(2):
                started = time.perf_counter()
                for r in self.rules(("en", "fr")):
                    list(r.regex.finditer(t))
                best = min(best, time.perf_counter() - started)
            return best

        self.assertLess(run(mixed), 2.0 * run(plain) + 0.05)

    def test_six_keyword_rules_take_the_linear_path(self):
        # a rule with label words runs through detect._LabelSubset, whose regex of the whole is the _KeywordTail
        linear = [r.id for r in self.rules() if isinstance(getattr(r.regex, "_full", r.regex), detect._KeywordTail)]
        self.assertEqual(len(linear), 6, linear)   # the seventh starts with the value, its \\w* ends the regex

    def fuzz_texts(self, rng):
        parts = ["password", "pwd", "api_key", "secret", "db_pass", "Passwd", "token", "_", "x", "Ab9", "value",
                 "=", "==", "!=", ":", " : ", "=>", " ", "  ", "'", '"', "`", ";", ",", "]", "\\", "\t", "\n", "-",
                 "#7", "Kennwort", "mot de passe", "\u00e4"]
        texts = []
        for k in range(1200):
            t = "".join(rng.choice(parts) for _ in range(rng.randint(2, 14)))
            if k % 3 == 0:   # a word tail of 0 to 5000 characters, the old bound 199 to 201 included
                n = rng.choice((0, 1, 50, 199, 200, 201, 202, 250, 251, 1000, 2500, 5000, rng.randint(0, 5000)))
                t = t.replace("_", "_" + "w" * n, 1) if "_" in t else "password" + "w" * n + t
            texts.append(t)
        return texts

    def test_fuzz_the_linear_rules_find_what_the_vendored_ones_find(self):
        """On word tails of 0 to 5000 characters, also with German and French labels on, both give the same matches,
        group by group."""
        rng = random.Random(1616)
        texts = self.fuzz_texts(rng)
        found = 0
        for langs in (("en",), ("en", "de", "fr")):
            for r in self.rules(langs):
                if not isinstance(getattr(r.regex, "_full", r.regex), detect._KeywordTail):
                    continue
                old = re.compile(r.regex.pattern, r.regex.flags)
                for t in texts:
                    spans = [[m.span(i) for i in range(old.groups + 1)] for m in r.regex.finditer(t)]
                    want = [[m.span(i) for i in range(old.groups + 1)] for m in old.finditer(t)]
                    self.assertEqual(spans, want, f"{r.id} {langs}: {t[:80]!r} ({len(t)} chars)")
                    found += len(spans)
        self.assertGreater(found, 400, "the fuzz inputs must hold labels and values, or the comparison proves nothing")

    def test_a_label_with_a_tail_of_201_and_more_characters_is_still_a_label(self):
        v = rnd(12) + "#7"
        for n in (199, 200, 201, 5000):
            with self.subTest(n=n):
                self.assertIn(v, [m.value for m in detect.scan("password" + "x" * n + " = " + v)])


if __name__ == "__main__":
    unittest.main()
