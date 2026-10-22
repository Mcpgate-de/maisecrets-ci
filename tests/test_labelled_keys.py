"""Keys that a label names but no label rule took: each key in a list after a label that names secrets, and an
Elasticsearch API key in an `Authorization: ApiKey` header.

Run: python3 -m unittest tests.test_labelled_keys -v
Every value is built at run time from a hash or a seeded random source, so no literal sits in the tree and the tree
scan stays clean. The false alarms these rules must not raise in developer text (tokenizer output, lockfiles, ids,
paths, crypto test vectors, prose about the ApiKey scheme) are in tests/fp_corpus.py NO_HIT.
"""
from __future__ import annotations

import base64
import hashlib
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

RNG = random.Random(16)
ALNUM = string.ascii_letters + string.digits


def hexkey(seed: str, n: int = 32) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:n]


def b64key(seed: str, n: int = 32) -> str:
    """A key as most services hand it out: base64url of random bytes, with a capital, a small letter and a digit."""
    while True:
        k = base64.urlsafe_b64encode(hashlib.sha512(seed.encode()).digest()).decode().rstrip("=")[:n]
        if any(c.isupper() for c in k) and any(c.islower() for c in k) and any(c.isdigit() for c in k):
            return k
        seed += "+"


def es_key(ident: str, secret: str) -> str:
    """An Elasticsearch API key as the header carries it: base64 of id:key."""
    return base64.b64encode(f"{ident}:{secret}".encode()).decode()


def hits(text: str, kind: str) -> list[str]:
    return [m.value for m in detect.scan(text) if m.kind == kind]


def values(text: str) -> list[str]:
    return [m.value for m in detect.scan(text)]


class SecretListTests(unittest.TestCase):
    def test_each_key_in_a_list_after_a_secret_label_is_a_hit(self):
        a, b = hexkey("list-a", 32), b64key("list-b")
        for text in (f'{{"api_keys": ["{a}", "{b}"], "color": null}}',
                     f"passwords = ['{a}', '{b}']",
                     f'\tSecrets:   []string{{"{a}", "{b}"}},',
                     f'"refresh_tokens": [\n    "{a}",\n    "{b}"\n]',
                     f'const password = ["{a}", "{b}"];',
                     f'clientSecrets: ["{a}", "{b}"]'):
            with self.subTest(text=text[:20]):
                self.assertEqual(hits(text, "label-secret-list"), [a, b])

    def test_a_long_list_is_masked_to_its_end(self):
        keys = [hexkey(f"long-{i}", 32) for i in range(200)]
        text = '"api_keys": [' + ", ".join(f'"{k}"' for k in keys) + "]"
        self.assertEqual(hits(text, "label-secret-list"), keys)

    def test_a_list_longer_than_a_megabyte_is_masked_to_its_end(self):
        # a cut 1 MB after the label left 2,159 of 33,000 keys in the clear (codex Gate A of 0.6.16)
        keys = [hexkey(f"big-{i}", 32) for i in range(33000)]
        text = '"api_keys": [' + ", ".join(f'"{k}"' for k in keys) + "]"
        self.assertGreater(len(text), 1 << 20)
        got = hits(text, "label-secret-list")
        self.assertEqual(len(got), len(keys))
        self.assertEqual(got[-1], keys[-1])

    def test_a_list_after_a_label_that_names_no_secret_is_no_hit(self):
        k = hexkey("not-secret", 32)
        for label in ("tokens", "token", "Tokens", "code_tokens", "cache_tokens", "revokedTokens", "payment_tokens",
                      "vault_secrets", "keys", "access_keys", "token_hashes"):
            with self.subTest(label=label):
                self.assertEqual(values(f'"{label}": ["{k}", "{b64key(label)}"]'), [])

    def test_values_that_are_no_key_stay_text(self):
        bcrypt = "$2b$12$" + "".join(RNG.choice(ALNUM) for _ in range(53))
        for item in ("DB_PASSWORD", "ProdDbPassword2024Rotated", "TokenizerPiece2024X", "convertToUTF8String",
                     "projects/my-proj/secrets/db-pass/versions/3", "secret/data/app/" + b64key("vault", 12),
                     ":".join(["arn", "aws", "secretsmanager", "eu-central-1", "123456789012", "sec" + "ret",
                               b64key("arn", 12)]), bcrypt,
                     "0x" + hexkey("eth", 40), "pm_" + b64key("stripe", 24), "sess_" + b64key("clerk", 24),
                     "sha256:" + hexkey("dg", 64),
                     "sha384-" + base64.b64encode(hashlib.sha384(b"sri").digest()).decode(),
                     "${API_KEY_1}", "a" * 20 + "1", "0" * 16, str(int(hexkey("numeric-id"), 16))[:18]):
            with self.subTest(item=item[:24]):   # other rules may take a part (an ARN, a typed id) as before
                self.assertEqual(hits(f'"secrets": ["{item}"]', "label-secret-list"), [])

    def test_the_list_ends_at_its_bracket(self):
        a, other = hexkey("end-a", 32), hexkey("end-b", 32)
        self.assertEqual(hits(f'"api_keys": ["{a}"], "ids": ["{other}"]', "label-secret-list"), [a])
        self.assertEqual(hits(f'"api_keys": ["{a}"]\n"{other}",\n', "label-secret-list"), [a])
        self.assertEqual(hits(f'"api_keys": [{{"id": "{other}"}}]', "label-secret-list"), [])

    def test_a_tuple_is_no_list_of_secrets(self):
        # the Elasticsearch client takes api_key=("<id>", "<key>"); the id is public
        self.assertEqual(values(f'es = Elasticsearch(hosts, api_key=("{b64key("es-id", 20)}", os.environ["K"]))'), [])

    def test_a_key_after_a_word_in_the_list_is_still_a_hit(self):
        a = hexkey("after-word", 32)
        self.assertEqual(hits(f'"passwords": ["Bearer", "{a}"]', "label-secret-list"), [a])


class ApiKeySchemeTests(unittest.TestCase):
    def test_an_elasticsearch_api_key_header_is_a_hit(self):
        k = es_key(b64key("es-id", 20), b64key("es-key", 22))
        for text in (f"Authorization: ApiKey {k}",
                     f"curl -H 'Authorization: ApiKey {k}' https://localhost:9200/_search",
                     f"headers: {{ authorization: 'ApiKey {k}' }}",
                     f'headers = {{"Authorization": "ApiKey {k}"}}',
                     f'req.headers["Authorization"] = "ApiKey {k}"'):
            with self.subTest(text=text[:24]):
                self.assertEqual(hits(text, "auth-scheme-apikey"), [k])

    def test_a_key_without_a_digit_is_a_hit_too(self):
        k = base64.b64encode(b"a:" + b"a" * 20).decode()
        self.assertEqual(hits(f"Authorization: ApiKey {k}", "auth-scheme-apikey"), [k])

    def test_a_value_that_is_no_id_and_key_is_no_hit(self):
        for v in (base64.b64encode(hashlib.sha256(b"no-colon").digest()[:9]).decode(),
                  "aB3dE5fG7hJ9", "YOUR_ENCODED_API_KEY", base64.b64encode(b":only-a-key").decode()):
            with self.subTest(v=v[:8]):
                self.assertEqual(values(f"Authorization: ApiKey {v}"), [])

    def test_the_scheme_outside_a_header_is_no_hit(self):
        k = es_key(b64key("prose-id", 20), b64key("prose-key", 22))
        for text in (f"API docs example: ApiKey {k}",
                     f"We migrated from ApiKey {k} to OAuth.",
                     "ApiKey OAuth2Migration is rotated monthly by the platform team.",
                     "Set the header to Authorization: ApiKey <base64-encoded id:key>.",
                     "Authorization: ApiKey ${ES_API_KEY}"):
            with self.subTest(text=text[:30]):
                self.assertEqual(values(text), [])


class ProseKeyTests(unittest.TestCase):
    """label-prose-key: a key that a sentence names, with no `:` or `=` before it (benchmark V3, Nemotron dev: about
    1,300 keys in the clear)."""

    def test_a_random_key_after_a_key_word_in_a_sentence_is_a_hit(self):
        alnum = "".join(RNG.choice(ALNUM) for _ in range(32))
        uuid = "-".join(hexkey("prose-uuid")[a:b] for a, b in ((0, 8), (8, 12), (12, 16), (16, 20), (20, 32)))
        for v in (alnum, hexkey("prose-hex", 32), uuid, b64key("prose-b64", 40)):
            for text in (f"Use the API key {v} for the call.", f"The API key is {v}.",
                         f"Please rotate the API key, {v}, today.", f"Here is the access token {v} for staging."):
                with self.subTest(text=text[:30], n=len(v)):
                    self.assertEqual(values(text), [v])

    def test_a_key_of_a_known_format_keeps_its_rule(self):
        v = "glpat-" + b64key("prose-glpat", 20)
        self.assertEqual([m.kind for m in detect.scan(f"Use the token {v} for the job.")], ["gitlab-pat"])

    def test_words_numbers_and_templates_after_a_key_word_are_no_hit(self):
        for text in ("The token count is 50256 for this model.", "Set the API key YOUR_API_KEY_HERE first.",
                     "the token PaymentsServiceV2Prod is the name of the service",
                     "The API key, which we rotate every month, lives in the vault.",
                     "the access token /run/secrets/api_token_v2 is mounted",
                     "Use the API key " + es_key("doc-id", "doc-key") + " from the docs.",
                     "the API key 1.2.3-beta.4 version"):
            with self.subTest(text=text[:30]):
                self.assertEqual(values(text), [])


if __name__ == "__main__":
    unittest.main()
