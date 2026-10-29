"""Secrets in config and code forms that Benchmark V3 found in the clear (aparte, llmredactor, CredSweeper dev,
2026-10): a key or a salt of PHP's define(), and the other forms this file adds a class for.

Run: python3 -m unittest tests.test_config_forms -v
Every value is built at run time from a seeded random source, so no literal sits in the tree and the tree scan stays
clean.
"""
from __future__ import annotations

import base64
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

RNG = random.Random(2210)
ALNUM = string.ascii_letters + string.digits
# the signs of a WordPress salt (wp-config.php, api.wordpress.org/secret-key): no quote and no backslash
SALT_SIGNS = ALNUM + "!@#$%^&*()-_[]{}<>~`+=,.;:/?|"


def salt(n: int = 64) -> str:
    while True:
        v = "".join(RNG.choice(SALT_SIGNS) for _ in range(n))
        if any(c in "()|`" for c in v) and any(c.isdigit() for c in v):
            return v


def key(n: int = 32) -> str:
    while True:
        v = "".join(RNG.choice(ALNUM) for _ in range(n))
        if any(c.isupper() for c in v) and any(c.islower() for c in v) and any(c.isdigit() for c in v):
            return v


def hits(text: str, channel: str = "prompt") -> list[tuple[str, str]]:
    return [(m.kind, m.value) for m in detect.scan(text, channel=channel)]


def values(text: str, channel: str = "prompt") -> list[str]:
    return [v for _, v in hits(text, channel)]


class PhpDefineTests(unittest.TestCase):
    def test_a_wordpress_salt_in_define_is_a_hit(self):
        names = ("AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "NONCE_SALT")
        salts = [salt() for _ in names]
        text = "<?php\n" + "".join(f"define( '{n}', '{s}' );\n" for n, s in zip(names, salts))
        for channel in ("prompt", "tool"):
            got = values(text, channel)
            for s in salts:
                self.assertIn(s, got, channel)

    def test_a_key_in_double_quotes_is_a_hit(self):
        s = salt(48)
        self.assertIn(("label-php-define-key", s), hits(f'define("STRIPE_SECRET", "{s}");'))

    def test_a_placeholder_a_constant_or_a_short_value_is_no_hit(self):
        for value in ("put your unique phrase here", "MY_OTHER_KEY_CONSTANT_NAME", "something_here_for_you",
                      "short" + "Val1", "x" * 64):
            text = f"define( 'AUTH_KEY', '{value}' );"
            self.assertEqual([], values(text), value)

    def test_a_name_that_names_no_key_is_no_hit(self):
        self.assertEqual([], [k for k, _ in hits(f"define( 'WP_HOME', '{salt()}' );")
                              if k == "label-php-define-key"])


def password() -> str:
    while True:
        v = "".join(RNG.choice(string.ascii_letters) for _ in range(7)) + str(RNG.randint(10, 99)) + RNG.choice("$!#")
        if any(c.isupper() for c in v):
            return v


class TerraformDefaultTests(unittest.TestCase):
    def test_the_default_of_a_secret_variable_is_a_hit(self):
        k, pw = key(40), password()
        text = (f'variable "aws_secret_key" {{\n  default = "{k}"\n}}\n\n'
                f'variable "vpn_password" {{\n  type    = string\n  description = "the tunnel"\n'
                f'  default = "{pw}"\n}}\n')
        got = values(text)
        self.assertIn(k, got)
        self.assertIn(pw, got)

    def test_a_variable_that_names_no_secret_or_has_no_value_is_no_hit(self):
        for text in (f'variable "db_host" {{\n  default = "{key(24)}"\n}}\n',
                     'variable "api_token" {\n  default = ""\n}\n',
                     'variable "db_password" {\n  type = string\n  sensitive = true\n}\n'
                     'variable "region" {\n  default = "eu-central-1"\n}\n'):
            self.assertEqual([], values(text), text)


class UrlPasswordSignsTests(unittest.TestCase):
    def test_a_url_password_with_a_reserved_sign_is_a_hit_and_the_user_stays(self):
        for sign in "!$&+,;=*#?":
            pw = key(9) + sign + key(3)
            for url in (f"postgres://app:{pw}@db.internal:5432/orders", f"mysql://app:{pw}@10.0.0.7:3306/app",
                        f"postgres://app:{pw}@localhost/orders", f"amqp://app:{pw}@rabbit:5672"):
                got = values(f"DATABASE_URL={url}\n")
                self.assertIn(pw, got, url)
                self.assertNotIn("app", got, url)

    def test_an_at_sign_inside_a_password_with_a_sign_stays_in_it(self):
        pw = key(6) + "+" + key(4) + "@" + key(4)
        self.assertIn(pw, values(f'url = "postgres://report:{pw}@pg-01.internal:5432/reports"'))

    def test_a_template_a_query_and_a_plain_url_are_no_hit(self):
        for text in ("postgres://${DB_USER}:${DB_PASSWORD}@db:5432/app",
                     "postgres://app:$(cat /run/secrets/pw)@db:5432/app",
                     "https://example.com/a?x=1&y=2@foo",
                     "git clone https://gitlab.com/group/repo.git",
                     "http://localhost:3000?next=x#top@foo", "https://example.com:8080?a#b@cdn.example.com",
                     "https://app.example.com:8443/#/login?next=a@b"):
            self.assertEqual([], [k for k, _ in hits(text) if k == "url-password-signs"], text)


def b64_bytes(n: int) -> str:
    return base64.b64encode(bytes(RNG.randrange(256) for _ in range(n))).decode()


class FrameworkAppKeyTests(unittest.TestCase):
    def test_laravel_app_key_is_a_hit(self):
        k = "base64:" + b64_bytes(32)
        text = f"APP_NAME=shop\nAPP_ENV=production\nAPP_KEY={k}\nAPP_DEBUG=false\n"
        self.assertIn(("label-laravel-app-key", k), hits(text))

    def test_each_key_of_strapi_app_keys_is_a_hit(self):
        keys = [b64_bytes(16) for _ in range(4)]
        text = "HOST=0.0.0.0\nPORT=1337\nAPP_KEYS=" + ",".join(keys) + "\nDATABASE_CLIENT=postgres\n"
        got = hits(text)
        for k in keys:
            self.assertIn(("label-env-key-list", k), got)

    def test_placeholders_and_other_names_stay_text(self):
        for text in ("APP_KEYS=toBeModified1,toBeModified2\n", "APP_KEY=\n", "APP_KEY=base64:\n",
                     "APP_KEY=base64:" + "A" * 44 + "\n", f"APP_KEYSTORE={b64_bytes(16)}\n",
                     "# APP_KEYS is a list of keys\n"):
            self.assertEqual([], [k for k, _ in hits(text)
                                  if k in ("label-laravel-app-key", "label-env-key-list")], text)


class PasswordNoteTests(unittest.TestCase):
    def test_a_password_in_a_note_line_is_a_hit(self):
        pw = key(8)
        for text in (f"10.0.0.7(pw:{pw})", f"ssh admin@10.0.0.7 port:22 (password:{pw})",
                     f"10.0.0.7(ID/PW:{pw})", f"10.0.0.7/pw:{pw}", f"-id:admin port:22 -pwd:{pw}",
                     f"login with (PWD={pw}) first"):
            for channel in ("prompt", "tool"):
                self.assertIn(pw, values(text, channel), (text, channel))

    def test_code_in_parentheses_stays_text(self):
        for text in ("login(password=self.password)", "f(pass: true)", "call(pw=pw_input)",
                     "connect(password=os.environ['DB_PASSWORD'])", "run(--password-file=/run/secrets/db)",
                     "see docs/pw:latest", "(token:abc)"):
            self.assertEqual([], values(text, "tool"), text)


class EnvEntryTests(unittest.TestCase):
    def test_the_value_of_a_secret_env_entry_is_a_hit(self):
        pw, k = password(), key(32)
        text = ("          env:\n            - name: DB_HOST\n              value: db.internal\n"
                f"            - name: MAIL_PASSWORD\n              value: \"{pw}\"\n"
                f"            - name: API_TOKEN\n              value: '{k}'\n")
        got = values(text)
        self.assertIn(pw, got)
        self.assertIn(k, got)

    def test_an_entry_that_names_no_secret_or_takes_a_reference_stays_text(self):
        for text in (f"  - name: DB_HOST\n    value: \"{key(20)}\"\n",
                     "  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db\n",
                     "  - name: DB_PASSWORD\n    value: \"${DB_PASSWORD}\"\n"):
            self.assertEqual([], values(text), text)


if __name__ == "__main__":
    unittest.main()
