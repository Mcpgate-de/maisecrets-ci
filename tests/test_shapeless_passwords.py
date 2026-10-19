"""Passwords with no shape where no `=` or `:` stands between label and value, and keyword labels in a JSON object
inside a string. A public benchmark (Cloakroom holdout v7, 2026-10-12) leaked ten such passwords: .netrc, CLI flags,
`mysql -p`, Redis AUTH and prose. Samsung CredData, line by line, held 62 credentials behind `\\"password\\":\\"`.

Run: python3 -m unittest tests.test_shapeless_passwords -v
Every value is built at run time from parts, so no literal sits in the tree and the tree scan stays clean.
"""
from __future__ import annotations

import os
import random
import re
import string
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import detect, regions  # noqa: E402

J = "".join
RNG = random.Random(1012)


def found(text: str) -> list[tuple[str, str]]:
    active = regions.Active(regions=("generic",), languages=("en",), source="test")
    with detect.Detector(regions=active).activate():
        return [(m.type, m.value) for m in detect.scan(text)]


def password(n: int = 12, symbols: str = "#%*!-") -> str:
    """A password of the benchmark's shape: capitals, small letters, digits and a symbol, in random order. No `&` or
    `;` by default: unquoted in a shell they end the command, so no unquoted value holds them."""
    parts = [RNG.choice(string.ascii_uppercase), RNG.choice(string.ascii_lowercase), RNG.choice(string.digits),
             RNG.choice(symbols)]
    parts += [RNG.choice(string.ascii_letters + string.digits) for _ in range(n - len(parts))]
    RNG.shuffle(parts)
    return J(parts)


PW_FLAG = J(["--pass", "word"])
PW = J(["pass", "word"])


class CliFlagTests(unittest.TestCase):
    def test_a_password_after_a_flag_and_a_space_is_a_hit(self):
        pw = password()
        for text in (f"$ pg_dump --host db1 --username app {PW_FLAG} '{pw}' prod > dump.sql",
                     f'nats server info --user admin {PW_FLAG} "{pw}" --help',
                     f"ogg --user ggadmin {PW_FLAG} {pw} \\",
                     f"tool --db-{PW} {pw}",
                     f"$cred = Connect-Thing -User bob -{PW.capitalize()} {pw}"):
            with self.subTest(text=text.replace(pw, "<pw>")):
                self.assertEqual(found(text), [("SECRET", pw)])

    def test_options_placeholders_and_words_after_the_flag_are_no_hit(self):
        for text in (f'echo "$CI_REGISTRY_{PW.upper()}" | docker login -u ci {PW_FLAG}-stdin',
                     f"tool {PW_FLAG}-file ./secret.txt", f"tool {PW_FLAG} {PW.upper()}",
                     f"tool {PW_FLAG} <{PW}>", f"[-user <domain-user>] [-{PW} <domain-{PW}>]",
                     f"use the {PW_FLAG} argument to set it", f'tool {PW_FLAG} "$DB_{PW.upper()}"',
                     f"tool {PW_FLAG} ${{DB_{PW.upper()}}}", f"dpl heroku --username user {PW_FLAG} pass",
                     f"tool {PW_FLAG} <admin-pw>, then the host", f"git send-email --no-{PW} --force-tls \\"):
            with self.subTest(text=text):
                self.assertEqual(found(text), [])

    def test_an_elided_value_in_docs_is_no_hit(self):
        # a keyword filter of scan(): the label rules without `=` or `:` get them too (KEYWORD_RULES)
        self.assertEqual(found(f"tool {PW_FLAG} {password(8)[:8]}... (shortened)"), [])

    def test_a_flag_password_in_test_code_is_a_fixture(self):
        # a label rule (LABEL_RULES): in test code it is a fixture, as `password = "<value>"` is
        pw = password()
        text = f'def test_login(self):\n    cmd = "tool {PW_FLAG} {pw} --verbose"\n'
        hits = [m for m in detect.scan(text) if m.value == pw]
        self.assertEqual(len(hits), 1)
        self.assertTrue(detect.is_fixture(hits[0], text, "tests/test_login.py"))


class MysqlTests(unittest.TestCase):
    def test_a_password_glued_to_dash_p_is_a_hit(self):
        pw = password()
        for text in (f"$ mysql -h 10.2.0.14 -u report -p'{pw}' analytics",
                     f"mysqldump -uroot -p{pw} shop > shop.sql", f'mariadb -u app -p"{pw}" -e "select 1"'):
            with self.subTest(text=text.replace(pw, "<pw>")):
                self.assertEqual(found(text), [("SECRET", pw)])

    def test_a_prompt_a_port_and_a_variable_are_no_hit(self):
        for text in ("mysql -u root -p app", "mysql -h db -P3306 -u root -p", "mysql -u root -proot app",
                     f'mysql -u root -p"$MYSQL_{PW.upper()}" app', "grep -pattern x mysql.log"):
            with self.subTest(text=text):
                self.assertEqual(found(text), [])


class RedisTests(unittest.TestCase):
    def test_auth_at_the_prompt_and_redis_cli_dash_a_are_hits(self):
        pw = password(11)
        for text in (f"127.0.0.1:6379> AUTH {pw}\nOK\n127.0.0.1:6379> KEYS session:*\n",
                     f"AUTH default {pw}", f"redis-cli -h cache.internal -a {pw} ping"):
            with self.subTest(text=text.replace(pw, "<pw>")):
                self.assertEqual(found(text), [("SECRET", pw)])

    def test_auth_words_and_prose_are_no_hit(self):
        for text in ("AUTH LOGIN", "the auth token expired, AUTH failed", "250-AUTH PLAIN LOGIN",
                     "step:\nauth 2fa-required",
                     "127.0.0.1:6379> AUTH $REDIS_" + PW.upper()):
            with self.subTest(text=text):
                self.assertEqual(found(text), [])


class NetrcTests(unittest.TestCase):
    def test_a_netrc_password_on_several_lines_and_on_one_is_a_hit(self):
        pw = password(10)
        for text in (f"machine git.example-corp.net\n  login deploy\n  {PW} {pw}\n",
                     f"machine api.example-corp.net login ci {PW} {pw}",
                     f"default login anonymous {PW} {pw}"):
            with self.subTest(text=text.replace(pw, "<pw>")):
                self.assertEqual(found(text), [("SECRET", pw)])

    def test_a_default_entry_after_another_entry_on_its_line_is_a_hit(self):
        pw, other = password(10), password(10)
        text = f"machine api.example-corp.net login ci {PW} {other} default login anonymous {PW} {pw}"
        self.assertEqual(found(text), [("SECRET", other), ("SECRET", pw)])

    def test_prose_with_machine_or_default_is_no_hit(self):
        for text in (f"the default {PW} is printed on the label", f"machine learning {PW} reset flow",
                     f"==== Disabling default {PW} expiration",
                     f"machine host login user {PW} $NETRC_{PW.upper()}"):
            with self.subTest(text=text):
                self.assertEqual(found(text), [])


class ProseTests(unittest.TestCase):
    def test_a_password_in_a_sentence_is_a_hit(self):
        pw = password(11, symbols="%#&*")
        for text in (f"the staging db is down again, my {PW} is {pw} if you want to try logging in yourself",
                     f'the {PW} was "{pw}".', f"{PW.capitalize()} is: {pw}", f"my {PW} is {pw}. Thanks"):
            with self.subTest(text=text.replace(pw, "<pw>")):
                self.assertEqual(found(text), [("SECRET", pw)])

    def test_words_of_a_sentence_are_no_hit(self):
        for text in (f"the {PW} is incorrect.", f"the {PW} is base64-encoded before it is stored",
                     f"the {PW} is hunter2 and the user is max", f"the {PW} is shown as plain text",
                     f"the {PW} is required", f"the {PW} is ${{DB_{PW.upper()}}}", f"the {PW} is 12345678",
                     f'"description": "The {PW} is invalid."', f"<p>The {PW} is ignored.</p>",
                     f'"doc": "the user for whom the {PW} is valid.\\n@param userName"', f"the {PW} is set.*/",
                     f"the {PW} is Read-Only", f'"doc": "the {PW} is v2\\n@param"'):
            with self.subTest(text=text):
                self.assertEqual(found(text), [])


class EscapedJsonTests(unittest.TestCase):
    def test_a_value_behind_escaped_quotes_is_a_hit_without_its_backslash(self):
        pw = password(14)
        tok = J(RNG.choice(string.ascii_letters + string.digits) for _ in range(24))
        for text, value in ((f'{{\\"username\\":\\"bob\\",\\"{PW}\\":\\"{pw}\\"}}', pw),
                            (f'body: "{{\\"access_token\\":\\"{tok}\\",\\"token_type\\":\\"Bearer\\"}}"', tok),
                            (f'"{{\\"secret\\": \\"{pw}\\"}}"', pw)):
            with self.subTest(text=text.replace(value, "<v>")):
                self.assertEqual(found(text), [("SECRET", value)])

    def test_a_derived_label_behind_escaped_quotes_is_no_hit(self):
        h = J(RNG.choice("0123456789abcdef") for _ in range(16))
        for text in (f'{{\\"hashed_token\\":\\"{h}\\"}}', f'{{\\"token_last_eight\\":\\"{h[:8]}\\"}}',
                     f'{{\\"{PW}_hash\\":\\"{h}\\"}}', '{\\"token_type\\":\\"Bearer\\"}'):
            with self.subTest(text=text.replace(h, "<h>")):
                self.assertEqual(found(text), [])

    def test_runs_that_count_up_after_a_label_stay_a_hit(self):
        # 0.6.14 found these after a password label; a filter for an AWS documentation example (abc+123+xyz+789)
        # dropped them in a candidate of 0.6.15 and was taken out (codex review of the release): detection only grows
        for v in (J(["abcd", "1234"]), J(["abc", "123", "xyz", "789"]), J(["ab", "12", "cd", "34", "ef"])):
            with self.subTest(shape=re.sub(r"[0-9]", "9", re.sub(r"[a-z]", "a", v))):
                self.assertEqual(found(f"{PW}: {v}"), [("SECRET", v)])
                self.assertEqual(found(f'{{\\"{PW}\\":\\"{v}\\"}}'), [("SECRET", v)])

    def test_an_unquoted_value_reads_the_same_escaped_and_plain(self):
        # an escaped null was a hit and a plain one was not: the comma before the escaped quote stayed in the value
        # (Gate B of 0.6.15)
        for v in ("null", "true", "false", "1234567"):   # the literals JSON writes without quotes
            plain = f'{{"{PW}":{v},"remember":true}}'
            escaped = '"' + plain.replace('"', '\\"') + '"'
            with self.subTest(shape=re.sub(r"[A-Za-z]", "a", re.sub(r"[0-9]", "9", v))):
                self.assertEqual(found(escaped), found(plain))

    def test_code_after_an_escaped_label_is_no_hit(self):
        # JSON inside a string holds its values as escaped strings: a value without an escaped quote is code
        # (`\\"access_token\\": finding[\\"secret\\"]` in the vendored rules file, Gate A of 0.6.15)
        for text in ('"{\\"access_token\\": finding[\\"secret\\"]}"', f'"{{\\"{PW}\\": X9k2mQ7vR4,\\"x\\":1}}"'):
            with self.subTest(text=text[:24]):
                self.assertEqual(found(text), [])

    def test_a_uuid_behind_an_escaped_secret_label_is_a_hit(self):
        # the label filters read the escaped label too: a UUID after a token label is a token (_SECRET_LABEL_RE)
        u = "-".join(J(RNG.choice("0123456789abcdef") for _ in range(n)) for n in (8, 4, 4, 4, 12))
        self.assertEqual(found(f'{{\\"api_token\\":\\"{u}\\"}}'), [("SECRET", u)])

    def test_a_number_behind_an_escaped_measure_label_is_no_hit(self):
        # _LABEL_TAIL_RE reads the escaped label: a duration after it is no secret (_MEASURE_LABEL_RE)
        self.assertEqual(found('{\\"refresh_token_ttl\\":\\"15552000\\"}'), [])


class NoPasswordAfterTheNewLabelsTests(unittest.TestCase):
    """The label paths of 0.6.15 read no password in a date or a timestamp, a file a tool reads (@/path), a template
    variable a build fills (@NAME@) or a CHANGE_ME placeholder (release review of 0.6.15, Gate B)."""

    def test_dates_files_templates_and_placeholders_are_no_hit(self):
        day, stamp = J(["2024-10", "-13"]), J(["2024-10-01", "T12:00:00Z"])
        texts = [
            J(['"{\\"', PW, 'LastChanged\\":\\"', stamp, '\\"}"']),
            f"the {PW} is {stamp}",
            f"redis 127.0.0.1:6379> AUTH {day}",
            f"myapp {PW_FLAG} @/run/secrets/pw",
            J(["mysql -u root -p@", "MYSQL_PWD@ < schema.sql"]),
            f"myapp {PW_FLAG} {J(['CHANGE', '_ME_2024'])}",
        ]
        for text in texts:
            with self.subTest(text=text[:30]):
                self.assertEqual(found(text), [])

    def test_a_real_value_after_the_same_labels_stays_a_hit(self):
        pw = password()
        for text in (f"myapp {PW_FLAG} {pw}", f"redis> AUTH default {pw}", f"mysql -u root -p{pw} db",
                     J(['"{\\"', PW, '\\":\\"', pw, '\\"}"'])):
            with self.subTest(text=text[:24]):
                self.assertEqual(found(text), [("SECRET", pw)])

    def test_a_password_that_only_starts_like_a_date_or_a_placeholder_stays_a_hit(self):
        # the whole value is compared, its last character too (codex, verification of 0.6.15)
        for pw in (J(["2024-10", "-13!"]), J(["@2024", "-10-13"]), J(["CHANGE", "_ME_2024!x"])):
            for text in (f"redis> AUTH {pw}", f"myapp {PW_FLAG} {pw}", J(['"{\\"', PW, '\\":\\"', pw, '\\"}"'])):
                with self.subTest(text=text[:20], value=pw[:5]):
                    self.assertEqual(found(text), [("SECRET", pw)])

    def test_a_date_after_a_plain_json_label_is_as_in_0_6_14(self):
        # the shared ds path is not changed: it took this value in 0.6.14 too
        stamp = J(["2024-10-01", "T12:00:00Z"])
        self.assertEqual(found(J(['{"', PW, 'LastChanged":"', stamp, '"}'])), [("SECRET", stamp)])


if __name__ == "__main__":
    unittest.main()
