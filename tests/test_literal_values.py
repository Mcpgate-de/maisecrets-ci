"""A label and a literal value that no older rule took (a password that is no word after a password label, a key
after a secret label), and four token formats with a public prefix (NTLMSSP, NATS nkey seed, PASERK, PASETO).

Run: python3 -m unittest tests.test_literal_values -v
Every value is built at run time from a seeded random source, so no literal sits in the tree and the tree scan stays
clean. The developer text these rules must not flag (references, templates, masks, words, vault and Kubernetes
references) is in tests/fp_corpus.py NO_HIT.
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

RNG = random.Random(616)
ALNUM = string.ascii_letters + string.digits


def password(n: int = 10, symbols: str = "") -> str:
    """A password with a capital, a small letter and a digit that is no word, also after undoing leet."""
    while True:
        v = "".join(RNG.choice(ALNUM + symbols) for _ in range(n))
        if (any(c.isupper() for c in v) and any(c.islower() for c in v) and any(c.isdigit() for c in v)
                and detect._wordlike(detect._deleet(v)) < 0.3):
            return v


def kinds(text: str) -> list:
    return [(m.kind, m.value) for m in detect.scan(text)]


class PasswordLiteralTests(unittest.TestCase):
    def test_a_password_after_a_password_label_is_a_hit(self):
        """Forms the keyword rules missed: an XML element, SQL, PowerShell, a value of 4 to 7 characters, a call
        with the label as its name."""
        p4, p6, p10 = password(4), password(6), password(10, "!#%")
        cases = [
            f"<password>{p10}</password>",
            f"<db:Password>{p10}</db:Password>",
            f"ALTER USER app IDENTIFIED BY '{p10}';",
            f"CREATE USER app WITH LOGIN IDENTIFIED WITH mysql_native_password BY '{p10}';",
            f"$sec = ConvertTo-SecureString '{p10}' -AsPlainText -Force",
            f'mysql_pwd = "{p4}"',
            f"PASSWORD: '{p6}'",
            f'conn.Password("{p10}")',
            f"db.passwd={p4}",
            f'"userPassword": "{p6}"',
        ]
        for text in cases:
            with self.subTest(text=text.replace(p10, "<p10>").replace(p6, "<p6>").replace(p4, "<p4>")):
                got = kinds(text)
                self.assertTrue(any(k == "label-pw-literal" for k, _ in got), got and [k for k, _ in got])
                self.assertTrue(any(v in (p4, p6, p10) for _, v in got))

    def test_a_measure_or_a_word_of_another_language_after_a_password_label_stays_text(self):
        """A value that no English word covers is no password without evidence of chance (codex and Opus Gate A/B of
        0.6.16): a number, a ratio, a time, a duration, a section, an abbreviation, a word with a number, a word of
        another language, and a comparison in code."""
        for text in ("pass: 95.2%", "pass: 118/124", "PASS: 41/41", "unit tests pass: 312/312", "Season pass: 2025/26",
                     "Boarding pass: 14C/27", "pw: 8-64", "Passwort: \u00a73.2", "password: ~30d", "password: 12:30",
                     "password: 24h/7d", "Passwort: Seite#3", "Passwort: s.o.", 'password = "senhaAtual"',
                     'wachtwoord: "geheimpje"', '<password>wachtwoord</password>',
                     '<password>contrasenaNueva</password>',
                     'if pw == "Xk9qTz2wLm":', 'if (pw != "Xk9qTz2wLm")'):
            with self.subTest(text=text):
                self.assertEqual([k for k, _ in kinds(text) if k == "label-pw-literal"], [])

    def test_a_password_needs_evidence_and_more_of_it_after_pass(self):
        p = password(10, "!#%")
        for text, value in (("<password>xkcdq" + "wrtzp</password>", "xkcdqwrtzp"),         # few vowels
                            (f"<password>{p}</password>", p), (f"<pass>{p}</pass>", p),
                            (f'("password", "{p}")', p)):                              # a quoted label before a comma
            with self.subTest(text=text.replace(p, "<p>")):
                self.assertIn(("label-pw-literal", value), kinds(text))
        for text in ("<pass>xkcdqwrtzp</pass>", "Boarding pass: Kq9zT2", f'check(password, "{p}")',
                     'args: ["--password-file=/etc/app/pw", "--token-ttl=15m"]'):
            with self.subTest(text=text.replace(p, "<p>")):
                self.assertEqual([k for k, _ in kinds(text) if k == "label-pw-literal"], [])

    def test_an_unquoted_value_with_a_semicolon_is_taken_whole(self):
        p = password(10)
        for text, value in ((f"pw = {p[:5]};{p[5:]}", f"{p[:5]};{p[5:]}"), (f"pw = {p};", p),
                            (f"pwd={p} ; the old one", p)):
            with self.subTest(text=text.replace(p, "<p>")):
                self.assertIn(value, [v for _, v in kinds(text)])   # whole, by this rule or a keyword rule

    def test_an_escaped_or_doubled_quote_is_part_of_the_value(self):
        """The whole literal, never a prefix: SQL and YAML double a quote, PowerShell doubles it or escapes it with a
        backtick, C-like languages, JSON and MySQL escape it with a backslash."""
        p = password(10)
        a, b = p[:5], p[5:]
        cases = [
            (f"ALTER USER app IDENTIFIED BY '{a}''{b}';", f"{a}''{b}"),                          # SQL
            (f"ALTER USER app IDENTIFIED BY '{a}\\'{b}';", f"{a}\\'{b}"),                        # MySQL
            (f"$s = ConvertTo-SecureString '{a}''{b}' -AsPlainText -Force", f"{a}''{b}"),        # PowerShell ''
            (f'$s = ConvertTo-SecureString "{a}`"{b}" -AsPlainText -Force', f'{a}`"{b}'),        # PowerShell `"
            (f'conn.Password("{a}\\"{b}")', f'{a}\\"{b}'),                                     # C#, Java, JavaScript
            (f'{{"password": "{a}\\"{b}"}}', f'{a}\\"{b}'),                                     # JSON
            (f"password: '{a}''{b}'", f"{a}''{b}"),                                              # YAML single quotes
            (f'password: "{a}\\"{b}"', f'{a}\\"{b}'),                                           # YAML double quotes
            (f"pwd = '{p}", p),                                                                  # no closing quote
        ]
        for text, value in cases:
            with self.subTest(text=text.replace(a, "<a>").replace(b, "<b>")):
                self.assertIn(("label-pw-literal", value), kinds(text))
                self.assertFalse([v for _, v in kinds(text) if v in (a, b) or (v != value and v in value)],
                                 "a part of the value was taken on its own")

    def test_a_doubled_quote_first_middle_or_last_is_part_of_the_value(self):
        """codex verification of 0.6.16: a doubled delimiter as the first character of the value left it unmasked."""
        p = password(10)
        a, b = p[:5], p[5:]
        cases = []
        for inner in (f"''{p}", f"{a}''{b}", f"{p}''"):
            cases += [(f"ALTER USER app IDENTIFIED BY '{inner}';", inner),                         # SQL
                      (f"$s = ConvertTo-SecureString '{inner}' -AsPlainText -Force", inner),       # PowerShell
                      (f"pw: '{inner}'", inner)]                                                  # YAML
        for text, value in cases:
            with self.subTest(text=text.replace(a, "<a>").replace(b, "<b>")):
                self.assertIn(("label-pw-literal", value), kinds(text))
        for text in ("password: ''", "ALTER USER app IDENTIFIED BY '';", 'pw = ""'):   # an empty literal
            with self.subTest(text=text):
                self.assertEqual([k for k, _ in kinds(text) if k == "label-pw-literal"], [])

    def test_a_powershell_backtick_escape_is_part_of_the_value_in_any_form(self):
        """Opus verification of 0.6.16: `$pw = "a`"b"` masked only `a`."""
        p = password(10)
        a, b = p[:5], p[5:]
        for text in (f'$pw = "{a}`"{b}"', f'$cred.Password = "{a}`"{b}"'):
            with self.subTest(text=text.replace(a, "<a>").replace(b, "<b>")):
                self.assertIn(("label-pw-literal", f'{a}`"{b}'), kinds(text))
                self.assertNotIn(a, [v for _, v in kinds(text)])

    def test_an_identifier_a_ui_string_a_pattern_or_a_duration_stays_text(self):
        """A name joined by _ - . (snake_case, kebab-case, dotted), a word of another script or with accents, a regular
        expression after a secret label, an ISO 8601 duration (codex and Opus verification of 0.6.16)."""
        texts = ['password = "senha_atual"', 'password = "nueva-contrasena"', 'password = "clave.nueva"',
                 'password = "mot_de_passe_oublie"', 'password: "contrase' + chr(0xF1) + 'a_nueva"',
                 '"password": "Jelsz' + chr(0xF3) + '"',
                 '{"password": "\u041f\u0430\u0440\u043e\u043b\u044c"}',                          # Russian
                 '"password": "\u039a\u03c9\u03b4\u03b9\u03ba\u03cc\u03c2"',                      # Greek
                 '"password": "\u041b\u043e\u0437\u0438\u043d\u043a\u0430"',                      # Serbian
                 '{"password": "\u092a\u093e\u0938\u0935\u0930\u094d\u0921"}',                    # Hindi
                 '{"password": "\u0e23\u0e2b\u0e31\u0e2a\u0e1c\u0e48\u0e32\u0e19"}',             # Thai
                 '{"password": "\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631"}',  # Arabic
                 '{"password": "\u05e1\u05d9\u05e1\u05de\u05d4"}',                                  # Hebrew
                 '{"password": "\u5bc6\u7801"}', '{"password": "\u30d1\u30b9\u30ef\u30fc\u30c9"}',  # CJK
                 '{"password": "\ube44\ubc00\ubc88\ud638"}',                                         # Korean
                 "token: '[A-Za-z0-9_-]{20,}'", "secret: '[a-f0-9]{64}'", "api_key: '^" + chr(92) + "d{6}$'",
                 "password: P90D", "password: PT15M"]
        for text in texts:
            with self.subTest(text=text):
                self.assertEqual([k for k, _ in kinds(text) if k.startswith("label-")], [])
        p = password(10)
        for text, value in ((f'password = "{p[:5]}_{p[5:]}"', f"{p[:5]}_{p[5:]}"),       # random parts stay passwords
                            ('password = "xkcdq' + 'wrtzp_nb"', "xkcdqwrtzp_nb")):
            with self.subTest(text=text.replace(p[:5], "<a>")):
                self.assertIn(value, [v for _, v in kinds(text)])   # whole, by this rule or a keyword rule

    def test_a_word_with_a_number_and_a_sign_is_a_password(self):
        """The form people choose: a word, a number and a sign. Undoing leet makes it a word, so the word check alone
        let it through in the forms that only this rule reads."""
        for value in ("Sommer2024!", "Herbst2025#", "Welcome1!", "Dragon#77x"):
            for form in ("<password>{}</password>", "ALTER USER app IDENTIFIED BY '{}';",
                         "$s = ConvertTo-SecureString '{}' -AsPlainText -Force"):
                text = form.format(value)
                with self.subTest(text=text):
                    self.assertIn(("label-pw-literal", value), kinds(text))
        # no sign, a fixture, a reference, a name joined by _, a scheme
        for value in ("Winter2023", "postgres15", "P@ssw0rd!", "${DB_PASS}!1", "ABC_123_DEF", "b64:!!notbase64"):
            with self.subTest(value=value):
                self.assertEqual([k for k, _ in kinds(f"<password>{value}</password>") if k == "label-pw-literal"], [])

    def test_a_word_or_a_reference_after_a_password_label_is_no_hit(self):
        """No value or one that says what it is: a word, a word in leet, a fixture, a mask, a template, a reference."""
        for value in ("hunter", "Sunshine", "P4ssw0rd", "testpass", "changeme", "********", "abcdef", "123456789",
                      "secret123", "mypassword", "${DB_PASSWORD}", "{{ db_password }}", "%(password)s",
                      "settings.DB_PASSWORD", "<your-password>", "xxxxxxxx", "dragonfly", "v1.2.3-rc1",
                      "dragon42", "Sunshine7"):
            for form in ('db_password = "{}"', "<password>{}</password>", "PASSWORD={}", "?pwd={}&x=1"):
                text = form.format(value)
                with self.subTest(text=text):
                    self.assertEqual([k for k, _ in kinds(text) if k == "label-pw-literal"], [])

    def test_a_label_that_names_something_else_is_no_hit(self):
        v = password(10)
        for label in ("password_hint", "passwordPolicy", "password_regex", "new_password_title", "password_field",
                      "password_hash", "bypass", "compass", "two_pass", "PASSWORD_MIN_LENGTH", "skip_pw",
                      "hashed_password", "encrypted_password", "show_password", "input_password"):
            for text in (f'{label} = "{v}"', f"<{label}>{v}</{label}>"):   # the XML form no keyword rule reads
                with self.subTest(text=text.replace(v, "<v>")):
                    self.assertEqual([k for k, _ in kinds(text) if k == "label-pw-literal"], [])

    def test_an_expression_a_split_value_and_label_words_stay_text(self):
        """A string that a + continues is an expression (the tests here assemble values so); a list of label words
        with an umlaut is words; a key with a character outside ASCII is a split test value."""
        p = password(10)
        k = key(16)
        for text in (f'pw = "{p[:5]}" + "{p[5:]}"', f'PASSWORD = "{p}" + suffix',
                     'for label in ("passwort", "Kennwort", "Schl\u00fcssel", "zugangsdaten"):',
                     'check("password", "Schl' + chr(92) + 'u00fcssel")',   # an escape in source code is its character
                     # escaped quotes of a JSON text: signs only
                     "J(['\"{\\\\\"', PW, '\\\\\":\\\\\"', pw])",
                     f"('SECRET', '{k[:4]}\u00a7{k[4:10]}\u00a7{k[10:]}')", f'client_secret = "{k[:8]}\u00e4{k[8:]}"'):
            with self.subTest(text=text[:10]):
                self.assertEqual([x for x, _ in kinds(text) if x in ("label-pw-literal", "label-secret-literal")], [])

    def test_the_word_list_is_read_only_after_a_password_label(self):
        detect._WORDS.clear()
        detect.scan("def handler(event):\n    return {'status': 'active', 'region': 'eu-west-1'}\n" * 50)
        self.assertEqual(detect._WORDS, [], "text without a password label read the word list")
        detect.scan(f'password = "{password(10)}"')
        self.assertEqual(len(detect._WORDS), 1)

    def test_a_broken_word_list_never_crashes_and_takes_no_word(self):
        """Missing, not UTF-8, not words: no exception, and a value of letters only is no password then; a value with
        a digit still is (codex Gate A of 0.6.16)."""
        import tempfile
        from unittest import mock
        from maisecrets.detection import value_checks   # _word_set() reads _WORDS_FILE from its own module
        d = Path(tempfile.mkdtemp(prefix="wordlist-"))
        (d / "binary.txt").write_bytes(b"\xff\xfe\x00 not utf-8 \xc3\x28")
        (d / "few.txt").write_text("alpha\nbeta\n", encoding="utf-8")
        (d / "junk.txt").write_text("\n".join(["word"] * 1000 + ["1234", "<html>"] * 100), encoding="utf-8")
        p = password(10)
        letters = "".join(c for c in "xkcdqwrtzpbv")
        try:
            for name in ("missing.txt", "binary.txt", "few.txt", "junk.txt"):
                with self.subTest(name=name), mock.patch.object(value_checks, "_WORDS_FILE", str(d / name)):
                    detect._WORDS.clear()
                    self.assertEqual([k for k, _ in kinds(f"<password>{letters}</password>")], [])
                    self.assertFalse(detect._WORDS_OK[0])
                    self.assertIn(("label-pw-literal", p), kinds(f"<password>{p}</password>"))
        finally:
            detect._WORDS.clear()
            detect._WORDS_OK[:] = [True]

    def test_the_word_list_is_the_one_its_license_names(self):
        rules = ROOT / "maisecrets" / "detection" / "rules"
        words = (rules / "words_en.txt").read_text(encoding="utf-8").split("\n")[:-1]
        self.assertEqual(words, sorted(set(words)))
        self.assertTrue(all(w.isascii() and w.isalpha() and w.islower() and 4 <= len(w) <= 8 for w in words))
        self.assertTrue(15000 <= len(words) <= 25000, len(words))
        lic = (rules / "LICENSE-scowl").read_text(encoding="utf-8")
        version = (rules / "SCOWL_VERSION").read_text(encoding="utf-8").strip()
        self.assertIn("Copyright 2000-2026 by Kevin Atkinson", lic)
        self.assertIn(version, lic)
        self.assertIn("words_en.txt", (ROOT / "NOTICE").read_text(encoding="utf-8"))


def key(n: int = 16) -> str:
    """A key: letters of both cases and digits, no word, high entropy."""
    while True:
        v = password(n)
        if detect._norm_entropy(v) >= 0.9 and detect._wordlike(detect._deleet(v)) < 0.15:
            return v


class SecretLiteralTests(unittest.TestCase):
    """A key after a label that names a secret (label-secret-literal) or may name one (label-weak-key), in forms the
    keyword rules did not read: an XML element, a call, a session, cookie, HMAC or PSK label."""

    def test_a_key_after_a_secret_label_is_a_hit(self):
        k12, k16 = key(12), key(16)
        for rule, text, value in (("label-secret-literal", f"<clientSecret>{k12}</clientSecret>", k12),
                                  ("label-secret-literal", f"<AccessToken>{k16}</AccessToken>", k16),
                                  ("label-weak-key", f'hmac = "{k16}"', k16),
                                  ("label-weak-key", f'session = "{k16}"', k16),
                                  ("label-weak-key", f'cookie: "{k16}"', k16),
                                  ("label-weak-key", f'"psk": "{k16}"', k16),
                                  ("label-weak-key", f'appKey("{k16}")', k16),
                                  ("label-weak-key", f"<key>{k16}</key>", k16)):
            with self.subTest(rule=rule, form=text.split(value)[0]):
                self.assertIn((rule, value), kinds(text))

    def test_a_word_a_public_part_or_a_nonce_stays_text(self):
        k16 = key(16)
        while True:   # a hex value no word letters cover, so only its label decides
            hex32 = "".join(RNG.choice("0123456789abcdef") for _ in range(32))
            if detect._wordlike(hex32) < 0.1 and detect._norm_entropy(hex32) >= 0.9:
                break
        texts = [f'public_key = "{k16}"', f'cache_key = "{k16}"', f'primary_key = "{k16}"', f'nonce = "{hex32}"',
                 f'key = "{hex32}"', f"<key>{hex32}</key>", f"<nonce>{hex32}</nonce>",
                 f"<X-Amz-Credential>{k16}</X-Amz-Credential>", 'session = "user-session-cookie"',
                 '<clientSecret>${CLIENT_SECRET}</clientSecret>',
                 '<AccessToken>{{ access_token }}</AccessToken>', 'hmac = "HMAC-SHA256-SIGNATURE"', f"session: {k16}",
                 'x-amz-signature: "' + k16 + '"']
        for text in texts:
            with self.subTest(text=text.split(" ")[0]):
                self.assertEqual([k for k, _ in kinds(text) if k in ("label-secret-literal", "label-weak-key")], [])


class OtpSeedTests(unittest.TestCase):
    """A TOTP or HOTP seed (base32) after a one-time-password label: label-otp-seed."""

    def seed(self, n: int = 32) -> str:
        while True:
            v = "".join(RNG.choice(string.ascii_uppercase + "234567") for _ in range(n))
            if detect._wordlike(v) < 0.3:
                return v

    def test_a_base32_seed_after_an_otp_label_is_a_hit(self):
        s16, s32 = self.seed(16), self.seed(32)
        for text, value in ((f"TOTP_SEED={s32}", s32), (f"otp_seed: {s16}", s16), (f"totp: {s32}", s32),
                            (f"MFA_DEVICE_SEED={s16}", s16)):
            with self.subTest(form=text.split(value)[0]):
                self.assertIn(("label-otp-seed", value), kinds(text))

    def test_a_code_a_word_or_a_name_after_an_otp_label_stays_text(self):
        for text in ("otp: 123456", "MFA_METHOD=AUTHENTICATORAPP", "totp_issuer=EXAMPLECORPORATION",
                     "mfa_type: SOFTWARE_TOKEN_MFA", "otp_seed=abcdefghijklmnop", "2fa: XXXXXXXXXXXXXXXXXXXX"):
            with self.subTest(text=text):
                self.assertEqual([k for k, _ in kinds(text) if k == "label-otp-seed"], [])


def b64(raw: bytes, url: bool = False) -> str:
    return (base64.urlsafe_b64encode(raw).decode().rstrip("=") if url else base64.b64encode(raw).decode())


def rnd(n: int) -> bytes:
    return bytes(RNG.randrange(256) for _ in range(n))


B32 = string.ascii_uppercase + "234567"


class TokenFormatTests(unittest.TestCase):
    """Four token formats with a public prefix: an NTLMSSP message, a NATS nkey seed, a PASERK secret key, a PASETO
    token."""

    def cases(self):
        ntlm = b64(b"NTLMSSP\x00\x03\x00\x00\x00" + rnd(60))
        seed = "SU" + "".join(RNG.choice(B32) for _ in range(56))
        paserk = "k4.local." + b64(rnd(32), url=True)
        paseto = "v4.local." + b64(rnd(64), url=True)
        return [("ntlmssp-message", f"Authorization: NTLM {ntlm}", ntlm),
                ("ntlmssp-message", f"Authorization: Negotiate {ntlm}", ntlm),
                ("nats-nkey-seed", f"seed: {seed}", seed),
                ("nats-nkey-seed", f"nkeys.FromSeed([]byte(\"{seed}\"))", seed),
                ("paserk-secret-key", f"PASERK={paserk}", paserk),
                ("paserk-secret-key", f"k = '{paserk}'", paserk),
                ("paseto-token", f"headers = {{\"X-Session\": \"{paseto}\"}}", paseto),
                ("paseto-token", f"token = {paseto}", paseto)]

    def test_each_format_is_a_hit_by_its_rule(self):
        for rule, text, value in self.cases():
            with self.subTest(rule=rule, form=text.split(value)[0]):
                self.assertIn((rule, value), kinds(text))

    def test_a_paserk_key_ends_before_sentence_punctuation(self):
        """codex Gate A of 0.6.16: the period after a key in a sentence was part of the hit."""
        key = "k4.local." + b64(rnd(32), url=True)
        wrapped = "k4.local-wrap.pie." + b64(rnd(64), url=True)
        for k in (key, wrapped):
            for after in (".", ". Next sentence.", ",", ");", "!", ":"):
                with self.subTest(form=k[:14], after=after):
                    self.assertIn(("paserk-secret-key", k), kinds(f"The key is {k}{after}"))

    def test_public_parts_and_short_lookalikes_stay_text(self):
        pub = "U" + "".join(RNG.choice(B32) for _ in range(55))
        for text in (f"nkey public: {pub}",                                   # a public nkey: U, N, A …
                     "k4.public." + b64(rnd(32), url=True),                     # a PASERK public key
                     "k4.lid." + b64(rnd(33), url=True),                        # a PASERK key id
                     "v4.local.short",                                          # no token
                     "TlRMTVNTUA",                                              # the prefix alone, in prose
                     "Authorization: Negotiate " + b64(b"NTLMSSP\x00\x01\x00\x00\x00" + rnd(30)),   # type 1, negotiate
                     "WWW-Authenticate: NTLM " + b64(b"NTLMSSP\x00\x02\x00\x00\x00" + rnd(40)),     # type 2, challenge
                     "the field SUPERCALIFRAGILISTICEXPIALIDOCIOUS is long"):
            with self.subTest(text=text[:12]):
                self.assertEqual([k for k, _ in kinds(text) if k in ("ntlmssp-message", "nats-nkey-seed",
                                                                      "paserk-secret-key", "paseto-token")], [])


class AwsSessionTokenTests(unittest.TestCase):
    """The STS session token in X-Amz-Security-Token (a presigned URL, a header) is a secret; the other X-Amz-
    parameters stay text (label-aws-session-token)."""

    def token(self) -> str:
        return "IQoJb3JpZ2luX2Vj" + b64(rnd(600))

    def test_the_session_token_of_a_presigned_url_and_a_header_is_a_hit(self):
        tok = self.token()
        enc = tok.replace("/", "%2F").replace("+", "%2B").replace("=", "%3D")
        sig = "".join(RNG.choice("0123456789abcdef") for _ in range(64))
        url = ("https://bucket.s3.eu-central-1.amazonaws.com/report.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256"
               "&X-Amz-Date=20261013T120000Z&X-Amz-Expires=900&X-Amz-Security-Token=" + enc
               + "&X-Amz-SignedHeaders=host&X-Amz-Signature=" + sig)
        got = kinds(url)
        self.assertIn(("label-aws-session-token", enc), got)
        self.assertNotIn(sig, [v for _, v in got], "the signature stays text")
        for text in (f"X-Amz-Security-Token: {tok}", f'headers = {{"x-amz-security-token": "{tok}"}}'):
            with self.subTest(form=text[:22]):
                self.assertIn(("label-aws-session-token", tok), kinds(text))

    def test_a_reference_prose_and_the_other_parameters_stay_text(self):
        k = key(16)
        for text in ("X-Amz-Security-Token: ${AWS_SESSION_TOKEN}",
                     "the X-Amz-Security-Token parameter carries the session token",
                     f"<X-Amz-Signature>{k}</X-Amz-Signature>", f"<X-Amz-Credential>{k}</X-Amz-Credential>"):
            with self.subTest(text=text[:24]):
                self.assertEqual([x for x, _ in kinds(text) if x in ("label-aws-session-token", "label-secret-literal",
                                                                      "label-weak-key")], [])


if __name__ == "__main__":
    unittest.main()
