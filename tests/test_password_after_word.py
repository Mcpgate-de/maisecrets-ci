"""A password after its word in a sentence, and the stop of the sentence after a value.

Field report (2026-10-16, Codex in the ChatGPT app, 0.6.28): "Messe-Account: <mail>, Passwort <value>." was blocked,
and the cleaned prompt kept the value in the clear, because no rule read a password word with only a space before its
value. And "password: <value>." stored the value with the stop of the sentence, so a document written from the
placeholder got a wrong password.

Run: python3 -m unittest tests.test_password_after_word -v
Every value is put together at run time, so no literal in the tree has the shape of one.
"""
from __future__ import annotations

import json
import shutil
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
# the store of these tests is a plain file in the temp home, never a keychain
Path(_isolate.HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
sys.path.insert(0, str(ROOT))
from maisecrets import detect, hooks, regions  # noqa: E402
from maisecrets.vault import Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

_TMP = _isolate.HOME
# invented values: two words and a digit (the shape of the report), letters and digits, a sign
REPORT = "".join(("Hafen", "7", "Kran-", "Moewe"))
MIXED = "".join(("Tz8", "qLw2", "vR4"))
SIGNED = "".join(("Kx#9", "mP!q", "2w"))
MAIL = "messe" + "@" + "example.com"


def _scan(text: str, channel: str, languages: tuple = ("en", "de")) -> list:
    active = regions.Active(regions=("generic",), languages=languages, source="test")
    with detect.Detector(regions=active).activate():
        return [(m.type, m.value) for m in detect.scan(text, channel=channel)]


def _secrets(text: str, channel: str, languages: tuple = ("en", "de")) -> list:
    return [v for t, v in _scan(text, channel, languages) if t == "SECRET"]


class SentenceFormTests(unittest.TestCase):
    def test_the_report_sentence_gives_the_value_without_its_stop(self):
        for ch in ("prompt", "tool"):
            for text in (f"Messe-Account: {MAIL}, Passwort {REPORT}.", f"Passwort {REPORT}",
                         f"Kennwort {MIXED}, dann weiter", f"das Passwort ist {SIGNED}.",
                         f"Das Passwort lautet {MIXED}; danke", f"password {MIXED}\nnext line",
                         f"my passphrase was {MIXED}?", f"password -> {MIXED}.", f"Passwort – {MIXED}",
                         f"password ({MIXED})", f"Passwort „{MIXED}“.", f"Passwort - {MIXED}.",
                         f"password -- {MIXED}", f"Passwort ist `{MIXED}`", f"Passwort `{MIXED}`.",
                         f"Passwort ist **{MIXED}**"):
                with self.subTest(channel=ch, text=text.replace(REPORT, "<v>")):
                    want = [REPORT if REPORT in text else SIGNED if SIGNED in text else MIXED]
                    self.assertEqual(_secrets(text, ch), want)

    def test_a_star_a_backslash_or_an_angle_inside_the_value_stays_in_it(self):
        # the whole password, never a part of it: a part leaves the rest in the clear
        for value in ("Tz8*" + "qLw2", "a&9Aa%Aa" + "\\*1$4lyqM", "Tz8<" + "qLw2", "Tz8qLw2" + "*"):
            with self.subTest(value=value):
                self.assertEqual(_secrets(f"Das Passwort ist '{value}'.", "prompt"), [value])
                # after a space only, $ and < read as a rule or a pattern: the value is then no hit at all, never a part
                self.assertIn(_secrets(f"Passwort {value}.", "prompt"), ([value], []))
        self.assertEqual(_secrets("Passwort " + "Tz8*" + "qLw2!", "prompt"), ["Tz8*qLw2!"])

    def test_a_bang_stays_part_of_the_value(self):
        # passwords end with ! (Winter2024!); in a sentence it is no stop of the value
        value = MIXED + "!"
        self.assertEqual(_secrets(f"Passwort {value}", "prompt"), [value])
        self.assertEqual(_secrets(f"Passwort {value}.", "prompt"), [value])

    def test_prose_after_the_password_word_stays_text(self):
        texts = ["Passwort vergessen", "Passwort ändern", "password reset link", "Passwort Manager",
                 "password is required", "Passwort des Nutzers", "password123 is a weak example",
                 "Das Passwort muss mindestens 12 Zeichen lang sein.", "password (min. 8 characters)",
                 "Password (Base64)", "password PBKDF2-SHA256", "password -> hash -> compare",
                 "Kennwort – siehe Wiki", "password SHA256-hashed", "the password field v2",
                 # the example of a weak password in a sentence (tests/fp_corpus.py)
                 "Das Passwort ist " + "Sommer" + "2024! und der Nutzer ist max",
                 "The password is " + "Hunter" + "2!", ".netrc: default password " + "Admin" + "1234",
                 "check_password(userInput1)", "hash(password) ToHex2",
                 # a technical term or a ticket after the word and a space: runs of English words, an id
                 "Passwort SHA256-Hash", "password iPhone15", "Passwort JDK21-Update", "Passwort 2FA-Code",
                 "password (PBE-3403)", "Passwort -> Ticket OPS-1234",
                 # references, standards and rules after the word (Gate A of this change)
                 "Wir müssen das Passwort CVE-2024-3094 betreffend prüfen", "password #PR-1234 merged",
                 "Das Passwort KW42/2026 rotieren", "Passwort (BSI-C5:2020)", "password (A07:2021)",
                 "password NIST-800-63B", "password OWASP-ASVS4", "Passwort DSGVO-Art32",
                 "Passwort (Länge≥12)", "Passwort – Länge>=12", "Passwort #1-Fehler", "password (A-Za-z0-9)",
                 "password ^[A-Za-z0-9]{12}$",
                 # German example passwords
                 "Das Passwort ist " + "Willkommen" + "1", "Das Passwort ist " + "Hallo" + "123!",
                 "Das Passwort ist " + "Init" + "1234"]
        for ch in ("prompt", "tool"):
            for text in texts:
                with self.subTest(channel=ch, text=text):
                    self.assertEqual(_scan(text, ch), [])

    def test_a_copula_joins_only_the_words_of_its_own_language(self):
        for lang, text in (("fi", "password on " + "GitLab" + "16 must be rotated"),
                           ("pl", "Set the password to " + "DB01" + "-Prod for staging"),
                           ("es", f"password era {MIXED}")):
            with self.subTest(lang=lang):
                self.assertEqual(_scan(text, "prompt", ("en", lang)), [])
        # a language that writes the English word joins its copula to it
        self.assertEqual(_secrets(f"la password è {MIXED}.", "prompt", ("en", "it")), [MIXED])

    def test_the_password_word_itself_with_a_number_is_an_example_in_every_language(self):
        for lang, text in (("pl", "hasło to " + "Hasło" + "2024"), ("fi", "salasana on " + "Salasana" + "1")):
            with self.subTest(lang=lang):
                self.assertEqual(_scan(text, "prompt", ("en", lang)), [])

    def test_a_dictionary_word_or_a_pin_after_the_word_stays_text(self):
        for text in ("Passwort sunshine.", "password 4821", "Kennwort Sonnenschein"):
            with self.subTest(text=text):
                self.assertEqual(_scan(text, "prompt"), [])

    def test_the_words_of_a_language_count_only_with_that_language_on(self):
        cases = {"fr": f"mot de passe est {MIXED}.", "es": f"contraseña {MIXED}.", "pt": f"senha é {MIXED}.",
                 "nl": f"wachtwoord {MIXED}.", "pl": f"hasło to {MIXED}.", "tr": f"şifre {MIXED}.",
                 "nb": f"passord er {MIXED}.", "sv": f"lösenord är {MIXED}.", "da": f"adgangskode {MIXED}.",
                 "fi": f"salasana on {MIXED}.", "cs": f"heslo je {MIXED}.", "ko": f"비밀번호는 {MIXED}.",
                 "th": f"รหัสผ่าน คือ {MIXED}.", "de": f"Kennwort ist {MIXED}."}
        for lang, text in cases.items():
            with self.subTest(lang=lang):
                self.assertEqual(_secrets(text, "prompt", ("en", lang)), [MIXED])
                self.assertEqual(_secrets(text, "prompt", ("en",)), [])

    def test_clave_alone_stays_no_label(self):
        # clave alone is a code or an id in Spanish (Mexico: clave CURP, clave de producto) and a keyword (palabra
        # clave): even a value in the shape of a password stays text after it (Gate B of this change)
        on = ("en", "es")
        for text in (f"clave: {MIXED}.", "palabras clave: seguridad, redes", "clave: " + "ABC" + "-1234",
                     "Clave: " + "CURP-ABCD" + "010101", "clave: " + "B2B" + "-Ventas"):
            with self.subTest(text=text):
                self.assertEqual(_scan(text, "prompt", on), [])
        self.assertEqual(_secrets(f"clave de acceso: {MIXED}.", "prompt", on), [MIXED])

    def test_more_forms_of_real_sentences(self):
        cases = [(("en", "de"), f"Das Passwort lautet: {MIXED}"), (("en", "de"), f"Das Passwort ist: {MIXED}."),
                 (("en", "fr"), f"Le mot de passe est : {MIXED}"), (("en", "de"), f"WLAN-Passwort {MIXED}."),
                 (("en", "de"), f"Das Root-Passwort ist {MIXED}."), (("en", "de"), f"Adminpasswort {MIXED}"),
                 (("en",), f"wifi-password {MIXED}"), (("en", "sv"), f"Lösenordet är {MIXED}"),
                 (("en", "da"), f"Adgangskoden er {MIXED}"), (("en", "nb"), f"Passordet er {MIXED}"),
                 (("en", "ko"), f"비밀번호가 {MIXED}"), (("en", "ko"), f"비밀번호는 {MIXED}입니다"),
                 (("en", "de"), f"Passwort {MIXED}\u3002"), (("en", "th"), f"รหัสผ่านคือ {MIXED}")]
        for langs, text in cases:
            with self.subTest(text=text):
                self.assertEqual(_secrets(text, "prompt", langs), [MIXED])

    def test_real_passwords_after_the_word_and_a_space(self):
        # word and number forms that people choose, and capitals before a hyphen (Gate B, round 2)
        for value in ("Berg" + "see1987!", "Sonnen" + "blume42!", "Mau" + "si1234", "AB-" + "xY7q2Lw",
                      "LKW7-" + "Pq2x", "Ka-z" + "7Qp2"):
            with self.subTest(value=value):
                self.assertEqual(_secrets(f"Passwort {value}.", "prompt"), [value])
        for value in ("Hafen7" + "-kran", "Kx9mQ2" + "-stern"):
            with self.subTest(value=value):
                self.assertEqual(_secrets(f"Das Passwort ist {value}.", "prompt"), [value])

    def test_a_word_that_ends_in_a_password_word_by_chance_is_no_label(self):
        self.assertEqual(_scan("deşifre " + "Kayıt" + "2024A", "prompt", ("en", "tr")), [])
        self.assertEqual(_scan("A resenha é " + "Top10" + "-Livros", "prompt", ("en", "pt")), [])
        self.assertEqual(_scan("user_password " + MIXED, "prompt"), [])   # an identifier of code, no sentence

    def test_a_participle_or_a_word_and_a_number_after_the_word_stays_text(self):
        cases = [(("en", "de"), "Das Passwort ist SHA256-gehasht."), (("en", "de"), "Das Passwort war 2FA-geschützt"),
                 (("en", "fr"), "Le mot de passe est SHA256-haché."), (("en", "es"), "La contraseña es AES256-cifrada"),
                 (("en", "pl"), "hasło to SHA256-hash"), (("en", "de"), "Passwort Version" + "2"),
                 (("en", "de"), "Passwort Kapitel" + "4"), (("en",), "Password (Kerberos" + "5)"),
                 (("en", "ko"), "암호 ECC-P256")]
        for langs, text in cases:
            with self.subTest(text=text):
                self.assertEqual(_scan(text, "prompt", langs), [])

class SentenceStopTests(unittest.TestCase):
    def test_the_stop_after_an_unquoted_value_is_no_part_of_it(self):
        for ch in ("prompt", "tool"):
            for text, want in ((f"password: {MIXED}.", MIXED), (f"Passwort: {REPORT}. Danke", REPORT),
                               (f"password={MIXED};", MIXED), (f"export DB_PASSWORD={MIXED}; run", MIXED),
                               (f"password: {MIXED}.\nnext", MIXED), (f"password: {MIXED},", MIXED),
                               (f"password: {MIXED}.;", MIXED + "."), (f"password: {MIXED}.\r\nnext", MIXED),
                               (f"pw: {MIXED}.", MIXED), (f"mysql --password {MIXED}.", MIXED)):
                with self.subTest(channel=ch, text=text.replace(REPORT, "<v>")):
                    self.assertEqual(_secrets(text, ch), [want])

    def test_a_dot_before_a_quote_stays(self):
        # only whitespace or the end of the text after the stop make it a stop of the sentence
        self.assertEqual(_secrets(f'echo "password: {MIXED}."', "tool"), [MIXED + "."])

    def test_a_dot_inside_the_value_or_inside_quotes_stays(self):
        inner = MIXED + ".x9"
        self.assertEqual(_secrets(f"password: {inner}", "tool"), [inner])
        quoted = MIXED + "."
        self.assertEqual(_secrets(f'password: "{quoted}"', "tool"), [quoted])


class HookTests(unittest.TestCase):
    def setUp(self):
        _hygiene.watch_children(self)
        for name in ("index.json", "vault.json", "audit.log", "events.log", "hooks.log"):
            Path(_TMP, name).unlink(missing_ok=True)
        shutil.rmtree(Path(_TMP, "pending"), ignore_errors=True)
        hooks._live_cache.clear()
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)

    def _stored(self, session: str) -> list:
        v = Vault()
        out = []
        for n in range(1, 6):
            got = v.get(f"SECRET_c{n}", session=session)
            if got and got[1] == "ok":
                out.append(got[0])
        return out

    def test_the_report_prompt_is_blocked_and_its_store_holds_the_value_without_the_stop(self):
        for session, client in (("codex", CODEX), ("claude", CLAUDE)):
            with self.subTest(client=session):
                prompt = f"Messe-Account: {MAIL}, Passwort {REPORT}."
                out = hooks.user_prompt({"prompt": prompt, "session_id": session, **client})
                self.assertEqual(out.get("decision"), "block")
                self.assertNotIn(REPORT, json.dumps(out))
                self.assertEqual(self._stored(session), [REPORT])

    def test_a_colon_label_at_the_end_of_a_sentence_stores_the_value_without_the_stop(self):
        out = hooks.user_prompt({"prompt": f"Das password: {MIXED}.", "session_id": "s2", **CLAUDE})
        self.assertEqual(out.get("decision"), "block")
        self.assertEqual(self._stored("s2"), [MIXED])


if __name__ == "__main__":
    unittest.main()
