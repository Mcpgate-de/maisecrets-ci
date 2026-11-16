"""Unit tests for detector, placeholder, vault and hook handlers.

Run: python3 -m unittest discover -s tests -v
Mutation probes: see docs/TESTING.md — counts are
recorded per probe in harness/out/mutations.md when a probe has been run.
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
# this module set its own MAISECRETS_HOME after another module had fixed the vault home, so its
# reset deleted files in a directory the vault did not use (suite review, 2026-09-27)
_TMP = _isolate.HOME
# tests never touch the real keychain
Path(_TMP).mkdir(parents=True, exist_ok=True)
Path(_TMP, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import detect, hooks, placeholder  # noqa: E402
from maisecrets.vault import HOME, Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

assert str(HOME) == _TMP, "the vault home is the one _isolate made"


def tearDownModule():  # noqa: N802 - unittest hook
    _hygiene.assert_pristine()

GLPAT = "glpat-" + "A1b2C3d4E5f6G7h8I9j0"          # 20 chars after prefix
AKIA = "AKIA" + "ABCDEFGHIJKLMNOP"
GHP = "ghp_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2"  # mixed: the github-pat rule needs entropy >= 3
GLRT = "glrt-" + "AbCdEfGhIjKlMnOpQrStUv.01.1a2b3c4d5"
# canonical public test values, assembled at runtime so no literal sits in the tree
IBAN_OK = " ".join(["DE89", "3704", "0044", "0532", "0130", "00"])
CARD_OK = " ".join(["4929", "1844", "0817", "2239"])   # synthetic Luhn number, not in rules/public_test_values.txt
JWT = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"])


class DetectTests(unittest.TestCase):
    def test_secret_shapes_are_found_with_the_exact_value(self):
        for kind, val in [("gitlab-pat", GLPAT), ("aws-access-token", AKIA), ("github-pat", GHP), ("jwt", JWT),
                          ("gitlab-runner-token", GLRT)]:
            with self.subTest(kind=kind):
                ms = detect.scan(f"token is {val} ok")
                self.assertEqual([(m.kind, m.value) for m in ms], [(kind, val)])

    def test_a_routable_gitlab_token_is_taken_whole(self):
        # GitLab's routable tokens end in ".<version>.<id>": the token characters stopped at the dot, and the
        # tail stayed in the clear (field report, 2026-10-06)
        token = "glpat-" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7" + ".01." + "0abcd12ef"
        for text in (f'Wert="{token}"', f"{token}.", f"see {token}, then", f"{token}.x9", f"TOKEN={token}\n"):
            with self.subTest(text[:12]):
                self.assertEqual([m.value for m in detect.scan(text)], [token])
        # every GitLab prefix, and the older form with one dot (version, length and CRC as 9 characters)
        for prefix in ("glrt-", "gldt-"):
            other_token = prefix + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7" + ".01." + "0abcd12ef"
            with self.subTest(prefix):
                self.assertIn(other_token, [m.value for m in detect.scan(f"token {other_token}")])
        older = "glpat-" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7" + ".0ab0znlm9"
        self.assertEqual([m.value for m in detect.scan(f"token {older}")], [older])
        # the tail belongs to a GitLab token only, and it is exactly 9 characters: a dotted word stays text
        other = "ghp_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2"
        self.assertEqual([m.value for m in detect.scan(f"{other}.01.release9x")], [other])
        short = "glpat-" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7"
        for tail in (".01.backup", ".01.0abcd12efg", ".v1.release"):
            with self.subTest(tail):
                self.assertEqual([m.value for m in detect.scan(f"{short}{tail}")], [short])

    def test_a_token_longer_than_its_fixed_shape_is_taken_whole(self):
        long_pat = GLPAT + "6789"                       # 24 chars after the prefix, the rule says 20
        ms = detect.scan(f"TOKEN={long_pat}\n")
        self.assertEqual([m.value for m in ms], [long_pat])
        ms = detect.scan(f"token {long_pat}, then text")
        self.assertEqual([m.value for m in ms], [long_pat])

    def test_webhook_signing_secret_on_a_bare_line_is_a_hit(self):
        import base64
        fake = "whsec_" + base64.b64encode(bytes(range(32))).decode()
        ms = detect.scan("https://example.org/api/webhooks/marketplace-push/marketplace_0123\n" + fake + "\n")
        self.assertEqual([(m.kind, m.value) for m in ms], [("webhook-signing-secret", fake)])

    def test_prefixed_tokens_newer_than_the_vendored_rulesets_are_hits_when_bare(self):
        cf = "cfut_" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cDe0f"
        for text in (cf, f"token {cf}", f"cloudflare token {cf}"):
            with self.subTest(text[:12]):
                self.assertEqual([(m.kind, m.value) for m in detect.scan(text)], [("cloudflare-user-api-token", cf)])

    def test_two_secrets_in_one_text_become_two_references(self):
        # the vault home is shared by every module: count only what this test adds
        before = {e.key for e in Vault().list()}
        text = f"token {GLPAT} and key {AKIA} please"
        ms = detect.scan(text)
        self.assertEqual([m.value for m in ms], [GLPAT, AKIA])
        _hygiene.patch(self, hooks, "_clipboard", lambda t: True)
        out = hooks.user_prompt({"prompt": text, "session_id": "s2", "transcript_path": "", **CLAUDE})
        self.assertEqual(out["decision"], "block")
        self.assertIn("maisecrets kept a secret from the AI.", out["reason"])
        self.assertIn("paste it to edit it first", out["reason"], "the paste key, with the clipboard")
        # a tip may follow the last line on some platforms; the wrong-hit line itself names no key
        self.assertIn("A wrong hit? /maisecrets:not-a-secret KEY\n", out["reason"] + "\n",
                      "two values: the wrong-hit line names no key")
        # the two references exist, the notice does not need to list them
        self.assertEqual(len({e.key for e in Vault().list()} - before), 2)
        self.assertNotIn(GLPAT, out["reason"])
        self.assertNotIn(AKIA, out["reason"])

    def test_the_keyword_window_finds_exactly_what_the_whole_regex_finds(self):
        """generic-api-key runs in windows around its keywords on long text (6x faster on 157 MB of
        real logs and history, the same 902 matches; 2026-09-27). Border cases: a value at the end
        of a line, of the text, after a separator on the next line, a long base64 value, a keyword
        50 characters into a word, and noise between."""
        import random
        rnd = random.Random(7)
        alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

        def tok(n: int) -> str:
            return "".join(rnd.choice(alphabet) for _ in range(n))
        pieces = []
        for i in range(400):
            pieces.append(rnd.choice([
                f"GET /api/v1/items?id={i} 200",
                f"client_secret = {tok(24)}",
                f"access_token:\n  {tok(32)}",
                f"{'x' * 45}_apikey={tok(18)};",
                f"auth => '{tok(40)}'",
                f"password: {tok(12)}{'=' * (i % 3)}",
                f"key = {tok(8)}",
                f"token={tok(200)}",
                "nothing to see here " * 3,
            ]))
        text = "\n".join(pieces) + "\nsecret: " + tok(30)
        rule = [r for r in detect.rules() if r.id == "generic-api-key"][0]
        whole = [(m.start(), m.end()) for m in rule.regex.finditer(text)]
        kw = detect._WINDOWED["generic-api-key"]
        window = [(m.start(), m.end()) for m in detect._windowed(rule, kw, text)]
        self.assertGreater(len(whole), 100)
        self.assertEqual(window, whole)

    def test_a_condition_that_ends_in_a_colon_is_not_a_label(self):
        for code in ('if kind != "SECRET":\n    continue\n', 'elif token == "x":\n    return value\n',
                     "while password:\n    retry_after_delay()\n"):
            with self.subTest(code[:12]):
                self.assertEqual(detect.scan(code), [])
        # a real label on its own line still takes the next line
        value = "".join(chr(c) for c in (84, 114, 48, 98, 107, 55, 118, 81, 114)) + "&3xyz"
        self.assertEqual([m.value for m in detect.scan("passwort:\n" + value)], [value])
        # a label inside a sentence is not code (review, 2026-09-27: "for" and "if" hid these)
        for text in ("for the db, password:\n" + value, "if needed, passwort:\n" + value,
                     "class notes, secret:\n" + value):
            with self.subTest(text[:16]):
                self.assertEqual([m.value for m in detect.scan(text)], [value])

    def test_a_value_after_a_blank_line_is_found_in_long_text_too(self):
        value = "Ab3dEf6hIj9kLm2n"
        for filler in ("", "x" * 5000 + "\n"):
            with self.subTest(len(filler)):
                text = filler + "password for prod:\n\n" + value + "\n" + "y" * 200
                self.assertIn(value, [m.value for m in detect.scan(text)])

    def test_german_credential_labels_are_keywords_too(self):
        for label in ("passwort", "Kennwort", "Schlüssel", "zugangsdaten"):
            with self.subTest(label):
                ms = detect.scan(f"{label}: Sommer2026!xyz")
                self.assertEqual([(m.type, m.value) for m in ms], [("SECRET", "Sommer2026!xyz")])

    def test_label_on_its_own_line_takes_the_value_from_the_next_line(self):
        # a console or a chat renders "passwort:" and the value on the next line (field report,
        # 2026-09-26: the AKIA id on the line above was stored, the secret below it was not)
        sk = "q9Zr2Tk7Lm4Pv8Wx1Yc6" + "Hd3Jf5Ng0Rb/sT2uV+wZ"
        for text in ("User: admin\npasswort:\n" + sk + "\n", "passwort:\n\n" + sk):
            with self.subTest(text[:12]):
                ms = detect.scan(text)
                self.assertEqual([(m.type, m.value) for m in ms], [("SECRET", sk)])
                self.assertEqual(text[ms[0].start:ms[0].end], sk)
        self.assertEqual(detect.scan("passwort:\nbitte schick mir das morgen\n"), [])
        self.assertEqual(detect.scan("env:\n  - FOO=bar\n"), [])

    def test_aws_secret_key_is_taken_when_an_access_key_id_is_nearby(self):
        akid = "AKIA" + "Q7R2T9V4X1Z6B8N3"
        sk = "q9Zr2Tk7Lm4Pv8Wx1Yc6" + "Hd3Jf5Ng0Rb/sT2uV+wZ"
        for text in ("Access key ID,Secret access key\n" + akid + "," + sk,
                     "User: " + akid + "\npasswort:\n" + sk + "\n"):
            with self.subTest(text[:10]):
                values = [m.value for m in detect.scan(text)]
                self.assertIn(sk, values)
        # the 40-character shape alone is a git SHA or a hash, never a secret
        self.assertEqual([m.value for m in detect.scan("blob " + sk)], [])

    def test_the_plugins_own_command_names_are_never_a_secret(self):
        # "maisecrets" carries the keyword; a command name of 8+ characters after the colon looked
        # like a labelled value (field report, 2026-09-27)
        for text in ("/maisecrets:shortcut", "/maisecrets:shortcut ms", "run /maisecrets:configure now",
                     "maisecrets: 1 SECRET detected and stored as SECRET_c19. The prompt did not reach the model.",
                     "maisecrets stopped this prompt. The AI did not receive it.",
                     "maisecrets: a secret was found and kept from the AI.",
                     "maisecrets kept a secret and personal data in a subagent's report from the AI.",
                     "Found: 1 secret (⟦SECRET_c19⟧). To send it: /maisecrets:send (or /ms)."):
            with self.subTest(text[:24]):
                self.assertEqual(detect.scan(text), [])
        # a real label keeps working, also with a prefix before the keyword
        # assembled at run time so the repo scan never sees the shape
        value = "".join(chr(c) for c in (84, 114, 48, 98, 107, 55, 118, 81, 114)) + "&3xyz"
        self.assertEqual([m.value for m in detect.scan("my_secret: " + value)], [value])

    def test_named_credential_keeps_the_name_and_takes_the_value(self):
        ms = detect.scan("DB_PASSWORD=" + "Qx7vR2mK" + "9pLwT4")
        self.assertEqual(len(ms), 1)
        self.assertEqual(ms[0].value, "Qx7vR2mK" + "9pLwT4")
        self.assertEqual(ms[0].type, "SECRET")
        self.assertTrue(ms[0].kind.startswith("ds-keyword"))
        self.assertEqual(detect.scan('password = "${DB_PASSWORD}"'), [])     # templated, not a value
        self.assertEqual(detect.scan('password: "changeme"'), [])            # placeholder

    def test_email_iban_card_are_pii_and_validated(self):
        text = "mail max.mustermann@beispiel-gmbh.de iban " + IBAN_OK + " credit card " + CARD_OK
        types = [m.type for m in detect.scan(text)]
        self.assertEqual(types, ["EMAIL", "IBAN", "CARD"])

    def test_invalid_iban_and_luhn_failing_card_are_not_hits(self):
        self.assertEqual([m.type for m in detect.scan("IBAN " + IBAN_OK[:-1] + "1")], [])
        self.assertEqual([m.type for m in detect.scan("card " + CARD_OK[:-1] + "2")], [])

    def test_private_ips_are_ignored_public_ips_are_hits(self):
        self.assertEqual(detect.scan("host 127.0.0.1 and 10.0.0.5 and 192.168.1.1"), [])
        self.assertEqual([(m.type, m.value) for m in detect.scan("edge 93.184.216.34")], [("IP", "93.184.216.34")])

    def test_validators_never_raise_on_odd_shapes(self):
        for v in ("0/8", "999.1.1.1", "", "DE", "abc"):
            for name, fn in detect.VALIDATORS.items():
                with self.subTest(validator=name, value=v):
                    try:
                        self.assertIn(fn(v), (True, False))
                    except (ValueError, IndexError, TypeError):
                        self.fail(f"{name} raised on {v!r}")

    def test_a_span_that_contains_a_placeholder_is_not_a_hit(self):
        self.assertEqual(detect.scan('curl -u "app:⟦SECRET_c1⟧" https://h/x'), [])
        self.assertEqual(detect.scan("password = ⟦SECRET_c2:•••⟧"), [])

    def test_placeholder_is_not_a_hit(self):
        self.assertEqual(detect.scan("send to ⟦EMAIL_c1:ma•••@example.org⟧ now"), [])
        self.assertEqual(detect.scan("legacy <EMAIL_c1:ma***@example.org> form"), [])

    def test_url_userinfo_is_a_secret_not_an_email(self):
        pw = "Kx7Qp2" + "Zr9Lm4"
        ms = detect.scan("postgres://etl:" + pw + "@db.internal:5432/x")
        self.assertEqual([(m.kind, m.value) for m in ms], [("ds-basic-auth", pw)])

    def test_query_parameter_secret(self):
        ms = detect.scan("GET https://x/api?api_key=" + "0123456789abcdef0123")
        self.assertEqual(ms[0].type, "SECRET")

    def test_betterleaks_ruleset_is_loaded(self):
        ids = {r.id for r in detect.rules()}
        self.assertGreater(len(ids), 200)
        self.assertTrue({"gitlab-pat", "aws-access-token", "private-key", "email", "ds-basic-auth"} <= ids)
        self.assertTrue(any(i.startswith("iban") for i in ids))

    def test_german_tax_id_needs_context_and_checksum(self):
        valid = "86095742719"   # the BZSt example number
        self.assertEqual([m.type for m in detect.scan("Meine Steuer-ID lautet " + valid)], ["DE_TAX_ID"])
        self.assertEqual(detect.scan("Bestellung " + valid + " ist raus"), [])           # no context word
        self.assertEqual(detect.scan("Steuer-ID " + valid[:-1] + "0"), [])                # checksum fails

    def test_german_vat_id_and_plz(self):
        self.assertEqual([m.type for m in detect.scan("USt-IdNr. DE123456789")], ["DE_VAT_ID"])
        self.assertEqual(detect.scan("10115 Berlin"), [])
        self.assertEqual([m.type for m in detect.scan("PLZ 10115")], ["DE_PLZ"])

    def test_presidio_regions_are_opt_in(self):
        ids = {r.id.split("#")[0] for r in detect.rules()}
        self.assertIn("de-tax-id", ids)
        self.assertNotIn("pl-pesel", ids)   # not in the default regions
        self.assertNotIn("in-pan", ids)     # Presidio tags it "en"; region is the switch

    def test_placeholder_types_with_underscores(self):
        self.assertEqual(placeholder.key_of("⟦DE_TAX_ID_c2⟧"), "DE_TAX_ID_c2")
        self.assertEqual(detect.scan("see ⟦DE_TAX_ID_c2⟧ above"), [])

    def test_a_keyword_inside_a_product_name_before_markdown_is_not_a_credential(self):
        self.assertEqual(detect.scan("| shown next to `/maisecrets:report` | the notice"), [])

    def test_two_words_of_prose_after_a_keyword_are_not_a_credential(self):
        self.assertEqual(detect.scan('sys.stderr.write("maisecrets: bad payload")'), [])
        self.assertEqual(detect.scan("secret: very important"), [])
        self.assertNotEqual(detect.scan("secret: " + "Somm" + "er20" + "26 x"), [])   # a digit keeps it a value

    def test_a_short_prose_word_after_token_is_not_a_credential(self):
        self.assertEqual(detect.scan("the token expired yesterday"), [])


class PlaceholderTests(unittest.TestCase):
    def test_refs_round_trip_with_and_without_display(self):
        self.assertEqual(placeholder.key_of("⟦EMAIL_c3:ma•••@x.de⟧"), "EMAIL_c3")
        self.assertEqual(placeholder.key_of("⟦SECRET_c1⟧"), "SECRET_c1")
        self.assertEqual(placeholder.key_of("<SECRET_c1>"), "SECRET_c1")   # legacy form still resolves
        self.assertIsNone(placeholder.key_of("⟦EMAIL_3⟧"))  # gateway-minted, not ours
        self.assertEqual(placeholder.make_ref("EMAIL", 4, "ma•••@x.de"), "⟦EMAIL_c4:ma•••@x.de⟧")

    def test_find_refs_reports_offsets(self):
        text = 'curl -H "Bearer ⟦SECRET_c1⟧" https://x/⟦EMAIL_c2:a•••@b.c⟧'
        self.assertEqual([k for k, _, _ in placeholder.find_refs(text)], ["SECRET_c1", "EMAIL_c2"])

    def test_secret_display_is_never_shown(self):
        self.assertIsNone(placeholder.display_for("SECRET", GLPAT))
        # gateway rules (pii_display.py): the domain shows only for freemail providers at "standard"
        self.assertEqual(placeholder.display_for("EMAIL", "max.mustermann@example.org"), "ma•••@•••.org")
        self.assertEqual(placeholder.display_for("EMAIL", "max.mustermann@gmail.com"), "ma•••@gmail.com")
        self.assertEqual(placeholder.display_for("EMAIL", "max@gmail.com"), "m•••@gmail.com")   # 2 chars stay hidden
        self.assertEqual(placeholder.display_for("IBAN", "DE89 3704 0044 0532 0130 00"), "DE89••••••••••••••3000")


class VaultTests(unittest.TestCase):
    def setUp(self):
        # the vault files only: the home is shared with the other modules of this process
        for name in ("index.json", "vault.json", "audit.log", "events.log"):
            Path(_TMP, name).unlink(missing_ok=True)
        self.v = Vault({"backend": "jsonfile", "ttl_seconds": {"default": 60},
                        "max_ttl_seconds": 120, "renew_on_use": True})

    def test_put_get_same_value_same_ref(self):
        a = self.v.put(GLPAT, "SECRET", "gitlab-pat")
        b = self.v.put(GLPAT, "SECRET", "gitlab-pat")
        self.assertEqual(a.key, b.key)
        self.assertEqual(self.v.get(a.key, human=True), (GLPAT, "ok"))
        self.assertEqual(self.v.get(a.key), (None, "no-session"))   # hooks need a session

    def test_counter_is_per_type(self):
        self.v.put(GLPAT, "SECRET", "gitlab-pat")
        e = self.v.put("max@example.org", "EMAIL", "email")
        self.assertEqual(e.key, "EMAIL_c1")

    def test_expired_value_is_deleted_but_metadata_stays(self):
        e = self.v.put(AKIA, "SECRET", "aws-access-token")
        self.v._index["entries"][e.key]["expires"] = 0
        self.v._save_index()
        self.assertEqual(self.v.get(e.key, human=True), (None, "expired"))
        self.assertTrue(self.v._index["entries"][e.key]["purged"])
        self.assertIsNone(self.v.backend.get(e.key))
        self.assertEqual(self.v.get("SECRET_c99", human=True), (None, "unknown"))

    def test_non_default_home_uses_its_own_keychain_service(self):
        from maisecrets import vault as v
        self.assertNotEqual(v.SERVICE, "maisecrets")
        self.assertTrue(v.SERVICE.startswith("maisecrets@"))

    @unittest.skipIf(sys.platform == "win32", "no openssl on a stock Windows PATH; Windows uses the Credential Locker")
    def test_encrypted_file_backend_roundtrip_and_tamper(self):
        from maisecrets.vault import EncryptedFileBackend
        b = EncryptedFileBackend()
        b.put("SECRET_c9", GLPAT)
        self.assertEqual(b.get("SECRET_c9"), GLPAT)
        raw = Path(b.path).read_text()
        self.assertNotIn(GLPAT, raw)                       # encrypted at rest
        self.assertEqual(os.stat(b.key_file).st_mode & 0o777, 0o600)
        d = json.loads(raw)
        d["SECRET_c9"]["t"] = "0" * 64                     # tamper with the tag
        Path(b.path).write_text(json.dumps(d))
        self.assertIsNone(b.get("SECRET_c9"))               # fail closed
        b.delete("SECRET_c9")
        self.assertIsNone(b.get("SECRET_c9"))

    @unittest.skipIf(sys.platform == "win32", "POSIX file modes do not apply on Windows")
    def test_vault_file_is_private(self):
        self.v.put(AKIA, "SECRET", "aws-access-token")
        mode = os.stat(self.v.backend.path).st_mode & 0o777
        self.assertEqual(mode, 0o600)


class HookTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        import shutil
        _hygiene.watch_children(self)
        # the vault files only: the home is shared with the other modules of this process
        for name in ("index.json", "vault.json", "audit.log", "events.log", "hooks.log"):
            Path(_TMP, name).unlink(missing_ok=True)
        shutil.rmtree(Path(_TMP, "pending"), ignore_errors=True)
        hooks._live_cache.clear()
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)  # no real clipboard in tests

    def test_prompt_with_secret_is_blocked_and_stored(self):
        out = hooks.user_prompt({"prompt": f"check {GLPAT} in CI", "session_id": "s1", **CLAUDE})
        self.assertEqual(out["decision"], "block")
        self.assertNotIn(GLPAT, json.dumps(out))
        self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        self.assertEqual(Vault().get("SECRET_c1", session="s1"), (GLPAT, "ok"))

    def test_prompt_without_hit_passes(self):
        self.assertEqual(hooks.user_prompt({"prompt": "say hi", **CLAUDE}), {})

    def test_at_mention_of_existing_file_is_blocked(self):
        with tempfile.NamedTemporaryFile(suffix=".env", delete=False) as f:
            f.write(b"X=1")
        out = hooks.user_prompt({"prompt": f"look at @{f.name}", "cwd": "/", **CLAUDE})
        self.assertEqual(out["decision"], "block")

    def test_pre_tool_rewrites_bash_to_a_granted_resolve_and_denies_unknown(self):
        e = Vault().put(GLPAT, "SECRET", "gitlab-pat", session="s1")
        out = hooks.pre_tool({"tool_name": "Bash", "session_id": "s1", **CLAUDE,
                              "tool_input": {"command": f'curl -H "PRIVATE-TOKEN: {e.ref}" u'}})
        cmd = out["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertNotIn(GLPAT, cmd)                     # the value is never spliced into the command
        self.assertTrue(cmd.startswith('__ms_1="$('), cmd)              # read up front in the main shell
        self.assertIn(f"value for {e.key} was not delivered", cmd)
        self.assertTrue(cmd.endswith('curl -H "PRIVATE-TOKEN: ${__ms_1}" u'), cmd)   # double-quote context
        self.assertNotIn("permissionDecision", out["hookSpecificOutput"])
        out = hooks.pre_tool({"tool_name": "Bash", "session_id": "s1", **CLAUDE,
                              "tool_input": {"command": "echo ⟦SECRET_c42⟧"}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_pre_tool_resolves_a_stored_value_in_gateway_tool_arguments(self):
        e = Vault().put("max@example.org", "EMAIL", "email", session="s1")
        out = hooks.pre_tool({"tool_name": "mcp__example-gateway__x", "tool_input": {"q": e.ref}, "session_id": "s1",
                              **CLAUDE,
                              "mcp_server": {"name": "example-gateway", "source": "user"}})
        self.assertEqual(out["hookSpecificOutput"]["updatedInput"], {"q": "max@example.org"})

    def test_post_tool_redacts_bash_output_keeping_shape(self):
        out = hooks.post_tool({"tool_name": "Bash", "tool_input": {"command": "cat .env"}, **CLAUDE,
                               "tool_response": {"stdout": f"TOKEN={GLPAT}\n", "stderr": "",
                                                 "interrupted": False, "isImage": False}})
        upd = out["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(set(upd), {"stdout", "stderr", "interrupted", "isImage"})
        self.assertNotIn(GLPAT, upd["stdout"])
        self.assertIn("⟦SECRET_c1⟧", upd["stdout"])

    def test_post_tool_without_hit_returns_nothing(self):
        self.assertEqual(hooks.post_tool({"tool_response": {"stdout": "all good"}, **CLAUDE}), {})

    def test_main_fails_closed_on_bad_payload(self):
        from unittest import mock
        buf = io.StringIO()
        with mock.patch.object(sys, "stdin", io.StringIO("not json")), redirect_stdout(buf):
            rc = hooks.main(["hook", "user-prompt"])
        # a refusal in JSON, exit 0: Codex runs the tool on exit 2
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
