"""core._personal_hits runs a sub-step (personal.hits, names_above_bank, key_values.hits) only when `enabled` holds
one of the kinds it reports (#59). With all rules (the hooks) every step runs; with the secret rules of the skill's
audit none runs, and the findings stay the same."""
from __future__ import annotations

import secrets
import string
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: no client environment, a temp home and temp dir
sys.path.insert(0, str(ROOT / "skills" / "secret-hygiene" / "scripts"))
import _detector  # noqa: E402
from maisecrets.detection import core, key_values, personal, holder_line  # noqa: E402

LETTERS_PW = "pozk" + "emva"      # random small letters that read as no word (tests/test_skill.py)


def _rnd(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _texts() -> list:
    """Tool results and prompts with secrets and personal data of several kinds; built at run time."""
    pw = _rnd(6, string.ascii_lowercase) + "#" + _rnd(5, string.digits)
    return [
        "export GITHUB_TOKEN=gh" + "p_" + _rnd(36) + "\nok",
        '{"user": {"name": "Jane Roe", "password": "' + pw + '", "iban": "DE89370400440532013000"}}',
        f"db_password: {pw}\nuser_id: jroe42\ncontact: Jane Roe, jane.roe@example.org, +49 30 1234567",
        f'password = Some("{_rnd(8, string.ascii_lowercase)}"),'
        f'\nKontoinhaber: Max Beispiel\nIBAN DE89370400440532013000',
        "| name | password |\n|---|---|\n| Jane Roe | " + pw + " |",
        f"Authorization: Bearer {_rnd(40)}\ntoken = '{_rnd(32)}'",
    ]


class PersonalStepsTests(unittest.TestCase):
    """core._personal_hits runs a sub-step only when `enabled` holds one of its kinds (#59)."""

    def setUp(self):
        self.detect = _detector.load()
        self.secret = _detector.secret_rules(self.detect)

    def counted(self):
        calls = {"personal": 0, "kv": 0, "bank": 0}

        def wrap(name, fn):
            def inner(*a, **k):
                calls[name] += 1
                return fn(*a, **k)
            return inner
        patches = [mock.patch.object(personal, "hits", wrap("personal", personal.hits)),
                   mock.patch.object(key_values, "hits", wrap("kv", key_values.hits)),
                   mock.patch.object(holder_line, "names_above_bank", wrap("bank", holder_line.names_above_bank))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        return calls

    def scan_all(self, enabled, channel):
        return [[(m.kind, m.type, m.value, m.start, m.end) for m in self.detect.scan(t, enabled, channel)]
                for t in self.texts]

    def test_the_secret_rules_run_no_personal_sub_step_and_find_the_same(self):
        self.texts = _texts()
        for channel in ("tool", "prompt"):
            with self.subTest(channel):
                with mock.patch.object(core, "_personal_steps", lambda *a: (True, True, True)):
                    old = self.scan_all(self.secret, channel)
                calls = self.counted()
                new = self.scan_all(self.secret, channel)
                self.assertEqual(new, old)
                self.assertTrue(any(old), "the texts must hold findings")
                self.assertEqual(calls, {"personal": 0, "kv": 0, "bank": 0})

    def test_all_rules_run_every_sub_step_as_before(self):
        self.texts = _texts()
        calls = self.counted()
        self.scan_all(None, "tool")
        self.assertGreaterEqual(min(calls["personal"], calls["kv"]), len(self.texts), calls)
        self.assertGreater(calls["bank"], 0, calls)   # it needs a colon and a line break

    def test_an_enabled_personal_secret_kind_still_runs_its_step(self):
        """A kind of the personal pass can be a secret (password-after-key): enabled alone, its step runs."""
        text = '{"service": "billing", "db_password": "' + LETTERS_PW + "47" + '"}'
        got = [m for m in self.detect.scan(text, {"password-after-key"}, "tool")]
        with mock.patch.object(core, "_personal_steps", lambda *a: (True, True, True)):
            old = [m for m in self.detect.scan(text, {"password-after-key"}, "tool")]
        self.assertEqual([(m.kind, m.value) for m in got], [(m.kind, m.value) for m in old])
        self.assertEqual([m.kind for m in got], ["password-after-key"])
        self.assertEqual(core._personal_steps({"password-after-key"}, "tool", personal.RULE_IDS, key_values.KINDS),
                         (True, True, True))
        self.assertEqual(core._personal_steps({"name-after-label"}, "tool", personal.RULE_IDS, key_values.KINDS),
                         (True, True, True))
        self.assertEqual(core._personal_steps({"phone-us-national"}, "tool", personal.RULE_IDS, key_values.KINDS),
                         (True, False, False))
        self.assertEqual(core._personal_steps({"name-after-label"}, "prompt", personal.RULE_IDS, key_values.KINDS),
                         (True, False, False))


if __name__ == "__main__":
    unittest.main()
