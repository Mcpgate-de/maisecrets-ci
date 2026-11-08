"""The values for the person's screen (maisecrets/show_values.py, dispatch.py mod-values, setting show_values).

The mod's drawing is tested in tests/show-values.test.ts (`claude plugin test`); that no value reaches a model
request or the transcript, in harness/run.py (show_values_stay_on_screen)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

Path(_isolate.HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import hooks, settings, show_values  # noqa: E402
from maisecrets.vault import Vault, load_config  # noqa: E402

NAME = "Erika " + "Testfrau"


def cfg(mode: str = "always") -> dict:
    c = dict(load_config())
    c["show_values"] = mode
    return c


def _clean_store():
    # the store files this module writes: a module after it reads a store it did not make (test_settings rewrites
    # config.json without the file backend, and an index with entries then asked the keychain for the fingerprint key)
    for name in ("index.json", "vault.json", "audit.log", "events.log"):
        Path(_isolate.HOME, name).unlink(missing_ok=True)


def tearDownModule():  # noqa: N802 - unittest hook
    _clean_store()


class AnswerTests(unittest.TestCase):
    def setUp(self):
        _clean_store()
        self.addCleanup(_clean_store)
        self.vault = Vault(cfg())
        self.key = self.vault.put(NAME, "NAME", "name", session="s1").key

    def ask(self, keys, session="s1", mode="always"):
        return show_values.answer({"keys": keys, "session_id": session}, cfg(mode), self.vault)

    def test_a_value_of_this_session_is_given(self):
        a = self.ask([self.key])
        self.assertEqual(a["mode"], "always")
        self.assertEqual(a["values"], {self.key: NAME})

    def test_another_sessions_value_is_not_given(self):
        self.assertEqual(self.ask([self.key], session="s2")["values"], {})
        self.assertEqual(self.ask([self.key], session=None)["values"], {})

    def test_off_reads_nothing(self):
        from unittest import mock
        with mock.patch.object(self.vault, "status", side_effect=AssertionError("read under off")):
            self.assertEqual(self.ask([self.key], mode="off"), {"mode": "off", "links": show_values.links(),
                                                                   "values": {}})

    def test_a_server_token_or_a_reference_is_never_resolved(self):
        # a key without `c` is a server's token; sref:… a gateway's reference: both cost the gateway a resolve
        for key in ("NAME_1", "sref:email:abc", "EMAIL_c1:ma•••@x.de", "name_c1"):
            with self.subTest(key=key):
                self.assertEqual(self.ask([key])["values"], {})

    def test_a_setting_that_is_no_mode_shows_nothing(self):
        self.assertEqual(show_values.mode({"show_values": "maybe"}), "off")
        self.assertEqual(show_values.mode({}), "off")

    def test_terminal_app_gets_no_links(self):
        self.assertFalse(show_values.links({"TERM_PROGRAM": "Apple_Terminal"}))
        self.assertTrue(show_values.links({"TERM_PROGRAM": "ghostty"}))
        self.assertTrue(show_values.links({}))


class SettingTests(unittest.TestCase):
    def test_always_is_the_default_and_a_policy_can_only_show_less(self):
        from maisecrets import home
        self.assertEqual(home.DEFAULT_CONFIG["show_values"], "always")
        self.assertEqual(settings._CHOICES["show_values"], ("always", "click", "off"))

    def test_showing_more_loosens_a_protection(self):
        self.assertTrue(settings.loosens("show_values", "off", "always"))
        self.assertTrue(settings.loosens("show_values", "click", "always"))
        self.assertFalse(settings.loosens("show_values", "always", "off"))


class AgentTests(unittest.TestCase):
    def test_a_shell_command_that_asks_for_the_values_is_refused(self):
        for command in ('bash "/p/hooks/run.sh" mod-values', "python3 hooks/dispatch.py mod-values < q.json",
                        'cmd /c "C:\\p\\hooks\\run.cmd" mod-values', "python3 hooks/dispatch.py mod-reveal < q.json"):
            with self.subTest(command=command):
                self.assertEqual(hooks._store_read_match(command), "the mod's values")
                self.assertTrue(hooks._HOOK_ENTRY_TEXT_RE.search(command))
        self.assertIsNone(hooks._store_read_match("echo the mod-values docs"))


class DispatchTests(unittest.TestCase):
    def test_the_entry_answers_json_and_a_broken_question_answers_nothing(self):
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "mod-values"],
                           input=json.dumps({"keys": [], "session_id": "s1"}), capture_output=True, text=True,
                           timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["maisecrets"], "mod-values")
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "mod-values"], input="not json",
                           capture_output=True, text=True, timeout=60)
        self.assertEqual((r.returncode, r.stdout, r.stderr), (1, "", ""))


if __name__ == "__main__":
    unittest.main()
