"""Every action that loosens a protection writes one events.log line (time, kind, key or setting, route; never a
value), and the next session start names them to the person in one sentence, once (C22)."""
from __future__ import annotations

import io
import json
import os
import random
import string
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import cli, events, hooks, settings  # noqa: E402
from maisecrets.vault import HOME, Vault, load_config  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

TEST_CONFIG = {"backend": "jsonfile", "allow_plaintext_store": True}
CONFIG = Path(HOME, "config.json")
SHOWN = Path(HOME, ".weakenings-shown")


def tearDownModule():  # noqa: N802 - unittest hook
    _reset()
    _hygiene.assert_pristine()


def _reset(**user) -> None:
    CONFIG.write_text(json.dumps({**TEST_CONFIG, **user}))
    for p in (events.EVENTS, SHOWN):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass


def _lines() -> list[dict]:
    try:
        return [json.loads(x) for x in events.EVENTS.read_text().splitlines()]
    except FileNotFoundError:
        return []


def _weakened() -> list[dict]:
    return [e for e in _lines() if "weakened" in e]


def _prompt(text: str, client: dict = CLAUDE) -> dict:
    return hooks.user_prompt({"prompt": text, "session_id": "S1", **client})


def _value() -> str:
    # synthetic, built at run time: no secret shape stands in the tree
    rnd = random.Random(7)
    return "forget-me-" + "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(28))


class SettingsThatLoosen(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_two_changes_at_once_record_the_weakening_once(self):
        # a second prompt takes the lock first and loosens the same setting (codex review of 0.8.7, round 4)
        _reset(rehydration="block")
        real, done = settings._lock_for, []

        def other_prompt_first(path):
            if not done:
                done.append(1)
                CONFIG.write_text(json.dumps({**TEST_CONFIG, "rehydration": "automatic"}))
                events.record_weakening("setting", "rehydration", "typed prompt")
            return real(path)
        with mock.patch.object(settings, "_lock_for", other_prompt_first):
            changed, _text = settings.apply_typed("rehydration", "automatic")
        self.assertTrue(changed and done)
        self.assertEqual([e["name"] for e in _weakened()], ["rehydration"])

    def test_a_looser_setting_writes_one_line_with_its_route_and_no_value(self):
        _reset(rehydration="block")
        _prompt("maisecrets: set rehydration automatic")
        _prompt("/maisecrets:settings max_resolves_per_hour 5000")
        _prompt("/maisecrets:settings ssh_autonomous_hosts add web7.example.invalid")
        _prompt("maisecrets: set resolve_in_files on", CODEX)
        got = [(e["weakened"], e["name"], e["route"]) for e in _weakened()]
        self.assertEqual(got, [("setting", "rehydration", "typed prompt"),
                               ("setting", "max_resolves_per_hour", "slash command"),
                               ("setting", "ssh_autonomous_hosts", "slash command")],
                         "resolve_in_files is on by default: turning it on loosens nothing")
        text = json.dumps([{k: v for k, v in e.items() if k not in ("t", "ts")} for e in _lines()])
        for value in ("automatic", "5000", "web7"):
            self.assertNotIn(value, text, "a line names the setting, never its value")
        for e in _weakened():
            self.assertTrue(e["ts"] and isinstance(e["t"], int))

    def test_a_stricter_or_neutral_setting_writes_nothing(self):
        for text in ("maisecrets: set rehydration block", "maisecrets: set ssh_consent on",
                     "maisecrets: set max_keys_per_session 20", "maisecrets: set tips off",
                     "/maisecrets:settings ssh_autonomous_hosts remove web7.example.invalid",
                     "maisecrets: set rehydration block"):
            _prompt(text)
        self.assertEqual(_weakened(), [])

    def test_back_to_the_default_is_judged_by_the_value_in_effect(self):
        _reset(ssh_consent=True)
        _prompt("maisecrets: set ssh_consent default")
        self.assertEqual([e["name"] for e in _weakened()], ["ssh_consent"])

    def test_a_prompt_that_changes_nothing_writes_nothing(self):
        _prompt("maisecrets: set rehydration automatic", {**CLAUDE, "source": "schedule_wakeup"})
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}):
            _prompt("maisecrets: set ssh_consent off")
        _prompt("maisecrets: set rehydration nonsense")
        self.assertEqual(_weakened(), [])

    def test_every_setting_a_prompt_changes_has_a_direction(self):
        keys = set(settings._BOOL_KEYS) | set(settings._CHOICES) | set(settings._INT_KEYS) | {"ssh_autonomous_hosts"}
        known = set(settings.PROTECTIVE_BOOL) | set(settings.STRICTER_LAST) | set(settings._INT_KEYS) | \
            set(settings.NEUTRAL) | set(settings.OWN_DIRECTION) | {"ssh_autonomous_hosts"}
        self.assertEqual(sorted(keys - known), [], "a new setting needs a direction (settings.PROTECTIVE_BOOL, …)")
        self.assertEqual(sorted(set(settings.PROTECTIVE_BOOL) - set(settings._BOOL_KEYS)), [])


class Forget(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_forget_writes_one_line_with_the_key_and_its_route(self):
        value = _value()
        key = Vault(load_config()).put(value, "SECRET", "manual", session="S1").key
        with mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(cli.main(["forget", key]), 0)
            self.assertEqual(cli.main(["forget", "SECRET_c999"]), 1)
        got = [(e["weakened"], e["name"], e["route"]) for e in _weakened()]
        self.assertEqual(got, [("forget", key, "cli")], "an unknown key deletes nothing and writes nothing")
        self.assertNotIn(value, events.EVENTS.read_text())
        key = Vault(load_config()).put(_value() + "x", "SECRET", "manual", session="S1").key
        with mock.patch("sys.stdin", new=io.StringIO(key + "\n")), mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(cli.main(["forget", "--args-stdin"]), 0)
        self.assertEqual(_weakened()[-1]["route"], "slash command")


class TypedForget(unittest.TestCase):
    """Decision I: a forget the person typed (/maisecrets:forget, the panel, not-a-secret) is no start notice; any
    other deletion still is, and events.log keeps every line."""

    def setUp(self):
        _reset()
        try:
            os.unlink(events._TYPED_FORGET)
        except FileNotFoundError:
            pass

    def _key(self, n: int = 0) -> str:
        return Vault(load_config()).put(_value() + "x" * n, "SECRET", "manual", session="S1").key

    def _slash_forget(self, key: str, session: str | None = "S1") -> None:
        # the command file runs `run.sh forget --args-stdin` with the keys on stdin; the client gives the command its
        # session id (CLAUDE_CODE_SESSION_ID)
        env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID")}
        if session:
            env["CLAUDE_CODE_SESSION_ID"] = session
        with mock.patch("sys.stdin", new=io.StringIO(key + "\n")), mock.patch("sys.stdout", new=io.StringIO()), \
                mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(cli.main(["forget", "--args-stdin"]), 0)

    def test_a_mark_that_cannot_be_taken_out_is_not_used_and_the_notice_stays(self):
        key = self._key(10)
        _prompt(f"/maisecrets:forget {key}")
        with mock.patch.object(events, "_keep_notes", side_effect=OSError("disk full")):
            self._slash_forget(key)
        self.assertIsNone(_weakened()[-1].get("typed"))
        self.assertIn(f"stored value {key} deleted", events.weakenings_since_last_start())

    def test_a_forget_in_another_session_or_without_a_session_keeps_the_notice(self):
        key = self._key(8)
        _prompt(f"/maisecrets:forget {key}")             # typed in session S1
        self._slash_forget(key, session="S2")              # another session runs the command for the same key
        self.assertIsNone(_weakened()[-1].get("typed"))
        self.assertIn(f"stored value {key} deleted", events.weakenings_since_last_start())
        key = self._key(9)
        _prompt(f"/maisecrets:forget {key}")
        self._slash_forget(key, session=None)              # no session id: the safe side
        self.assertIn(f"stored value {key} deleted", events.weakenings_since_last_start())

    def test_a_forget_the_person_typed_gives_no_notice_and_stays_in_the_log(self):
        key = self._key()
        _prompt(f"/maisecrets:forget {key}")
        self._slash_forget(key)
        self.assertEqual([(e["weakened"], e["name"], e.get("typed")) for e in _weakened()], [("forget", key, True)])
        self.assertIsNone(events.weakenings_since_last_start())

    def test_the_same_command_that_the_person_did_not_type_keeps_the_notice(self):
        typed, other = self._key(1), self._key(2)
        _prompt(f"/maisecrets:forget {typed}")
        self._slash_forget(other)        # an agent ran the command for another key
        self.assertIsNone(_weakened()[-1].get("typed"))
        self.assertIn(f"stored value {other} deleted (a slash command)", events.weakenings_since_last_start())

    def test_a_forget_typed_long_ago_or_by_a_subagent_keeps_the_notice(self):
        key = self._key(3)
        _prompt(f"/maisecrets:forget {key}")
        notes = json.loads(events._TYPED_FORGET.read_text())
        notes["S1"]["t"] -= events.TYPED_FORGET_SECONDS + 1
        events._TYPED_FORGET.write_text(json.dumps(notes))
        self._slash_forget(key)
        self.assertIn(f"stored value {key} deleted", events.weakenings_since_last_start())
        key = self._key(4)
        hooks.user_prompt({"prompt": f"/maisecrets:forget {key}", "session_id": "S1", "agent_id": "a1", **CLAUDE})
        self._slash_forget(key)
        self.assertIn(f"stored value {key} deleted", events.weakenings_since_last_start())

    def test_the_panel_and_not_a_secret_give_no_notice_and_a_terminal_forget_still_does(self):
        from maisecrets import hub, not_a_secret
        panel, nas, term = self._key(5), self._key(6), self._key(7)
        hub.pane_forget(panel)
        for _ in range(2):      # a key type asks for the command twice
            not_a_secret.allow_typed(nas, "S1", "typed prompt")
        with mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(cli.main(["forget", term]), 0)
        forgets = sorted(e["name"] for e in _weakened() if e["weakened"] == "forget")
        self.assertEqual(forgets, sorted([panel, nas, term]), "events.log keeps every forget")
        line = events.weakenings_since_last_start()
        self.assertIn("1 protection was loosened: stored value " + term + " deleted (a terminal command)", line)
        self.assertNotIn(panel, line)
        self.assertNotIn(nas, line)
        self.assertIsNone(events.weakenings_since_last_start(), "the typed lines are marked as shown too")



class SessionStart(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_the_next_start_names_them_once(self):
        events.record_weakening("setting", "rehydration", "typed prompt")
        events.record_weakening("forget", "SECRET_c3", "cli")
        line = events.weakenings_since_last_start()
        # the setting by its title, the route in words: the raw key and route said nothing to the person
        self.assertEqual(line, "maisecrets: since the last session start, 2 protections were loosened: the setting "
                               "Stored values in tool calls (your prompt), stored value SECRET_c3 deleted (a terminal "
                               "command). If you did not do this, check /maisecrets:settings and /maisecrets:list.")
        self.assertIsNone(events.weakenings_since_last_start(), "shown once")
        events.record_weakening("forget", "SECRET_c4", "slash command")
        self.assertIn("1 protection was loosened: stored value SECRET_c4 deleted (a slash command).",
                      events.weakenings_since_last_start())

    def test_a_broken_byte_in_the_log_neither_stops_the_line_nor_the_sentence(self):
        events.EVENTS.parent.mkdir(parents=True, exist_ok=True)
        events.EVENTS.write_bytes(b"\xff\n")
        events.record_weakening("forget", "SECRET_c5", "cli")
        self.assertIn("1 protection was loosened: stored value SECRET_c5 deleted (a terminal command).",
                      events.weakenings_since_last_start())

    def test_many_are_counted_and_a_detection_never_pushes_one_out(self):
        for i in range(7):
            events.record_weakening("forget", f"SECRET_c{i}", "cli")
        from types import SimpleNamespace
        for _ in range(events.KEEP + 20):
            events.record("PostToolUse", "claude", [SimpleNamespace(key="SECRET_c1", type="SECRET", kind="k")])
        self.assertEqual(len(_weakened()), 7)
        self.assertEqual(len(events.load(events.KEEP)), events.KEEP - 7, "the report reads detections only")
        line = events.weakenings_since_last_start()
        self.assertIn("7 protections were loosened", line)
        self.assertIn("and 2 more in events.log", line)

    def test_the_session_start_hook_shows_the_sentence_to_the_person(self):
        events.record_weakening("setting", "ssh_consent", "slash command")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "CODEX_", "CLAUDE"))}
        env["TMPDIR"] = tempfile.gettempdir()
        payload = json.dumps({"session_id": "SS", "transcript_path": "", "source": "startup"})
        runs = [subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "session-start"], input=payload,
                               capture_output=True, text=True, env=env, timeout=60, cwd=tempfile.gettempdir())
                for _ in range(2)]
        first, second = (json.loads(r.stdout)["systemMessage"] for r in runs)
        self.assertIn("1 protection was loosened: the setting SSH consent (a slash command).", first)
        self.assertNotIn("loosened", second)
        self.assertNotIn("loosened", json.loads(runs[0].stdout)["hookSpecificOutput"]["additionalContext"],
                         "the sentence is for the person, not for the model")


if __name__ == "__main__":
    unittest.main()
