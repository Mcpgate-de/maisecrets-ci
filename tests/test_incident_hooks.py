"""The incident record in the hooks (docs/DIAGNOSTICS.md, sections 5, 7 and 10): the report comes from the prompt
hook before the config and the store, a failure is recorded after the answer, the answer stays the same, and the
watchdog leaves its marker.

Run: python3 -m unittest tests.test_incident_hooks -v
"""
from __future__ import annotations

import io
import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import home, hooks, incidents, vault  # noqa: E402

HOME = Path(os.environ["MAISECRETS_HOME"])
CLAUDE = {"prompt_id": "p1", "session_id": "S1", "transcript_path": "", "cwd": "/tmp"}
CODEX = {"turn_id": "t1", "model": "m", "session_id": "S1", "transcript_path": "", "cwd": "/tmp"}


def boom(*a, **k):
    raise AssertionError("must not be called")


class _Clean(unittest.TestCase):
    def setUp(self):
        HOME.mkdir(parents=True, exist_ok=True)
        (HOME / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        incidents.clear(HOME)
        incidents.discard()
        self.addCleanup(lambda: incidents.clear(HOME))

    def run_main(self, event: str, payload: dict, **patches) -> dict:
        buf = io.StringIO()
        with mock.patch.object(hooks.sys, "stdin", io.StringIO(json.dumps(payload))), \
                mock.patch.object(hooks.sys, "stdout", buf), \
                mock.patch.object(hooks.os, "_exit", lambda code: None):
            ctx = [mock.patch.dict(hooks.HANDLERS, {event: patches["handler"]})] if "handler" in patches else []
            ctx += [mock.patch.dict(hooks.WATCHDOG_SECONDS, {event: patches["watchdog"]})] if "watchdog" in patches \
                else []
            for c in ctx:
                c.start()
            try:
                hooks.main(["hook", event])
            finally:
                for c in reversed(ctx):
                    c.stop()
        return json.loads(buf.getvalue())


class ReportFromThePromptHookTests(_Clean):
    def test_the_report_needs_no_config_and_no_store(self):
        incidents.record_path().write_text(incidents.dumps(incidents.add({}, {
            "code": "store.lock", "cause": "lock", "class": "fail-closed", "event": "UserPromptSubmit"})))
        with mock.patch.object(hooks, "load_config", boom), mock.patch.object(hooks, "Vault", boom), \
                mock.patch.object(hooks, "_has_live", boom), \
                mock.patch.object(vault, "load_config", side_effect=vault.ConfigError("/private/x is not valid")), \
                mock.patch.object(home, "load_config", side_effect=vault.ConfigError("/private/x is not valid")):
            # events.report_url() reads the config through home
            out = hooks.user_prompt(dict(CLAUDE, prompt="/maisecrets:report incident"))
        self.assertEqual(out["decision"], "block")
        self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        self.assertTrue(out["reason"].startswith("maisecrets: your incident report"))
        self.assertIn("store.lock/lock", out["reason"])
        self.assertIn("link: unavailable (configuration)", out["reason"])
        self.assertNotIn("/private/x", out["reason"])

    def test_a_damaged_index_and_a_broken_config_still_give_the_report_through_the_whole_hook(self):
        (HOME / "index.json").write_text("{")
        (HOME / "config.json").write_text("{")
        try:
            out = self.run_main("user-prompt", dict(CLAUDE, prompt="/maisecrets:report\tIncident"))
        finally:
            (HOME / "index.json").unlink()
        self.assertTrue(out["reason"].startswith("maisecrets: your incident report"), out)

    def test_near_misses_get_the_usage_line_and_clear_names_the_terminal(self):
        out = hooks.user_prompt(dict(CLAUDE, prompt="/maisecrets:report incident please"))
        self.assertEqual(out["reason"], incidents.USAGE)
        out = hooks.user_prompt(dict(CLAUDE, prompt="/maisecrets:report incident clear"))
        self.assertIn("in a terminal", out["reason"])
        self.assertIn(os.path.join("hooks", "run.cmd" if os.name == "nt" else "run.sh"), out["reason"])

    def test_the_mod_passes_the_prompt_on_without_config_or_store(self):
        with mock.patch.object(hooks, "load_config", boom), mock.patch.object(hooks, "Vault", boom), \
                mock.patch.object(hooks, "_has_live", boom):
            self.assertEqual(hooks.rewrite_prompt(dict(CLAUDE, prompt="/maisecrets:report incident")), {})

    def test_codex_and_other_report_forms_take_the_normal_path(self):
        for payload in (dict(CODEX, prompt="/maisecrets:report incident"),
                        dict(CLAUDE, prompt="/maisecrets:report last it is a build id"),
                        dict(CLAUDE, prompt=" /maisecrets:report incident")):
            with self.subTest(payload["prompt"]):
                out = hooks.user_prompt(payload)
                self.assertFalse(str(out.get("reason", "")).startswith("maisecrets: your incident report"))


class RecordAfterTheAnswerTests(_Clean):
    def failing(self, payload):
        raise vault.LockTimeout("vault lock busy for 6s (/private/path/.lock)")

    def test_a_failure_is_recorded_after_the_answer_with_its_code(self):
        out = self.run_main("user-prompt", dict(CLAUDE, prompt="hello"), handler=self.failing)
        self.assertEqual(out["decision"], "block")
        groups = incidents.load()[0]
        self.assertEqual(list(groups), ["store.lock/lock"])
        self.assertEqual(groups["store.lock/lock"]["event"], "UserPromptSubmit")
        self.assertNotIn("private", incidents.record_path().read_text())

    def test_the_answer_is_the_same_with_the_recorder_on_off_raising_and_locked(self):
        on = self.run_main("pre-tool", dict(CLAUDE, tool_name="Bash", tool_input={"command": "ls"},
                                            tool_use_id="c1"), handler=self.failing)
        answers = [on]
        for patch in (mock.patch.object(incidents, "flush", lambda *a, **k: None),
                      mock.patch.object(incidents, "flush", side_effect=RuntimeError("x")),
                      mock.patch.object(incidents, "queue", side_effect=RuntimeError("x"))):
            with patch:
                try:
                    answers.append(self.run_main("pre-tool", dict(CLAUDE, tool_name="Bash",
                                                                  tool_input={"command": "ls"}, tool_use_id="c1"),
                                                 handler=self.failing))
                except RuntimeError:
                    answers.append("raised")
        with incidents._OneTry(HOME / incidents.LOCK_NAME):
            answers.append(self.run_main("pre-tool", dict(CLAUDE, tool_name="Bash", tool_input={"command": "ls"},
                                                          tool_use_id="c1"), handler=self.failing))
        self.assertEqual(answers[1:], [on] * 4, "off, flush raising, queue raising, lock held")

    def test_the_fail_closed_line_names_the_report_for_each_client(self):
        claude = hooks._fail_closed("pre-tool", CLAUDE, "x")["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("Type /maisecrets:report incident", claude)
        codex = hooks._fail_closed("pre-tool", CODEX, "x")["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn(hooks._run_sh() + " report incident", codex)
        self.assertTrue(os.path.isabs(hooks._run_sh()))


class ExitCodeTests(_Clean):
    def test_a_store_failure_keeps_its_exit_code_in_the_record(self):
        def failing(payload):
            raise vault.CodedError("keychain add failed (rc 45)", "store.keychain-add", "rc", 45)
        self.run_main("user-prompt", dict(CLAUDE, prompt="hello"), handler=failing)
        g = incidents.load()[0]["store.keychain-add/rc"]
        self.assertEqual((g["number_kind"], g["number"]), ("exit", 45))

    def test_an_exit_code_out_of_range_goes_and_the_occurrence_stays(self):
        def failing(payload):
            raise vault.CodedError("x", "store.locker-add", "rc", 3221225477)
        self.run_main("user-prompt", dict(CLAUDE, prompt="hello"), handler=failing)
        self.assertNotIn("number", incidents.load()[0]["store.locker-add/rc"])


class LockLimitTests(_Clean):
    def test_a_handler_stuck_in_its_own_write_cannot_hold_the_watchdog(self):
        exits = []
        real_out = hooks._out

        def stuck(obj):
            if not exits and "took longer" not in json.dumps(obj):
                time.sleep(3)                         # the handler's write hangs while it holds the answer lock
            real_out(obj)
        started = time.monotonic()
        with mock.patch.object(hooks.sys, "stdin", io.StringIO(json.dumps(dict(CLAUDE, prompt="hello")))), \
                mock.patch.object(hooks.sys, "stdout", io.StringIO()), \
                mock.patch.object(hooks.os, "_exit", lambda code: exits.append(time.monotonic() - started)), \
                mock.patch.object(hooks, "_out", stuck), \
                mock.patch.dict(hooks.HANDLERS, {"user-prompt": lambda p: {}}), \
                mock.patch.dict(hooks.WATCHDOG_SECONDS, {"user-prompt": 0.2}):
            hooks.main(["hook", "user-prompt"])
        self.assertTrue(exits, "the watchdog reached its exit")
        self.assertLess(exits[0], 2.0, "after at most 1 s of waiting for the lock, not after the 3 s write")


class ConfigCodeTests(_Clean):
    def test_a_user_file_of_a_wrong_type_is_noted_as_ignored(self):
        (HOME / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true, "tips": "x"}')
        self.run_main("user-prompt", dict(CLAUDE, prompt="hello"))
        self.assertIn("config.user-ignored/shape", incidents.load()[0])

    def test_a_policy_of_a_wrong_type_is_recorded_as_invalid(self):
        import platform
        import tempfile
        policy = Path(tempfile.mkdtemp(prefix="maisecrets-policy-")) / "policy.json"
        policy.write_text('{"tips": "x"}')
        with mock.patch.dict(vault.POLICY_PATHS, {platform.system(): policy}):
            out = self.run_main("user-prompt", dict(CLAUDE, prompt="hello"))
        self.assertEqual(out["decision"], "block")
        self.assertIn("config.policy-invalid/parse", incidents.load()[0])


class WatchdogTests(_Clean):
    def test_a_winning_watchdog_leaves_its_marker_and_the_losing_handler_records_nothing(self):
        def slow(payload):
            incidents.queue("store.decrypt", "other", "best-effort", "UserPromptSubmit")
            time.sleep(0.6)
            return {}
        out = self.run_main("user-prompt", dict(CLAUDE, prompt="hello"), handler=slow, watchdog=0.2)
        self.assertIn("took longer", out["reason"])
        self.assertTrue((HOME / (incidents.MARKER_PREFIX + "hook.user-prompt.watchdog")).is_dir())
        self.assertNotIn("store.decrypt/other", incidents.load()[0])

    def test_post_answer_work_that_hangs_still_ends_at_the_deadline(self):
        exits = []

        def hang(*a, **k):
            time.sleep(1.0)
        incidents.queue("store.decrypt", "other", "best-effort", "UserPromptSubmit")
        started = time.monotonic()
        buf = io.StringIO()
        with mock.patch.object(hooks.sys, "stdin", io.StringIO(json.dumps(dict(CLAUDE, prompt="hello")))), \
                mock.patch.object(hooks.sys, "stdout", buf), \
                mock.patch.object(hooks.os, "_exit", exits.append), \
                mock.patch.dict(hooks.HANDLERS, {"user-prompt": lambda p: {}}), \
                mock.patch.dict(hooks.WATCHDOG_SECONDS, {"user-prompt": 0.3}), \
                mock.patch.object(incidents, "flush", hang):
            hooks.main(["hook", "user-prompt"])
        self.assertEqual(exits, [0], "the losing watchdog still ends the process")
        self.assertEqual(json.loads(buf.getvalue()), {})
        self.assertFalse((HOME / (incidents.MARKER_PREFIX + "hook.user-prompt.watchdog")).exists(),
                         "a losing watchdog leaves no marker")
        self.assertLess(time.monotonic() - started, 3)


WRAPPER = (
    "import sys; sys.path.insert(0, sys.argv[1]); from maisecrets import hooks; "
    "hooks.WATCHDOG_SECONDS['user-prompt'] = float(sys.argv[2]); sys.exit(hooks.main(['hook', 'user-prompt']))")


@unittest.skipIf(os.name == "nt", "FIFOs and the signal-free exit are measured on POSIX")
class RealProcessTests(unittest.TestCase):
    """The hook as a process with its real os._exit: it must end, with one JSON answer, before the client's timeout."""

    def setUp(self):
        import shutil
        import tempfile
        self.home = Path(tempfile.mkdtemp(prefix="maisecrets-process-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        (self.home / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

    def run_hook(self, payload: dict, watchdog: float, **env) -> tuple:
        import subprocess
        e = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX_"))}
        e.update({"MAISECRETS_HOME": str(self.home), "PYTHONDONTWRITEBYTECODE": "1", **env})
        started = time.monotonic()
        r = subprocess.run([sys.executable, "-c", WRAPPER, str(ROOT), str(watchdog)], input=json.dumps(payload),
                           capture_output=True, text=True, env=e, timeout=20)
        return r, time.monotonic() - started

    def test_a_hanging_handler_ends_at_the_watchdog_with_one_answer(self):
        r, took = self.run_hook(dict(CLAUDE, prompt="hello"), 0.5, MAISECRETS_TEST_FAULT="user-prompt-slow",
                                MAISECRETS_TEST_HOME_OWNED="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("took longer", json.loads(r.stdout)["reason"])
        self.assertLess(took, 3.0, "the watchdog's real exit, not the handler's sleep")

    def test_a_stalled_home_cannot_hold_the_winning_watchdog(self):
        # FIFOs with no reader stand in for a stalled disk at both heartbeat files (Opus code review, round 1)
        sys.path.insert(0, str(ROOT / "hooks"))
        import guard
        (self.home / "guard.json").write_text('{"expect": "always"}')
        alive = self.home / "alive"
        alive.mkdir()
        name = guard.heartbeat_name("S1", "user-prompt", "p1")
        for n in (name, name + ".s"):
            os.mkfifo(alive / n)
        r, took = self.run_hook(dict(CLAUDE, prompt="hello"), 0.5)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("took longer", json.loads(r.stdout)["reason"])
        self.assertLess(took, 4.0, "the watchdog writes the done heartbeat only in its bounded thread")


if __name__ == "__main__":
    unittest.main()
