"""Settings and hints (maisecrets/settings.py): a setting changes only from a prompt the person typed, a missing key
is "not decided", and a hint goes to the model once, at the first case it is about."""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import hooks, settings  # noqa: E402
from maisecrets.vault import _CONFIG_TYPES, DEFAULT_CONFIG, HOME, load_config  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

TEST_CONFIG = {"backend": "jsonfile", "allow_plaintext_store": True}
CONFIG = Path(HOME, "config.json")
HINTS = Path(HOME, "hints.json")
HINTS_REV = settings.HINTS["ssh_consent"]["revision"]


def tearDownModule():  # noqa: N802 - unittest hook
    _reset()
    _hygiene.assert_pristine()


def _reset(**user) -> None:
    CONFIG.write_text(json.dumps({**TEST_CONFIG, **user}))
    try:
        os.unlink(HINTS)
    except FileNotFoundError:
        pass


def _user() -> dict:
    return json.loads(CONFIG.read_text())


def _prompt(text: str, client: dict = CLAUDE, **extra) -> dict:
    return hooks.user_prompt({"prompt": text, "session_id": "S1", **client, **extra})


def _post(command: str, client: dict = CLAUDE, **extra) -> dict:
    payload = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": command},
               "tool_response": {"stdout": "ok", "stderr": "", "interrupted": False}, "session_id": "S1",
               **client, **extra}
    return hooks._post_tool_guarded(payload)


def _context(out: dict) -> str:
    return (out.get("hookSpecificOutput") or {}).get("additionalContext") or out.get("reason") or ""


class Classes(unittest.TestCase):
    def test_every_config_key_is_in_exactly_one_class(self):
        keys = set(DEFAULT_CONFIG) | set(_CONFIG_TYPES)
        classes = [settings.DISCOVERABLE, settings.ADVANCED, settings.INTERNAL]
        self.assertGreater(len(keys), 25)
        for key in sorted(keys):
            with self.subTest(key):
                self.assertEqual(sum(key in c for c in classes), 1, f"{key} needs exactly one class in settings.py")
        self.assertEqual(set().union(*classes), keys, "a class names a key the config does not have")
        for key in settings.DISCOVERABLE + settings.ADVANCED:
            self.assertIn(key, settings.MEANING, f"{key} is shown, so it needs one line of meaning")


class State(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_a_missing_key_is_not_decided_and_false_is_a_decision(self):
        cfg = load_config()
        self.assertIs(cfg["ssh_consent"], False)
        self.assertEqual(settings.state("ssh_consent", cfg), "not decided")
        _reset(ssh_consent=False)
        cfg = load_config()
        self.assertIs(cfg["ssh_consent"], False, "the same value")
        self.assertEqual(settings.state("ssh_consent", cfg), "set by you")
        _reset(rehydration="confirm")
        self.assertEqual(settings.state("rehydration", load_config()), "set by you")
        cfg = {**load_config(), "policy_keys": ["ssh_consent"]}
        self.assertEqual(settings.state("ssh_consent", cfg), "set by a policy")

    def test_the_list_shows_cards_with_value_state_meaning_and_the_next_command(self):
        _reset(ssh_consent=False)
        lines = settings.render().splitlines()
        at = lines.index("  SSH consent · off · set by you")
        self.assertEqual(lines[at + 1].strip(), settings.MEANING["ssh_consent"])
        self.assertEqual(lines[at + 2].strip(), "Turn on: /maisecrets:settings ssh_consent on")
        text = "\n".join(lines)
        for mode in ("automatic", "confirm", "block"):
            self.assertIn(f"    {mode}", text, "rehydration explains its three modes together")
        self.assertIn("Change: /maisecrets:settings rehydration confirm", text)
        self.assertNotIn("allow_plaintext_store", text, "an internal key is not shown")
        self.assertNotIn("Block @file mentions", text, "an advanced setting only with --all")
        self.assertIn(f"More settings ({len(settings.ADVANCED)}): /maisecrets:settings --all", text)
        full = settings.render(show_all=True)
        self.assertIn("Block @file mentions", full)
        self.assertIn("Lifetime of a value · 24 h (CARD 1 h)", full, "a lifetime reads as hours, not JSON")
        self.assertIn("the hint for it may come once more", text, "default says that it resets the decision")
        self.assertIn("  SSH consent · not shown yet", text, "the hint state is visible")
        with mock.patch.object(settings, "load_config", return_value={**load_config(), "policy_keys": ["ssh_consent"]}):
            self.assertIn("cannot be changed here", settings.render())


class EveryShownCommandWorks(unittest.TestCase):
    """Every /maisecrets:settings command the list prints runs through the hook and the command without an error.
    The list told the user `ssh_autonomous_hosts add HOST`, and the command then exited 1 (field report on 0.6.6):
    each part had a test, the path the user types had none."""

    def test_each_printed_command_changes_or_shows_without_an_error(self):
        import re as _re
        from maisecrets import cli
        _reset(ssh_autonomous_hosts=["ops1"])
        text = settings.render(show_all=True)
        _reset(ssh_autonomous_hosts=["ops1"], secret_destinations="off", ssh_consent=True)
        text += settings.render(show_all=True)      # the commands a card shows only in another state
        shown = sorted(set(_re.findall(r"(/maisecrets:settings [^\n(]+?)\s*(?:\(|$)", text, _re.M)))
        commands = [c.replace("HOST", "ops2").replace("KEY default", "ssh_consent default")
                    .replace(" DIR", " " + str(Path(_isolate.TMP, "team-rules").resolve()))
                    .replace(" FILE", " " + str(Path(_isolate.TMP, "values.jsonl").resolve())).strip() for c in shown]
        self.assertGreater(len(commands), 10, commands)
        for must in ("/maisecrets:settings secret_destinations observe", "/maisecrets:settings ssh_consent off",
                     "/maisecrets:settings ssh_autonomous_hosts add ops2"):
            self.assertIn(must, commands, "a command of a card is missing from the population")
        for command in commands:
            with self.subTest(command):
                _reset(ssh_autonomous_hosts=["ops1"])
                out = _prompt(command)
                self.assertNotEqual(out.get("decision"), "block", out)
                args = command.split()[1:]
                with mock.patch("sys.stdout") as stdout:
                    rc = cli.main(["settings", *args])
                said = "".join(c.args[0] for c in stdout.write.call_args_list)
                self.assertEqual(rc, 0, said)
                self.assertNotIn("is no setting", said)


class Change(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_a_typed_prompt_changes_a_setting(self):
        for client, text in ((CODEX, "maisecrets: set ssh_consent on"),
                             (CLAUDE, "  maisecrets: set ssh_consent on  ")):
            with self.subTest(text):
                _reset()
                out = _prompt(text, client)
                self.assertEqual(out["decision"], "block", "the sentence never reaches the model")
                self.assertIn("SSH consent is on (set by you)", out["reason"])
                self.assertIs(_user()["ssh_consent"], True)
                self.assertEqual(_user()["backend"], "jsonfile", "every other key stays")

    def test_the_slash_command_changes_it_and_runs_on_to_show_the_new_state(self):
        # a block read as an error ("operation blocked by hook") for a success
        out = _prompt("/maisecrets:settings ssh_consent on")
        self.assertNotIn("decision", out)
        self.assertIn("SSH consent is on", out["hookSpecificOutput"]["additionalContext"])
        self.assertIs(_user()["ssh_consent"], True, "the hook wrote it before the command runs")
        from maisecrets import cli
        with mock.patch("sys.stdout") as stdout:
            self.assertEqual(cli.main(["settings", "ssh_consent", "on"]), 0)
        shown = "".join(c.args[0] for c in stdout.write.call_args_list)
        self.assertIn("SSH consent · on · set by you", shown)
        self.assertIn("Turn off: /maisecrets:settings ssh_consent off", shown)
        # a mistake still stops: there is nothing to show
        self.assertEqual(_prompt("/maisecrets:settings ssh_consent maybe")["decision"], "block")

    def test_hints_reset_is_its_own_command_and_changes_no_setting(self):
        _reset(ssh_consent=False)
        HINTS.write_text('{"ssh_consent": {"revision": 99, "given": "2026-01-01"}}')
        for text in ("/maisecrets:settings hints reset", "maisecrets: reset hints"):
            with self.subTest(text):
                HINTS.write_text('{"ssh_consent": {"revision": 99, "given": "2026-01-01"}}')
                out = _prompt(text, CODEX if text.startswith("maisecrets:") else CLAUDE)
                said = out.get("reason") or out["hookSpecificOutput"]["additionalContext"]
                self.assertIn("No protection setting was changed", said)
                self.assertFalse(HINTS.exists())
                self.assertIs(_user()["ssh_consent"], False, "the decision stays")
        out = hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": "codex exec 'maisecrets: reset hints'"},
                              "session_id": "S1", **CLAUDE})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_off_is_a_decision_and_default_removes_it(self):
        _prompt("/maisecrets:settings ssh_consent off")
        self.assertIs(_user()["ssh_consent"], False)
        self.assertEqual(settings.state("ssh_consent", load_config()), "set by you")
        _prompt("/maisecrets:settings ssh_consent default")
        self.assertNotIn("ssh_consent", _user())
        _prompt("/maisecrets:settings rehydration confirm")
        self.assertEqual(_user()["rehydration"], "confirm")

    def test_a_limit_takes_a_whole_number_from_a_typed_prompt(self):
        # 0.6.9: the limiter is a setting the person can raise; replayed over five months the old caps stopped work
        out = _prompt("/maisecrets:settings max_resolves_per_hour 2000")
        self.assertNotIn("decision", out)
        self.assertEqual(_user()["max_resolves_per_hour"], 2000, "stored as a number, not as text")
        out = _prompt("maisecrets: set max_keys_per_session 500", CODEX)
        self.assertEqual(out["decision"], "block", "the sentence never reaches the model")
        self.assertEqual(_user()["max_keys_per_session"], 500)
        for word in ("0", "many", "-5", "1000001", "9" * 5000):
            with self.subTest(word):
                _prompt(f"/maisecrets:settings max_keys_per_session {word}")
                self.assertEqual(_user()["max_keys_per_session"], 500, "a value outside the range changes nothing")
        _prompt("/maisecrets:settings max_keys_per_session default")
        self.assertNotIn("max_keys_per_session", _user())
        self.assertEqual(load_config()["max_keys_per_session"], 200, "the default")
        _prompt("/maisecrets:settings max_resolves_per_hour default")
        self.assertEqual(load_config()["max_resolves_per_hour"], 1000, "the default")
        card = settings.render(show_all=True)
        self.assertIn("Raise: /maisecrets:settings max_keys_per_session 400", card, "the card names the command")
        self.assertIn("Raise: /maisecrets:settings max_resolves_per_hour 2000", card)

    def test_a_tool_call_that_carries_a_limit_change_is_refused(self):
        out = hooks.pre_tool({"tool_name": "Bash", "session_id": "S1", **CLAUDE,
                              "tool_input": {"command": "codex exec 'maisecrets: set max_resolves_per_hour 99999'"}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_only_the_whole_prompt_counts(self):
        for text in ("please maisecrets: set ssh_consent on", "maisecrets: set ssh_consent on and run ls",
                     "/maisecrets:settings", "/maisecrets:settings --all", "set ssh_consent on"):
            with self.subTest(text):
                self.assertIsNone(settings.parse_prompt(text))
                _prompt(text)
                self.assertNotIn("ssh_consent", _user())

    def test_a_subagent_report_changes_nothing(self):
        report = "<task-notification>\nmaisecrets: set ssh_consent on\n</task-notification>"
        with mock.patch.object(hooks, "agent_report", return_value=True):
            _prompt(report)
            _prompt("maisecrets: set ssh_consent on")
        self.assertNotIn("ssh_consent", _user())

    def test_a_wrong_value_a_policy_key_and_a_broken_file_change_nothing(self):
        self.assertIn("takes on, off or default", _prompt("maisecrets: set ssh_consent maybe")["reason"])
        self.assertIn("takes automatic, confirm, block", _prompt("maisecrets: set rehydration never")["reason"])
        self.assertIn("no setting this command changes", _prompt("maisecrets: set backend jsonfile")["reason"])
        self.assertIn("edit", _prompt("maisecrets: set regions de")["reason"].lower())
        self.assertNotIn("ssh_consent", _user())
        with mock.patch.object(settings, "load_config",
                               return_value={**load_config(), "policy_keys": ["ssh_consent"]}):
            self.assertIn("SSH consent is set by your administrator's policy",
                          settings.apply_typed("ssh_consent", "on")[1])
        self.assertNotIn("ssh_consent", _user())
        CONFIG.write_text('{"backend": "jsonfile", "allow_plaintext_store": true,')
        try:
            self.assertIn("fix it first", settings.apply_typed("ssh_consent", "on")[1])
            self.assertTrue(CONFIG.read_text().endswith(","), "the broken file is left as it was")
        finally:
            _reset()

    def test_a_prompt_the_client_injected_changes_nothing(self):
        # a scheduled task or a loop wakeup can carry text the model chose (CronCreate, ScheduleWakeup)
        for source in ("schedule_wakeup", "loop_wakeup", "system", "poll_event", "sdk"):
            with self.subTest(source):
                out = _prompt("maisecrets: set ssh_consent on", source=source)
                self.assertEqual(out["decision"], "block", "it does not reach the model either")
                self.assertIn("counts only when you type it", out["reason"])
                self.assertNotIn("ssh_consent", _user())
        for source in ("user",):
            with self.subTest(source):
                _reset()
                _prompt("maisecrets: set ssh_consent on", source=source)
                self.assertIs(_user()["ssh_consent"], True)

    def test_a_prompt_from_a_client_a_program_started_changes_nothing(self):
        # measured on Claude Code 2.1.300: `claude -p` sends no `source` and runs its hooks with
        # CLAUDE_CODE_ENTRYPOINT=sdk-cli, which env -u and a preset `cli` do not change; the terminal client sends
        # no `source` either and has `cli`. Codex sends no `source` and sets no entry point of its own
        for entry in ("sdk-cli", "sdk-ts", "sdk-py"):
            with self.subTest(entry), mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": entry}):
                _reset()
                for client, text in ((CLAUDE, "maisecrets: set ssh_consent on"),
                                     (CLAUDE, "/maisecrets:settings rehydration block"),
                                     (CODEX, "maisecrets: set tips off")):
                    out = _prompt(text, client)
                    self.assertEqual(out["decision"], "block", "it does not reach the model either")
                    self.assertIn("a program started", out["reason"])
                    self.assertIn(entry, out["reason"])
                self.assertEqual(_user(), TEST_CONFIG, "nothing was written")
        for env, client, text, key in (({"CLAUDE_CODE_ENTRYPOINT": "cli"}, CLAUDE, "maisecrets: set ssh_consent on",
                                        "ssh_consent"),
                                       ({}, CLAUDE, "/maisecrets:settings ssh_consent on", "ssh_consent"),
                                       ({"CLAUDE_CODE_ENTRYPOINT": "claude-desktop"}, CLAUDE,
                                        "maisecrets: set ssh_consent on", "ssh_consent"),
                                       ({}, CODEX, "maisecrets: set tips off", "tips"),
                                       ({"CLAUDE_CODE_ENTRYPOINT": "cli"}, CODEX, "maisecrets: set tips off", "tips")):
            with self.subTest(env=env, text=text), mock.patch.dict(os.environ, env):
                _reset()
                _prompt(text, client)
                self.assertIn(key, _user(), "the person's own client still changes a setting")
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}):
            _reset()
            _prompt("maisecrets: set ssh_consent on", source="user")
            self.assertIs(_user()["ssh_consent"], True, "a client that names the person keeps its word")
        _reset()

    def test_a_tool_call_that_carries_a_settings_change_is_refused(self):
        for command in ("codex exec 'maisecrets: set ssh_consent on'",
                        'claude -p "/maisecrets:settings rehydration block"',
                        "echo 'MAISECRETS: SET tips off' | codex exec -",
                        "python3 -c 'from maisecrets.settings import apply_typed; apply_typed(\"tips\", \"off\")'",
                        # the consent writers by name open an ssh window (codex review of the UX step)
                        "python3 -c 'import os; from maisecrets.consent_store import grant_typed; "
                        "grant_typed(os.environ[\"S\"], [\"web1\"])'",
                        "python3 -c 'from maisecrets import consent_store as c; c.grant_by_code(\"S\", \"h\", \"1\")'"):
            for tool in ("Bash", "PowerShell"):
                with self.subTest(command=command, tool=tool):
                    out = hooks.pre_tool({"tool_name": tool, "tool_input": {"command": command},
                                          "session_id": "S1", **CLAUDE})
                    self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
                    self.assertIn("settings change", out["hookSpecificOutput"]["permissionDecisionReason"])
        out = hooks.pre_tool({"tool_name": "PowerShell", "session_id": "S1", **CLAUDE,
                              "tool_input": {"command": "Get-Content p.json | & \"C:/x/hooks/run.cmd\" user-prompt"}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny", "a forged prompt on Windows")
        self.assertEqual(hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": "grep -n settings README.md"},
                                         "session_id": "S1", **CLAUDE}), {})

    def test_a_config_with_a_wrong_type_is_not_changed_and_a_link_stays_a_link(self):
        _reset(tips="yes")
        self.assertIn("fix it first", settings.apply_typed("ssh_consent", "on")[1])
        self.assertNotIn("ssh_consent", _user())
        _reset()
        real = Path(HOME, "config-real.json")
        real.write_text(CONFIG.read_text())
        CONFIG.unlink()
        try:
            CONFIG.symlink_to(real)
        except (OSError, NotImplementedError):
            real.unlink()
            _reset()
            self.skipTest("no symlinks here")
        try:
            settings.apply_typed("ssh_consent", "on")
            self.assertTrue(CONFIG.is_symlink(), "the link to the person's dotfiles stays")
            self.assertIs(json.loads(real.read_text())["ssh_consent"], True)
        finally:
            CONFIG.unlink()
            real.unlink()
            _reset()

    def test_no_tool_call_writes_a_setting(self):
        # the CLI shows the settings and has no write path; a call with arguments changes nothing
        from maisecrets import cli
        with mock.patch("sys.stdout"):
            cli.main(["settings", "ssh_consent", "on"])
        self.assertNotIn("ssh_consent", _user())
        # PreToolUse and PostToolUse of any command leave the config alone
        for command in ("maisecrets: set ssh_consent on", "echo 'maisecrets: set ssh_consent on'",
                        "bash hooks/run.sh settings ssh_consent on"):
            with self.subTest(command):
                hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": command}, "session_id": "S1",
                                **CLAUDE})
                _post(command)
                self.assertNotIn("ssh_consent", _user())


class Hint(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_the_first_ssh_write_gives_the_hint_once(self):
        self.assertNotIn("ssh_consent", _context(_post("ls -la")))
        self.assertNotIn("ssh_consent", _context(_post("ssh web1 uptime")), "a read is no case for it")
        self.assertNotIn("ssh_consent", _context(_post("grep ssh README.md")), "a text that names ssh is none")
        out = _post("ssh web1 'sudo systemctl restart nginx'")
        self.assertIn("/maisecrets:settings ssh_consent on", _context(out))
        self.assertIn("Do not change settings yourself", _context(out))
        self.assertNotIn("ssh_consent", _context(_post("ssh web2 reboot")), "once, not per host or per session")
        self.assertNotIn("ssh_consent", _context(_post("ssh web2 reboot", session_id="S2")))

    def test_codex_gets_its_sentence_and_an_unread_form_is_no_case(self):
        # an unread form shares its class with a plain mention (`echo ssh`), so it gives no hint
        self.assertNotIn("ssh_consent", _context(_post("bash -c 'ssh web1 reboot'", CODEX)))
        out = _post("ssh web1 reboot", CODEX)
        self.assertIn("maisecrets: set ssh_consent on", _context(out))
        self.assertNotIn("/maisecrets:settings", _context(out), "Codex has no slash command for plugins")

    def test_no_hint_after_a_decision_with_tips_off_in_a_policy_or_a_subagent(self):
        for user, extra, why in (({"ssh_consent": False}, {}, "decided: off"),
                                 ({"ssh_consent": True}, {}, "decided: on"),
                                 ({"tips": False}, {}, "tips off"),
                                 ({}, {"agent_id": "sub1"}, "a subagent")):
            with self.subTest(why):
                _reset(**user)
                self.assertNotIn("maisecrets can ask", _context(_post("ssh web1 reboot", **extra)))
                self.assertFalse(HINTS.exists(), "a hint not given is not marked as given")
        _reset()
        with mock.patch.object(hooks, "load_config", return_value={**load_config(), "policy_keys": ["ssh_consent"]}):
            self.assertNotIn("maisecrets can ask", _context(_post("ssh web1 reboot")))

    def test_default_resets_the_decision_but_not_the_given_hint(self):
        _post("ssh web1 reboot")
        _prompt("maisecrets: set ssh_consent off")
        _prompt("maisecrets: set ssh_consent default")
        self.assertNotIn("maisecrets can ask", _context(_post("ssh web1 reboot")), "this revision was given")
        with mock.patch.dict(settings.HINTS["ssh_consent"], {"revision": HINTS_REV + 1}):
            self.assertIn("maisecrets can ask", _context(_post("ssh web1 reboot")), "a new revision comes once more")
            self.assertNotIn("maisecrets can ask", _context(_post("ssh web1 reboot")))

    def test_a_decision_in_a_file_that_was_ignored_still_stops_the_hint(self):
        _reset(ssh_consent=False, tips="yes")       # a wrong type elsewhere: load_config ignores the file
        self.assertNotIn("maisecrets can ask", _context(_post("ssh web1 reboot")))

    def test_an_unwritable_record_gives_no_hint_and_parallel_hooks_give_it_once(self):
        with mock.patch.object(settings, "atomic_write", side_effect=OSError):
            for _ in range(3):
                self.assertNotIn("maisecrets can ask", _context(_post("ssh web1 reboot")))
        _reset()
        import subprocess
        code = ("import sys; sys.path.insert(0, sys.argv[1]); from maisecrets import settings; "
                "print(settings.claim_hint('ssh_consent'))")
        env = dict(os.environ, MAISECRETS_HOME=str(HOME))
        procs = [subprocess.Popen([sys.executable, "-c", code, str(ROOT)], stdout=subprocess.PIPE, text=True, env=env)
                 for _ in range(6)]
        got = [p.communicate(timeout=60)[0].strip() for p in procs]
        self.assertEqual(sorted(got), ["False"] * 5 + ["True"], got)

    def test_the_codex_block_answer_carries_the_hint_after_its_output(self):
        result = {"decision": "block", "reason": "[maisecrets: the command ran and finished]\n\noutput"}
        with mock.patch.object(hooks, "post_tool", return_value=result):
            out = _post("ssh web1 reboot", CODEX)
        self.assertEqual(set(out), {"decision", "reason"}, "Codex reads PostToolUse through a strict schema")
        self.assertTrue(out["reason"].startswith(result["reason"]))
        self.assertIn("maisecrets: set ssh_consent on", out["reason"])

    def test_the_hint_keeps_what_the_answer_does(self):
        # a redacted result keeps its output and its own context; the hint comes after it
        result = {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": {"stdout": "x"},
                                         "additionalContext": "maisecrets masked 1 value(s)"}}
        with mock.patch.object(hooks, "post_tool", return_value=result):
            out = _post("ssh web1 reboot")
        self.assertEqual(out["hookSpecificOutput"]["updatedToolOutput"], {"stdout": "x"})
        self.assertTrue(_context(out).startswith("maisecrets masked 1 value(s)"))
        self.assertIn("maisecrets can ask", _context(out))
        # a hint that fails does not withhold the output
        _reset()
        with mock.patch.object(hooks, "post_tool", return_value=result), \
                mock.patch.object(settings, "hint_due", side_effect=RuntimeError):
            self.assertEqual(_post("ssh web1 reboot"), result)


if __name__ == "__main__":
    unittest.main()
