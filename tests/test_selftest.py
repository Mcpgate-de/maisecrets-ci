"""The self-test (maisecrets/selftest.py): /maisecrets:status test proves the tool-result path and the prompt path in
the real client. The PreToolUse hook registers the value, the PostToolUse hook masks it and records the tool path, the
prompt hook answers "passed" only for the pending value, and the value never lands in the vault.

Run: python3 -m unittest tests.test_selftest -v
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import cli, hooks, selftest  # noqa: E402

HOME = Path(os.environ["MAISECRETS_HOME"])
SESSION = "selftest-session-1"
COMMAND = 'bash "/x/maisecrets/hooks/run.sh" status test'
CLAUDE = {"prompt_id": "p1", "session_id": SESSION, "transcript_path": "", "cwd": "/tmp"}
CODEX = {"turn_id": "t1", "model": "m", "session_id": SESSION, "transcript_path": "", "cwd": "/tmp"}


class _Clean(unittest.TestCase):
    def setUp(self):
        HOME.mkdir(parents=True, exist_ok=True)
        (HOME / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        for name in ("selftest.json", "vault.json", "index.json", "events.log", "incidents.json"):
            (HOME / name).unlink(missing_ok=True)
        hooks._live_cache.clear()
        import _hygiene
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)  # no real clipboard in tests

    def arm(self, base=CLAUDE) -> str:
        hooks.pre_tool({**base, "hook_event_name": "PreToolUse", "tool_name": "Bash",
                        "tool_input": {"command": COMMAND}, "tool_use_id": "u1"})
        return selftest.load()["pending"]["value"]

    def command_output(self) -> str:
        buf = io.StringIO()
        with redirect_stdout(buf), mock.patch.dict(os.environ, {"CLAUDE_CODE_SESSION_ID": SESSION}):
            self.assertEqual(cli.cmd_status(["test"]), 0)
        return buf.getvalue()

    def post(self, output, base=CLAUDE, tool_use_id="u1", command=COMMAND) -> dict:
        return hooks._post_tool_guarded({**base, "hook_event_name": "PostToolUse", "tool_name": "Bash",
                                         "tool_input": {"command": command}, "tool_use_id": tool_use_id,
                                         "tool_response": output})

    def pin(self, value: str) -> None:
        """The pending value set to a fixed one (a test builds a text around it)."""
        state = selftest.load()
        state["pending"]["value"] = value
        (HOME / "selftest.json").write_text(json.dumps(state))

    def stored(self) -> str:
        return "".join((HOME / n).read_text() for n in ("vault.json", "index.json") if (HOME / n).exists())


class RegisterTests(_Clean):
    def test_the_tool_call_hook_registers_a_fresh_value_that_names_itself(self):
        value = self.arm()
        self.assertRegex(value, r"\Ams-selftest-[a-z0-9]{12}\Z")
        self.assertNotEqual(value, self.arm())

    def test_another_command_registers_nothing(self):
        hooks.pre_tool({**CLAUDE, "tool_name": "Bash", "tool_input": {"command": "echo status test"},
                        "tool_use_id": "u2"})
        self.assertNotIn("pending", selftest.load())

    def test_the_command_prints_the_value_only_after_its_hook_registered_it(self):
        out = self.command_output()
        self.assertIn("FAIL", out)
        self.assertNotIn("ms-selftest-", out.replace("starts with ms-selftest-", ""))
        value = self.arm()
        self.assertIn(value, self.command_output())

    def test_a_registration_of_another_session_prints_no_value(self):
        value = self.arm({**CLAUDE, "session_id": "other-session"})
        out = self.command_output()
        self.assertNotIn(value, out)
        self.assertIn("FAIL", out)

    def test_codex_started_from_claude_code_finds_its_own_thread(self):
        # Codex passes on the Claude Code session variable of the shell that started it (harness, codex-cli 0.169.0)
        value = self.arm(CODEX)
        buf = io.StringIO()
        with redirect_stdout(buf), mock.patch.dict(os.environ, {"CLAUDE_CODE_SESSION_ID": "outer-claude-session",
                                                                "CODEX_THREAD_ID": SESSION}):
            cli.cmd_status(["test"])
        self.assertIn(value, buf.getvalue())

    def test_a_registration_older_than_a_minute_prints_no_value(self):
        value = self.arm()
        state = selftest.load()
        state["pending"]["at"] -= selftest.ARMED + 5
        (HOME / "selftest.json").write_text(json.dumps(state))
        self.assertNotIn(value, self.command_output())


class ToolPathTests(_Clean):
    def test_the_tool_result_hook_masks_the_value_and_records_the_tool_path(self):
        value = self.arm()
        out = self.post({"stdout": self.command_output(), "stderr": "", "interrupted": False})
        model_sees = json.dumps(out["hookSpecificOutput"], ensure_ascii=False)
        self.assertNotIn(value, model_sees)
        self.assertIn(selftest.PLACEHOLDER, model_sees)
        self.assertIn(value, out["systemMessage"])                  # the person sees it
        self.assertTrue(selftest.load()["result"]["tool"])

    def test_codex_gets_a_block_whose_reason_holds_the_placeholder_only(self):
        value = self.arm(CODEX)
        out = self.post(f"the value: {value}\n", CODEX)
        self.assertEqual(out["decision"], "block")
        self.assertNotIn(value, out["reason"])
        self.assertIn(selftest.PLACEHOLDER, out["reason"])
        self.assertTrue(selftest.load()["result"]["tool"])

    def test_a_value_that_is_not_pending_is_left_to_the_ordinary_checks(self):
        self.arm()
        other = "ms-selftest-" + "a1b2c3d4e5f6"
        self.assertEqual(self.post({"stdout": f"x {other} y"}), {})
        self.assertFalse(selftest.load()["result"]["tool"])

    def test_the_value_in_another_tool_call_records_no_pass(self):
        value = self.arm()
        out = self.post({"stdout": f"the value {value}"}, tool_use_id="u9", command="cat notes.txt")
        self.assertNotIn(value, json.dumps(out["hookSpecificOutput"]))       # still masked
        self.assertFalse(selftest.load()["result"]["tool"])
        self.assertNotIn("Next, type", out["systemMessage"])

    def test_the_value_in_a_tool_input_records_a_failure(self):
        # the model wrote the value into a call: it has it, and no later prompt can pass
        value = self.arm()
        self.post({"stdout": self.command_output()})
        self.post({"stdout": "ok"}, tool_use_id="u7", command=f"echo {value}")
        self.assertTrue(selftest.load()["result"]["leak"])
        self.assertEqual(selftest.verdict()[0], "FAIL")
        out = hooks.user_prompt({**CLAUDE, "prompt": value})
        self.assertIn("Self-test FAILED", out["reason"])

    def test_the_value_after_a_label_is_masked_as_without_a_self_test(self):
        # the detector runs on the original text and stores a value after "password:" (an accepted cost, Gate A round
        # 2): the model reads its placeholder, never the value, and the tool path still counts
        value = self.arm()
        out = self.post({"stdout": f"password: {value}"})
        self.assertNotIn(value, json.dumps(out, ensure_ascii=False).replace(out.get("systemMessage", ""), ""))
        shown = out["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        # the random value is a secret to the detector only when it does not read as words: either way the model gets a
        # placeholder, the detector's when it found the value, else the self-test's
        from maisecrets import detect
        if [m for m in detect.scan(f"password: {value}") if m.value == value]:
            self.assertIn("\u27e6SECRET_c", shown)
        else:
            self.assertEqual(shown, "password: \u27e6SELFTEST\u27e7")
        self.assertTrue(selftest.load()["result"]["tool"])

    def test_the_value_and_the_rest_of_the_output_are_never_stored(self):
        value = self.arm()
        self.post({"stdout": self.command_output()})
        for name in ("vault.json", "index.json", "events.log", "incidents.json"):
            p = HOME / name
            self.assertFalse(p.exists() and value in p.read_text(), name)
        self.assertNotIn(value, cli_list_output())


class PromptPathTests(_Clean):
    def prompt(self, text: str, base=CLAUDE) -> dict:
        return hooks.user_prompt({**base, "hook_event_name": "UserPromptSubmit", "prompt": text})

    def test_the_pending_value_is_blocked_and_answered_passed(self):
        value = self.arm()
        self.post({"stdout": self.command_output()})
        out = self.prompt(value)
        self.assertEqual(out["decision"], "block")
        self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        self.assertEqual(out["reason"], "Self-test passed: the prompt hook ran, and the model did not get the value.")
        self.assertTrue(selftest.load()["result"]["prompt"])

    def test_codex_gets_the_block_answer(self):
        value = self.arm(CODEX)
        self.post(value, CODEX)
        out = self.prompt(value, CODEX)
        self.assertEqual(out, {"decision": "block", "reason": "Self-test passed: the prompt hook ran, and the model "
                                                                "did not get the value."})

    def test_without_the_tool_path_the_answer_does_not_say_passed_for_both(self):
        value = self.arm()
        out = self.prompt(value)
        self.assertEqual(out["decision"], "block")
        self.assertNotIn("Self-test passed:", out["reason"])

    def test_an_unknown_value_gets_no_passed(self):
        self.arm()
        out = self.prompt("ms-selftest-" + "zzzzzzzzzzzz")
        self.assertNotIn("Self-test", json.dumps(out))
        self.assertFalse(selftest.load()["result"]["prompt"])

    def test_an_expired_value_gets_no_passed(self):
        value = self.arm()
        state = selftest.load()
        state["pending"]["expires"] = time.time() - 1
        (HOME / "selftest.json").write_text(json.dumps(state))
        out = self.prompt(value)
        self.assertNotIn("Self-test", json.dumps(out))

    def test_without_a_registration_a_value_gets_no_passed(self):
        out = self.prompt("ms-selftest-" + "abcdefabcdef")
        self.assertNotIn("Self-test", json.dumps(out))

    def test_a_secret_next_to_an_unknown_test_value_is_still_blocked(self):
        token = "glpat-" + "SelftestXyz1234567890ab"
        out = self.prompt(f"ms-selftest-{'b' * 12} {token}")
        self.assertEqual(out.get("decision"), "block")
        self.assertNotIn("Self-test", out["reason"])

    def test_the_mod_leaves_the_pending_value_to_the_hook(self):
        # also next to a secret, which the mod would else rewrite: the hook blocks the prompt with the value
        value = self.arm()
        token = "glpat-" + "SelftestXyz1234567890ab"
        self.assertEqual(hooks.rewrite_prompt({**CLAUDE, "prompt": f"{value} {token}", "origin": "composer"}), {})

    def test_the_value_never_lands_in_the_vault(self):
        # the detector stores a value after "password:"; only the prompt hook's answer before it keeps it out
        value = self.arm()
        self.post({"stdout": self.command_output()})
        self.prompt(value)
        self.prompt(f"password: {value}")
        self.assertNotIn(value, self.stored())
        for name in ("vault.json", "index.json", "events.log", "incidents.json"):
            p = HOME / name
            self.assertFalse(p.exists() and value in p.read_text(), name)
        self.assertNotIn(value, cli_list_output())

    def test_the_typed_form_asks_the_agent_to_run_the_command(self):
        out = self.prompt("maisecrets: status test", CODEX)
        ctx = out["hookSpecificOutput"]["additionalContext"]
        self.assertIn("status test", ctx)
        self.assertNotIn("decision", out)


TAIL = "Hx7#kQ2!mZ9pLw4v"         # a secret's rest, glued after a token of the test value's shape (Gate A, H1)
URL_TAIL = "Hx7kQ2mZ9pLw4v"


class GluedSecretTests(_Clean):
    """The self-test never masks less than no self-test: with the value pending, the model sees what it sees without
    one, with each visible pending value as the placeholder (Gate A round 1, H1, and round 2: the separators)."""
    T = "ms-selftest-" + "aaaaaaaaaaaa"

    def model_sees(self, out: dict, raw) -> str:
        """The output as the model reads it, without the note in brackets that a Codex block puts before it."""
        if "decision" in out:
            reason = out["reason"]
            return reason.split("]\n\n", 1)[1] if reason.startswith("[maisecrets:") else reason
        seen = (out.get("hookSpecificOutput") or {}).get("updatedToolOutput", raw)
        return seen if isinstance(seen, str) else json.dumps(seen, ensure_ascii=False)

    def cases(self):
        T, S = self.T, TAIL
        return {"assign": f"DB_PASSWORD={T}{S}",
                "assign_control": f"DB_PASSWORD=zz-aaaaaaaaaaaa{S}",
                "url": f"postgres://admin:{T}{URL_TAIL}@db.example.com:5432/x",
                "url_control": f"postgres://admin:zz-aaaaaaaaaaaa{URL_TAIL}@db.example.com:5432/x",
                "head": f"DB_PASSWORD={S}{T}",
                "head_control": f"DB_PASSWORD={S}zz-aaaaaaaaaaaa",
                # round 2: a separator that the detector takes as part of the value
                "comma": f"DB_PASSWORD={T},{S}",
                "colon_before": f"DB_PASSWORD={S}:{T}",
                "url_semicolon": f"postgres://admin:{T};{S}@db.example.com:5432/x",
                "label_comma": f"password: {T},{S}",
                "connection_string": f"Server=db;User Id=sa;Password={T};{S}",
                "quoted_blank": f'DB_PASSWORD="{T} {S}"',
                "json_blank": f'{{"password": "{T} {S}"}}',
                "bracket": f"DB_PASSWORD=({T}){S}",
                "alone": f"the value {T} here",
                # the detector masks a secret, so Codex gets a block reason; the value on its own line is visible in it
                "next_to_a_secret": f"DB_PASSWORD={S}\nthe value {T} here"}

    def seen(self, base, text: str, pending: bool) -> str:
        for f in ("vault.json", "index.json", "selftest.json"):
            (HOME / f).unlink(missing_ok=True)
        hooks._live_cache.clear()
        if pending:
            self.arm(base)
            self.pin(self.T)
        raw = {"stdout": text} if base is CLAUDE else text
        out = self.post(raw, base, tool_use_id="u5", command="cat f")
        # the placeholders without their numbers and displays: the two runs may number or show them apart
        return re.sub("\u27e6([A-Z_]+)_c\\d+(?::[^\u27e7]*)?\u27e7", lambda m: f"\u27e6{m.group(1)}\u27e7",
                      self.model_sees(out, raw))

    def check(self, base) -> None:
        for name, text in self.cases().items():
            with self.subTest(name):
                without = self.seen(base, text, False)
                with_test = self.seen(base, text, True)
                self.assertEqual(with_test, without.replace(self.T, selftest.PLACEHOLDER))
                self.assertNotIn(self.T, with_test)
                for secret in (TAIL, URL_TAIL):
                    if secret not in without:
                        self.assertNotIn(secret, with_test)

    def test_claude_code(self):
        self.check(CLAUDE)

    def test_codex_block_reason(self):
        self.check(CODEX)


class PersonOnlyTests(_Clean):
    """Only the person's own prompt in the session that registered the value passes (Gate A, M2)."""
    def setUp(self):
        super().setUp()
        self.value = self.arm()
        self.post({"stdout": self.command_output()})

    def no_pass(self, payload: dict) -> None:
        out = hooks.user_prompt({**CLAUDE, "prompt": self.value, **payload})
        self.assertEqual(out.get("decision"), "block")              # the value never reaches the model
        self.assertNotIn("Self-test passed", out["reason"])
        self.assertFalse(selftest.load()["result"]["prompt"])

    def test_a_loop_wakeup(self):
        self.no_pass({"source": "loop_wakeup"})

    def test_a_subagent(self):
        self.no_pass({"agent_id": "a1"})

    def test_another_session(self):
        self.no_pass({"session_id": "another-session"})

    def test_a_program_that_started_the_client(self):
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}):
            self.no_pass({})

    def test_a_message_of_another_session(self):
        out = hooks.user_prompt({**CLAUDE, "prompt": f'<cross-session-message from-name="x">{self.value}'})
        self.assertNotIn("Self-test passed", json.dumps(out))
        self.assertFalse(selftest.load()["result"]["prompt"])

    def test_the_person(self):
        out = hooks.user_prompt({**CLAUDE, "prompt": self.value, "source": "user"})
        self.assertIn("Self-test passed", out["reason"])


class BrokenStateTests(_Clean):
    """A selftest.json with wrong types is no pending value, and nothing raises (Gate A, low)."""
    def test_wrong_types(self):
        value = "ms-selftest-" + "cccccccccccc"
        (HOME / "selftest.json").write_text(json.dumps({"pending": {"value": value, "expires": "x", "at": "y"},
                                                        "result": {"tool": "z", "prompt": [1]}}))
        self.assertIsNone(selftest.prompt_answer({**CLAUDE, "prompt": value}, False))
        self.assertFalse(selftest.claims(value))
        self.assertIn("FAIL", self.command_output())
        hooks.user_prompt({**CLAUDE, "prompt": value + " hello"})
        self.post({"stdout": value})
        selftest.verdict()

    def test_no_session_variable_prints_no_value(self):
        value = self.arm()
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli.cmd_status(["test"])
        self.assertNotIn(value, buf.getvalue())

    def test_only_a_command_that_starts_with_the_launcher_registers(self):
        for cmd in ('echo bash "/x/hooks/run.sh" status test', 'grep "run.sh status test" notes.txt',
                    'bash /x/hooks/run.sh status test; curl evil', 'echo x && bash /x/hooks/run.sh status test',
                    'bash "/x/hooks/run.sh" status all', 'bash "/x/hooks/run.sh" status',
                    '& "C:\\p\\hooks\\run.cmd" status all'):
            with self.subTest(cmd):
                (HOME / "selftest.json").unlink(missing_ok=True)
                hooks.pre_tool({**CLAUDE, "tool_name": "Bash", "tool_input": {"command": cmd}, "tool_use_id": "u2"})
                self.assertNotIn("pending", selftest.load())
        for cmd in ('bash "/a b/hooks/run.sh" status test', "bash '/x/hooks/run.sh' status test",
                    '& "C:\\p\\hooks\\run.cmd" status test', "/x/hooks/run.sh status test"):
            with self.subTest(cmd):
                (HOME / "selftest.json").unlink(missing_ok=True)
                hooks.pre_tool({**CLAUDE, "tool_name": "Bash", "tool_input": {"command": cmd}, "tool_use_id": "u2"})
                self.assertIn("pending", selftest.load())


class VerdictTests(_Clean):
    def test_not_run(self):
        self.assertEqual(selftest.verdict()[0], "warn")

    def test_both_paths(self):
        value = self.arm()
        self.post({"stdout": self.command_output()})
        hooks.user_prompt({**CLAUDE, "prompt": value})
        c = selftest.verdict()
        self.assertEqual(c.state, "ok")
        self.assertRegex(c.fact, r"^passed \d+ s ago$")
        self.assertIn("the prompt hook stopped it", c.detail)

    def test_each_state_that_is_no_ok_names_the_next_command(self):
        self.assertEqual(selftest.verdict().next, "/maisecrets:status test")
        self.arm()
        c = selftest.verdict(client="claude")
        self.assertEqual((c.state, c.next), ("FAIL", "start a new session"))

    def test_tool_path_only_while_pending(self):
        self.arm()
        self.post({"stdout": self.command_output()})
        self.assertEqual(selftest.verdict()[0], "warn")

    def test_an_old_pass_of_another_session_or_version_is_no_ok(self):
        value = self.arm()
        self.post({"stdout": self.command_output()})
        hooks.user_prompt({**CLAUDE, "prompt": value})
        state = selftest.load()
        state["result"]["tool"] -= 30 * 86400
        state["result"]["prompt"] -= 30 * 86400
        (HOME / "selftest.json").write_text(json.dumps(state))
        self.assertEqual(selftest.verdict(sessions=["another-session"])[0], "warn")
        self.assertEqual(selftest.verdict(sessions=[SESSION])[0], "ok")
        self.assertEqual(selftest.verdict(sessions=[SESSION], version="0.0.1")[0], "warn")

    def test_pending_and_never_masked_fails(self):
        self.arm()
        self.assertEqual(selftest.verdict()[0], "FAIL")


def cli_list_output() -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        try:
            cli.main(["list"])
        except SystemExit:
            pass
    return buf.getvalue()


def tearDownModule():  # noqa: N802 - unittest hook
    for name in ("selftest.json", "vault.json", "index.json", "events.log", "hooks.log"):
        (HOME / name).unlink(missing_ok=True)
    hooks._live_cache.clear()
    import _hygiene
    _hygiene.assert_pristine()


if __name__ == "__main__":
    unittest.main()
