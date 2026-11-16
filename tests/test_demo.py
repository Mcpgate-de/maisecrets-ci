"""/maisecrets:demo on|off (maisecrets/demo.py, #57): while the demo is on, every prompt of the session gets an answer
from maisecrets and never reaches the model; its values are stored as for a sent prompt; only the person's typed
prompt switches it (C22); only the exact forms of the person's own commands pass; a report passes only when it proves
itself (C19); the demo ends with off or with its session.

Synthetic values only; a placeholder is built from OPEN and CLOSE.
Run: python3 -m unittest tests.test_demo -v
"""
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

from maisecrets import demo, detect, events, hooks, settings, status_verdict as sv  # noqa: E402
from maisecrets.placeholder import CLOSE, OPEN  # noqa: E402
from maisecrets.vault import HOME, Vault, load_config  # noqa: E402
from test_remote_detector import NAME  # noqa: E402
from test_allow_list_name_service import _ServiceBase  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

CONFIG = Path(HOME, "config.json")
SESSION = "S-demo-1"
TOKEN = "glpat-" + "DEMOxxxxx1234567890abcd"         # split: the repository scan stays clean
MAIL = "jo.demo" + "@" + "demo-mail.de"              # not a reserved domain: those are no hit
PROMPT = f"please check the token {TOKEN} and write to {MAIL} today"
FILES = ("index.json", "vault.json", "audit.log", "events.log", "demo.json", "destinations.json", "ner.log",
         "terms.marked.json", "allow.txt", "allowed.json", "hints.json", ".weakenings-shown")
PENDING = Path(HOME, "pending")


def _reset(**user) -> None:
    CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True, **user}))
    for f in FILES:
        try:
            os.unlink(Path(HOME, f))
        except FileNotFoundError:
            pass
    for f in PENDING.glob("*.txt") if PENDING.exists() else []:
        f.unlink()
    hooks._live_cache.clear()
    detect.reset_rules()


def tearDownModule():  # noqa: N802 - unittest hook
    _reset()
    _hygiene.assert_pristine()


def _prompt(prompt: str, source: str | None = "user", client=CLAUDE, session=SESSION, **extra) -> dict:
    hooks._live_cache.clear()
    payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "session_id": session,
               "transcript_path": "", **client, **extra}
    if source is not None:
        payload["source"] = source
    return hooks.user_prompt(payload)


def _entries() -> dict:
    return Vault(load_config())._index["entries"]


def _ph(key: str) -> str:
    return f"{OPEN}{key}{CLOSE}"


def _is_demo(out: dict) -> bool:
    return out.get("decision") == "block" and out["reason"].startswith("maisecrets demo: nothing was sent to the AI.")


class _Base(unittest.TestCase):
    def setUp(self):
        _reset()
        self.addCleanup(_reset)
        self.copied: list = []
        _hygiene.patch(self, hooks, "_clipboard", lambda t: self.copied.append(t) or True)

    def on(self, session=SESSION, client=CLAUDE, source="user"):
        out = _prompt("/maisecrets:demo on" if client is CLAUDE else "maisecrets: demo on", source=source,
                      client=client, session=session)
        self.assertTrue(demo.active(session), out)
        return out


# ------------------------------------------------------------ switching it --
class SwitchTests(_Base):
    def test_on_and_off_by_the_persons_typed_prompt(self):
        out = self.on()
        self.assertEqual(out["decision"], "block")
        self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        self.assertIn("demo is on in this session", out["reason"])
        self.assertIn("A new session or /clear ends the demo.", out["reason"])
        out = _prompt("/maisecrets:demo off")
        self.assertIn("demo is off", out["reason"])
        self.assertFalse(demo.active(SESSION))
        self.assertFalse(demo.STATE.exists(), "off removes the state")
        lines = [json.loads(x) for x in events.EVENTS.read_text().splitlines()]
        self.assertEqual([x.get("demo") for x in lines], ["on", "off"])
        self.assertEqual(events.load(), [], "a switch is no detection event")

    def test_codex_typed_form(self):
        out = self.on(client=CODEX, source=None)
        self.assertEqual(set(out), {"decision", "reason"})
        self.assertIn("maisecrets: demo off to send again", out["reason"])
        _prompt("maisecrets: demo off", source=None, client=CODEX)
        self.assertFalse(demo.active(SESSION))

    def test_one_session_only(self):
        self.on()
        self.assertFalse(demo.active("S-other"))
        out = _prompt(PROMPT, session="S-other")
        self.assertFalse(_is_demo(out))

    def test_no_time_limit_and_it_ends_with_its_session(self):
        self.on()
        with mock.patch.object(demo.time, "time", return_value=4_000_000_000.0):
            self.assertTrue(demo.active(SESSION), "no time limit")
        demo.end_session("S-other")
        self.assertTrue(demo.active(SESSION))
        demo.end_session(SESSION)
        self.assertFalse(demo.active(SESSION))

    def test_the_session_end_hook_ends_the_demo(self):
        import subprocess
        self.on()
        demo._write({**demo._read(), "S-other": 1.0})
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "session-end"], text=True,
                           input=json.dumps({"session_id": SESSION, "hook_event_name": "SessionEnd"}),
                           capture_output=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(demo.active(SESSION))
        self.assertTrue(demo.active("S-other"), "another session keeps its demo")

    def test_the_demo_ends_at_session_end_when_another_step_fails(self):
        from maisecrets import session_end, vault, vault_refs
        for target, name in ((vault, "load_config"), (vault, "Vault"), (vault_refs, "end_session")):
            with self.subTest(failing=name):
                self.on()
                with mock.patch.object(target, name, side_effect=RuntimeError("down")):
                    ok = session_end.run({"session_id": SESSION})
                self.assertFalse(ok, "the failure is reported")
                self.assertFalse(demo.active(SESSION), "the demo ended all the same")
        self.on()
        self.assertTrue(session_end.run({"session_id": SESSION}))
        self.assertFalse(demo.active(SESSION))
        with mock.patch.object(demo, "end_session", side_effect=OSError("disk")):
            self.on()
            self.assertFalse(session_end.run({"session_id": SESSION}), "a failed demo step is reported too")

    def test_the_command_from_anywhere_but_the_persons_typed_prompt_changes_nothing(self):
        cases = {"a subagent": dict(agent_id="a1"), "a program": dict(source="sdk"),
                 "a scheduled task": dict(source="scheduled"), "a loop": dict(source="loop_wakeup"),
                 "a system prompt": dict(source="system")}
        for why, extra in cases.items():
            with self.subTest(why):
                source = extra.pop("source", "user")
                out = _prompt("/maisecrets:demo on", source=source, **extra)
                self.assertEqual(out["decision"], "block")
                self.assertIn("nothing was changed", out["reason"])
                self.assertFalse(demo.active(SESSION))
        with self.subTest("a client a program started (claude -p)"), \
                mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}):
            out = _prompt("/maisecrets:demo on", source=None)
            self.assertIn("came from a program", out["reason"])
            self.assertFalse(demo.active(SESSION))

    def test_a_program_cannot_switch_it_off_either(self):
        self.on()
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}):
            out = _prompt("/maisecrets:demo off", source=None)
        self.assertIn("nothing was changed", out["reason"])
        self.assertTrue(demo.active(SESSION))

    def test_a_subagent_prompt_is_refused_by_the_gate_itself(self):
        # guard 2 alone: demo.gate checks agent_id itself, also when typed_by_the_person says yes
        with mock.patch.object(settings, "typed_by_the_person", return_value=True):
            out = _prompt("/maisecrets:demo on", agent_id="a1")
        self.assertIn("nothing was changed", out["reason"])
        self.assertFalse(demo.active(SESSION))

    def test_a_message_of_another_session_is_no_command(self):
        wrapped = '<cross-session-message from-name="x">\n/maisecrets:demo on'
        self.assertIsNone(demo.parse(wrapped))
        _prompt(wrapped)
        self.assertFalse(demo.active(SESSION))
        with mock.patch.object(demo, "parse", return_value="on"):
            out = _prompt(wrapped)
        self.assertIn("came from another Claude session", out["reason"])
        self.assertFalse(demo.active(SESSION))

    def test_a_tool_call_that_carries_the_command_or_names_the_writer_is_refused(self):
        for command in ("codex exec 'maisecrets: demo off'",
                        'claude -p "/maisecrets:demo on"',
                        "claude -p \"/maisecrets:de\"'mo off'",
                        "python3 -c 'from maisecrets.demo import switch_typed'"):
            for tool in ("Bash", "PowerShell"):
                with self.subTest(command=command, tool=tool):
                    out = hooks.pre_tool({"tool_name": tool, "tool_input": {"command": command},
                                          "session_id": SESSION, **CLAUDE})
                    self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
                    self.assertIn("/maisecrets:demo", out["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertEqual(hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": "grep -n demo README.md"},
                                         "session_id": SESSION, **CLAUDE}), {})

    def test_the_command_without_a_word_shows_the_state(self):
        self.assertIn("off in this session", _prompt("/maisecrets:demo")["reason"])
        self.on()
        self.assertIn("on in this session", _prompt("/maisecrets:demo")["reason"])

    def test_parse(self):
        self.assertEqual(demo.parse("/maisecrets:demo on"), "on")
        self.assertEqual(demo.parse("  /maisecrets:demo OFF "), "off")
        self.assertEqual(demo.parse("maisecrets:demo on"), "on")
        self.assertEqual(demo.parse("/maisecrets:demo maybe"), "show")
        for other in ("please /maisecrets:demo on", "/maisecrets:demo on\nmore", "a demo of the page"):
            self.assertIsNone(demo.parse(other), other)


# ------------------------------------------------------------ the answer --
class DemoAnswerTests(_Base):
    def test_a_prompt_with_a_token_and_an_address_is_answered_and_its_values_are_stored(self):
        self.on()
        out = _prompt(PROMPT)
        self.assertTrue(_is_demo(out), out)
        self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        reason = out["reason"]
        self.assertIn("\nIt masks 1 secret, 1 e-mail address.\n", reason)
        self.assertIn(f"please check the token {_ph('SECRET_c1')} and write to {OPEN}EMAIL_c1:", reason)
        self.assertTrue(reason.endswith("\n\n/maisecrets:demo off to send again"), reason)
        for value in (TOKEN, MAIL, TOKEN[-8:]):
            self.assertNotIn(value, reason)
        # stored as for a sent prompt: the vault holds both values, with this session's keys
        self.assertEqual({e["type"] for e in _entries().values()}, {"SECRET", "EMAIL"})
        v = Vault(load_config())
        self.assertEqual(v.backend.get("SECRET_c1"), TOKEN)
        self.assertEqual(v.status("SECRET_c1", SESSION), "ok")
        self.assertEqual(self.copied, [reason.split("\n\n")[1]], "the clipboard gets the masked text")
        self.assertFalse(any(PENDING.glob("*.txt")) if PENDING.exists() else False, "no prompt is kept for /ms")

    def test_the_answer_says_this_and_nothing_else(self):
        self.on()
        lines = _prompt(f"see {TOKEN}")["reason"].split("\n")
        self.assertEqual(lines, ["maisecrets demo: nothing was sent to the AI.", "It masks 1 secret.", "",
                                 f"see {_ph('SECRET_c1')}", "", "/maisecrets:demo off to send again"])

    def test_codex_gets_the_answer_as_the_block_reason(self):
        self.on(client=CODEX, source=None)
        out = _prompt(PROMPT, source=None, client=CODEX)
        self.assertEqual(set(out), {"decision", "reason"})
        self.assertTrue(_is_demo(out))
        self.assertTrue(out["reason"].endswith("maisecrets: demo off to send again"))
        self.assertNotIn(TOKEN, out["reason"])

    def test_a_clean_prompt_is_answered_and_the_clipboard_is_left_alone(self):
        self.on()
        out = _prompt("what is the capital of France?")
        self.assertTrue(_is_demo(out))
        self.assertIn("It finds nothing to mask in this prompt.", out["reason"])
        self.assertIn("what is the capital of France?", out["reason"])
        self.assertEqual(self.copied, [])

    def test_a_placeholder_the_person_typed_is_no_finding(self):
        self.on()
        Vault(load_config()).put(TOKEN, "SECRET", "gitlab-pat", session=SESSION)
        out = _prompt(f"use {_ph('SECRET_c1')} again")
        self.assertIn("It finds nothing to mask", out["reason"])
        self.assertEqual(self.copied, [])

    def test_a_long_prompt_is_cut_after_20_lines(self):
        self.on()
        text = TOKEN + "\n" + "\n".join(f"row {i}" for i in range(44))
        reason = _prompt(text)["reason"]
        self.assertIn("row 18\n… 25 more lines\n", reason)
        self.assertNotIn("row 19", reason)
        self.assertIn("row 43", self.copied[0], "the clipboard gets the whole masked text")
        self.assertNotIn(TOKEN, self.copied[0])

    def test_a_very_long_line_is_cut_too(self):
        self.on()
        reason = _prompt("x" * 9000)["reason"]
        self.assertIn(f"… {9000 - demo.SHOWN_CHARS} more characters", reason)
        self.assertLess(len(reason), demo.SHOWN_CHARS + 1000)

    def test_a_marked_name_is_taken_only_from_the_persons_typed_prompt(self):
        self.on()
        reason = _prompt("write to {{Jan Demoquist}} today")["reason"]
        self.assertNotIn("Demoquist", reason)
        self.assertIn("1 name", reason)
        _reset()
        _prompt("/maisecrets:demo on")
        with mock.patch.object(demo, "own_command", return_value=False):
            out = _prompt("write to {{Jan Demoquist}} today", source="scheduled")
        self.assertTrue(_is_demo(out))
        self.assertFalse(Path(HOME, "terms.marked.json").exists(), "a prompt the person did not type marks no name")

    def test_the_transcript_on_disk_loses_the_values(self):
        self.on()
        transcript = Path(HOME).parent / "demo-transcript.jsonl"
        transcript.write_text(json.dumps({"type": "user", "message": PROMPT}) + "\n")
        self.addCleanup(transcript.unlink)
        with mock.patch.object(hooks, "_scrub_transcript_later"):
            _prompt(PROMPT, transcript_path=str(transcript))
        text = transcript.read_text()
        self.assertNotIn(TOKEN, text)
        self.assertNotIn(MAIL, text)

    def test_an_answer_that_fails_still_sends_nothing(self):
        self.on()
        with mock.patch.object(demo, "_hook_text", side_effect=ValueError("boom")):
            out = _prompt(PROMPT)
        self.assertTrue(_is_demo(out))
        self.assertIn("could not be built (ValueError)", out["reason"])
        self.assertNotIn(TOKEN, out["reason"])


# ------------------------------------------------------------ the mod --
class ModTests(_Base):
    def _mod(self, prompt: str, origin: str = "composer", session=SESSION) -> dict:
        hooks._live_cache.clear()
        return hooks.rewrite_prompt({"prompt": prompt, "session_id": session, "cwd": "", "origin": origin})

    def test_the_mod_drops_every_prompt_with_the_answer_and_stores_its_values(self):
        session = "0b6f1c2e-0000-4000-8000-000000000057"    # the mod rewrites only for a session id of its shape
        self.on(session=session)
        drop = self._mod(PROMPT + "\nsecond line", session=session)["drop"]
        self.assertTrue(drop.startswith("maisecrets demo: nothing was sent to the AI. It masks 1 secret, "
                                        "1 e-mail address. «please check the token "
                                        f"{_ph('SECRET_c1')}"), drop)
        self.assertIn("today ↵ second line» /maisecrets:demo off to send again", drop)
        self.assertNotIn("\n", drop, "the client prints a line break of a drop as a replacement character")
        self.assertNotIn(TOKEN, drop)
        self.assertEqual(Vault(load_config()).backend.get("SECRET_c1"), TOKEN, "stored as by a normal rewrite")
        self.assertEqual(len(self.copied), 1)

    def test_the_mod_leaves_commands_and_reports_to_the_hook(self):
        session = "0b6f1c2e-0000-4000-8000-000000000058"
        self.on(session=session)
        for prompt in ("maisecrets: demo off", "maisecrets: status", "maisecrets: set tips off",
                       "<task-notification>\n<status>completed</status>\n</task-notification>"):
            with self.subTest(prompt):
                self.assertEqual(self._mod(prompt, session=session), {})

    def test_an_own_command_from_claude_p_is_dropped(self):
        session = "0b6f1c2e-0000-4000-8000-00000000005c"
        self.on(session=session)
        self.assertEqual(self._mod("maisecrets: status", session=session), {})
        out = self._mod("maisecrets: status", origin="sdk", session=session)
        self.assertIn("maisecrets demo: nothing was sent to the AI.", out["drop"])
        out = self._mod("", session=session)
        self.assertIn("maisecrets demo: nothing was sent to the AI.", out["drop"], "an image alone in claude -p")

    def test_a_pasted_report_tag_inside_text_is_dropped(self):
        session = "0b6f1c2e-0000-4000-8000-000000000059"
        self.on(session=session)
        out = self._mod(f"here is my log <task-notification> {TOKEN}", session=session)
        self.assertIn("maisecrets demo: nothing was sent to the AI.", out["drop"])

    def test_the_transcript_of_a_dropped_fallback_prompt_is_scrubbed(self):
        # the mod gives no transcript path: the child finds the record by the session id, written after the drop
        import time
        session = "0b6f1c2e-0000-4000-8000-000000000060"
        self.on(session=session)
        prompt = f"here is my log <task-notification> {TOKEN}"
        out = self._mod(prompt, session=session)
        self.assertIn("maisecrets demo: nothing was sent to the AI.", out["drop"])
        folder = Path(os.environ["CLAUDE_CONFIG_DIR"]) / "projects" / "demo-scrub"
        folder.mkdir(parents=True, exist_ok=True)
        transcript = folder / f"{session}.jsonl"
        self.addCleanup(lambda: transcript.unlink(missing_ok=True))
        transcript.write_text(json.dumps({"type": "queue-operation", "content": prompt}) + "\n")
        def text():  # Windows locks the file while the child replaces it
            for _ in range(50):
                try:
                    return transcript.read_text()
                except PermissionError:
                    time.sleep(0.05)
            return transcript.read_text()

        for _ in range(100):
            if TOKEN not in text():
                break
            time.sleep(0.1)
        self.assertNotIn(TOKEN, text())

    def test_off_the_mod_rewrites_as_before(self):
        out = self._mod(PROMPT, session="0b6f1c2e-0000-4000-8000-00000000005a")
        self.assertIn("SECRET_c1", out.get("text", ""))


# ------------------------------------------------------------ what passes, and what does not --
class ExceptionTests(_Base):
    def test_the_persons_own_commands_keep_working(self):
        self.on()
        with self.subTest("a setting"):
            out = _prompt("maisecrets: set tips off")
            self.assertIn("Tips and hints is off", out["reason"])
        with self.subTest("ms:(…)"):
            out = _prompt(f"ms:({TOKEN})")
            self.assertFalse(_is_demo(out))
            self.assertIn("masks this", out["reason"])
        with self.subTest("a term"):
            self.assertFalse(_is_demo(_prompt("/maisecrets:term add Quentin Demoquist")))
        with self.subTest("not-a-secret"):
            self.assertIn("there is no stored value NAME_c99", _prompt("/maisecrets:not-a-secret NAME_c99")["reason"])
        for cmd in ("/maisecrets:status", "/maisecrets:status all", "/maisecrets:list", "/maisecrets:audit 5",
                    "/maisecrets:forget SECRET_c3", "/maisecrets:guard status", "/maisecrets:report last",
                    "maisecrets: status all"):
            with self.subTest(cmd):
                self.assertEqual(_prompt(cmd, source=None if cmd.startswith("maisecrets") else "user"), {})
        with self.subTest("off"):
            _prompt("/maisecrets:demo off")
            self.assertFalse(demo.active(SESSION))

    def test_an_own_command_passes_only_when_the_person_typed_it(self):
        self.on()
        cases = {"a subagent": dict(agent_id="a1"), "a program": dict(source="sdk"),
                 "a scheduled task": dict(source="schedule_wakeup"), "a loop": dict(source="loop_wakeup"),
                 "a system prompt": dict(source="system")}
        for why, extra in cases.items():
            for cmd in ("/maisecrets:status", "maisecrets: status all"):
                with self.subTest(why=why, cmd=cmd):
                    source = extra.get("source", "user")
                    out = _prompt(cmd, source=source, **{k: v for k, v in extra.items() if k != "source"})
                    self.assertTrue(_is_demo(out), out)
        with self.subTest("a client a program started (claude -p)"), \
                mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}):
            self.assertTrue(_is_demo(_prompt("/maisecrets:status", source=None)))
        # guard 2 alone: the gate checks agent_id itself, also when typed_by_the_person says yes
        with mock.patch.object(settings, "typed_by_the_person", return_value=True):
            self.assertTrue(_is_demo(_prompt("/maisecrets:status", agent_id="a1")))

    def test_an_image_alone_is_blocked_too(self):
        # the terminal gives "[Image #1]", claude -p "" (measured on 2.1.325); a missing field is blocked as well
        self.on()
        for prompt in ("[Image #1]", ""):
            with self.subTest(prompt=prompt):
                self.assertTrue(_is_demo(_prompt(prompt)))
        hooks._live_cache.clear()
        out = hooks.user_prompt({"hook_event_name": "UserPromptSubmit", "session_id": SESSION, "source": "user",
                                 "transcript_path": "", **CLAUDE})
        self.assertTrue(_is_demo(out), out)
        out = demo.gate({"session_id": SESSION, "prompt": None, **CLAUDE}, load_config(), True)
        self.assertTrue(_is_demo(out), out)
        self.assertIsNone(demo.gate({"session_id": "S-other", "prompt": None, **CLAUDE}, load_config(), True))

    def test_only_the_exact_forms_pass(self):
        self.on()
        for prompt in ("/maisecrets:madeup confidential plan", "/maisecrets:status please summarise the plan",
                       "/ms", "/ms the plan", "/maisecrets:send", "/maisecrets:demo on\nmore text",
                       "/maisecrets:report bug the plan", "maisecrets: status the plan", "maisecrets: list\nthe plan",
                       "maisecrets: put the plan", "/maisecrets:forget the plan"):
            with self.subTest(prompt):
                out = _prompt(prompt, source=None if prompt.startswith("maisecrets") else "user")
                self.assertTrue(_is_demo(out), out)

    def test_every_command_has_its_forms_or_is_left_out_on_purpose(self):
        names = {p.stem for p in (ROOT / "commands").glob("*.md")}
        self.assertEqual(names - set(demo.FORMS), set(demo.NOT_PASSED))
        self.assertTrue((ROOT / "skills" / "secret-hygiene" / "SKILL.md").exists())

    def test_ms_sends_nothing_during_the_demo(self):
        hooks._save_pending(f"an older blocked prompt {_ph('SECRET_c1')}", SESSION)
        self.on()
        out = _prompt("/ms")
        self.assertTrue(_is_demo(out))
        self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        _prompt(PROMPT)
        self.assertEqual(hooks.take_pending(SESSION), f"an older blocked prompt {_ph('SECRET_c1')}",
                         "the demo keeps no prompt of its own for /ms")

    def test_a_message_of_another_session_passes_only_when_the_client_marks_it(self):
        self.on()
        wrapped = f'<cross-session-message from-name="x">\nthe token is {TOKEN}'
        self.assertTrue(_is_demo(_prompt(wrapped)), "a header the person typed is the person's prompt")
        self.assertTrue(_is_demo(_prompt(wrapped, source=None)), "no source: it may be typed")
        out = _prompt(wrapped, source="peer")
        self.assertFalse(_is_demo(out))
        self.assertIn("x", out["reason"])

    def test_a_pasted_report_tag_gets_the_demo_answer(self):
        self.on()
        out = _prompt(f"here is my log <task-notification> {TOKEN}")
        self.assertTrue(_is_demo(out))

    def test_a_report_that_proves_itself_passes_before_the_gate(self):
        self.on()
        report = "<task-notification>\n<status>completed</status>\n</task-notification>"
        with mock.patch.object(hooks, "agent_report", return_value=True):
            self.assertEqual(_prompt(report), {})
        self.assertTrue(_is_demo(_prompt(report)), "a report that does not prove itself gets the demo answer")


# ------------------------------------------------------------ a damaged state fails closed --
class DamagedStateTests(_Base):
    """Only a missing demo.json means off. A file that cannot be read or holds another shape blocks the prompt of
    every session with a fixed answer, and /maisecrets:demo off, typed by the person, resets it (Gate A round 2)."""
    CASES = {"invalid JSON": "{not json", "a list": json.dumps([SESSION]),
             "a value that is no number": json.dumps({SESSION: "yes"}), "a bool": json.dumps({SESSION: True}),
             "an empty session id": json.dumps({"": 1.0}),
             "a session id that is too long": json.dumps({"s" * 129: 1.0}),
             "a time of zero": json.dumps({SESSION: 0}), "a negative time": json.dumps({SESSION: -5.0}),
             "NaN": '{"' + SESSION + '": NaN}', "Infinity": '{"' + SESSION + '": Infinity}',
             "-Infinity": '{"' + SESSION + '": -Infinity}', "a huge number that is inf": '{"' + SESSION + '": 1e999}'}

    def test_each_check_names_its_reason(self):
        # the parser refuses the constants itself; the shape check refuses an infinite number that the parser makes
        for text, why in (('{"S": NaN}', "json"), ('{"S": Infinity}', "json"), ('{"S": 1e999}', "shape"),
                          ('{"S": 0}', "shape"), ('{"": 1}', "shape")):
            with self.subTest(text):
                demo.STATE.write_text(text)
                with self.assertRaises(demo.Damaged) as cm:
                    demo._read()
                self.assertEqual(str(cm.exception), why)

    def test_the_longest_session_id_and_an_int_time_are_valid(self):
        demo.STATE.write_text(json.dumps({"s" * demo.SESSION_CHARS: 1, SESSION: 1.5}))
        self.assertFalse(demo.damaged())
        self.assertTrue(demo.active(SESSION))
    ANSWER = "maisecrets demo: the demo state cannot be read, so nothing was sent. /maisecrets:demo off resets it."

    def check_blocked_then_recovered(self, write):
        write()
        for session in (SESSION, "S-other"):
            out = _prompt(PROMPT, session=session)
            self.assertEqual(out.get("reason"), self.ANSWER, out)
        self.assertFalse(Path(HOME, "index.json").exists() and _entries(), "nothing was stored either")
        self.assertEqual(_prompt("/maisecrets:status"), {}, "the person's own status passes, and shows it")
        c = sv.demo_verdict([SESSION])
        self.assertEqual((c.state, c.fact), ("warn", "state unreadable"))
        self.assertEqual(_prompt("maisecrets: demo off", source=None, client=CODEX)["reason"].split(".")[0],
                         "maisecrets demo is off")

    def test_a_damaged_file_blocks_every_session_and_demo_off_resets_it(self):
        for why, text in self.CASES.items():
            with self.subTest(why):
                _reset()
                self.check_blocked_then_recovered(lambda: demo.STATE.write_text(text))
                self.assertFalse(demo.damaged())
                self.assertFalse(_is_demo(_prompt("what is the capital of France?")), "back to normal")

    def test_an_unreadable_file_blocks_too(self):
        demo.STATE.write_text(json.dumps({SESSION: 1.0}))
        with mock.patch.object(demo, "_text", side_effect=PermissionError("denied")):
            for session in (SESSION, "S-other"):
                self.assertEqual(_prompt(PROMPT, session=session).get("reason"), self.ANSWER)
            out = _prompt("/maisecrets:demo off")
            self.assertIn("it was reset", out["reason"])
        self.assertFalse(demo.STATE.exists(), "off removed the file it could not read")
        self.assertFalse(_is_demo(_prompt("what is the capital of France?")))

    def test_the_mod_drops_with_the_fixed_answer(self):
        demo.STATE.write_text("{not json")
        hooks._live_cache.clear()
        out = hooks.rewrite_prompt({"prompt": PROMPT, "session_id": "0b6f1c2e-0000-4000-8000-00000000005d",
                                    "cwd": "", "origin": "composer"})
        self.assertEqual(out, {"drop": self.ANSWER})

    REPORT = "<task-notification>\n<status>completed</status>\n</task-notification>"

    def test_a_verified_report_does_not_pass_a_damaged_state(self):
        def invalid_json():
            demo.STATE.write_text("{not json")
            return mock.patch.object(demo, "_text", wraps=demo._text)

        def unreadable():
            demo.STATE.write_text(json.dumps({SESSION: 1.0}))
            return mock.patch.object(demo, "_text", side_effect=PermissionError("denied"))
        session = "0b6f1c2e-0000-4000-8000-00000000005e"
        for why, damage in (("invalid JSON", invalid_json), ("PermissionError", unreadable)):
            with self.subTest(why), damage(), mock.patch.object(hooks, "agent_report", return_value=True):
                self.assertEqual(_prompt(self.REPORT).get("reason"), self.ANSWER, "the hook path")
                hooks._live_cache.clear()
                out = hooks.rewrite_prompt({"prompt": self.REPORT, "session_id": session, "cwd": "",
                                            "origin": "composer"})
                self.assertEqual(out, {"drop": self.ANSWER}, "the mod path")
                wrapped = '<cross-session-message from-name="x">\nhello'
                self.assertEqual(_prompt(wrapped, source="peer").get("reason"), self.ANSWER, "a peer message")
                self.assertEqual(_prompt("/maisecrets:status"), {}, "the person's typed own command passes")
            _reset()

    def test_a_verified_report_passes_a_healthy_demo(self):
        self.on()
        with mock.patch.object(hooks, "agent_report", return_value=True):
            self.assertEqual(_prompt(self.REPORT), {})
        session = "0b6f1c2e-0000-4000-8000-00000000005f"
        self.on(session=session)
        hooks._live_cache.clear()
        self.assertEqual(hooks.rewrite_prompt({"prompt": self.REPORT, "session_id": session, "cwd": "",
                                               "origin": "composer"}), {})

    def test_on_from_another_session_does_not_reset_a_damaged_state(self):
        demo.STATE.write_text("{not json")
        out = _prompt("/maisecrets:demo on", session="S-B")
        self.assertEqual(out["reason"], self.ANSWER)
        self.assertEqual(demo.STATE.read_text(), "{not json", "the damaged file stays")
        self.assertEqual(_prompt(PROMPT, session="S-A").get("reason"), self.ANSWER, "A's prompt is still blocked")
        self.assertIn("it was reset", _prompt("/maisecrets:demo off", session="S-B")["reason"])
        self.assertFalse(_is_demo(_prompt("what is the capital of France?", session="S-A")))

    def test_a_program_cannot_reset_it(self):
        demo.STATE.write_text("{not json")
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}):
            out = _prompt("/maisecrets:demo off", source=None)
        self.assertIn("nothing was changed", out["reason"])
        self.assertTrue(demo.damaged())

    def test_a_missing_file_is_off_and_session_end_leaves_a_damaged_one(self):
        self.assertFalse(demo.STATE.exists())
        self.assertFalse(demo.active(SESSION))
        demo.STATE.write_text("{not json")
        demo.end_session(SESSION)
        self.assertTrue(demo.damaged(), "only the person's off resets it")


# ------------------------------------------------------------ the status --
class StatusTests(_Base):
    def test_a_warn_line_while_on_and_nothing_while_off(self):
        self.assertIsNone(sv.demo_verdict([SESSION]))
        self.on()
        c = sv.demo_verdict([SESSION])
        self.assertEqual((c.state, c.name, c.fact, c.next), ("warn", "demo", "on, none sent to AI",
                                                             "/maisecrets:demo off"))
        self.assertLessEqual(len(c.fact), sv.FACT_COL)
        line = sv.check_lines([c], "claude")[0]
        self.assertEqual(line, " ! demo        " + "on, none sent to AI".ljust(sv.FACT_COL)
                         + "  →  /maisecrets:demo off")
        self.assertTrue(sv.check_lines([c], "codex")[0].endswith("→  maisecrets: demo off"))
        ok = [sv.Check("ok", n, "x", None, None) for n in sv.NAMES]
        self.assertTrue(sv.head_line("0.9.13", ok + [c], "claude").startswith("\U0001F512"), "a warn, not a FAIL")

    def test_the_report_adds_it(self):
        self.on()
        with mock.patch("maisecrets.selftest.sessions_of_this_command", return_value=[SESSION]):
            rep = sv.report(ROOT, Path(HOME, "no-claude"), Path(HOME, "no-codex"))
        self.assertEqual(rep["checks"][-1].name, "demo")


# ------------------------------------------------------------ the name service, in the mod's rewrite --
class NameServiceTests(_ServiceBase):
    SESSION = "0b6f1c2e-0000-4000-8000-00000000005b"

    def setUp(self):
        super().setUp()
        _hygiene.patch(self, hooks, "_clipboard", lambda t: True)
        demo._write({self.SESSION: 1.0})
        self.addCleanup(demo._write, {})

    def _mod(self, origin="composer"):
        hooks._live_cache.clear()
        return hooks.rewrite_prompt({"prompt": f"please ask {NAME} today", "session_id": self.SESSION, "cwd": "",
                                     "origin": origin})

    def test_the_name_service_takes_part(self):
        self.on()
        drop = self._mod()["drop"]
        self.assertIn(f"please ask {OPEN}NAME_c", drop)
        self.assertNotIn(NAME, drop)

    def _network(self, prompts: bool):
        cfg = json.loads(CONFIG.read_text())
        cfg["remote_detector"] = {"url": "https://names.invalid/v1", "format": "hf", "model": "fake@1",
                                  **({"prompts": True} if prompts else {})}
        CONFIG.write_text(json.dumps(cfg))
        with mock.patch("maisecrets.remote_layer.prepare", return_value=None) as asked:
            out = self._mod()
        self.assertIn("maisecrets demo", out["drop"])
        return asked

    def test_a_network_source_gets_the_prompt_only_with_prompts_on(self):
        self._network(False).assert_not_called()
        self._network(True).assert_called_once()


if __name__ == "__main__":
    unittest.main()
