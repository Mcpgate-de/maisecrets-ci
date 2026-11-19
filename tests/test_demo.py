"""/maisecrets:demo on (maisecrets/demo.py, #57): in a session in the demo each prompt takes the normal way of a prompt
(its values stored, placeholders in place of them), and in Claude Code the mod lets the masked prompt enter and answers
each model step itself, so no request goes out. Where the mod did not let the prompt enter, the prompt hook blocks it
with the same line. Only the person's typed prompt switches it on (C22), and only in a session with no turn yet; it
ends only with /clear (a new session id): `off` and SessionEnd change nothing. A damaged state fails closed.

Synthetic values only; a placeholder is built from OPEN and CLOSE.
Run: python3 -m unittest tests.test_demo -v
"""
from __future__ import annotations

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

from maisecrets import demo, detect, events, hooks, session_end, settings, status_verdict as sv  # noqa: E402
from maisecrets.placeholder import CLOSE, OPEN  # noqa: E402
from maisecrets.vault import HOME, Vault, load_config  # noqa: E402
from test_remote_detector import NAME  # noqa: E402
from test_allow_list_name_service import _ServiceBase  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

CONFIG = Path(HOME, "config.json")
SESSION = "S-demo-1"
UUID = "0b6f1c2e-0000-4000-8000-0000000000{:02x}"     # the mod rewrites only for a session id of this shape
TOKEN = "glpat-" + "DEMOxxxxx1234567890abcd"         # split: the repository scan stays clean
MAIL = "jo.demo" + "@" + "demo-mail.de"              # not a reserved domain: those are no hit
PROMPT = f"please check the token {TOKEN} and write to {MAIL} today"
FILES = ("index.json", "vault.json", "audit.log", "events.log", "demo.json", "destinations.json", "ner.log",
         "terms.marked.json", "allow.txt", "allowed.json", "hints.json", ".weakenings-shown")
PENDING = Path(HOME, "pending")
LINE = "Demo mode: nothing was sent to the AI. /clear to switch it off."
LINE_CODEX = "Demo mode: nothing was sent to the AI. A new session switches it off."
ON = ("Demo mode is on: what you send stays here, no prompt goes to the AI. /clear switches it off. If an "
      "organization manages this Claude Code, /compact and side requests (a title by /rename, /btw, /recap, "
      "suggestions) can still go to the AI, with placeholders only; an administrator stops them by installing "
      "maisecrets as the organization's own plugin.")


def _reset(**user) -> None:
    CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True, **user}))
    for f in FILES:
        try:
            os.unlink(Path(HOME, f))
        except FileNotFoundError:
            pass
    for d in (PENDING, demo.PASS_DIR):
        for f in (list(d.glob("*")) if d.exists() else []):
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


def _mod(prompt: str, session: str, origin: str = "composer") -> dict:
    hooks._live_cache.clear()
    return hooks.rewrite_prompt({"prompt": prompt, "session_id": session, "cwd": "", "origin": origin})


def _entries() -> dict:
    return Vault(load_config())._index["entries"]


def _on_windows_too(fn, seconds: float = 2.0, swallow: bool = False):
    """fn(), again for up to `seconds` while Windows refuses the file (WinError 32): the scrub child replaces the
    transcript while a test touches it. `swallow`: a cleanup that still fails at the end is left alone."""
    end = time.monotonic() + seconds
    while True:
        try:
            return fn()
        except PermissionError:
            if time.monotonic() >= end:
                if swallow:
                    return None
                raise
            time.sleep(0.05)


def _ph(key: str) -> str:
    return f"{OPEN}{key}{CLOSE}"


def _is_demo(out: dict, line: str = LINE) -> bool:
    return out.get("decision") == "block" and out.get("reason") == line


def _transcript(tmp: Path, *records) -> str:
    path = tmp / "transcript.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    return str(path)


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

    def tmp(self) -> Path:
        import tempfile
        d = Path(tempfile.mkdtemp(prefix="demo-tx-"))
        self.addCleanup(lambda: [p.unlink() for p in d.glob("*")] and None or d.rmdir())
        return d



# ------------------------------------------------------------ `/maisecrets demo on`, with a space --
class SpacedCommandTests(_Base):
    """Without the mod (Codex, claude -p, a client without mods) the prompt hook sees `/maisecrets demo on` as text: it
    keeps it from the AI and names the form that runs it. It changes nothing (prompt_commands.spaced_answer); with the
    mod, the person's own prompt runs as the colon form (tests/mod.test.ts)."""

    def test_a_known_command_with_a_space_is_kept_from_the_ai_with_the_colon_form(self):
        for typed, form in (("/maisecrets demo on", "/maisecrets:demo on"),
                            ("  /maisecrets Status all ", "/maisecrets:status all"),
                            ("/maisecrets not-a-secret SECRET_c1", "/maisecrets:not-a-secret SECRET_c1"),
                            ("/maisecrets settings rehydration confirm", "/maisecrets:settings rehydration confirm")):
            for source in ("user", None, "cron"):
                out = _prompt(typed, source=source)
                self.assertEqual(out["decision"], "block", typed)
                self.assertEqual(out["reason"], f"maisecrets: send {form} with the colon to run it. This prompt was "
                                                "not sent to the AI.")
                self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        self.assertFalse(demo.active(SESSION), "the space form switches nothing")
        self.assertEqual(load_config().get("rehydration", "automatic"), "automatic", "and changes no setting")

    def test_codex_gets_its_own_form(self):
        out = _prompt("/maisecrets demo on", source=None, client=CODEX)
        self.assertEqual(out, {"decision": "block", "reason": "maisecrets: in Codex, send maisecrets: demo on. This "
                                                             "prompt was not sent to the AI."})
        self.assertFalse(demo.active(SESSION))

    def test_other_prompts_keep_their_way(self):
        for typed in ("/maisecrets", "/maisecrets wibble on", "/maisecrets secret-hygiene",
                      "/maisecrets-demo on", "please run /maisecrets demo on", "/maisecrets demo on\nand more"):
            out = _prompt(typed)
            self.assertNotEqual(out.get("decision"), "block", typed)

    def test_a_value_in_it_is_blocked_as_a_value(self):
        out = _prompt(f"/maisecrets settings rehydration {TOKEN}")
        self.assertEqual(out["decision"], "block")
        self.assertNotIn("with the colon", out["reason"])
        self.assertNotIn(TOKEN, json.dumps(out))


class FillCheckTests(_Base):
    """The mod's value check of a command it puts into the input box (prompt_commands.fill_check, Gate A of !591): the
    colon form with each value masked and stored, the transcript record scrubbed later; no command runs."""

    def test_a_value_in_a_command_the_mod_fills_is_masked_and_stored(self):
        session = UUID.format(7)
        out = _mod_fill(f"/maisecrets:status {TOKEN}", session)
        self.assertEqual(out["count"], 1)
        self.assertNotIn(TOKEN, json.dumps(out))
        self.assertTrue(out["masked"].startswith("/maisecrets:status " + OPEN + "SECRET_c"), out)
        self.assertTrue(any(e["session"] == session for e in _entries().values()), "stored for this session")

    def test_a_command_with_no_value_comes_back_as_it_is_and_runs_nothing(self):
        session = UUID.format(8)
        for text in ("/maisecrets:status all", "/maisecrets:demo on", "/maisecrets:settings rehydration block"):
            self.assertEqual(_mod_fill(text, session), {"masked": text, "count": 0})
        self.assertFalse(demo.active(session), "the demo was not switched")
        self.assertEqual(load_config().get("rehydration", "automatic"), "automatic", "no setting changed")

    def test_no_answer_for_another_text_or_a_session_of_another_shape(self):
        for text, session in ((f"status {TOKEN}", UUID.format(9)), (f"/maisecrets:status {TOKEN}", "a b/c"),
                              ("/maisecrets:status a\nb", UUID.format(9))):
            self.assertEqual(_mod_fill(text, session), {})
        self.assertEqual(_entries(), {}, "nothing stored")


def _mod_fill(prompt: str, session: str) -> dict:
    hooks._live_cache.clear()
    return hooks.rewrite_prompt({"prompt": prompt, "session_id": session, "cwd": "", "origin": "composer",
                                 "fill_check": True})

# ------------------------------------------------------------ switching it on --
class SwitchTests(_Base):
    def test_on_by_the_persons_typed_prompt(self):
        out = self.on()
        self.assertEqual(out["decision"], "block")
        self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        self.assertEqual(out["reason"], ON)
        self.assertEqual([json.loads(x).get("demo") for x in events.EVENTS.read_text().splitlines()], ["on"])
        self.assertEqual(events.load(), [], "a switch is no detection event")
        self.assertEqual(_prompt("/maisecrets:demo on")["reason"], ON, "on again says it is on")
        self.assertEqual(len(events.EVENTS.read_text().splitlines()), 1, "and changes nothing")

    def test_off_changes_nothing(self):
        self.on()
        out = _prompt("/maisecrets:demo off")
        self.assertEqual(out["reason"], "The demo ends with /clear: it starts a new conversation, so the demo lines do "
                                        "not go to the AI.")
        self.assertTrue(demo.active(SESSION))
        self.assertEqual(len(events.EVENTS.read_text().splitlines()), 1, "no events line for off")

    def test_codex_typed_form(self):
        out = self.on(client=CODEX, source=None)
        self.assertEqual(set(out), {"decision", "reason"})
        self.assertEqual(out["reason"], "Demo mode is on: what you send stays here, nothing goes to the AI. A new "
                                        "session switches it off.")
        out = _prompt("maisecrets: demo off", source=None, client=CODEX)
        self.assertIn("a new session", out["reason"])
        self.assertTrue(demo.active(SESSION))

    def test_only_in_a_session_with_no_turn_yet(self):
        tmp = self.tmp()
        not_first = "Start the demo in a new session (or after /clear), so this conversation stays as it is."
        cases = {
            "Claude Code, an answer": ([{"type": "user", "message": {"role": "user", "content": "hi"}},
                                        {"type": "assistant", "message": {"role": "assistant", "content": "ho"}}],
                                       CLAUDE, "user", not_first),
            "Codex, an answer": ([{"type": "session_meta", "payload": {}},
                                  {"type": "response_item", "payload": {"type": "message", "role": "user"}},
                                  {"type": "response_item", "payload": {"type": "message", "role": "assistant"}}],
                                 CODEX, None, "Start the demo in a new session, so this conversation stays as it is."),
        }
        for why, (records, client, source, answer) in cases.items():
            with self.subTest(why):
                cmd = "/maisecrets:demo on" if client is CLAUDE else "maisecrets: demo on"
                out = _prompt(cmd, source=source, client=client, transcript_path=_transcript(tmp, *records))
                self.assertEqual(out["reason"], answer)
                self.assertFalse(demo.active(SESSION))
        # measured: a new session has no transcript yet (Claude Code), or one with no answer (Codex; and the /clear
        # command's own records in Claude Code)
        free = {"no file": str(tmp / "missing.jsonl"),
                "a /clear record": _transcript(tmp, {"type": "user", "isMeta": True, "message": {"role": "user"}},
                                               {"type": "user", "message": {"role": "user", "content": "/clear"}}),
                "Codex, a new thread": _transcript(tmp, {"type": "session_meta", "payload": {}}, {
                    "type": "response_item", "payload": {"type": "message", "role": "user"}})}
        for why, path in free.items():
            with self.subTest(why):
                _reset()
                self.assertEqual(_prompt("/maisecrets:demo on", transcript_path=path)["reason"], ON)
                self.assertTrue(demo.active(SESSION))

    def test_it_does_not_end_with_the_session_and_no_entry_is_swept(self):
        self.on()
        self.assertTrue(session_end.run({"session_id": SESSION}))
        self.assertTrue(demo.active(SESSION), "a resumed session stays in the demo")
        demo._write({"S-old": time.time() - 400 * 86400})
        self.on(session="S-new")
        self.assertEqual(set(demo._read()), {"S-old", "S-new"})

    def test_the_command_from_anywhere_but_the_persons_typed_prompt_changes_nothing(self):
        cases = {"a subagent": dict(agent_id="a1"), "a program": dict(source="sdk"),
                 "a scheduled task": dict(source="scheduled"), "a loop": dict(source="loop_wakeup"),
                 "a system prompt": dict(source="system")}
        for why, extra in cases.items():
            with self.subTest(why):
                source = extra.pop("source", "user")
                out = _prompt("/maisecrets:demo on", source=source, **extra)
                self.assertIn("nothing was changed", out["reason"])
                self.assertFalse(demo.active(SESSION))
        with self.subTest("a client a program started (claude -p)"), \
                mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}):
            out = _prompt("/maisecrets:demo on", source=None)
            self.assertIn("came from a program", out["reason"])
            self.assertFalse(demo.active(SESSION))

    def test_a_subagent_prompt_is_refused_by_the_gate_itself(self):
        with mock.patch.object(settings, "typed_by_the_person", return_value=True):
            out = _prompt("/maisecrets:demo on", agent_id="a1")
        self.assertIn("nothing was changed", out["reason"])
        self.assertFalse(demo.active(SESSION))

    def test_a_message_of_another_session_is_no_command(self):
        wrapped = '<cross-session-message from-name="x">\n/maisecrets:demo on'
        self.assertIsNone(demo.parse(wrapped))
        with mock.patch.object(demo, "parse", return_value="on"):
            out = _prompt(wrapped)
        self.assertIn("came from another Claude session", out["reason"])
        self.assertFalse(demo.active(SESSION))

    def test_a_tool_call_that_carries_the_command_or_names_the_writer_is_refused(self):
        for command in ("codex exec 'maisecrets: demo on'", 'claude -p "/maisecrets:demo on"',
                        "claude -p \"/maisecrets:de\"'mo on'", "python3 -c 'from maisecrets.demo import switch_typed'",
                        "python3 -c 'import maisecrets.demo as d; d._write({})'",
                        "python3 -c 'from maisecrets import demo; demo._write({})'",
                        "cd maisecrets && python3 -c 'import demo'",
                        "python3 -c 'from maisecrets import hooks, demo'",
                        "python3 -c 'x._write_pass(\"S\", \"t\")'",
                        "echo '{}' | python3 hooks/dispatch.py mod-demo",
                        "echo '{}' | python3 hooks/dispatch.py mod-prompt"):
            for tool in ("Bash", "PowerShell"):
                with self.subTest(command=command, tool=tool):
                    out = hooks.pre_tool({"tool_name": tool, "tool_input": {"command": command},
                                          "session_id": SESSION, **CLAUDE})
                    self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": "grep -n demo README.md"},
                                         "session_id": SESSION, **CLAUDE}), {})

    def test_the_command_without_a_word_shows_the_state(self):
        self.assertIn("Demo mode is off in this session", _prompt("/maisecrets:demo")["reason"])
        self.on()
        self.assertEqual(_prompt("/maisecrets:demo")["reason"], ON)

    def test_parse(self):
        self.assertEqual(demo.parse("/maisecrets:demo on"), "on")
        self.assertEqual(demo.parse("  /maisecrets:demo OFF "), "off")
        self.assertEqual(demo.parse("maisecrets:demo on"), "on")
        self.assertEqual(demo.parse("/maisecrets:demo maybe"), "show")
        for other in ("please /maisecrets:demo on", "/maisecrets:demo on\nmore", "a demo of the page"):
            self.assertIsNone(demo.parse(other), other)


# ------------------------------------------------------------ the mod lets it enter, the hook blocks the rest --
class EnterTests(_Base):
    def test_the_mod_lets_the_masked_prompt_enter_and_the_hook_passes_that_text_once(self):
        session = UUID.format(1)
        self.on(session=session)
        out = _mod(PROMPT, session)
        self.assertTrue(out["demo"])
        self.assertIn(f"please check the token {_ph('SECRET_c1')} and write to {OPEN}EMAIL_c1:", out["text"])
        self.assertNotIn(TOKEN, out["text"])
        self.assertEqual(Vault(load_config()).backend.get("SECRET_c1"), TOKEN, "stored as by a normal rewrite")
        self.assertNotIn("decision", _prompt(out["text"], session=session), "the prompt hook lets the text enter")
        self.assertTrue(_is_demo(_prompt(out["text"], session=session)), "once: the same text again is blocked")

    def test_the_entered_prompt_gets_a_title_and_a_forged_pass_lets_no_value_in(self):
        session = UUID.format(14)
        self.on(session=session)
        out = _mod(PROMPT, session)
        titled = {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "sessionTitle": "maisecrets demo"}}
        self.assertEqual(_prompt(out["text"], session=session), titled, "a title: the client asks the AI for none")
        demo._write_pass(session, PROMPT)            # a pass that a program wrote for a text with values
        self.assertTrue(_is_demo(_prompt(PROMPT, session=session)), "a text with a value never enters by a pass")

    def test_a_clean_prompt_enters_too(self):
        session = UUID.format(2)
        self.on(session=session)
        out = _mod("what is the capital of France?", session)
        self.assertEqual((out["text"], out["demo"]), ("what is the capital of France?", True))
        self.assertNotIn("decision", _prompt(out["text"], session=session))

    def test_a_prompt_the_mod_did_not_see_is_blocked_and_its_values_stored(self):
        self.on()
        out = _prompt(PROMPT)
        self.assertTrue(_is_demo(out), out)
        self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        self.assertEqual({e["type"] for e in _entries().values()}, {"SECRET", "EMAIL"}, "as for a sent prompt")
        self.assertNotIn(TOKEN, json.dumps(out))
        self.assertFalse(any(PENDING.glob("*.txt")) if PENDING.exists() else False, "nothing for /ms")

    def test_another_text_or_an_old_pass_is_blocked(self):
        session = UUID.format(3)
        self.on(session=session)
        out = _mod(PROMPT, session)
        self.assertTrue(_is_demo(_prompt(out["text"] + " and more", session=session)), "another text")
        out = _mod(PROMPT, session)
        with mock.patch.object(demo.time, "time", return_value=time.time() + demo.PASS_SECONDS + 5):
            self.assertTrue(_is_demo(_prompt(out["text"], session=session)), "an old pass")
        out = _mod(PROMPT, session)
        self.on(session=UUID.format(4))
        self.assertTrue(_is_demo(_prompt(out["text"], session=UUID.format(4))), "another session")

    def test_codex_blocks_with_its_line(self):
        self.on(client=CODEX, source=None)
        out = _prompt(PROMPT, source=None, client=CODEX)
        self.assertEqual(out, {"decision": "block", "reason": LINE_CODEX})

    def test_a_pass_never_opens_codex(self):
        session = UUID.format(5)
        self.on(session=session, client=CODEX, source=None)
        demo._write_pass(session, "hello")
        self.assertEqual(_prompt("hello", source=None, client=CODEX, session=session)["reason"], LINE_CODEX)

    def test_the_mod_leaves_commands_and_reports_to_the_hook(self):
        session = UUID.format(6)
        self.on(session=session)
        self.assertEqual(_mod("<task-notification>\n<status>completed</status>\n</task-notification>", session), {})
        # the person's own commands: the mod drops them with the hook's own answer (prompt_commands.mod_command), so
        # none reads as a block and none reaches the model
        self.assertEqual(_mod("maisecrets: demo off", session), {"drop": demo.OFF})
        self.assertIn("drop", _mod("maisecrets: set tips off", session))

    def test_an_own_command_from_claude_p_enters_masked_as_any_prompt(self):
        session = UUID.format(7)
        self.on(session=session)
        out = _mod("maisecrets: status", session, origin="sdk")
        self.assertTrue(out["demo"])

    def test_a_mention_is_left_to_the_hook(self):
        session = UUID.format(8)
        self.on(session=session)
        self.assertEqual(_mod("look at @notes.txt", session), {})

    def test_off_the_mod_rewrites_as_before(self):
        out = _mod(PROMPT, UUID.format(9))
        self.assertIn("SECRET_c1", out.get("text", ""))
        self.assertNotIn("demo", out)

    def test_the_mods_question_at_a_model_step(self):
        session = UUID.format(10)
        self.assertEqual(demo.mod_demo({"session_id": session}), {"demo": False})
        self.on(session=session)
        self.assertEqual(demo.mod_demo({"session_id": session}), {"demo": True})
        demo.STATE.write_text("{not json")
        self.assertEqual(demo.mod_demo({"session_id": "S-any"}), {"demo": True, "damaged": True},
                         "a damaged state: every session, and the mod keeps no true of it")

    def test_the_dispatcher_answers_in_demo_and_the_step_question(self):
        import subprocess
        session = UUID.format(11)
        self.on(session=session)
        for cmd, payload, want in (
                ("mod-demo", {"session_id": session}, {"maisecrets": "mod-demo", "demo": True}),
                ("mod-prompt", {"prompt": "hello", "session_id": session, "cwd": "", "origin": "composer"},
                 {"maisecrets": "mod-prompt", "text": "hello", "count": 0, "demo": True, "inDemo": True,
                  "masked": "", "namesUnchecked": True}),
                ("mod-prompt", {"prompt": "hello", "session_id": UUID.format(12), "cwd": "", "origin": "composer"},
                 {"maisecrets": "mod-prompt", "inDemo": False})):
            with self.subTest(cmd=cmd, payload=payload):
                r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), cmd], text=True,
                                   input=json.dumps(payload), capture_output=True, timeout=60)
                self.assertEqual(json.loads(r.stdout), want, r.stderr)

    def test_the_transcript_of_an_entered_prompt_loses_the_typed_values(self):
        # the client's own record of the typed text, written after the mod returned: the child finds it by the id
        session = UUID.format(13)
        self.on(session=session)
        out = _mod(PROMPT, session)
        self.assertNotIn(TOKEN, out["text"])
        folder = Path(os.environ["CLAUDE_CONFIG_DIR"]) / "projects" / "demo-scrub"
        folder.mkdir(parents=True, exist_ok=True)
        transcript = folder / f"{session}.jsonl"
        self.addCleanup(lambda: _on_windows_too(lambda: transcript.unlink(missing_ok=True), swallow=True))
        record = json.dumps({"type": "queue-operation", "content": PROMPT}) + "\n"
        _on_windows_too(lambda: transcript.write_text(record))
        for _ in range(100):
            if TOKEN not in _on_windows_too(transcript.read_text):
                break
            time.sleep(0.1)
        self.assertNotIn(TOKEN, _on_windows_too(transcript.read_text))


# ------------------------------------------------------------ what passes, and what does not --
class ExceptionTests(_Base):
    def test_the_persons_own_commands_keep_working(self):
        self.on()
        with self.subTest("a setting"):
            self.assertIn("Tips and hints is off", _prompt("maisecrets: set tips off")["reason"])
        with self.subTest("ms:(…)"):
            self.assertIn("masks this", _prompt(f"ms:({TOKEN})")["reason"])
        with self.subTest("a term"):
            self.assertFalse(_is_demo(_prompt("/maisecrets:term add Quentin Demoquist")))
        with self.subTest("not-a-secret"):
            self.assertIn("there is no stored value NAME_c99", _prompt("/maisecrets:not-a-secret NAME_c99")["reason"])
        for cmd in ("/maisecrets:status", "/maisecrets:status all", "/maisecrets:list", "/maisecrets:audit 5",
                    "/maisecrets:forget SECRET_c3", "/maisecrets:guard status", "/maisecrets:report last",
                    "maisecrets: status all"):
            with self.subTest(cmd):
                self.assertEqual(_prompt(cmd, source=None if cmd.startswith("maisecrets") else "user"), {})

    def test_an_own_command_passes_only_when_the_person_typed_it(self):
        self.on()
        cases = {"a subagent": dict(agent_id="a1"), "a program": dict(source="sdk"),
                 "a scheduled task": dict(source="schedule_wakeup"), "a loop": dict(source="loop_wakeup"),
                 "a system prompt": dict(source="system")}
        for why, extra in cases.items():
            with self.subTest(why=why):
                source = extra.get("source", "user")
                out = _prompt("/maisecrets:status", source=source, **{k: v for k, v in extra.items() if k != "source"})
                self.assertTrue(_is_demo(out), out)
        with mock.patch.object(settings, "typed_by_the_person", return_value=True):
            self.assertTrue(_is_demo(_prompt("/maisecrets:status", agent_id="a1")))

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

    def test_an_image_alone_is_blocked_too(self):
        self.on()
        for prompt in ("[Image #1]", ""):
            with self.subTest(prompt=prompt):
                self.assertTrue(_is_demo(_prompt(prompt)))
        out = demo.gate({"session_id": SESSION, "prompt": None, **CLAUDE}, load_config(), True)
        self.assertTrue(_is_demo(out), out)

    def test_a_message_of_another_session_passes_only_when_the_client_marks_it(self):
        self.on()
        wrapped = f'<cross-session-message from-name="x">\nthe token is {TOKEN}'
        self.assertTrue(_is_demo(_prompt(wrapped)))
        self.assertTrue(_is_demo(_prompt(wrapped, source=None)))
        self.assertFalse(_is_demo(_prompt(wrapped, source="peer")))

    def test_a_report_that_proves_itself_passes_and_a_pasted_tag_does_not(self):
        self.on()
        report = "<task-notification>\n<status>completed</status>\n</task-notification>"
        with mock.patch.object(hooks, "agent_report", return_value=True):
            self.assertEqual(_prompt(report), {})
        self.assertTrue(_is_demo(_prompt(report)))
        self.assertTrue(_is_demo(_prompt(f"here is my log <task-notification> {TOKEN}")))

    def test_an_answer_that_fails_still_sends_nothing(self):
        self.on()
        with mock.patch.object(demo, "_hook_text", side_effect=ValueError("boom")):
            self.assertTrue(_is_demo(_prompt(PROMPT)))


# ------------------------------------------------------------ a damaged state fails closed --
class DamagedStateTests(_Base):
    CASES = {"invalid JSON": "{not json", "a list": json.dumps([SESSION]),
             "a value that is no number": json.dumps({SESSION: "yes"}), "a bool": json.dumps({SESSION: True}),
             "an empty session id": json.dumps({"": 1.0}),
             "a session id that is too long": json.dumps({"s" * 129: 1.0}),
             "a time of zero": json.dumps({SESSION: 0}), "a negative time": json.dumps({SESSION: -5.0}),
             "NaN": '{"' + SESSION + '": NaN}', "Infinity": '{"' + SESSION + '": Infinity}',
             "-Infinity": '{"' + SESSION + '": -Infinity}', "a huge number that is inf": '{"' + SESSION + '": 1e999}'}
    ANSWER = "Demo mode: the demo state cannot be read, so nothing was sent. /maisecrets:demo off resets it."
    RESET = ("Demo mode: its state could not be read, so it was reset. A session with demo lines stays in the demo "
             "until /clear; a session that had only switched it on is out of it.")

    def test_a_damaged_file_blocks_every_session_and_demo_off_resets_it(self):
        for why, text in self.CASES.items():
            with self.subTest(why):
                _reset()
                demo.STATE.write_text(text)
                for session in (SESSION, "S-other"):
                    self.assertEqual(_prompt(PROMPT, session=session).get("reason"), self.ANSWER)
                self.assertEqual(_prompt("/maisecrets:status"), {}, "the person's own status passes")
                self.assertEqual(sv.demo_verdict([SESSION]).fact, "state unreadable")
                self.assertEqual(_prompt("/maisecrets:demo off")["reason"], self.RESET)
                self.assertFalse(demo.damaged())
                self.assertFalse(_is_demo(_prompt("what is the capital of France?")), "back to normal")

    def test_the_longest_session_id_and_an_int_time_are_valid(self):
        demo.STATE.write_text(json.dumps({"s" * demo.SESSION_CHARS: 1, SESSION: 1.5}))
        self.assertFalse(demo.damaged())
        self.assertTrue(demo.active(SESSION))

    def test_each_check_names_its_reason(self):
        for text, why in (('{"S": NaN}', "json"), ('{"S": Infinity}', "json"), ('{"S": 1e999}', "shape"),
                          ('{"S": 0}', "shape"), ('{"": 1}', "shape")):
            with self.subTest(text):
                demo.STATE.write_text(text)
                with self.assertRaises(demo.Damaged) as cm:
                    demo._read()
                self.assertEqual(str(cm.exception), why)

    def test_an_unreadable_file_blocks_too(self):
        demo.STATE.write_text(json.dumps({SESSION: 1.0}))
        with mock.patch.object(demo, "_text", side_effect=PermissionError("denied")):
            for session in (SESSION, "S-other"):
                self.assertEqual(_prompt(PROMPT, session=session).get("reason"), self.ANSWER)
            self.assertEqual(_prompt("/maisecrets:demo off")["reason"], self.RESET)
        self.assertFalse(demo.STATE.exists())

    def test_on_does_not_reset_a_damaged_state(self):
        demo.STATE.write_text("{not json")
        self.assertEqual(_prompt("/maisecrets:demo on", session="S-B")["reason"], self.ANSWER)
        self.assertEqual(demo.STATE.read_text(), "{not json")
        self.assertEqual(_prompt(PROMPT, session="S-A").get("reason"), self.ANSWER)

    def test_the_mod_drops_with_the_fixed_answer_and_passes_no_report(self):
        demo.STATE.write_text("{not json")
        self.assertEqual(_mod(PROMPT, UUID.format(20)), {"drop": self.ANSWER})
        report = "<task-notification>\n<status>completed</status>\n</task-notification>"
        with mock.patch.object(hooks, "agent_report", return_value=True):
            self.assertEqual(_prompt(report).get("reason"), self.ANSWER)
            self.assertEqual(_mod(report, UUID.format(21)), {"drop": self.ANSWER})

    def test_a_program_cannot_reset_it_and_session_end_leaves_it(self):
        demo.STATE.write_text("{not json")
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}):
            self.assertIn("nothing was changed", _prompt("/maisecrets:demo off", source=None)["reason"])
        session_end.run({"session_id": SESSION})
        self.assertTrue(demo.damaged())


# ------------------------------------------------------------ the transcript is the lasting truth --
def _demo_answer_record() -> dict:
    # the shape Claude Code 2.1.326 writes for a step a hook answered without a request
    return {"type": "assistant", "answeredWithoutRequest": True,
            "message": {"id": "msg_hook_0b6f1c2e", "role": "assistant", "content": [{"type": "text", "text": LINE}]}}


class TranscriptTruthTests(_Base):
    """A session whose transcript holds the mod's demo answer is in the demo, whatever demo.json says (Gate A of the
    demo turn: the sweep and a damaged-state reset freed sessions with demo rows)."""

    def transcript(self, *records) -> str:
        return _transcript(self.tmp(), {"type": "user", "message": {"role": "user", "content": "hi"}}, *records)

    def test_a_resumed_session_with_demo_rows_stays_in_the_demo_without_any_entry(self):
        path = self.transcript(_demo_answer_record())
        self.assertFalse(demo.STATE.exists())
        out = _prompt(PROMPT, transcript_path=path)
        self.assertTrue(_is_demo(out), "a session with a demo answer is in the demo, also after an entry went")
        self.assertTrue(demo.active(SESSION, path))

    def test_demo_on_in_a_session_with_demo_rows_says_it_is_on(self):
        path = self.transcript(_demo_answer_record())
        self.assertEqual(_prompt("/maisecrets:demo on", transcript_path=path)["reason"], ON)

    def test_a_damaged_reset_leaves_a_session_with_demo_rows_blocked(self):
        path = self.transcript(_demo_answer_record())
        demo.STATE.write_text("{not json")
        self.assertIn("it was reset", _prompt("/maisecrets:demo off", session="S-other")["reason"])
        self.assertTrue(_is_demo(_prompt(PROMPT, transcript_path=path)), "its demo rows keep it in the demo")
        self.assertFalse(_is_demo(_prompt("what is the capital of France?", session="S-new")), "/clear: a new one")

    def test_the_line_counts_only_as_the_mods_answer(self):
        user = {"type": "user", "origin": "assistant", "message": {"role": "user", "content": LINE}}
        for record in (user, {"type": "assistant", "message": {"content": [{"type": "text", "text": LINE + " "}]}}):
            with self.subTest(record=record["type"]):
                _reset()
                self.assertFalse(demo.active(SESSION, self.transcript(record)), "a pasted line is no demo answer")
        made = {"type": "assistant", "answeredWithoutRequest": True, "message": {"id": "msg_hook_1", "content": LINE}}
        self.assertTrue(demo.active(SESSION, self.transcript(made)))
        # the model writes the sentence: an API answer (its own id, no answeredWithoutRequest) is no demo answer
        for model in ({"type": "assistant", "message": {"id": "msg_01AbC", "content": LINE}},
                      {"type": "assistant", "answeredWithoutRequest": True, "message": {"id": "msg_01AbC",
                                                                                       "content": LINE}},
                      {"type": "assistant", "message": {"id": "msg_hook_1", "content": LINE}}):
            with self.subTest(model=model):
                _reset()
                self.assertFalse(demo.active(SESSION, self.transcript(model)))

    def test_a_transcript_that_cannot_be_read_counts_as_one_with_demo_rows(self):
        path = self.transcript()
        with mock.patch("builtins.open", side_effect=PermissionError("denied")):
            self.assertTrue(demo.has_demo_rows(SESSION, path))
        with mock.patch("os.stat", side_effect=PermissionError("denied")):
            self.assertTrue(demo.has_demo_rows(SESSION, path))
        self.assertFalse(demo.has_demo_rows(SESSION, path + ".missing"), "no file: no demo row")

    def test_the_last_answer_tells_and_rows_after_it_do_not_matter(self):
        demo_row = _demo_answer_record()
        tool_only = {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Bash", "input": {}}]}}
        real = {"type": "assistant", "message": {"content": [{"type": "text", "text": "a real answer"}]}}
        system = {"type": "system", "content": "hook ran"}
        user = {"type": "user", "message": {"role": "user", "content": "more"}}
        cases = {"a demo row last": ([real, demo_row, user, system], True),
                 "rows of other kinds after it": ([demo_row, system, user, {"type": "attachment"}], True),
                 "a tool-call record without text after it": ([demo_row, tool_only], True),
                 "a real answer last (no demo session)": ([demo_row, real], False),
                 "no answer at all": ([user, system], False)}
        for why, (records, want) in cases.items():
            with self.subTest(why):
                self.assertEqual(demo.has_demo_rows(SESSION, self.transcript(*records)), want)

    def test_the_tail_widens_until_it_holds_an_answer(self):
        big = {"type": "user", "message": {"role": "user", "content": "y" * (300 * 1024)}}
        self.assertTrue(demo.has_demo_rows(SESSION, self.transcript(_demo_answer_record(), big, big)),
                        "the answer stands 600 KB before the end")
        self.assertFalse(demo.has_demo_rows(SESSION, self.transcript(big, big)))

    def test_a_half_written_last_line_is_skipped(self):
        path = self.transcript(_demo_answer_record())
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"type": "assistant", "message": {"content": "a real"}})[:25])
        self.assertTrue(demo.has_demo_rows(SESSION, path))

    def test_the_mod_path_finds_the_transcript_by_the_session_id(self):
        session = UUID.format(40)
        folder = Path(os.environ["CLAUDE_CONFIG_DIR"]) / "projects" / "demo-truth"
        folder.mkdir(parents=True, exist_ok=True)
        transcript = folder / f"{session}.jsonl"
        _on_windows_too(lambda: transcript.write_text(json.dumps(_demo_answer_record()) + "\n"))
        self.addCleanup(lambda: _on_windows_too(lambda: transcript.unlink(missing_ok=True), swallow=True))
        self.assertEqual(demo.mod_demo({"session_id": session}), {"demo": True})
        self.assertTrue(_mod(PROMPT, session)["demo"])

    def test_the_cost_on_a_50_mb_transcript(self):
        path = Path(self.tmp()) / "big.jsonl"
        row = json.dumps({"type": "user", "message": {"role": "user", "content": "x" * 900}}) + "\n"
        answer = json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": "ok"}]}}) + "\n"
        block = row * 20 + answer
        with open(path, "w", encoding="utf-8") as f:
            f.write(block * (50 * 1024 * 1024 // len(block)))
            f.write(json.dumps(_demo_answer_record()) + "\n")
        times = []
        for _ in range(5):
            t0 = time.perf_counter()
            self.assertTrue(demo.has_demo_rows(SESSION, str(path)))
            times.append(time.perf_counter() - t0)
        print(f"\n  demo check on a 50 MB transcript: {min(times) * 1000:.2f} ms (best of 5), "
              f"{max(times) * 1000:.2f} ms (worst)", file=sys.stderr)
        self.assertLess(min(times), 0.005)


# ------------------------------------------------------------ the status --
class StatusTests(_Base):
    def test_a_warn_line_while_on_and_nothing_while_off(self):
        self.assertIsNone(sv.demo_verdict([SESSION]))
        self.on()
        c = sv.demo_verdict([SESSION])
        self.assertEqual((c.state, c.name, c.fact), ("warn", "demo", "on, none sent to AI"))
        self.assertLessEqual(len(c.fact), sv.FACT_COL)
        ok = [sv.Check("ok", n, "x", None, None) for n in sv.NAMES]
        self.assertTrue(sv.head_line("0.9.14", ok + [c], "claude").startswith("\U0001F512"), "a warn, not a FAIL")


# ------------------------------------------------------------ the name service, in the mod's rewrite --
class NameServiceTests(_ServiceBase):
    def setUp(self):
        super().setUp()
        _hygiene.patch(self, hooks, "_clipboard", lambda t: True)
        self.session = UUID.format(30)
        demo._write({self.session: time.time()})
        self.addCleanup(demo._write, {})

    def test_the_name_service_takes_part(self):
        self.on()
        out = _mod(f"please ask {NAME} today", self.session)
        self.assertIn(f"please ask {OPEN}NAME_c", out["text"])
        self.assertNotIn(NAME, out["text"])
        self.assertEqual((out["masked"], out["namesUnchecked"]), ("masked: 1 name", False), "the service read it")

    def _network(self, **old):
        cfg = json.loads(CONFIG.read_text())
        cfg["remote_detector"] = {"url": "https://names.invalid/v1", "format": "hf", "model": "fake@1", **old}
        CONFIG.write_text(json.dumps(cfg))
        with mock.patch("maisecrets.remote_layer.prepare", return_value=None) as asked:
            out = _mod(f"please ask {NAME} today", self.session)
        self.assertTrue(out["demo"])
        return asked

    def test_a_network_source_gets_the_prompt_with_no_switch(self):
        # the demo of 2026-11-17: a gateway source found no name in a prompt, because prompts needed a switch
        self._network().assert_called_once()
        # `"prompts": false` of an older version in the person's own file stops it no more (only a policy does)
        self._network(prompts=False).assert_called_once()



# ------------------------------------------------------------ the UX test of 2026-11-17 --
class NightFindingsTests(_Base):
    def test_off_in_a_session_not_in_the_demo_says_it_is_off(self):
        out = _prompt("/maisecrets:demo off")
        self.assertEqual(out["reason"], "Demo mode is off in this session. Nothing was changed.")
        self.assertFalse(demo.active(SESSION))
        self.on()
        self.assertIn("The demo ends with /clear", _prompt("/maisecrets:demo off")["reason"], "on: as before")

    def test_the_demo_line_says_what_was_masked_and_that_names_were_not_checked(self):
        session = UUID.format(31)
        self.on(session=session)
        out = _mod(PROMPT, session)
        self.assertEqual((out["masked"], out["namesUnchecked"]), ("masked: 1 secret, 1 e-mail", True))
        out = _mod(f"again {_ph('SECRET_c1')} and nothing new", session)
        self.assertEqual(out["masked"], "", "a placeholder the person typed is no new mask")

    def test_own_commands_run_without_the_model_in_the_demo(self):
        session = UUID.format(32)
        self.on(session=session)
        Vault(load_config()).put("demo-own-" + "value-for-the-forget-test", "SECRET", "manual")
        listed = demo.mod_demo({"session_id": session, "prompt": "/maisecrets:list", "origin": "composer"})
        self.assertTrue(listed["demo"])
        self.assertIn("SECRET_c1", listed["drop"])
        self.assertNotIn("value-for-the-forget-test", listed["drop"])
        out = demo.mod_demo({"session_id": session, "prompt": "/maisecrets:forget SECRET_c1", "origin": "composer"})
        self.assertIn("Deleted SECRET_c1", out["drop"])
        self.assertEqual(_entries(), {}, "the value is gone, not only the demo line")
        status = demo.mod_demo({"session_id": session, "prompt": "/maisecrets:status", "origin": "composer"})
        self.assertNotEqual(status["drop"], LINE)
        self.assertIn("demo", status["drop"].lower())
        self.assertIn("did not run in the demo",
                      demo.mod_demo({"session_id": session, "prompt": "/maisecrets:status test",
                                     "origin": "composer"})["drop"])
        self.assertIn("did not run in the demo", _mod("maisecrets: report last", session)["drop"])

    def test_own_commands_outside_the_demo_or_not_typed_get_no_answer_here(self):
        session = UUID.format(33)
        self.assertEqual(demo.mod_demo({"session_id": session, "prompt": "/maisecrets:list", "origin": "composer"}),
                         {"demo": False})
        self.on(session=session)
        for prompt, origin in (("/maisecrets:list", "sdk"), ("/maisecrets:demo off", "composer"),
                               ("/maisecrets:settings tips off", "composer"), ("/maisecrets:list words", "composer")):
            with self.subTest(prompt=prompt, origin=origin):
                self.assertEqual(demo.mod_demo({"session_id": session, "prompt": prompt, "origin": origin}),
                                 {"demo": True})

    def test_own_commands_that_probe_a_service_send_no_text_of_the_demo(self):
        # status, ner and sref status may ask the person's name service or gateway whether it answers; what they
        # send is fixed, never a prompt of the demo (docs/USING.md, the demo)
        import http.client
        session = UUID.format(35)
        cfg = json.loads(CONFIG.read_text())
        cfg["remote_detector"] = {"url": "http://127.0.0.1:9/v1", "format": "hf", "model": "fake@1"}
        CONFIG.write_text(json.dumps(cfg))
        self.on(session=session)
        _mod(PROMPT, session)
        sent: list = []

        def record(conn, method, url, body=None, headers=None, **_kw):
            sent.append(f"{method} {conn.host}{url} {body!r} {headers!r}")
            raise OSError("no network in this test")

        with mock.patch.object(http.client.HTTPConnection, "request", record):
            for cmd in ("/maisecrets:status", "/maisecrets:ner", "/maisecrets:sref status"):
                demo.own_answer(cmd, session)
        self.assertTrue(sent, "the name service was asked: the check below is not empty")
        for line in sent:
            for text in (TOKEN, MAIL, "please check the token", "write to"):
                self.assertNotIn(text, line)

    def test_in_the_demo_shortcut_runs_only_its_status(self):
        self.assertEqual(demo.own_argv("/maisecrets:shortcut status"), ["shortcut", "status"])
        for form in ("/maisecrets:shortcut", "/maisecrets:shortcut my-command", "/maisecrets:shortcut --remove",
                     "/maisecrets:shortcut remove"):
            with self.subTest(form):
                self.assertIsNone(demo.own_argv(form), "an install or a remove waits for the end of the demo")

    def test_a_damaged_state_says_so_to_the_mod(self):
        demo.STATE.write_text("{not json")
        self.assertEqual(demo.mod_demo({"session_id": SESSION, "prompt": "/maisecrets:list", "origin": "composer"}),
                         {"demo": True, "damaged": True})
        import subprocess
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "mod-prompt"], text=True,
                           input=json.dumps({"prompt": "hello", "session_id": UUID.format(34), "cwd": "",
                                             "origin": "composer"}), capture_output=True, timeout=60)
        self.assertEqual(json.loads(r.stdout).get("damaged"), True, "the prompt's answer says it too")

    def test_a_settings_change_in_the_demo_is_answered_by_the_hook(self):
        self.on()
        out = _prompt("/maisecrets:settings tips off")
        self.assertEqual(out.get("decision"), "block", "it waits for no model turn, which the demo answers")
        self.assertIn("Tips and hints is off", out["reason"])
        out = _prompt("/maisecrets:settings tips on", session="S-not-in-demo")
        self.assertNotIn("decision", out, "out of the demo the command runs on as before")


if __name__ == "__main__":
    unittest.main()
