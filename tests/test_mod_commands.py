"""The person's own maisecrets commands in Claude Code with the mod (prompt_commands.mod_command), and ms:(value)
inside a prompt (check_value.inline_marks, prompt_commands.take_inline). Night UX test of 2026-11-18, findings C, D
and F:

- C: a command that the prompt hook answers (term add, not-a-secret, demo on, the incident report) read as "operation
  blocked by hook", and the client put the typed text back into the box. The mod now drops it with the hook's own
  answer (claude-mod/maisecrets-mod.mjs, tests/mod.test.ts). The pending self-test value is not one of them: the real
  prompt hook stops it, so its pass proves that hook ran.
- F: each Codex form `maisecrets: NAME` is answered in Claude Code too; none goes to the AI.
- D: ms:(value) inside a prompt stores the value, and its placeholder stands in its place.

Synthetic values only; a placeholder is built from OPEN and CLOSE.
Run: python3 -m unittest tests.test_mod_commands -v
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import check_value, demo, hooks, selftest  # noqa: E402
from maisecrets.placeholder import CLOSE, OPEN  # noqa: E402
from maisecrets.vault import HOME, Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CODEX  # noqa: E402

CONFIG = Path(HOME, "config.json")
SESSION = "0b6f1c2e-0000-4000-8000-0000000000a1"      # the mod rewrites only for a session id of this shape
NAME = "Bertolt" + " Quastenberg"                       # a synthetic person
PASSWORD = "Kx7-" + "plmQ29zr"                          # no detector shape: found only as a mark or when stored
KEY = "SECRET" + "_c1"
REF = OPEN + KEY + CLOSE
FILES = ("index.json", "vault.json", "audit.log", "events.log", "demo.json", "terms.txt", "terms.marked.json",
         "allow.txt", "allowed.json", "hints.json", selftest.FILE)


def _reset() -> None:
    CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))
    for f in FILES:
        Path(HOME, f).unlink(missing_ok=True)
    for d in (Path(HOME, "pending"), demo.PASS_DIR):
        for f in (list(d.glob("*")) if d.exists() else []):
            f.unlink()
    hooks._live_cache.clear()


def tearDownModule():  # noqa: N802 - unittest hook
    _reset()
    _hygiene.assert_pristine()


def _mod(prompt: str, origin: str | None = "composer", session: str = SESSION) -> dict:
    hooks._live_cache.clear()
    return hooks.rewrite_prompt({"prompt": prompt, "session_id": session, "cwd": "", "origin": origin})


class _Base(unittest.TestCase):
    def setUp(self):
        _reset()
        self.addCleanup(_reset)
        # a prompt counts as typed: no entry point of a program that started the client; an empty client config folder
        self.claude_dir = tempfile.mkdtemp(prefix="ms-claude-config-")
        env = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": self.claude_dir})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("CLAUDE_CODE_ENTRYPOINT", None)
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)
        _hygiene.patch(self, hooks, "_scrub_transcript_later", lambda *a, **k: None)


class HookCommandTests(_Base):
    """C: what the prompt hook answers comes back as the mod's drop, with the hook's own text."""

    def test_a_term_add_is_dropped_with_the_hook_answer_and_the_term_is_added(self):
        out = _mod(f"/maisecrets:term add {NAME}")
        self.assertIn("on your list now", out.get("drop", ""))
        self.assertNotIn("text", out)
        self.assertNotIn(NAME, out["drop"], "the answer names a label, never the term")
        masked = _mod(f"write to {NAME} today")
        self.assertNotIn(NAME, masked.get("text", NAME))

    def test_the_codex_form_of_term_add_is_dropped_too(self):
        self.assertIn("on your list now", _mod(f"maisecrets: term add {NAME}").get("drop", ""))

    def test_demo_on_in_a_new_session_is_dropped_and_switches_it_on(self):
        self.assertEqual(_mod("/maisecrets:demo on"), {"drop": demo.ON})
        self.assertTrue(demo.active(SESSION))

    def test_demo_on_after_a_turn_is_refused_the_transcript_is_found_by_the_session(self):
        folder = Path(self.claude_dir, "projects", "work")
        folder.mkdir(parents=True)
        Path(folder, SESSION + ".jsonl").write_text(json.dumps(
            {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": "hi"}]}})
            + "\n")
        self.assertEqual(_mod("maisecrets: demo on"), {"drop": demo.NOT_FIRST})
        self.assertFalse(demo.active(SESSION))

    def test_not_a_secret_is_dropped_with_the_hook_answer(self):
        Vault().put(PASSWORD, "SECRET", "manual", session=SESSION)
        out = _mod("/maisecrets:not-a-secret " + KEY)
        self.assertTrue(out.get("drop", "").startswith("maisecrets: "), out)
        self.assertNotIn(PASSWORD, out["drop"])

    def test_the_pending_selftest_value_goes_on_to_the_real_prompt_hook(self):
        # its pass proves that the UserPromptSubmit hook ran: the mod never answers it, also inside a command (Gate A)
        value = selftest.PREFIX + "abcdefghij12"
        now = time.time()
        selftest._save({"pending": {"value": value, "at": now, "expires": now + 60, "session": SESSION},
                        "result": {"started": now, "tool": now}})
        for prompt in (value, f"maisecrets: term add {value}"):
            with self.subTest(prompt):
                self.assertEqual(_mod(prompt), {})
        self.assertFalse(selftest.load()["result"].get("prompt"))

    def test_the_incident_report_is_dropped(self):
        out = _mod("/maisecrets:report incident")
        self.assertTrue(out.get("drop", "").startswith("maisecrets"), out)

    def test_a_settings_change_in_the_codex_form_is_dropped(self):
        out = _mod("maisecrets: set ssh_consent on")
        self.assertEqual(out, {"drop": "maisecrets: SSH consent is on (set by you)."})
        self.assertTrue(json.loads(CONFIG.read_text(encoding="utf-8")).get("ssh_consent"))

    def test_a_prompt_the_person_did_not_type_keeps_the_hook_path(self):
        for origin in ("sdk", None):
            with self.subTest(origin):
                self.assertEqual(_mod(f"/maisecrets:term add {NAME}", origin=origin), {})


class CodexFormTests(_Base):
    """F: each Codex form gets an answer in Claude Code, and none goes on to the AI."""

    def test_maisecrets_list_runs_without_the_model(self):
        self.assertEqual(_mod("maisecrets: list"), {"drop": "Nothing is stored."})

    def test_every_command_of_the_codex_form_table_is_answered(self):
        names = sorted(set(demo.FORMS) | set(demo.NOT_PASSED))
        with mock.patch.object(demo, "own_answer", lambda prompt, session: "ran: " + prompt):
            for name in names:
                with self.subTest(name):
                    out = _mod(f"maisecrets: {name}")
                    self.assertIsInstance(out.get("drop"), str, out)
                    self.assertNotIn("text", out)

    def test_a_form_that_needs_the_model_puts_its_slash_form_into_the_box(self):
        out = _mod("maisecrets: status test")
        self.assertEqual(out.get("fill"), "/maisecrets:status test")
        self.assertIn("/maisecrets:status test", out["drop"])

    def test_another_word_after_maisecrets_is_a_question_for_the_ai(self):
        self.assertNotIn("drop", _mod("maisecrets: why was my prompt blocked"))


class InlineMarkTests(_Base):
    """D: ms:(value) inside a prompt."""

    def test_the_marks_of_a_prompt(self):
        self.assertEqual(check_value.inline_marks(f"log in with ms:({PASSWORD}) now"),
                         [(12, 12 + len(PASSWORD) + 5, PASSWORD)])
        self.assertEqual([v for _a, _b, v in check_value.inline_marks("use ms:(a)b) here, then ms:(c).")],
                         ["a)b", "c"])
        self.assertEqual([v for _a, _b, v in check_value.inline_marks("no close ms:(open end  \nnext line")],
                         ["open end"])
        for prompt in ("We use MS: (Teams) for chat", "notms:(x) here", "ms:() empty", f"ms:({PASSWORD}) alone"):
            with self.subTest(prompt):
                self.assertEqual(check_value.inline_marks(prompt), [])

    def test_the_mod_stores_the_value_and_puts_its_placeholder_in_its_place(self):
        out = _mod(f"log in with ms:({PASSWORD}) now")
        self.assertEqual(out.get("text"), f"log in with {REF} now")
        self.assertEqual(out.get("count"), 1)
        self.assertEqual(Vault().get(KEY, session=SESSION), (PASSWORD, "ok"))

    def test_codex_blocks_with_the_rewritten_text_ready_for_send(self):
        payload = {"hook_event_name": "UserPromptSubmit", "prompt": f"log in with ms:({PASSWORD}) now",
                   "session_id": SESSION, "transcript_path": "", **CODEX}
        out = hooks.user_prompt(payload)
        self.assertEqual(out.get("decision"), "block")
        self.assertNotIn(PASSWORD, out["reason"])
        self.assertEqual(hooks._pending_path(SESSION).read_text(encoding="utf-8"), f"log in with {REF} now")

    def test_a_placeholder_next_to_a_value_stores_the_whole_mark_in_the_mod_and_in_codex(self):
        # Gate A: a mark that held a placeholder was skipped whole, and the value next to it went out unchanged
        Vault().put("Zq8-" + "older-value-1", "SECRET", "manual", session=SESSION)
        prompt = f"use ms:({REF} and {PASSWORD}) now"
        out = _mod(prompt)
        self.assertNotIn(PASSWORD, out.get("text", PASSWORD))
        self.assertEqual(out.get("count"), 1)
        _reset()
        Vault().put("Zq8-" + "older-value-1", "SECRET", "manual", session=SESSION)
        hooks._live_cache.clear()
        payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "session_id": SESSION,
                   "transcript_path": "", **CODEX}
        blocked = hooks.user_prompt(payload)
        self.assertEqual(blocked.get("decision"), "block")
        self.assertNotIn(PASSWORD, blocked["reason"])
        self.assertNotIn(PASSWORD, hooks._pending_path(SESSION).read_text(encoding="utf-8"))

    def test_a_mark_of_placeholders_alone_stays_as_typed(self):
        self.assertEqual(_mod(f"use ms:({REF}) now"), {})

    def test_a_prompt_that_is_not_the_persons_stores_nothing(self):
        _mod(f"log in with ms:({PASSWORD}) now", origin="sdk")
        self.assertIsNone(Vault().get(KEY, session=SESSION)[0])


if __name__ == "__main__":
    unittest.main()
