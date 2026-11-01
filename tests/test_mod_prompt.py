"""The prompt path of the mod (claude-mod/maisecrets-mod.mjs → dispatch.py mod-prompt → hooks.rewrite_prompt) and the
transcript scrub it starts by session id.

The mod's own JavaScript is tested in tests/mod.test.ts (`claude plugin test`); the real client with
and without the mod in harness/run.py (prompt_secret, prompt_secret_rewrite_off)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

_TMP = _isolate.HOME
Path(_TMP).mkdir(parents=True, exist_ok=True)
Path(_TMP, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

GLPAT = "glpat-" + "A1b2C3d4E5f6G7h8I9j0"
PASSWORD = "Wq7-" + "pLm2xZr9Tv"          # no detector shape: found only because the store holds it


def tearDownModule():  # noqa: N802 - unittest hook
    _hygiene.assert_pristine()


class RewriteTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        import shutil
        _hygiene.watch_children(self)
        for name in ("index.json", "vault.json", "audit.log", "events.log", "hooks.log"):
            Path(_TMP, name).unlink(missing_ok=True)
        shutil.rmtree(Path(_TMP, "pending"), ignore_errors=True)
        Path(_TMP, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        self.addCleanup(Path(_TMP, "config.json").write_text,
                        '{"backend": "jsonfile", "allow_plaintext_store": true}')
        hooks._live_cache.clear()
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)
        self.scrubs = []
        _hygiene.patch(self, hooks, "_scrub_transcript_later",
                       lambda path, values, refs, seconds=15.0, session=None:
                       self.scrubs.append((path, list(values), session)))

    def test_a_secret_becomes_a_placeholder_and_the_value_goes_to_the_store(self):
        out = hooks.rewrite_prompt({"prompt": f"check {GLPAT} in CI", "session_id": "s1"})
        # the first rewrite also names ms:(…) once (tip): not part of the rewrite itself
        self.assertEqual({k: v for k, v in out.items() if k != "tip"}, {"text": "check ⟦SECRET_c1⟧ in CI", "count": 1})
        self.assertEqual(Vault().get("SECRET_c1", session="s1"), (GLPAT, "ok"))

    def test_the_scrub_starts_with_the_values_and_the_session(self):
        hooks.rewrite_prompt({"prompt": f"check {GLPAT} in CI", "session_id": "s1"})
        self.assertEqual(self.scrubs, [("", [GLPAT], "s1")])

    def test_the_scrub_setting_off_starts_no_scrub(self):
        Path(_TMP, "config.json").write_text(
            '{"backend": "jsonfile", "allow_plaintext_store": true, "scrub_transcript": false}')
        out = hooks.rewrite_prompt({"prompt": f"check {GLPAT} in CI", "session_id": "s1"})
        self.assertIn("\u27e6SECRET_c1\u27e7", out["text"])
        self.assertEqual(self.scrubs, [])

    def test_a_value_the_store_holds_is_taken_out_without_a_shape(self):
        e = Vault().put(PASSWORD, "SECRET", "manual", session="s1")
        hooks._live_cache.clear()
        out = hooks.rewrite_prompt({"prompt": f"log in with {PASSWORD} please", "session_id": "s1"})
        self.assertEqual(out["text"], f"log in with {e.ref} please")

    def test_nothing_to_take_out_gives_no_answer(self):
        self.assertEqual(hooks.rewrite_prompt({"prompt": "say hi", "session_id": "s1"}), {})
        self.assertEqual(self.scrubs, [])

    def test_the_setting_off_gives_no_answer_and_stores_nothing(self):
        Path(_TMP, "config.json").write_text(
            '{"backend": "jsonfile", "allow_plaintext_store": true, "rewrite_prompts": false}')
        self.assertEqual(hooks.rewrite_prompt({"prompt": f"check {GLPAT}", "session_id": "s1"}), {})
        self.assertFalse(Path(_TMP, "index.json").exists())

    def test_no_session_or_a_session_id_that_is_a_path_gives_no_answer(self):
        for session in (None, "", "../evil", "a/b"):
            with self.subTest(session=session):
                self.assertEqual(hooks.rewrite_prompt({"prompt": f"check {GLPAT}", "session_id": session}), {})
        self.assertFalse(Path(_TMP, "index.json").exists())

    def test_a_subagent_report_is_left_to_the_hook(self):
        prompt = f"<task-notification><result>the token is {GLPAT}</result></task-notification>"
        self.assertEqual(hooks.rewrite_prompt({"prompt": prompt, "session_id": "s1"}), {})
        self.assertFalse(Path(_TMP, "index.json").exists())

    def test_an_at_mention_of_a_file_is_left_to_the_hook_and_stores_nothing(self):
        import tempfile
        with tempfile.TemporaryDirectory() as cwd:
            Path(cwd, "notes.env").write_text("X=1")
            for payload in ({"cwd": cwd}, {}):              # without a working directory: any mention
                with self.subTest(cwd=bool(payload)):
                    out = hooks.rewrite_prompt({"prompt": f"see @notes.env and {GLPAT}", "session_id": "s1",
                                                **payload})
                    self.assertEqual(out, {})
            self.assertFalse(Path(_TMP, "index.json").exists())
            self.assertFalse(Path(_TMP, "events.log").exists())
            hook = hooks.user_prompt({"prompt": f"see @notes.env and {GLPAT}", "session_id": "s1", "cwd": cwd,
                                      **CLAUDE})
            self.assertEqual(hook["decision"], "block")

    def test_a_mention_that_the_placeholder_would_make_is_left_to_the_hook(self):
        import tempfile
        with tempfile.TemporaryDirectory() as cwd:
            Path(cwd, "src").mkdir()
            out = hooks.rewrite_prompt({"prompt": f"see @src/{GLPAT} now", "session_id": "s1", "cwd": cwd})
        self.assertEqual(out, {})
        self.assertFalse(Path(_TMP, "index.json").exists())

    def test_a_stored_value_inside_a_mention_is_left_to_the_hook_and_admits_nothing(self):
        import tempfile
        e = Vault().put(PASSWORD, "SECRET", "manual", session="s0")
        hooks._live_cache.clear()
        with tempfile.TemporaryDirectory() as cwd:
            Path(cwd, "src").mkdir()
            out = hooks.rewrite_prompt({"prompt": f"see @src/{PASSWORD} now", "session_id": "s1", "cwd": cwd})
        self.assertEqual(out, {})
        self.assertEqual(Vault().status(e.key, "s1"), "foreign-session")      # not admitted to s1

    def test_the_count_is_one_per_place(self):
        out = hooks.rewrite_prompt({"prompt": f"{GLPAT} and again {GLPAT}", "session_id": "s1"})
        self.assertEqual(out["count"], 2)
        out = hooks.rewrite_prompt({"prompt": f"\u27e6SECRET_c1\u27e7 is {GLPAT}", "session_id": "s1"})
        self.assertEqual(out["count"], 1)

    def test_a_stored_value_counts_once(self):
        Vault().put(PASSWORD, "SECRET", "manual", session="s1")
        hooks._live_cache.clear()
        out = hooks.rewrite_prompt({"prompt": f"log in with {PASSWORD} please", "session_id": "s1"})
        self.assertEqual(out["count"], 1)

    def test_a_mention_of_no_file_with_a_working_directory_is_rewritten(self):
        import tempfile
        with tempfile.TemporaryDirectory() as cwd:
            out = hooks.rewrite_prompt({"prompt": f"ask @someone about {GLPAT}", "session_id": "s1", "cwd": cwd})
        self.assertEqual(out["text"], "ask @someone about \u27e6SECRET_c1\u27e7")

    def test_the_hook_after_the_mod_passes_the_rewritten_prompt(self):
        out = hooks.rewrite_prompt({"prompt": f"check {GLPAT} in CI", "session_id": "s1"})
        hook = hooks.user_prompt({"prompt": out["text"], "session_id": "s1", "transcript_path": "/t.jsonl",
                                  **CLAUDE})
        self.assertNotEqual(hook.get("decision"), "block")
        self.assertIn("additionalContext", hook["hookSpecificOutput"])     # the primer: a placeholder is in it


class BackstopTests(unittest.TestCase):
    def test_a_shell_command_that_asks_the_mod_question_is_named_by_the_backstop(self):
        for command in ('bash "/p/hooks/run.sh" mod-prompt', "python3 hooks/dispatch.py mod-prompt < x.json",
                        "bash /p/hooks/run.sh 'mod-prompt'",
                        'cmd /c "C:\\p\\hooks\\run.cmd" mod-prompt'):
            with self.subTest(command=command):
                self.assertEqual(hooks._store_read_match(command), "the mod's question")
        self.assertIsNone(hooks._store_read_match("echo the mod-prompt docs"))


class ScrubBySessionTests(unittest.TestCase):
    """The real child: it finds the transcript under the config directory by the session id alone."""

    def test_the_child_finds_the_transcript_by_session_id_and_masks_the_value(self):
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as cfg:
            t = Path(cfg, "projects", "-some-project", "sess-42.jsonl")
            t.parent.mkdir(parents=True)
            other = Path(cfg, "projects", "-some-project", "sess-43.jsonl")
            record = json.dumps({"type": "queue-operation", "content": f"check {GLPAT} in CI"}) + "\n"
            other.write_text(record)
            with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": cfg}):
                child = hooks._scrub_transcript_later("", [GLPAT], [], seconds=4, session="sess-42")
            time.sleep(0.5)
            t.write_text(record)                        # the record appears after the child started
            deadline = time.time() + 10
            while GLPAT in t.read_text() and time.time() < deadline:
                time.sleep(0.2)
            self.assertNotIn(GLPAT, t.read_text())
            json.loads(t.read_text())                   # still one valid record
            self.assertIn(GLPAT, other.read_text())     # another session's transcript is not touched
            child.wait(timeout=10)

    def test_an_older_record_of_the_value_does_not_end_the_scrub_before_the_new_one(self):
        # the child watches the whole window: the old record is masked at its first look, and the record of this
        # prompt, written two seconds later, is masked too (Gate A and Gate B, 2026-10-06)
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as cfg:
            t = Path(cfg, "projects", "-p", "sess-7.jsonl")
            t.parent.mkdir(parents=True)
            t.write_text(json.dumps({"type": "user", "content": f"old {GLPAT}"}) + "\n")
            with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": cfg}):
                child = hooks._scrub_transcript_later("", [GLPAT], [], seconds=6, session="sess-7")
            deadline = time.time() + 5
            while GLPAT in t.read_text() and time.time() < deadline:
                time.sleep(0.1)
            self.assertNotIn(GLPAT, t.read_text(), "the old record was never masked")
            time.sleep(1.5)
            with open(t, "a", encoding="utf-8") as f:
                f.write(json.dumps({"type": "queue-operation", "content": f"check {GLPAT}"}) + "\n")
            deadline = time.time() + 5
            while GLPAT in t.read_text() and time.time() < deadline:
                time.sleep(0.2)
            self.assertNotIn(GLPAT, t.read_text())
            child.wait(timeout=10)

    def test_a_same_size_overwrite_and_a_replaced_file_are_read_again(self):
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as cfg:
            t = Path(cfg, "projects", "-p", "sess-8.jsonl")
            t.parent.mkdir(parents=True)
            record = json.dumps({"type": "queue-operation", "content": f"check {GLPAT}"}) + "\n"
            t.write_text(record)
            with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": cfg}):
                child = hooks._scrub_transcript_later("", [GLPAT], [], seconds=12, session="sess-8")

            def masked_soon() -> bool:
                deadline = time.time() + 4
                while GLPAT in t.read_text() and time.time() < deadline:
                    time.sleep(0.1)
                return GLPAT not in t.read_text()
            self.assertTrue(masked_soon(), "first record")
            time.sleep(0.3)
            with open(t, "r+", encoding="utf-8") as f:   # the same bytes again, in place: same size
                f.write(record)
            self.assertTrue(masked_soon(), "same-size overwrite")
            time.sleep(0.3)
            tmp = Path(cfg, "projects", "-p", "new.tmp")
            tmp.write_text(record)
            for _ in range(50):                          # another file, same name and size
                try:
                    os.replace(tmp, t)
                    break
                except PermissionError:                  # Windows: the child has it open for a pass
                    time.sleep(0.1)
            else:
                self.fail("the transcript stayed locked for five seconds")
            self.assertTrue(masked_soon(), "replaced file")
            child.wait(timeout=15)     # the window is 12 s: a busy runner took most of 6 s for the first mask

    def test_a_session_id_that_is_a_pattern_starts_no_child(self):
        from unittest import mock
        with mock.patch.object(hooks.subprocess, "Popen") as popen:
            for session in (None, "", "*", "../x", "a/b"):
                hooks._scrub_transcript_later("", [GLPAT], [], session=session)
        popen.assert_not_called()


class DispatchTests(unittest.TestCase):
    """The launcher's answer, as the mod reads it: one JSON object with the marker, or no answer."""

    def run_dispatch(self, payload) -> subprocess.CompletedProcess:
        env = {**os.environ, "MAISECRETS_HOME": _TMP}
        # in the plugin folder, as the mod starts it
        return subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "mod-prompt"],
                              input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=60,
                              cwd=str(ROOT))

    def setUp(self):
        for name in ("index.json", "vault.json", "events.log"):
            Path(_TMP, name).unlink(missing_ok=True)
        # the answer is under test here, not the scrub: no child outlives the test
        Path(_TMP, "config.json").write_text(
            '{"backend": "jsonfile", "allow_plaintext_store": true, "scrub_transcript": false}')
        self.addCleanup(Path(_TMP, "config.json").write_text,
                        '{"backend": "jsonfile", "allow_plaintext_store": true}')

    def test_a_rewrite_carries_the_marker_and_no_value(self):
        r = self.run_dispatch({"prompt": f"check {GLPAT}", "session_id": "s9"})
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["maisecrets"], "mod-prompt")
        self.assertEqual(out["text"], "check ⟦SECRET_c1⟧")
        self.assertNotIn(GLPAT, r.stdout + r.stderr)
        r.stdout.encode("ascii")        # a console code page without ⟦ can write it (Windows, cp1252)

    def test_a_mention_is_checked_in_the_session_folder_not_in_the_plugin_folder(self):
        # the mod starts the launcher in the plugin folder (a fixed command line for the directory review)
        import tempfile
        with tempfile.TemporaryDirectory() as cwd:
            Path(cwd, "notes.env").write_text("X=1")
            r = self.run_dispatch({"prompt": f"see @notes.env and {GLPAT}", "session_id": "s9", "cwd": cwd})
            self.assertEqual(json.loads(r.stdout), {"maisecrets": "mod-prompt"})        # left to the hook
            # `hooks` is a folder of the plugin, not of the session: the prompt is rewritten
            r = self.run_dispatch({"prompt": f"see @hooks and {GLPAT}", "session_id": "s9", "cwd": cwd})
            self.assertIn("text", json.loads(r.stdout))

    def test_a_clean_prompt_answers_without_a_text(self):
        r = self.run_dispatch({"prompt": "say hi", "session_id": "s9"})
        self.assertEqual(json.loads(r.stdout), {"maisecrets": "mod-prompt"})

    def test_a_plugin_folder_whose_code_cannot_load_answers_nothing_and_no_traceback(self):
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            Path(d, "hooks").mkdir()
            shutil.copyfile(ROOT / "hooks" / "dispatch.py", Path(d, "hooks", "dispatch.py"))
            Path(d, "maisecrets").mkdir()
            Path(d, "maisecrets", "__init__.py").write_text("raise ImportError('half updated')\n")
            r = subprocess.run([sys.executable, str(Path(d, "hooks", "dispatch.py")), "mod-prompt"],
                               input=json.dumps({"prompt": f"check {GLPAT}", "session_id": "s9"}),
                               capture_output=True, text=True, timeout=60)
        self.assertEqual((r.returncode, r.stdout, r.stderr), (1, "", ""))

    def test_input_that_is_no_json_answers_nothing(self):
        env = {**os.environ, "MAISECRETS_HOME": _TMP}
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "mod-prompt"],
                           input="{not json", capture_output=True, text=True, env=env, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")
        self.assertEqual(r.stderr, "", "no traceback: the answer passes back through other mods")


if __name__ == "__main__":
    unittest.main()
