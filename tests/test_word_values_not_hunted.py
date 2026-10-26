"""A word that a label rule took in a tool result blocks no later prompt; a random value and a word the person gives
in a prompt are still hunted everywhere, and every hunted value is still masked in a later tool result.

`password: Wartungsfenster` in a tool result stored the German word, and the store then hunted it: every later tool
result of every session showed a placeholder for the word, and a typed prompt about the maintenance window was
blocked, for a day (field report on 0.6.16, 2026-10-14). Each call below runs the real entry point (hooks/dispatch.py)
in a new process, as the client does.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

CFG = '{"backend": "jsonfile", "allow_plaintext_store": true}'
WORD = "Wartungs" + "fenster"          # German: maintenance window
FOREIGN = "Lieblings" + "farbe"       # German: favourite colour, an answer field only the tool channel takes
ENGLISH = "fall" + "back"              # an English word of the word list
RANDOM = "xqzv" + "bnmq"              # random small letters (Codex review, 2026-09-29): a secret wherever it shows up
RANDOM_TOOL = "pozk" + "emva"          # random small letters only the tool channel takes; 8 letters, because a later
#                                        text of another session hunts a value of 8 characters and more (0.6.16 too)


def tearDownModule():  # noqa: N802 - unittest hook
    _hygiene.assert_pristine()


class WordValuesNotHuntedTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _hygiene.watch_children(self)
        self.home = Path(tempfile.mkdtemp(prefix="word-hunt-", dir=_isolate.HOME))
        Path(self.home, "config.json").write_text(CFG)
        self.bin = Path(self.home, "bin")   # a blocked prompt copies its rewrite: a stand-in clipboard
        self.bin.mkdir()
        for name in ("pbcopy", "xclip", "clip"):
            Path(self.bin, name).write_text("#!/bin/sh\ncat > /dev/null\n")
            Path(self.bin, name).chmod(0o700)

    def hook(self, event: str, payload: dict) -> dict:
        # Windows finds clip.exe in System32 before PATH: MS_TEST_CLIP sends it to the fake of tests/_platform_fakes.py
        env = {**os.environ, "MAISECRETS_HOME": str(self.home), "MS_TEST_CLIP": str(Path(self.home, "clip")),
               "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}"}
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), event], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout) if r.stdout.strip() else {}

    def bash(self, stdout: str, session: str) -> str:
        out = self.hook("post-tool", {"tool_name": "Bash", "session_id": session, **CLAUDE,
                                      "tool_input": {"command": "x"},
                                      "tool_response": {"stdout": stdout, "stderr": "", "interrupted": False,
                                                        "isImage": False}})
        # no answer means the result goes to the model as it was: return that text, so assertNotIn can fail
        return json.dumps(out, ensure_ascii=False) if out else stdout

    def blocked(self, prompt: str, session: str) -> bool:
        return self.hook("user-prompt", {"prompt": prompt, "session_id": session, **CLAUDE}).get("decision") == "block"

    def test_a_word_after_a_password_label_in_a_tool_result_blocks_no_later_prompt(self):
        self.assertNotIn(WORD, self.bash(f"password: {WORD}\n", "s1"), "the result that held the label is redacted")
        self.assertFalse(self.blocked(f"Das {WORD} ist morgen ab 22 Uhr.", "s2"), "a prompt with the word is text")
        self.assertNotIn(WORD, self.bash(f"{WORD}: Montag 22 Uhr\n", "s3"), "a later tool result still masks it")

    def test_a_word_the_person_then_gives_after_a_label_is_hunted_in_prompts_again(self):
        self.bash(f"password: {WORD}\n", "s1")
        self.assertTrue(self.blocked(f"password: {WORD}", "s2"), "the label rule takes it in the prompt")
        self.assertTrue(self.blocked(f"Das {WORD} ist morgen.", "s3"), "from now on it is the person's password")

    def test_a_quiet_word_this_session_used_in_a_command_blocks_no_later_prompt(self):
        import re
        out = self.bash(f"password: {WORD}\n", "s1")
        ref = re.search(r"⟦SECRET_c\d+⟧", out).group(0)
        self.hook("pre-tool", {"tool_name": "Bash", "session_id": "s1", **CLAUDE,
                               "tool_input": {"command": f"echo {ref} > /dev/null"}})
        self.assertFalse(self.blocked(f"Das {WORD} ist morgen.", "s1"), "a resolved quiet word is text in a prompt")
        self.assertNotIn(WORD, self.bash(f"note: {WORD} Montag\n", "s1"), "and still masked in a tool result")

    def test_a_later_tool_result_with_another_rule_keeps_the_word_quiet(self):
        self.bash(f"password: {WORD}\n", "s1")
        self.assertNotIn(WORD, self.bash(f"clone https://deploy:{WORD}@git.example.com/app.git\n", "s2"))
        self.assertFalse(self.blocked(f"Das {WORD} ist morgen.", "s3"), "a URL password rule does not unquiet it")

    def drop_marks(self) -> None:
        """Rewrite the index as 0.6.16 does: it does not know the quiet field and writes each record without it."""
        index = Path(self.home, "index.json")
        idx = json.loads(index.read_text())
        for meta in idx["entries"].values():
            meta.pop("quiet", None)
        index.write_text(json.dumps(idx))

    def test_a_word_the_person_typed_stays_hunted_when_an_older_process_drops_its_mark(self):
        self.assertTrue(self.blocked(f"password: {WORD}", "s1"), "the person gives the word as a password")
        self.drop_marks()
        self.hook("session-start", {"session_id": "s2", **CLAUDE})
        self.assertNotIn(WORD, self.bash(f"password: {WORD}\n", "s2"), "a tool result with the same word")
        self.assertTrue(self.blocked(f"Das {WORD} ist morgen.", "s3"), "its origin is unknown: it stays hunted")

    def test_a_quiet_mark_an_older_process_drops_falls_back_to_hunted(self):
        self.bash(f"password: {WORD}\n", "s1")
        self.assertFalse(self.blocked(f"Das {WORD} ist morgen.", "s2"), "quiet while the mark stands")
        self.drop_marks()
        self.assertNotIn(WORD, self.bash(f"password: {WORD}\n", "s3"))
        self.assertTrue(self.blocked(f"Das {WORD} ist morgen.", "s4"), "no mark, no inference: hunted as in 0.6.16")

    def test_a_default_word_from_a_tool_result_stays_weak_as_in_0616(self):
        self.assertNotIn("database", self.bash("DB_PASS" + "WORD=database\n", "s1"), "masked where it was found")
        self.assertEqual(self.bash("connected to database app\n", "s2"), "connected to database app\n",
                         "weak wins over quiet: not hunted in a later tool result either (final codex review, LOW)")
        self.assertFalse(self.blocked("create the database first", "s3"))

    def test_an_english_word_from_a_tool_result_is_masked_only_where_it_was_found(self):
        # field report, 2026-10-17: ordinary words after a label in code were masked thousands of times a day
        self.assertNotIn(ENGLISH, self.bash(f"password: {ENGLISH}\n", "s1"), "masked where it was found")
        self.assertEqual(self.bash(f"use the {ENGLISH} path\n", "s2"), f"use the {ENGLISH} path\n")
        self.assertFalse(self.blocked(f"rename the {ENGLISH} option", "s3"))
        self.assertNotIn(WORD, self.bash(f"password: {WORD}\n", "s4"))
        self.assertNotIn(WORD, self.bash(f"Das {WORD} ist morgen.\n", "s5"), "a word outside the list stays hunted")

    def test_an_english_word_the_person_gives_after_a_label_stays_hunted(self):
        self.assertTrue(self.blocked(f"password: {ENGLISH}", "s1"), "a chosen word is a password")
        self.assertNotIn(ENGLISH, self.bash(f"use the {ENGLISH} path\n", "s2"))

    def test_a_quiet_english_word_an_older_version_stored_is_weak_after_the_next_start(self):
        for value in (ENGLISH, WORD):
            self.bash(f"password: {value}\n", "s1")
        index = Path(self.home, "index.json")
        idx = json.loads(index.read_text())
        for meta in idx["entries"].values():     # as 0.6.37 stored them: quiet, not weak
            self.assertTrue(meta["quiet"])
            meta["weak"] = False
        index.write_text(json.dumps(idx))
        self.assertNotIn(ENGLISH, self.bash(f"use the {ENGLISH} path\n", "s2"), "hunted before the start")
        self.hook("session-start", {"session_id": "s3", **CLAUDE})
        self.assertEqual(self.bash(f"use the {ENGLISH} path\n", "s3"), f"use the {ENGLISH} path\n")
        self.assertNotIn(WORD, self.bash(f"Das {WORD} ist morgen.\n", "s3"), "a word outside the list stays hunted")

    def test_a_tool_result_after_a_failed_command_takes_the_tool_rule_too(self):
        out = self.hook("post-tool-failure", {"tool_name": "Bash", "session_id": "s1", **CLAUDE,
                                              "tool_input": {"command": "x"},
                                              "error": f'error: password = Some("{RANDOM_TOOL}"), rejected'})
        self.assertIn("systemMessage", out, out)
        self.assertTrue(self.blocked(f"the value is {RANDOM_TOOL}", "s2"), "stored from the failed output, hunted")

    def test_a_random_value_that_reads_like_a_word_is_still_masked_in_a_later_tool_result(self):
        value = "ppsm" + "ohsyeeub"     # random small letters of common letter pairs (Codex review, 2026-10-14)
        self.assertNotIn(value, self.bash(f"DB_PASSWORD={value}\n", "s1"))
        self.assertNotIn(value, self.bash(f"echo {value}\n", "s2"), "hunted in every later tool result")
        # the named trade (README, limits): a bare re-typing in a prompt is not looked for. Adjudicated in the final
        # review of 0.6.17: a word from a file must not block prompts, and this value reads like a word
        self.assertFalse(self.blocked(f"the value is {value}", "s3"))

    def test_a_word_only_the_tool_channel_takes_is_not_hunted_either(self):
        self.assertNotIn(FOREIGN, self.bash(f'password = Some("{FOREIGN}"),\n', "s1"))
        self.assertFalse(self.blocked(f"rename the field {FOREIGN} in the form", "s2"))

    def test_a_random_value_after_a_label_is_still_hunted_in_a_later_prompt(self):
        self.assertNotIn(RANDOM, self.bash(f"DB_PASSWORD={RANDOM}\n", "s1"))
        self.assertTrue(self.blocked(f"the value is {RANDOM}", "s2"), "a random value is a secret wherever it shows up")

    def test_a_random_value_only_the_tool_channel_takes_is_still_hunted(self):
        self.assertNotIn(RANDOM_TOOL, self.bash(f'password = Some("{RANDOM_TOOL}"),\n', "s1"))
        self.assertTrue(self.blocked(f"the value is {RANDOM_TOOL}", "s2"))

    def post(self, tool: str, response: dict, session: str) -> str:
        """A tool result of another tool than Bash; the answer as text, or the result as it was when none came."""
        out = self.hook("post-tool", {"tool_name": tool, "session_id": session, **CLAUDE, "tool_input": {},
                                      "tool_response": response})
        return json.dumps(out, ensure_ascii=False) if out else json.dumps(response, ensure_ascii=False)

    # field report, 2026-10-25: label lines in a Bash result stored ordinary words, and later WebFetch, WebSearch and
    # Agent results of other sessions showed a placeholder for them. The word list holds base words of 4 to 8 letters
    # and only a value of 8 or more is hunted: an ending or a compound made it no dictionary word, and the word for
    # password in another language kept its accent
    PROSE = ("compar" + "ing", "specific" + "ally", "evaluat" + "ing", "direct" + "ly", "benchmark" + "ing",
             "contrase" + "ña")

    def store_from_a_tool_result(self, session: str) -> None:
        """Each prose word and the control WORD after a label in one Bash result; each is masked at its label, with
        a placeholder of its own and the type SECRET, as before the fix."""
        import re
        lines = [f"password: {w}" for w in (*self.PROSE, WORD)]
        out = self.hook("post-tool", {"tool_name": "Bash", "session_id": session, **CLAUDE,
                                      "tool_input": {"command": "x"},
                                      "tool_response": {"stdout": "\n".join(lines) + "\n", "stderr": "",
                                                        "interrupted": False, "isImage": False}})
        stdout = out["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        masked = stdout.splitlines()
        self.assertEqual(len(masked), len(lines))
        keys = [re.fullmatch(r"password: ⟦(SECRET_c\d+)⟧", line) for line in masked]
        self.assertTrue(all(keys), masked)
        self.assertEqual(len({k.group(1) for k in keys}), len(lines), "one key per value")

    def test_a_word_from_one_session_is_not_hunted_in_the_web_and_agent_results_of_others(self):
        self.store_from_a_tool_result("A")
        for word in self.PROSE:
            text = f"for {word} PII detectors, and {word} again."
            fetched = {"code": 200, "result": text, "url": "https://example.org/a"}
            self.assertEqual(self.post("WebFetch", fetched, "B"), json.dumps(fetched, ensure_ascii=False))
            searched = {"query": "q", "results": [f"{text}\n\n- **Bench** {text}"]}
            self.assertEqual(self.post("WebSearch", searched, "B"), json.dumps(searched, ensure_ascii=False))
        launched = {"isAsync": True, "status": "async_launched", "agentId": "a" + "1b2c3d4e5f6071" + "8a",
                    "description": "labels", "prompt": "count " + ", ".join(self.PROSE * 2)}
        self.assertEqual(self.post("Agent", launched, "C"), json.dumps(launched, ensure_ascii=False))
        # the control: a word outside the list is still hunted in each of those results
        self.assertNotIn(WORD, self.post("WebFetch", {"code": 200, "result": f"Das {WORD} ist morgen."}, "B"))
        self.assertNotIn(WORD, self.post("WebSearch", {"query": "q", "results": [f"{WORD} und {WORD}"]}, "B"))
        self.assertNotIn(WORD, self.post("Agent", {**launched, "prompt": f"plan the {WORD}"}, "C"))

    def put_by_hand(self, value: str) -> None:
        """/maisecrets:put from stdin: the entry kind `manual`."""
        # put copies the placeholder: the fake clipboard on PATH, and MS_TEST_CLIP for clip.exe on Windows (hook)
        env = {**os.environ, "MAISECRETS_HOME": str(self.home), "MS_TEST_CLIP": str(Path(self.home, "clip")),
               "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "PYTHONUTF8": "1"}
        # the answer names the placeholder; on Windows a pipe has the code page cp1252, which has no ⟦ (UTF-8 both ways)
        r = subprocess.run([sys.executable, "-m", "maisecrets.cli", "put"], input=value, capture_output=True,
                           text=True, encoding="utf-8", env=env, cwd=str(ROOT), timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)

    def marks(self) -> dict:
        idx = json.loads(Path(self.home, "index.json").read_text())
        return {k: (m["kind"], m.get("weak"), m.get("quiet")) for k, m in idx["entries"].items()}

    def test_the_migration_at_the_start_is_idempotent_and_weakens_only_quiet_words(self):
        hand = "explicit" + "ly"
        self.store_from_a_tool_result("s1")
        self.put_by_hand(hand)
        index = Path(self.home, "index.json")
        idx = json.loads(index.read_text())
        for meta in idx["entries"].values():     # as 0.8.1 stored them: no word of a tool result weak
            meta["weak"] = False
        index.write_text(json.dumps(idx))
        self.hook("session-start", {"session_id": "s2", **CLAUDE})
        first = self.marks()
        self.hook("session-start", {"session_id": "s3", **CLAUDE})
        self.assertEqual(self.marks(), first, "a second start changes no mark")
        for kind, weak, quiet in first.values():
            if kind == "manual":
                self.assertEqual((weak, quiet), (False, False), "a value stored by hand is never weakened")
            else:
                self.assertTrue(quiet, "a weak entry stays quiet: it never blocks a prompt")
        self.assertNotIn(hand, self.bash(f"covered {hand}\n", "s4"), "the value stored by hand stays hunted")
        self.assertNotIn(WORD, self.bash(f"Das {WORD} ist morgen.\n", "s4"), "a word outside the list stays hunted")
        self.assertEqual(self.bash(f"for {self.PROSE[0]} tools\n", "s4"), f"for {self.PROSE[0]} tools\n")

    def test_a_weak_word_the_person_then_gives_is_hunted_again(self):
        stored, typed = "compar" + "ing", "evaluat" + "ing"
        for word in (stored, typed):
            self.bash(f"password: {word}\n", "s1")
            self.assertEqual(self.bash(f"for {word} tools\n", "s2"), f"for {word} tools\n", "weak: not hunted")
        self.put_by_hand(stored)                  # the person stores the same word as a password
        self.assertNotIn(stored, self.bash(f"for {stored} tools\n", "s3"))
        self.blocked(f"password: {typed}", "s4")  # the person gives it after a label in a prompt
        self.assertNotIn(typed, self.bash(f"for {typed} tools\n", "s5"))

    def test_a_quiet_word_with_an_ending_an_older_version_stored_is_weak_after_the_next_start(self):
        words = ("compar" + "ing", "contrase" + "ña")
        for word in words:
            self.bash(f"password: {word}\n", "s1")
        index = Path(self.home, "index.json")
        idx = json.loads(index.read_text())
        for meta in idx["entries"].values():     # as 0.8.1 stored them: quiet, not weak
            self.assertTrue(meta["quiet"])
            meta["weak"] = False
        index.write_text(json.dumps(idx))
        self.assertNotIn(words[0], self.bash(f"for {words[0]} tools\n", "s2"), "hunted before the start")
        self.hook("session-start", {"session_id": "s3", **CLAUDE})
        for word in words:
            self.assertEqual(self.bash(f"for {word} tools\n", "s3"), f"for {word} tools\n")


if __name__ == "__main__":
    unittest.main()
