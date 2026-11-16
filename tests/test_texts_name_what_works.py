"""Texts that named a command or a pointer that does not work for the person who reads it: `/ms` without the shortcut,
a slash command in Codex, `/maisecrets:status` for "delete everything", a stray help line, a pattern name read as the
store, and a raw `source` value.

Run: python3 -m unittest tests.test_texts_name_what_works -v
"""
from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import cli, codex_vault, hooks, notices, settings, terms_cli  # noqa: E402
from maisecrets.vault import HOME, Vault  # noqa: E402

CONFIG = '{"backend": "jsonfile", "allow_plaintext_store": true}'


class SendCommandTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        old = os.environ.get("CLAUDE_CONFIG_DIR")
        os.environ["CLAUDE_CONFIG_DIR"] = self.dir.name
        self.addCleanup(lambda: os.environ.__setitem__("CLAUDE_CONFIG_DIR", old) if old is not None
                        else os.environ.pop("CLAUDE_CONFIG_DIR", None))

    def _notice(self, copied: bool) -> str:
        return "\n".join(notices.block_notice([SimpleNamespace(type="SECRET")], "rewritten", copied, False, {}, None))

    def test_the_block_notice_names_send_without_the_shortcut(self):
        # the plugin ships no /ms: without /maisecrets:shortcut it is an unknown command
        for copied in (True, False):
            text = self._notice(copied)
            self.assertIn("\n  /maisecrets:send   send the cleaned prompt now", text)
            self.assertNotIn("/ms ", text)

    def test_the_block_notice_names_ms_once_the_shortcut_is_installed(self):
        commands = Path(self.dir.name, "commands")
        commands.mkdir()
        Path(commands, "ms.md").write_text("!`bash ~/.maisecrets/bin/ms.sh`\n", encoding="utf-8")
        # the column width follows the paste key (⌘V on macOS, Ctrl+V elsewhere)
        self.assertRegex(self._notice(True), r"\n  /ms +send the cleaned prompt now")
        # a command file of the person's own with that name is no maisecrets shortcut
        Path(commands, "ms.md").write_text("my own command\n", encoding="utf-8")
        self.assertRegex(self._notice(True), r"\n  /maisecrets:send +send the cleaned prompt now")

    # the maintainer, 2026-11-16: the notice names /ms first, then the paste key, then the command for a wrong hit
    def _entries(self, *spec):
        return [SimpleNamespace(key=t + "_c" + str(n), type=t, kind=k) for t, n, k in spec]

    def _lines(self, entries, copied=True, codex=False, more=0, report=None):
        return notices.block_notice(entries, "the cleaned prompt", copied, codex, {}, None, more, report)

    def test_with_the_clipboard_the_notice_is_ms_then_the_paste_key_then_the_wrong_hit(self):
        key = notices._paste_key()
        width = max(len(key), len("/maisecrets:send")) + 3
        self.assertEqual(self._lines(self._entries(("SECRET", 12, "gitlab-pat"))), [
            "maisecrets kept a secret from the AI.", "",
            "  " + "/maisecrets:send".ljust(width) + "send the cleaned prompt now",
            "  " + key.ljust(width) + "paste it to edit it first", "",
            "A wrong hit? /maisecrets:" + "not-a-secret SECRET_c12"])

    def test_without_the_clipboard_the_notice_shows_the_prompt_under_ms(self):
        lines = self._lines(self._entries(("EMAIL", 3, "email")), copied=False)
        self.assertEqual(lines[0], "maisecrets kept personal data from the AI.")
        self.assertEqual(lines[2:5], ["  /maisecrets:send   send the cleaned prompt now", "", "    the cleaned prompt"])
        self.assertEqual(lines[-1], "A wrong hit? /maisecrets:" + "not-a-secret EMAIL_c3")
        self.assertFalse(any("paste" in x for x in lines))

    def test_the_wrong_hit_line_names_the_one_key_else_key_and_leaves_out_a_term(self):
        one = self._entries(("NAME", 4, "ner"))
        two = self._entries(("NAME", 4, "ner"), ("EMAIL", 5, "email"))
        term = self._entries(("NAME", 6, "term:clients"))
        imported = self._entries(("SECRET", 7, "import:abc"))
        self.assertTrue(self._lines(one)[-1].endswith(" NAME_c4"))
        self.assertTrue(self._lines(one + one)[-1].endswith(" NAME_c4"), "the same value twice is one value")
        self.assertTrue(self._lines(two)[-1].endswith(" KEY"))
        self.assertTrue(self._lines(one, more=1)[-1].endswith(" KEY"), "a stored value next to it: two values")
        self.assertTrue(self._lines([], more=1)[-1].endswith(" KEY"), "a stored value alone")
        for chosen in (term, imported):
            self.assertFalse(any("wrong hit" in x for x in self._lines(chosen)), "not_a_secret refuses a term")
        self.assertTrue(self._lines(term + one)[-1].endswith(" NAME_c4"))

    def test_codex_gets_the_paste_key_or_the_prompt_and_its_typed_wrong_hit_form(self):
        key = notices._paste_key()
        one = self._entries(("SECRET", 12, "gitlab-pat"))
        self.assertEqual(self._lines(one, codex=True), [
            "maisecrets kept a secret from the AI.", "",
            f"  {key.ljust(len(key) + 3)}paste the cleaned prompt, then send it",
            "", "A wrong hit? maisecrets: not a secret SECRET_c12"])
        self.assertEqual(self._lines(one, copied=False, codex=True)[2:5],
                         ["  Copy the cleaned prompt from here and send it:", "", "    the cleaned prompt"])
        for copied in (True, False):
            self.assertFalse(any("/maisecrets:" in x for x in self._lines(one, copied, codex=True)), "no slash command")

    def test_a_blocked_report_is_passed_on_with_ms(self):
        one = self._entries(("SECRET", 12, "gitlab-pat"))
        self.assertEqual(self._lines(one, copied=False, report="a subagent's report"), [
            "maisecrets kept a secret in a subagent's report from the AI.", "",
            "  /maisecrets:send   pass the report on with placeholders"])
        self.assertEqual(self._lines(one, copied=False, report="a background command's notice")[-1],
                         "  /maisecrets:send   pass the notice on with placeholders")

    def test_the_session_id_refusal_names_send(self):
        bash = hooks._pre_bash({}, {}, {"command": "CLAUDE_CODE_SESSION_ID=x true"})
        ps = hooks._pre_powershell({}, {"command": "$env:CLAUDE_CODE_SESSION_ID = 'x'"})
        for out in (bash, ps):
            reason = out["hookSpecificOutput"]["permissionDecisionReason"]
            self.assertIn("/maisecrets:send sends the blocked prompt", reason)
            self.assertNotIn("/ms ", reason)


class CodexTests(unittest.TestCase):
    def test_codex_is_told_the_sentence_it_can_send(self):
        # Codex has no plugin slash commands; its form of a settings change is `maisecrets: set KEY VALUE`
        text = codex_vault.notice("probe-server")
        self.assertIn("send this alone as your prompt: maisecrets: set client_header off.", text)
        self.assertNotIn("/maisecrets:settings", text)
        self.assertIn("the AI still sees only placeholders", text)


class ListAndTermTests(unittest.TestCase):
    def setUp(self):
        HOME.mkdir(parents=True, exist_ok=True)
        Path(HOME, "config.json").write_text(CONFIG)
        for f in ("index.json", "vault.json"):
            Path(HOME, f).unlink(missing_ok=True)
        self.addCleanup(lambda: [Path(HOME, f).unlink(missing_ok=True) for f in ("index.json", "vault.json")])

    def test_the_list_says_how_to_delete_everything(self):
        Vault().put("Zq8-" + "list-footer-probe", "SECRET", "manual", session="S1")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli._list_values()
        text = out.getvalue()
        self.assertNotIn("/maisecrets:status shows how", text, "status says nothing about deleting everything")
        self.assertIn("To delete one: /maisecrets:forget <placeholder>.", text)
        launcher = str(Path(ROOT, "hooks", "run.cmd" if os.name == "nt" else "run.sh"))
        self.assertIn(f"run in a terminal: {launcher} wipe --yes", text)

    def test_the_term_list_ends_with_the_add_line_alone(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            terms_cli.show()
        tail = out.getvalue().rstrip("\n").split("\n\n")[-1]
        self.assertTrue(tail.startswith("Add a term: type /maisecrets:term add"), tail)
        self.assertNotIn("terms.suggested.txt (overwritten", out.getvalue())


class StoreRefusalTests(unittest.TestCase):
    def test_the_refusal_names_what_it_matched_as_a_part_not_as_the_store(self):
        # "this command touches maisecrets get, the user's own store" read a pattern name as the store
        out = hooks._store_refusal("maisecrets get SECRET_c1")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertTrue(reason.startswith("maisecrets: this command reads a part of maisecrets that holds stored "
                                          "values (maisecrets get). The user manages them"), reason)
        self.assertNotIn("the user's own store", reason)


class StatusWordsTests(unittest.TestCase):
    def test_a_placeholder_that_cannot_be_used_is_named_in_words_and_its_hint_matches(self):
        # the transcript showed `(foreign-session)`: a code the person cannot act on
        reason = hooks._deny_reason(["SECRET_c1 (unknown)", "SECRET_c2 (foreign-session)", "SECRET_c3 (no-session)"])
        self.assertIn("cannot use SECRET_c1 (no such placeholder), SECRET_c2 (not given in this session), SECRET_c3 "
                      "(not given in this session).", reason)
        for code in ("(unknown)", "foreign-session", "no-session"):
            self.assertNotIn(code, reason)
        self.assertIn("A placeholder marked (no such placeholder) does not exist", reason)
        self.assertIn("A placeholder marked (not given in this session) works only", reason)


class CameFromTests(unittest.TestCase):
    def test_a_raw_source_is_said_in_words(self):
        self.assertEqual(settings.came_from({"source": "cron"}), "a scheduled task")
        self.assertEqual(settings.came_from({"source": "scheduled-task"}), "a scheduled task")
        self.assertEqual(settings.came_from({"source": "sdk"}), "a program")
        self.assertEqual(settings.came_from({"source": "schedule_wakeup"}), "a loop that wakes the session")
        self.assertEqual(settings.came_from({"source": "user", "agent_id": "a1"}), "a subagent")
        self.assertEqual(settings.came_from({"source": "system"}), "the client, not from you")

    def test_no_refusal_prints_the_raw_value(self):
        reason = settings.not_typed_reason({"source": "cron"})
        self.assertIn("came from a scheduled task, so nothing was changed", reason)
        self.assertNotIn("(cron)", reason)
        self.assertNotIn("None", settings.not_typed_reason({"source": None, "agent_id": "a1"}))


if __name__ == "__main__":
    unittest.main()
