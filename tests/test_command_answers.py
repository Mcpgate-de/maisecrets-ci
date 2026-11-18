"""The answers of the commands to a wrong or missing argument (UX test of every command, 2026-11-17).

Each answer names the fault and the next command, and changes nothing it should not.

Run: python3 -m unittest tests.test_command_answers -v
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import cli, hooks, ner_setup  # noqa: E402
from maisecrets.vault import HOME, Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

CONFIG = Path(HOME, "config.json")
TEST_CONFIG = {"backend": "jsonfile", "allow_plaintext_store": True}
# the brackets as escapes: a placeholder written out in this file would be resolved by a session that edits it
OPEN, CLOSE = "\u27e6", "\u27e7"


def setUpModule():  # noqa: N802 - unittest hook
    Path(HOME).mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(json.dumps(TEST_CONFIG))


def tearDownModule():  # noqa: N802 - unittest hook
    CONFIG.write_text(json.dumps(TEST_CONFIG))
    _hygiene.assert_pristine()


def _run(fn, args) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = fn(args)
    return rc, out.getvalue() + err.getvalue()


def _live() -> list:
    return [e for e in Vault().list() if not e.purged]


class PutTests(unittest.TestCase):
    def _put(self, text: str) -> tuple[int, str]:
        with mock.patch("maisecrets.hooks._clipboard_read", return_value=text), \
                mock.patch("maisecrets.hooks._clipboard", return_value=True):
            return _run(cli.cmd_put, ["--clipboard"])

    def test_a_placeholder_in_the_clipboard_is_refused_and_not_stored(self):
        rc, out = self._put("put-twice-example-value-not-a-secret")
        self.assertEqual(rc, 0, out)
        first = _live()[-1].ref
        before = len(_live())
        for text in (first, f" {first}\n", f"{OPEN}SECRET_c9{CLOSE} {OPEN}EMAIL_c2:ab•••@•••.example.com{CLOSE}"):
            with self.subTest(text=text):
                rc, out = self._put(text)
                self.assertEqual(rc, 2)
                self.assertIn("the clipboard holds a placeholder, not a value", out)
                self.assertEqual(len(_live()), before, "nothing new is stored")

    def test_a_value_that_only_mentions_a_placeholder_is_stored(self):
        # only placeholders of the canonical form, with white space between them, are refused (Gate A, 2026-11-17)
        for text in (f"put-example-value-not-a-secret {OPEN}SECRET_c1{CLOSE}", f"{OPEN}put-example-not-a-key{CLOSE}"):
            with self.subTest(text=text):
                rc, out = self._put(text)
                self.assertEqual(rc, 0, out)
                self.assertIn("Stored.", out)

    def test_a_list_of_placeholders_is_refused(self):
        # a comma or a semicolon between placeholders is no value either (Gate A, 2026-11-17)
        before = len(_live())
        # no letter or digit is left after the references (Gate A, 2026-11-17)
        for text in (f"{OPEN}SECRET_c1{CLOSE}, {OPEN}EMAIL_c2{CLOSE}", f"{OPEN}SECRET_c1{CLOSE};{OPEN}EMAIL_c2{CLOSE}",
                     f"{OPEN}SECRET_c1{CLOSE}.", f"{OPEN}SECRET_c1{CLOSE} / {OPEN}EMAIL_c2{CLOSE}",
                     f"- {OPEN}SECRET_c1{CLOSE}\n- {OPEN}EMAIL_c2{CLOSE}"):
            with self.subTest(text=text):
                rc, out = self._put(text)
                self.assertEqual(rc, 2, out)
                self.assertIn("holds a placeholder, not a value", out)
        self.assertEqual(len(_live()), before)

    def test_a_sensitive_reference_alone_is_refused(self):
        ref = f"{OPEN}sref:email:abcdefghijklmnopqrstuvwx:ab@example.com{CLOSE}"
        before = len(_live())
        for text in (ref, f"{ref}  {OPEN}SECRET_c1{CLOSE}"):
            with self.subTest(text=text):
                rc, out = self._put(text)
                self.assertEqual(rc, 2, out)
                self.assertIn("holds a placeholder, not a value", out)
        self.assertEqual(len(_live()), before)

    def test_a_placeholder_on_stdin_is_refused_without_naming_the_clipboard(self):
        before = len(_live())
        with mock.patch.object(sys, "stdin", io.StringIO(f"{OPEN}SECRET_c9{CLOSE}\n")):
            rc, out = _run(cli.cmd_put, [])
        self.assertEqual(rc, 2)
        self.assertIn("the input holds a placeholder, not a value", out)
        self.assertNotIn("clipboard", out)
        self.assertEqual(len(_live()), before, "nothing new is stored")

    def test_words_after_put_on_stdin_name_stdin_not_the_clipboard(self):
        with mock.patch.object(sys, "stdin", io.StringIO("put-stdin-example-value-not-a-secret\n")), \
                mock.patch("maisecrets.hooks._clipboard", return_value=False):
            rc, out = _run(cli.cmd_put, ["extra"])
        self.assertEqual(rc, 0, out)
        self.assertIn("the value comes from stdin only", out)
        self.assertNotIn("clipboard", out)


class ShortcutTests(unittest.TestCase):
    def setUp(self):
        self.cfg = Path(tempfile.mkdtemp(prefix="maisecrets-cfg-"))
        env = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.cfg), "CLAUDE_PLUGIN_ROOT": str(ROOT)})
        env.start()
        self.addCleanup(env.stop)

    def commands(self) -> list[str]:
        d = self.cfg / "commands"
        return sorted(p.name for p in d.iterdir()) if d.exists() else []

    def test_remove_and_status_are_subcommands_not_names(self):
        self.assertEqual(_run(cli.cmd_shortcut, [])[0], 0)
        self.assertEqual(self.commands(), ["ms.md"])
        rc, out = _run(cli.cmd_shortcut, ["status"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "The shortcut is installed.")
        rc, out = _run(cli.cmd_shortcut, ["remove"])
        self.assertEqual(rc, 0)
        self.assertIn("removed:", out)
        self.assertEqual(self.commands(), [], "no /remove or /status command was written")
        rc, out = _run(cli.cmd_shortcut, ["STATUS"])
        self.assertEqual(out.strip(), "The shortcut is not installed. Install it: /maisecrets:shortcut install NAME")
        self.assertEqual(self.commands(), [])

    def test_status_of_a_command_file_that_is_no_text_says_not_installed(self):
        (self.cfg / "commands").mkdir(parents=True)
        (self.cfg / "commands" / "ms.md").write_bytes(b"\xff\xfe not text")
        rc, out = _run(cli.cmd_shortcut, ["status"])
        self.assertEqual(rc, 0)
        self.assertIn("The shortcut is not installed", out)

    def test_status_says_incomplete_when_the_shared_wrapper_is_missing(self):
        self.assertEqual(_run(cli.cmd_shortcut, [])[0], 0)
        Path(HOME, "bin", "ms.sh").unlink()
        rc, out = _run(cli.cmd_shortcut, ["status"])
        self.assertEqual(rc, 0)
        self.assertIn("The shortcut is incomplete", out)
        self.assertIn("/maisecrets:shortcut install NAME", out)

    def test_remove_of_another_name_keeps_the_wrapper_a_shortcut_still_uses(self):
        self.assertEqual(_run(cli.cmd_shortcut, [])[0], 0)
        self.assertEqual(_run(cli.cmd_shortcut, ["remove", "other"])[0], 0)
        self.assertTrue(Path(HOME, "bin", "ms.sh").exists(), "/ms still uses the wrapper")
        self.assertEqual(self.commands(), ["ms.md"])
        self.assertEqual(_run(cli.cmd_shortcut, ["remove"])[0], 0)
        self.assertFalse(Path(HOME, "bin", "ms.sh").exists(), "no shortcut uses it any more")

    def test_remove_keeps_the_wrapper_when_a_command_file_cannot_be_read(self):
        # on any doubt the shared wrapper stays (Gate A, 2026-11-17)
        self.assertEqual(_run(cli.cmd_shortcut, [])[0], 0)
        (self.cfg / "commands" / "other.md").write_bytes(b"\xff\xfe not text")
        self.assertEqual(_run(cli.cmd_shortcut, ["remove"])[0], 0)
        self.assertTrue(Path(HOME, "bin", "ms.sh").exists())

    def test_install_with_a_name_and_remove_with_a_name(self):
        self.assertEqual(_run(cli.cmd_shortcut, ["install", "ms2"])[0], 0)
        self.assertEqual(self.commands(), ["ms2.md"])
        rc, out = _run(cli.cmd_shortcut, ["status", "ms2"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "The shortcut is installed.")
        self.assertEqual(_run(cli.cmd_shortcut, ["--remove", "ms2"])[0], 0)
        self.assertEqual(self.commands(), [])

    def test_a_name_of_two_words_or_with_signs_is_refused(self):
        victim = self.cfg / "commands" / "victim.md"
        victim.parent.mkdir(parents=True)
        victim.write_text("maisecrets/bin/ms.sh\n")
        # a word of the command counts only in the first place (Gate A, 2026-11-17)
        for args in (["bad", "name!"], ["bad!"], ["remove", "a", "b"], ["foo", "status"],
                     ["remove", "install", "victim"], ["install", "remove"], ["victim", "--remove"]):
            with self.subTest(args=args):
                rc, out = _run(cli.cmd_shortcut, args)
                self.assertEqual(rc, 2)
                self.assertIn("usage: /maisecrets:shortcut", out)
                self.assertEqual(self.commands(), ["victim.md"])


class SettingsTests(unittest.TestCase):
    def test_a_known_key_with_too_many_words_names_the_extra_word(self):
        # the prompt goes through the hook first: it must change nothing, then the command names the fault
        before = CONFIG.read_text()
        hooks.user_prompt({"prompt": "/maisecrets:settings tips off extra", "session_id": "S1", **CLAUDE})
        self.assertEqual(CONFIG.read_text(), before)
        rc, out = _run(cli.cmd_settings, ["tips", "off", "extra"])
        self.assertEqual(rc, 1)
        self.assertIn("too many words", out)
        self.assertIn("/maisecrets:settings tips VALUE", out)
        self.assertNotIn("is no setting", out)

    def test_the_host_list_with_too_many_words_names_its_own_form(self):
        rc, out = _run(cli.cmd_settings, ["ssh_autonomous_hosts", "add", "a.example.com", "b.example.com"])
        self.assertEqual(rc, 1)
        self.assertIn("/maisecrets:settings ssh_autonomous_hosts add|remove HOST as your own prompt", out)
        self.assertNotIn("VALUE", out)

    def test_codex_gets_the_codex_form(self):
        # Codex has no slash commands (Gate A, 2026-11-17)
        with mock.patch.object(cli, "_client_now", return_value="codex"):
            _rc, out = _run(cli.cmd_settings, ["tips", "off", "extra"])
            self.assertIn("Send maisecrets: set tips VALUE (one value) as your own prompt", out)
            self.assertNotIn("/maisecrets:settings", out.splitlines()[0])
            _rc, out = _run(cli.cmd_settings, ["ssh_autonomous_hosts", "add", "a.example.com", "b.example.com"])
            self.assertIn("Send maisecrets: ssh autonomous|ask HOST as your own prompt", out)

    def test_an_unknown_key_still_says_so(self):
        rc, out = _run(cli.cmd_settings, ["bogus-setting-example"])
        self.assertEqual(rc, 1)
        self.assertIn("is no setting this command shows", out)


class NerTests(unittest.TestCase):
    def setUp(self):
        CONFIG.write_text(json.dumps(TEST_CONFIG))

    def _prompt(self, text: str) -> str:
        return json.dumps(hooks.user_prompt({"prompt": text, "session_id": "S1", **CLAUDE}), ensure_ascii=False)

    def test_a_known_word_without_its_value_names_what_is_missing(self):
        before = CONFIG.read_text()
        for word, want in (("gateway", "gateway needs a server name or URL: /maisecrets:ner gateway NAME"),
                           ("url", "url needs the address of the service: /maisecrets:ner url URL"),
                           ("updates", "updates needs on or off: /maisecrets:ner updates on"),
                           ("unavailable", "unavailable needs rules or withhold: /maisecrets:ner unavailable rules"),
                           ("fallback", "fallback needs url URL or off: /maisecrets:ner fallback url URL")):
            with self.subTest(word=word):
                out = self._prompt(f"/maisecrets:ner {word}")
                self.assertIn(want, out)
                self.assertNotIn("does not know", out)
                self.assertEqual(CONFIG.read_text(), before)

    def test_gateway_without_a_value_counts_the_servers_and_names_none(self):
        # a count and the command that lists them, never a name: a name can be a stored value (Gate A, 2026-11-17)
        value = "zq7nerservervalue-not-a-secret"
        Vault().put(value, "SECRET", "manual")
        servers = {value: "https://gw.example.com/mcp", "team-gw": "https://gw.example.com/mcp"}
        with mock.patch.object(ner_setup, "_servers", return_value=servers):
            word, answer = ner_setup.typed_word("other:gateway")
        self.assertIsNone(word)
        self.assertIn("2 server(s) of your configuration can be named; /maisecrets:sref lists them.", answer)
        self.assertNotIn(value[:8], answer)
        self.assertNotIn("team-gw", answer)
        with mock.patch.object(ner_setup, "_servers", return_value={}):
            _word, answer = ner_setup.typed_word("other:gateway")
        self.assertNotIn("server(s)", answer)


class ArgumentTests(unittest.TestCase):
    """The smaller answers: a wrong argument gets one line that names it, and the next command."""

    def test_list_uses_with_a_word_names_the_list_form(self):
        rc, out = _run(cli.cmd_list, ["uses", "abc"])
        self.assertEqual(rc, 2)
        self.assertIn("usage: list uses [n]", out)
        self.assertNotIn("audit", out)

    def test_audit_with_a_negative_number_or_two_numbers_gets_the_usage(self):
        for args in (["-1"], ["0"], ["5", "6"]):
            with self.subTest(args=args):
                rc, out = _run(cli.cmd_audit, args)
                self.assertEqual((rc, out.strip()), (2, "usage: audit [n]"))

    def test_list_with_an_unknown_word_says_so_and_names_the_real_folder(self):
        rc, out = _run(cli.cmd_list, ["bogus-word"])
        self.assertEqual(rc, 0)
        self.assertIn("an unknown word follows the command; it takes uses [n]", out)
        Vault().put("list-example-value-not-a-secret", "SECRET", "manual")
        rc, out = _run(cli.cmd_list, [])
        self.assertIn(f"plaintext under {HOME}", out)
        self.assertNotIn("is no argument", out)

    def test_a_wrong_argument_is_never_echoed(self):
        # a placeholder resolves into the argument; a cut of the value is no whole value the redactor finds (Gate A)
        value = "zq7-echo-probe-value-not-a-secret"
        Vault().put(value, "SECRET", "manual")
        from maisecrets import events
        cfg = Path(tempfile.mkdtemp(prefix="maisecrets-cfg-"))
        with mock.patch.object(events, "load", return_value=[]), \
                mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(cfg)}):
            for fn in (cli.cmd_list, cli.cmd_report, cli.cmd_guard, cli.cmd_audit, cli.cmd_shortcut):
                with self.subTest(fn=fn.__name__):
                    _rc, out = _run(fn, [value])
                    self.assertNotIn(value[:8], out)
            _rc, out = _run(cli.cmd_list, ["uses", value])
            self.assertNotIn(value[:8], out)
            for fn, args in ((cli.cmd_shortcut, ["status", value[:32]]), (cli.cmd_forget, [value])):
                with self.subTest(fn=fn.__name__, args=len(args)):
                    _rc, out = _run(fn, args)
                    self.assertNotIn(value[:8], out)
            # an installed shortcut of that name: the status names neither it nor its path
            _run(cli.cmd_shortcut, ["install", value[:32]])
            _rc, out = _run(cli.cmd_shortcut, ["status", value[:32]])
            self.assertEqual(out.strip(), "The shortcut is installed.")
            self.assertNotIn(value[:8], out)
            _run(cli.cmd_shortcut, ["remove", value[:32]])
        self.assertEqual(sorted(p.name for p in (cfg / "commands").iterdir()) if (cfg / "commands").exists() else [],
                         [])

    def test_the_test_store_line_writes_a_home_under_the_users_home_with_a_tilde(self):
        Vault().put("list-tilde-example-value-not-a-secret", "SECRET", "manual")
        with mock.patch.object(Path, "home", return_value=Path(HOME).parent):
            _rc, out = _run(cli.cmd_list, [])
        self.assertIn(f"plaintext under ~/{Path(HOME).name})", out)

    def test_forget_all_names_the_two_ways_and_deletes_nothing(self):
        e = Vault().put("forget-all-example-value-not-a-secret", "SECRET", "manual")
        rc, out = _run(cli.cmd_forget, ["all"])
        self.assertEqual(rc, 1)
        self.assertIn("forget takes keys, not all", out)
        self.assertIn("wipe --yes", out)
        self.assertNotIn("There is no all", out)
        # the launcher path quoted for the shell it is pasted into (Gate A, 2026-11-17)
        with mock.patch.object(cli, "_launcher", return_value="/tmp/a folder/hooks/run.sh"), \
                mock.patch.object(cli.os, "name", "posix"):
            self.assertEqual(cli._wipe_command(), "'/tmp/a folder/hooks/run.sh' wipe --yes")
        with mock.patch.object(cli, "_launcher", return_value="C:\\a folder\\hooks\\run.cmd"), \
                mock.patch.object(cli.os, "name", "nt"):
            self.assertEqual(cli._wipe_command(), '& "C:\\a folder\\hooks\\run.cmd" wipe --yes')
        self.assertIn(e.key, [x.key for x in _live()])

    def test_forget_with_the_wrong_case_names_the_key_and_deletes_nothing(self):
        e = Vault().put("forget-case-example-value-not-a-secret", "SECRET", "manual")
        # looked up before Vault.forget, which also clears a destination record (Gate A, 2026-11-17)
        with mock.patch.object(Vault, "forget", side_effect=AssertionError("forget ran")):
            rc, out = _run(cli.cmd_forget, [e.key.lower()])
        self.assertEqual(rc, 1)
        self.assertIn(f"Did you mean {e.key}?", out)
        self.assertNotIn(e.key.lower(), out, "only the key of the index is printed")
        self.assertIn(e.key, [x.key for x in _live()])

    def test_not_a_secret_names_a_key_in_lower_case_and_changes_nothing(self):
        # a typo never loosens detection: the usage names the key, and the allow list stays (Gate A, 2026-11-17)
        from maisecrets import not_a_secret
        cmd = "/maisecrets:" + "not-a-secret"
        self.assertEqual(not_a_secret.parse(f"{cmd} secret_c12"), ("usage", "SECRET_c12"))
        self.assertEqual(not_a_secret.parse(f"{cmd} undo name_C3"), ("usage", "NAME_c3"))
        self.assertEqual(not_a_secret.parse(f"{cmd} 12"), ("usage", ""))
        e = Vault().put("nas-case-example-value-not-a-secret", "SECRET", "manual")
        out = hooks.user_prompt({"prompt": f"{cmd} {e.key.lower()}", "session_id": "S1", **CLAUDE})
        self.assertIn(f"Did you mean {e.key}?", out["reason"])
        self.assertIn(e.key, [x.key for x in _live()], "the stored value stays")
        self.assertFalse(not_a_secret.ALLOWED.exists(), "nothing is allowed")
        # a stored value in the shape of a key: the hint is built only from the index, never from the typed text
        value = "ZQSTOREDPROBEVALUE_c77"
        Vault().put(value, "SECRET", "manual")
        out = hooks.user_prompt({"prompt": f"{cmd} {value.lower()}", "session_id": "S1", **CLAUDE})
        self.assertNotIn(value, json.dumps(out))
        self.assertNotIn("Did you mean", out["reason"])

    def test_put_with_words_says_that_the_words_are_not_used(self):
        with mock.patch("maisecrets.hooks._clipboard_read", return_value="put-words-example-value-not-a-secret"), \
                mock.patch("maisecrets.hooks._clipboard", return_value=True):
            rc, out = _run(cli.cmd_put, ["--clipboard", "mein", "passwort"])
        self.assertEqual(rc, 0, out)
        self.assertIn("takes no words", out)

    def test_report_takes_bug_in_upper_case_and_names_an_unknown_form(self):
        from maisecrets import events
        with mock.patch.object(events, "load", return_value=[]):
            rc, out = _run(cli.cmd_report, ["BUG", "example", "text"])
            self.assertEqual(rc, 0)
            self.assertIn("Title:", out)
            rc, out = _run(cli.cmd_report, ["bogus"])
        self.assertIn("the first word is no form of this command", out)

    def test_guard_status_starts_with_a_verdict_and_names_an_unknown_form(self):
        cfg = Path(tempfile.mkdtemp(prefix="maisecrets-cfg-"))
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(cfg)}):
            rc, out = _run(cli.cmd_guard, [])
            self.assertEqual(out.splitlines()[0], "The guard is not installed. Install it: /maisecrets:guard install")
            self.assertNotIn("heartbeat", out)
            rc, out = _run(cli.cmd_guard, ["bogus"])
        self.assertEqual(out.splitlines()[0], "maisecrets guard: the first word is no form of this command; it takes "
                         "install [--always], remove, status or managed. Here is the status.")

    def test_run_sh_help_prints_the_help_of_the_commands(self):
        import subprocess
        for args in (["help"], ["-h"], ["--help"]):
            with self.subTest(args=args):
                r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), *args],
                                   capture_output=True, text=True, stdin=subprocess.DEVNULL)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertTrue(r.stdout.startswith("maisecrets status"), r.stdout[:200])

    def test_a_pending_prompt_that_starts_like_a_note_is_still_sent(self):
        # the templates name the two notes whole, so a prompt of the person that starts with "(maisecrets:" is no
        # note; take_pending hands it over as it is (Gate A, 2026-11-17)
        text = "(maisecrets: this is the person's own example prompt, not a note)"
        hooks._save_pending(text, "S-note-example")
        self.assertEqual(hooks.take_pending("S-note-example"), text)
        self.assertNotIn(text, (hooks.NOTHING_WAITING, hooks.TWO_WAITING))
        for template in ((ROOT / "commands" / "send.md").read_text(encoding="utf-8"), cli.SHORTCUT_COMMAND):
            joined = " ".join(template.split())
            self.assertIn(f"is exactly `{hooks.NOTHING_WAITING}` or exactly `{hooks.TWO_WAITING}`", joined)
            self.assertIn("also when it starts with `(maisecrets:`", joined)

    def test_the_send_templates_tell_the_model_to_stop_when_nothing_waits(self):
        # a check of the two templates only: what a model does with them is not tested here
        rule = "it is a note of maisecrets, not a prompt: show it to the user as is, and stop"
        self.assertIn(rule, (ROOT / "commands" / "send.md").read_text(encoding="utf-8"))
        self.assertIn(rule, cli.SHORTCUT_COMMAND)


if __name__ == "__main__":
    unittest.main()
