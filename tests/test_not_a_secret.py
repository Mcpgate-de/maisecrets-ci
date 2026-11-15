"""/maisecrets:not-a-secret KEY (maisecrets/not_a_secret.py): a value the name service or a rule found wrongly leaves
the store and goes on the person's allow list as one exact value; only the person's typed prompt does it; a key type
needs the command twice; undo takes it back. And the allow list holds for a name-service finding (remote_layer.py,
Detector.findings_with) as it holds for a rule's finding: before this change a value on the list was still masked
when the service named it.

A placeholder here is built from OPEN and CLOSE, so the file holds none. Synthetic names only.
Run: python3 -m unittest tests.test_not_a_secret -v
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
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

from maisecrets import cli, detect, hooks, not_a_secret, settings, verdict  # noqa: E402
from maisecrets.placeholder import CLOSE, OPEN  # noqa: E402
from maisecrets.user_rules import ALLOW_FILE  # noqa: E402
from maisecrets.vault import HOME, Vault, load_config  # noqa: E402
from test_remote_detector import NAME  # noqa: E402
from test_allow_list_name_service import LONGER, _ServiceBase  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

CONFIG = Path(HOME, "config.json")
KEY = re.compile(r"NAME_c\d+")
FILES = ("index.json", "vault.json", "audit.log", "events.log", "ner-rate.json", "allow.txt", "allowed.json",
         ".not-a-secret-pending.json", ".weakenings-shown")
SESSION = "S1"


def _reset(**user) -> None:
    CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True, **user}))
    for f in FILES:
        try:
            os.unlink(Path(HOME, f))
        except FileNotFoundError:
            pass
    hooks._live_cache.clear()
    detect.reset_rules()


def tearDownModule():  # noqa: N802 - unittest hook
    _reset()
    _hygiene.assert_pristine()


def _post(stdout: str, client=CLAUDE) -> dict:
    hooks._live_cache.clear()
    return hooks.post_tool({"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": SESSION, **client,
                            "tool_input": {"command": "cat notes.txt"},
                            "tool_response": {"stdout": stdout, "stderr": ""}})


def _out(answer: dict) -> str:
    return answer["hookSpecificOutput"]["updatedToolOutput"]["stdout"]


def _prompt(prompt: str, source: str | None = "user", client=CLAUDE, **extra) -> dict:
    hooks._live_cache.clear()
    payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "session_id": SESSION,
               "transcript_path": "", **client, **extra}
    if source is not None:
        payload["source"] = source
    return hooks.user_prompt(payload)


def _allow_text() -> str:
    try:
        return ALLOW_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _entries() -> dict:
    return Vault(load_config())._index["entries"]


# ------------------------------------------------------------ the typed command --
class NotASecretTests(_ServiceBase):
    def found_key(self) -> str:
        """The service names NAME in a tool result; the key it is stored under."""
        self.on()
        return KEY.search(_out(_post(f"please ask {NAME} today\n"))).group(0)

    def test_a_name_the_service_found_is_not_masked_in_the_next_prompt_or_tool_result(self):
        key = self.found_key()
        mod = {"prompt": f"write to {NAME} now", "session_id": SESSION, "origin": "composer"}
        self.assertNotIn(NAME, hooks.rewrite_prompt(dict(mod)).get("text", NAME), "premise: the mod masks it")
        out = _prompt(f"/maisecrets:not-a-secret {key}")
        self.assertEqual(out["decision"], "block")
        self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        self.assertIn(key, out["reason"])
        self.assertNotIn(NAME, out["reason"])
        self.assertNotIn(key, _entries())
        self.assertIn(NAME, _allow_text().splitlines())
        self.assertEqual(_post(f"please ask {NAME} again\n"), {}, "the next tool result")
        self.assertIn(hooks.rewrite_prompt(dict(mod)).get("text", f"write to {NAME} now"),
                      (f"write to {NAME} now",), "the next prompt the mod rewrites")
        self.assertEqual(_prompt(f"write to {NAME} now"), {}, "the next prompt")
        self.assertTrue(self.svc.received, "the service still named it")

    def test_a_hunted_name_is_not_masked_in_the_next_typed_prompt(self):
        key = self.found_key()
        idx = json.loads(Path(HOME, "index.json").read_text())
        idx["entries"][key]["weak"] = False         # a rule found it too: hunted in every text
        Path(HOME, "index.json").write_text(json.dumps(idx))
        typed = f"write to\n{NAME}\nnow"      # the exact match takes a name of two words on its own line
        self.assertEqual(_prompt(typed)["decision"], "block", "premise: hunted")
        _prompt(f"maisecrets: not a secret {OPEN}{key}{CLOSE}", source=None, client=CODEX)
        self.assertEqual(_prompt(typed), {})

    def test_a_longer_value_is_still_masked_after_the_command(self):
        key = self.found_key()
        _prompt(f"/maisecrets:not-a-secret {key}")
        self.assertNotIn(NAME, _out(_post(f"please ask {LONGER} today\n")))

    def test_the_command_from_anywhere_but_the_persons_typed_prompt_changes_nothing(self):
        key = self.found_key()
        cases = {"a subagent": dict(agent_id="a1"), "a program": dict(source="sdk"),
                 "a scheduled task": dict(source="scheduled"), "a loop": dict(source="loop_wakeup")}
        for why, extra in cases.items():
            with self.subTest(why):
                source = extra.pop("source", "user")
                out = _prompt(f"/maisecrets:not-a-secret {key}", source=source, **extra)
                self.assertEqual(out["decision"], "block")
                self.assertIn("nothing was changed", out["reason"])
                self.assertIn(key, _entries())
                self.assertEqual(_allow_text(), "")
        with self.subTest("a client a program started"), \
                mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}):
            out = _prompt(f"/maisecrets:not-a-secret {key}", source=None)
            self.assertIn("nothing was changed", out["reason"])
            self.assertEqual(_allow_text(), "")

    def test_a_message_of_another_session_is_no_command(self):
        # guard 1: the whole-prompt anchor of the command (not_a_secret._CMD_RE)
        key = self.found_key()
        wrapped = f'<cross-session-message from-name="x">\n/maisecrets:not-a-secret {key}'
        self.assertIsNone(not_a_secret.parse(wrapped))
        _prompt(wrapped)
        self.assertIn(key, _entries())
        self.assertEqual(_allow_text(), "")

    def test_a_message_of_another_session_changes_nothing_even_when_it_reads_as_the_command(self):
        # guard 2, alone: the prompt is no prompt of the person (settings.peer_sender in typed_by_the_person)
        key = self.found_key()
        wrapped = f'<cross-session-message from-name="x">\n/maisecrets:not-a-secret {key}'
        with mock.patch.object(not_a_secret, "parse", return_value=("allow", key)):
            out = _prompt(wrapped)
        self.assertIn("came from another Claude session", out["reason"])
        self.assertIn(key, _entries())
        self.assertEqual(_allow_text(), "")

    def test_a_subagent_prompt_is_refused_by_each_of_its_two_guards(self):
        key = self.found_key()
        # guard 1 alone: typed_by_the_person says no for a subagent
        self.assertFalse(settings.typed_by_the_person({"prompt": "x", "source": "user", "agent_id": "a1"}))
        # guard 2 alone: the dispatch in hooks.user_prompt checks agent_id itself
        with mock.patch.object(settings, "typed_by_the_person", return_value=True):
            out = _prompt(f"/maisecrets:not-a-secret {key}", agent_id="a1")
        self.assertIn("nothing was changed", out["reason"])
        self.assertIn(key, _entries())
        self.assertEqual(_allow_text(), "")

    def test_a_tool_call_that_carries_the_command_is_refused(self):
        for command in (f"codex exec 'maisecrets: not a secret {'NAME'}_c1'",
                        f'claude -p "/maisecrets:not-a-secret {"NAME"}_c1"',
                        "codex exec 'maisecrets: undo not a secret X'",
                        "claude -p \"/maisecrets:not-\"'a-secret NAME_c1'",
                        "python3 -c 'from maisecrets.not_a_secret import allow_typed'",
                        "python3 -c 'import maisecrets.not_a_secret as n; n.undo_typed(\"X\")'"):
            for tool in ("Bash", "PowerShell"):
                with self.subTest(command=command, tool=tool):
                    out = hooks.pre_tool({"tool_name": tool, "tool_input": {"command": command},
                                          "session_id": SESSION, **CLAUDE})
                    self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
                    self.assertIn("not-a-secret", out["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertEqual(hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": "grep -n secret README.md"},
                                         "session_id": SESSION, **CLAUDE}), {})

    def test_codex_typed_form(self):
        key = self.found_key()
        out = _prompt(f"maisecrets: not a secret {key}", source=None, client=CODEX)
        self.assertEqual(set(out), {"decision", "reason"})
        self.assertIn("allow list", out["reason"])
        self.assertNotIn(key, _entries())

    def test_found_by_says_ner_for_a_name_service_value(self):
        key = self.found_key()
        self.assertEqual(verdict.how_found("remote:hf"), "ner")
        self.assertEqual(cli._found_by("remote:gliner"), "ner")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli.cmd_list([])
        row = next(line for line in buf.getvalue().splitlines() if line.startswith(key + " "))
        self.assertRegex(row, r"\bner\b")

    def test_a_key_type_needs_the_command_twice(self):
        v = Vault(load_config())
        value = "Kolibri-Laterne-" + "4711"
        e = v.put(value, "SECRET", "generic-api-key", session=SESSION)
        first = _prompt(f"/maisecrets:not-a-secret {e.key}")
        self.assertIn("Type the command again", first["reason"])
        self.assertIn(e.key, _entries())
        self.assertEqual(_allow_text(), "")
        other = _prompt(f"/maisecrets:not-a-secret {e.key}", **{"session_id": "S2"})
        self.assertIn("Type the command again", other["reason"], "another session confirms nothing")
        _prompt(f"/maisecrets:not-a-secret {e.key}")                  # the first one in this session again
        later = time.time() + not_a_secret.CONFIRM_SECONDS + 5
        with mock.patch.object(time, "time", return_value=later):
            late = _prompt(f"/maisecrets:not-a-secret {e.key}")
        self.assertIn("Type the command again", late["reason"], "too late: it asks again")
        self.assertIn(e.key, _entries())
        with mock.patch.object(time, "time", return_value=later + 30):
            done = _prompt(f"/maisecrets:not-a-secret {e.key}")
        self.assertIn("allow list", done["reason"])
        self.assertNotIn(value, done["reason"])
        self.assertIn(value, _allow_text().splitlines())

    def test_a_name_needs_no_second_command(self):
        self.assertFalse(not_a_secret.needs_confirmation("NAME"))
        self.assertFalse(not_a_secret.needs_confirmation("EMAIL"))
        for t in ("SECRET", "CARD", "IBAN", "DE_TAX_ID", "US_BANK_NUMBER", "AU_TFN", "MY_OWN_TYPE"):
            self.assertTrue(not_a_secret.needs_confirmation(t), t)

    def test_undo_takes_the_allowance_back_and_the_value_is_masked_again(self):
        key = self.found_key()
        ALLOW_FILE.write_text("# mine\nkept-value\n", encoding="utf-8")
        _prompt(f"/maisecrets:not-a-secret {key}")
        with open(ALLOW_FILE, "a", encoding="utf-8") as f:
            f.write("later-value\n")                      # a line the person adds below it later
        self.assertEqual(_post(f"please ask {NAME} again\n"), {})
        out = _prompt(f"/maisecrets:not-a-secret undo {key}")
        self.assertIn("taken back", out["reason"])
        self.assertEqual(_allow_text(), "# mine\nkept-value\nlater-value\n", "the person's own lines stay")
        self.assertEqual(not_a_secret.records(), {})
        self.assertNotIn(NAME, _out(_post(f"please ask {NAME} again\n")), "detected again, masked again")
        again = _prompt(f"maisecrets: undo not a secret {key}", source=None, client=CODEX)
        self.assertIn("there is no allowance", again["reason"])

    def test_undo_works_after_a_wipe_of_the_store(self):
        key = self.found_key()
        _prompt(f"/maisecrets:not-a-secret {key}")
        for f in ("index.json", "vault.json"):          # a wipe: a new fingerprint key, new counters
            Path(HOME, f).unlink()
        out = _prompt(f"/maisecrets:not-a-secret undo {key}")
        self.assertIn("taken back", out["reason"])
        self.assertNotIn(NAME, _allow_text())

    def test_undo_without_its_comment_line_changes_nothing_and_says_so(self):
        key = self.found_key()
        _prompt(f"/maisecrets:not-a-secret {key}")
        ALLOW_FILE.write_text("".join(f"{x}\n" for x in _allow_text().splitlines() if not x.startswith("#")),
                              encoding="utf-8")
        out = _prompt(f"/maisecrets:not-a-secret undo {key}")
        self.assertIn("still on your allow list and is not masked", out["reason"])
        self.assertNotIn("masks the value again", out["reason"])
        self.assertIn(NAME, _allow_text().splitlines())
        self.assertIn(key, not_a_secret.records(), "kept: the person can finish it")
        self.assertEqual(_post(f"please ask {NAME} again\n"), {}, "the answer is true: not masked")
        ALLOW_FILE.write_text("", encoding="utf-8")       # the person deletes the line by hand
        done = _prompt(f"/maisecrets:not-a-secret undo {key}")
        self.assertIn("taken back", done["reason"])
        self.assertEqual(not_a_secret.records(), {})

    def test_undo_deletes_only_the_line_directly_under_its_comment(self):
        key = self.found_key()
        _prompt(f"/maisecrets:not-a-secret {key}")
        mark, value = _allow_text().splitlines()
        ALLOW_FILE.write_text(f"{mark}\nmine-below-the-comment\n{value}\n", encoding="utf-8")
        out = _prompt(f"/maisecrets:not-a-secret undo {key}")
        self.assertIn("Nothing was changed", out["reason"])
        self.assertIn("mine-below-the-comment", _allow_text())
        self.assertIn(key, not_a_secret.records())

    def test_a_value_the_person_allowed_before_gets_no_record_and_keeps_its_line(self):
        key = self.found_key()
        ALLOW_FILE.write_text(f"{NAME}\n", encoding="utf-8")
        detect.reset_rules()
        out = _prompt(f"/maisecrets:not-a-secret {key}")
        self.assertIn("a line you wrote", out["reason"])
        self.assertNotIn(key, _entries())
        self.assertEqual(_allow_text(), f"{NAME}\n", "not written twice")
        self.assertEqual(not_a_secret.records(), {})
        self.assertIn("there is no allowance", _prompt(f"/maisecrets:not-a-secret undo {key}")["reason"])
        self.assertEqual(_allow_text(), f"{NAME}\n")

    @unittest.skipIf(os.name == "nt", "a symlink needs rights on Windows")
    def test_a_key_type_is_not_written_through_a_link_out_of_the_home(self):
        v = Vault(load_config())
        value = "Kolibri-Laterne-" + "4711"
        e = v.put(value, "SECRET", "generic-api-key", session=SESSION)
        outside = Path(tempfile.mkdtemp(prefix="nas-team-"), "team-allow.txt")
        outside.write_text("# team\n", encoding="utf-8")
        self.addCleanup(lambda: outside.unlink())
        ALLOW_FILE.symlink_to(outside)
        for _ in range(2):
            out = _prompt(f"/maisecrets:not-a-secret {e.key}")
            self.assertIn("outside the maisecrets folder", out["reason"])
        self.assertEqual(outside.read_text(encoding="utf-8"), "# team\n")
        self.assertIn(e.key, _entries())
        inside = Path(HOME, "lists", "allow-real.txt")       # a link inside the maisecrets folder is fine
        inside.parent.mkdir(exist_ok=True)
        inside.write_text("", encoding="utf-8")
        self.addCleanup(lambda: inside.unlink())
        ALLOW_FILE.unlink()
        ALLOW_FILE.symlink_to(inside)
        _prompt(f"/maisecrets:not-a-secret {e.key}")
        self.assertIn("allow list", _prompt(f"/maisecrets:not-a-secret {e.key}")["reason"])
        self.assertIn(value, inside.read_text(encoding="utf-8").splitlines())
        ALLOW_FILE.unlink()
        ALLOW_FILE.symlink_to(outside)
        name = self.found_key()           # a name is no key type: it may go there
        self.assertIn("allow list", _prompt(f"/maisecrets:not-a-secret {name}")["reason"])
        self.assertIn(NAME, outside.read_text(encoding="utf-8"))

    def test_undo_from_anywhere_but_the_persons_typed_prompt_changes_nothing(self):
        key = self.found_key()
        _prompt(f"/maisecrets:not-a-secret {key}")
        out = _prompt(f"/maisecrets:not-a-secret undo {key}", agent_id="a1")
        self.assertIn("nothing was changed", out["reason"])
        self.assertIn(NAME, _allow_text())

    def test_the_list_shows_the_allowance_without_the_value(self):
        key = self.found_key()
        _prompt(f"/maisecrets:not-a-secret {key}")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli.cmd_list([])
        text = buf.getvalue()
        self.assertIn("Allowed by you with /maisecrets:not-a-secret (1)", text)
        row = next(line for line in text.splitlines() if line.startswith(key + " "))
        self.assertIn(time.strftime("%Y-%m-%d"), row)
        self.assertNotIn(NAME, text)
        for f in ("allowed.json", "events.log", "index.json"):
            self.assertNotIn(NAME, Path(HOME, f).read_text(encoding="utf-8"), f)

    def test_the_masking_line_has_one_hint(self):
        self.on()
        one = _post(f"please ask {NAME} today\n")
        self.assertRegex(one["systemMessage"], r"Wrong\? Type /maisecrets:not-a-secret NAME_c\d+\Z")
        many = _post(f"ask {NAME} and {LONGER}\n")
        self.assertEqual(many["systemMessage"].count("Wrong?"), 1)
        self.assertTrue(many["systemMessage"].endswith("Wrong? Type /maisecrets:not-a-secret KEY"))
        self.assertNotIn("Wrong?", _post(f"please ask {NAME} today\n", client=CODEX).get("reason", ""))

    def test_no_hint_for_a_key_type(self):
        v = Vault(load_config())
        value = "Kolibri-Laterne-" + "4711"
        e = v.put(value, "SECRET", "generic-api-key", session=SESSION)
        out = _post(f"token {value}\n")
        self.assertIn(e.key, out["systemMessage"], "premise: masked and named")
        self.assertNotIn("Wrong?", out["systemMessage"])

    def test_a_value_the_allow_list_cannot_hold_a_term_and_an_expired_value_change_nothing(self):
        v = Vault(load_config())
        hashed = v.put("#Kolibri Laterne", "NAME", "remote:hf", session=SESSION)
        term = v.put("Kolibri Laterne", "NAME", "term:e1", session=SESSION)
        old = v.put("Laterne Kolibri", "NAME", "remote:hf", session=SESSION)
        idx = json.loads(Path(HOME, "index.json").read_text())
        idx["entries"][old.key]["expires"] = time.time() - 10
        Path(HOME, "index.json").write_text(json.dumps(idx))
        for e, says in ((hashed, "cannot be one line"), (term, "term list"), (old, "has expired")):
            with self.subTest(says):
                out = _prompt(f"/maisecrets:not-a-secret {e.key}")
                self.assertIn(says, out["reason"])
                self.assertIn("Nothing was changed", out["reason"])
                self.assertIn(e.key, _entries())
                self.assertEqual(_allow_text(), "")
                self.assertEqual(not_a_secret.records(), {})

    def test_usage_and_unknown_keys(self):
        self.assertIn("name one stored value", _prompt("/maisecrets:not-a-secret")["reason"])
        self.assertIn("name one stored value", _prompt("/maisecrets:not-a-secret two words")["reason"])
        self.assertIn("there is no stored value NAME_c999", _prompt("/maisecrets:not-a-secret NAME_c999")["reason"])

    def test_parse(self):
        p = not_a_secret.parse
        self.assertEqual(p("/maisecrets:not-a-secret NAME_c12"), ("allow", "NAME_c12"))
        self.assertEqual(p(f"  maisecrets: not a secret {OPEN}NAME_c12:J***{CLOSE}  "), ("allow", "NAME_c12"))
        self.assertEqual(p("/maisecrets:not-a-secret undo NAME_c12-2"), ("undo", "NAME_c12-2"))
        self.assertEqual(p("maisecrets: undo not a secret NAME_c12."), ("undo", "NAME_c12"))
        self.assertIsNone(p("is NAME_c12 not a secret?"))
        self.assertIsNone(p("maisecrets: not a secret NAME_c12\nand more"))


if __name__ == "__main__":
    unittest.main()
