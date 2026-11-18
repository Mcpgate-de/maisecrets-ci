"""The /maisecrets panel (maisecrets/hub.py, `hooks/dispatch.py mod-settings`): each action enforces the checks of the
typed path, no answer holds a stored value, and a tool call that names the entry is refused (C22)."""
from __future__ import annotations

import json
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import events, hooks, hub, not_a_secret, selftest, settings  # noqa: E402
from maisecrets.home import HOME  # noqa: E402
from maisecrets.vault import CONFIG, Vault, load_config  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
ENTRY = "mod-" + "settings"
TEST_CONFIG = {"backend": "jsonfile", "allow_plaintext_store": True}
# values that name themselves: no detector stores them by accident; this file stores them on purpose
TOKEN = "my-test-token-" + "4711"
MAIL = "someone" + "@example.com"


def _reset(**user) -> None:
    CONFIG.write_text(json.dumps({**TEST_CONFIG, **user}), encoding="utf-8")
    v = Vault()
    for e in v.list():
        v.forget(e.key)
    for f in (not_a_secret.ALLOWED, not_a_secret.PENDING):
        try:
            Path(f).unlink()
        except OSError:
            pass


def _user() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def _store() -> tuple[str, str]:
    v = Vault()
    return v.put(TOKEN, "SECRET", "manual", session="S1").key, v.put(MAIL, "EMAIL", "manual", session="S1").key


def ask(**question) -> dict:
    return hub.mod_answer(question)


def entry(question) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), ENTRY],
                          input=question if isinstance(question, str) else json.dumps(question),
                          capture_output=True, text=True, timeout=60)


class SetTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_a_listed_setting_takes_one_of_its_choices(self):
        out = ask(action="set", key="rehydration", value="confirm")
        self.assertTrue(out["note"].startswith("Saved."))
        self.assertEqual(_user()["rehydration"], "confirm")
        row = next(i for g in out["groups"] for i in g["items"] if i["key"] == "rehydration")
        self.assertEqual((row["value"], row["mark"]), ("confirm", "✎"))

    def test_a_key_off_the_panel_a_value_off_the_list_and_a_bad_key_change_nothing(self):
        for key, value in (("scrub_transcript", "off"), ("max_keys_per_session", "999999"), ("backend", "keychain"),
                           ("rehydration", "never"), ("ttl_seconds", "3d"), ("regions", "xx"),
                           ("rehydration\nx", "block"), ("../config", "on"), ("", "")):
            with self.subTest((key, value)):
                out = ask(action="set", key=key, value=value)
                self.assertEqual(out["note"], "That setting cannot be changed here.")
                self.assertEqual(_user(), TEST_CONFIG)

    def test_a_policy_value_is_locked(self):
        with mock.patch.object(settings, "load_config", return_value={**load_config(), "policy_keys": ["rehydration"]}):
            out = ask(action="set", key="rehydration", value="automatic")
        self.assertIn("set by your administrator's policy", out["note"])
        self.assertNotIn("rehydration", _user())
        with mock.patch.object(hub, "load_config", return_value={**load_config(), "policy_keys": ["read_pdf"]}):
            row = next(i for g in hub.pane_rows(show_all=True) for i in g["items"] if i["key"] == "read_pdf")
        self.assertEqual((row["locked"], row["mark"]), (True, "⚙"))

    def test_a_loosening_from_the_panel_is_named_at_the_next_start(self):
        with mock.patch.object(events, "record_weakening") as record:
            ask(action="set", key="rehydration", value="confirm")
            record.assert_not_called()
            ask(action="set", key="rehydration", value="automatic")
        record.assert_called_once_with("setting", "rehydration", hub.PANE_ROUTE)

    def test_a_country_toggles_and_auto_clears_the_others(self):
        for code in ("de", "fr", "de"):
            ask(action="set", key="regions", value=code)
        self.assertEqual(_user()["regions"], ["fr"])
        ask(action="set", key="regions", value="auto")
        self.assertEqual(_user()["regions"], ["auto"])

    def test_all_rows_and_none_of_the_hidden_ones(self):
        keys = [i["key"] for g in ask(action="list")["groups"] for i in g["items"]]
        self.assertEqual(keys[:7], ["ssh_consent", "secret_destinations", "rehydration", "read_pdf", "read_image",
                                    "show_values", "tips"])
        self.assertEqual(keys[-1], "regions", "the countries are the last group")
        for hidden in settings.NOT_LISTED:
            self.assertNotIn(hidden, keys)


class ValuesTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_the_rows_hold_keys_and_masked_forms_and_never_a_value(self):
        _store()
        for question in ({"action": "values"}, {"action": "values", "offset": 0}, {"action": "list"},
                         {"action": "status", "session_id": "S1"}, {"action": "ner"}):
            with self.subTest(question):
                text = json.dumps(hub.mod_answer(question), ensure_ascii=False)
                self.assertNotIn(TOKEN, text)
                self.assertNotIn(MAIL, text)
        rows = ask(action="values")["rows"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(set(rows[0]), {"key", "type", "shown", "age", "uses", "expires", "live"})

    def test_a_page_is_twenty_rows_and_a_bad_offset_is_the_first_page(self):
        v = Vault()
        for i in range(25):
            v.put(f"my-test-token-{i:03d}", "SECRET", "manual", session="S1")
        self.assertEqual(len(ask(action="values")["rows"]), 20)
        self.assertEqual(len(ask(action="values", offset=20)["rows"]), 5)
        for bad in (-5, "20", True, None):
            self.assertEqual(ask(action="values", offset=bad)["offset"], 0)

    def test_forget_takes_a_key_of_the_shape_list_shows(self):
        key, _mail = _store()
        for bad in ("x; rm -rf ~", "SECRET_c1 SECRET_c2", "import:abc", "", "secret_c1"):
            with self.subTest(bad):
                self.assertEqual(ask(action="forget", key=bad)["note"], "That is no key.")
        self.assertEqual(ask(action="forget", key="SECRET_c999")["note"], "There is no SECRET_c999.")
        with mock.patch.object(events, "record_weakening") as record:
            out = ask(action="forget", key=key)
        self.assertTrue(out["note"].startswith(f"Forgot {key}."))
        record.assert_called_once_with("forget", key, hub.PANE_ROUTE, True)
        self.assertNotIn(key, [r["key"] for r in out["rows"]])

    def test_a_key_type_on_the_allow_list_needs_both_steps_of_this_session(self):
        key, mail = _store()
        out = ask(action="allow", key=key, session_id="S1")
        self.assertIn("Type the command again", out["note"], "the second step alone changes nothing")
        self.assertIn(key, [r["key"] for r in out["rows"]])
        ask(action="allow_ask", key=key, session_id="S1")
        self.assertIn("Type the command again", ask(action="allow", key=key, session_id="S2")["note"],
                      "the first step of another session does not count")
        ask(action="allow_ask", key=key, session_id="S1")
        out = ask(action="allow", key=key, session_id="S1")
        self.assertIn("allow list", out["note"])
        self.assertNotIn(TOKEN, json.dumps(out, ensure_ascii=False))
        # personal data that opens nothing takes one step, as the typed path does
        self.assertIn("allow list", ask(action="allow", key=mail, session_id="S1")["note"])

    def test_forget_all_needs_the_panels_sentence(self):
        _store()
        out = ask(action="forget_all")
        self.assertIn("Nothing was forgotten", out["note"])
        self.assertEqual(out["total"], 2)
        self.assertEqual(ask(action="forget_all", confirm="yes")["total"], 2)
        logs = {name: f"a line of {name}\n" for name in ("audit.log", "hooks.log", "events.log", "allow.txt")}
        for name, text in logs.items():
            (hub.HOME / name).write_text(text, encoding="utf-8")
        out = ask(action="forget_all", confirm=hub.WIPE_CONFIRM)
        self.assertEqual(out["note"], "Forgot 2 stored value(s). The logs and records stay.")
        self.assertEqual(out["total"], 0)
        for name, text in logs.items():
            self.assertTrue((hub.HOME / name).read_text(encoding="utf-8").startswith(text),
                            f"{name} stays: the full wipe is the terminal's")
        self.assertEqual((hub.HOME / "events.log").read_text(encoding="utf-8").count('"forget"'), 2,
                         "each forgotten value writes its line, as a single forget does")


class NameServiceTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_only_off_local_and_a_named_server_are_set_here(self):
        for value in ("url:http://10.0.0.1:8765/", "gateway:https://evil.example.com/", "gateway:", "gateway:a b",
                      "fallback:url:http://x", "on", ""):
            with self.subTest(value):
                self.assertEqual(ask(action="ner_set", value=value)["note"], "That source cannot be set here.")
        self.assertNotIn("remote_detector", _user())
        out = ask(action="ner_set", value="gateway:no-such-server")
        self.assertIn("no MCP server", out["note"])
        self.assertNotIn("remote_detector", _user())

    def test_a_named_server_becomes_its_address_and_asks_for_the_login(self):
        servers = {"team-gw": "https://gw.example.com/mcp"}
        with mock.patch("maisecrets.ner_setup._servers", return_value=servers), \
                mock.patch("maisecrets.ner_setup.check_url", return_value=""):
            out = ask(action="ner_set", value="gateway:team-gw")
        self.assertEqual(out.get("login"), "team-gw")
        self.assertTrue(_user()["remote_detector"].get("url", "").startswith("https://gw.example.com"))

    def test_local_starts_the_container_in_the_background_with_a_fixed_command(self):
        with mock.patch("subprocess.Popen") as popen:
            out = ask(action="ner_set", value="local")
        self.assertTrue(out.get("starting"))
        (call,) = [c for c in popen.call_args_list if "maisecrets.cli" in c.args[0]]
        self.assertEqual(call.args[0][1:], ["-m", "maisecrets.cli", "ner", "start"])
        self.assertTrue(call.kwargs.get("start_new_session"))
        ask(action="ner_set", value="off")

    def test_a_policy_source_is_locked(self):
        with mock.patch.object(settings, "load_config",
                               return_value={**load_config(), "policy_keys": ["remote_detector"]}), \
                mock.patch("subprocess.Popen") as popen:
            out = ask(action="ner_set", value="local")
        self.assertIn("policy", out["note"])
        self.assertFalse([c for c in popen.call_args_list if "maisecrets.cli" in c.args[0]])
        self.assertNotIn("remote_detector", _user())


class EntryTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_the_entry_answers_json_and_a_broken_question_answers_nothing(self):
        r = entry({"action": "list"})
        self.assertEqual((r.returncode, json.loads(r.stdout)["maisecrets"]), (0, ENTRY))
        for broken in ("not json", "[1, 2]"):
            with self.subTest(broken):
                r = entry(broken)
                self.assertIn(r.returncode, (0, 1))
                self.assertNotIn("Traceback", r.stdout + r.stderr)



class StatusTests(unittest.TestCase):
    """The panel's status line: no row of this session in hooks.log is no proof that a hook failed (a session has
    none before its first tool call); only a positive signal of a failure, the self-test, says NOT protecting."""

    def setUp(self):
        _reset()
        for name in ("hooks.log", selftest.FILE):
            try:
                (HOME / name).unlink()
            except OSError:
                pass

    def _hooks_note(self, out):
        return [n for n in out["notes"] if n["name"] == "hooks"]

    def test_a_session_with_no_row_yet_is_protected_with_a_note_on_the_hooks(self):
        out = ask(action="status", session_id="no-row-yet")
        self.assertIn("protects this session", out["line"])
        self.assertNotIn("NOT protecting", out["line"])
        self.assertEqual(self._hooks_note(out),
                         [{"name": "hooks", "fact": "not seen in this session yet", "next": "/maisecrets:status"}])

    def test_a_session_whose_hook_ran_has_no_note_on_the_hooks(self):
        hooks._run_log("session-start", {"session_id": "ran-once"}, "answer", "pass", 0)
        out = ask(action="status", session_id="ran-once")
        self.assertIn("protects this session", out["line"])
        self.assertEqual(self._hooks_note(out), [])

    def _row(self, event, session, at):
        # a hooks.log row as hooks._run_log writes it, at a given time
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(at))
        with open(HOME / "hooks.log", "a", encoding="utf-8") as f:
            f.write(f"{stamp}\t{event}\tclaude\t{session}\tBash\tpass\t1ms\tanswer\n")

    def _fails(self, session, call_at):
        out = ask(action="status", session_id=session, tool_call_at=call_at)
        return "NOT protecting" in out["line"] and "(hooks)" in out["line"]

    def test_a_tool_call_the_mod_saw_with_no_row_at_all_says_not_protecting(self):
        self.assertTrue(self._fails("no-row-yet", time.time() - 10))

    def test_a_session_start_row_then_a_tool_call_with_no_row_says_not_protecting(self):
        self._row("session-start", "S-start", time.time() - 60)
        self.assertTrue(self._fails("S-start", time.time() - 10))

    def test_an_old_tool_call_row_then_a_tool_call_with_no_row_says_not_protecting(self):
        self._row("user-prompt", "S-stale", time.time() - 120)
        self._row("pre-tool", "S-stale", time.time() - 60)
        self.assertTrue(self._fails("S-stale", time.time() - 10))

    def test_a_tool_call_row_at_the_call_says_protects(self):
        call = time.time() - 10
        self._row("pre-tool", "S-fresh", call)
        self.assertFalse(self._fails("S-fresh", call))
        # the row has whole seconds: a call that started late in the second of its row still counts
        self.assertFalse(self._fails("S-fresh", int(call) + 0.9))

    def test_a_tool_call_row_of_the_second_before_the_call_says_not_protecting(self):
        call = float(int(time.time()) - 10)
        self._row("pre-tool", "S-before", call - 1)
        self.assertTrue(self._fails("S-before", call))

    def test_a_tool_call_inside_the_grace_time_is_no_failure_yet(self):
        self._row("pre-tool", "S-grace", time.time() - 60)
        self.assertFalse(self._fails("S-grace", time.time() - hub.TOOL_CALL_GRACE / 4))

    def test_a_time_of_the_wrong_type_is_ignored(self):
        for odd in (True, -1, "5", None, float("inf"), 1e12):
            with self.subTest(tool_call_at=odd):
                self.assertFalse(self._fails("no-row-yet", odd))

    def test_a_failed_self_test_says_not_protecting(self):
        # the prompt hook stopped the test value, and no tool-result hook masked it: the tool path failed
        (HOME / selftest.FILE).write_text(json.dumps({"result": {"prompt": time.time() - 5}}), encoding="utf-8")
        out = ask(action="status", session_id="no-row-yet")
        self.assertIn("NOT protecting", out["line"])
        self.assertIn("(self-test)", out["line"])
        self.assertNotIn("hooks", out["line"])



class CommandNamesTests(unittest.TestCase):
    def test_the_mod_knows_each_command_of_the_plugin(self):
        """`/maisecrets WORD` means `/maisecrets:WORD` for each command file, and for nothing else."""
        import re
        mod = (ROOT / "claude-mod" / "maisecrets-mod.mjs").read_text(encoding="utf-8")
        listed = re.search(r"const COMMANDS = \[([^\]]*)\]", mod)
        self.assertIsNotNone(listed)
        self.assertEqual(sorted(re.findall(r"'([a-z-]+)'", listed.group(1))),
                         sorted(f.stem for f in (ROOT / "commands").glob("*.md")))

# every action the panel sends, as a tool call would write it: none may run (C22)
ACTIONS = [{"action": "set", "key": "rehydration", "value": "automatic"},
           {"action": "forget", "key": "SECRET_c1"}, {"action": "allow_ask", "key": "SECRET_c1"},
           {"action": "allow", "key": "SECRET_c1"}, {"action": "forget_all", "confirm": "forget every stored value"},
           {"action": "ner_set", "value": "local"}, {"action": "values"}, {"action": "list"}, {"action": "ner"},
           {"action": "status", "session_id": "S1"}]


class ToolCallTests(unittest.TestCase):
    def test_each_action_of_the_panel_is_refused_from_a_tool_call(self):
        for q in ACTIONS:
            body = json.dumps(q)
            for tool, command in (
                    ("Bash", f"echo '{body}' | python3 hooks/dispatch.py {ENTRY}"),
                    ("Bash", f"bash \"/p/hooks/run.sh\" {ENTRY} <<'X'\n{body}\nX"),
                    ("Bash", f"python3 /p/hooks/dispatch.py {ENTRY} < q.json"),
                    ("PowerShell", f"'{body}' | & \"C:\\p\\hooks\\run.cmd\" {ENTRY}")):
                with self.subTest((q["action"], tool, command[:40])):
                    self.assertEqual(hooks._store_read_match(command), "the mod's values")
                    out = hooks.pre_tool({"tool_name": tool, "tool_input": {"command": command}, "session_id": "S1",
                                          **CLAUDE})
                    self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny", out)

    def test_each_mod_entry_in_a_quoted_form_bash_hands_over_is_refused(self):
        # ANSI-C ($'…') and locale ($"…") quoting, split quotes and backslashes: bash hands the plain name to
        # dispatch.py, so the check reads the words as bash does. A name built at run time ($E) is C22's limit
        for entry in ("mod-prompt", "mod-values", "mod-reveal", "mod-settings", "mod-demo"):
            head, tail = entry.split("-")
            for form in (f"$'{entry}'", f'$"{entry}"', f"$'{head}\\x2d{tail}'", f"$'{head}\\055{tail}'",
                         f"{head[0]}'{head[1:]}-{tail}'", f'"{head}"-{tail}', f"{head}\\-{tail}",
                         f"$'{head}'-\"{tail}\""):
                for runner in ("python3 hooks/dispatch.py", 'bash "/p/hooks/run.sh"'):
                    command = f"echo '{{}}' | {runner} {form}"
                    with self.subTest(command):
                        out = hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": command},
                                              "session_id": "S1", **CLAUDE})
                        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny", out)
        for harmless in ("echo $'mod-settings'", "printf '%s' mod-settings", "python3 tools/other.py $'mod-settings'",
                         "printf '%s\\n' hooks/dispatch.py \"$'mod-settings'\"",
                         'printf "%s" "dispatch.py $\'mod-values\'"'):
            with self.subTest(harmless):
                out = hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": harmless}, "session_id": "S1",
                                      **CLAUDE})
                self.assertNotEqual((out.get("hookSpecificOutput") or {}).get("permissionDecision"), "deny", out)

    def test_a_mention_in_a_text_that_only_prints_is_no_call(self):
        self.assertIsNone(hooks._store_read_match("echo the mod-settings docs"))


if __name__ == "__main__":
    unittest.main()
