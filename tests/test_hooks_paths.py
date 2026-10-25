"""hooks.py paths the gate tests do not reach: the fail-closed answers per event and client, the
single answer of `main`, Codex and Claude answer shapes, nested redaction, the transcript scrub
on large and malformed files, the @file block, the pending prompt, the file tools, MCP asks,
the Windows grant path, the run dir and the run log; and a payload shape matrix through the
real entry point `hooks/dispatch.py`.

Every value is generated here. The store is always the plaintext test file in a temp
MAISECRETS_HOME whose config.json names the jsonfile backend BEFORE anything is imported or
started: a process that falls back to the Keychain backend opens a macOS dialog.
"""
from __future__ import annotations

import base64
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

JSONFILE_CFG = '{"backend": "jsonfile", "allow_plaintext_store": true}'
# the vault home is fixed at the first import of maisecrets.vault (another test module may have
# imported it first); every subprocess below gets the same home, so it is taken from there
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text(JSONFILE_CFG)

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import HOME, ConfigError, Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

_TMP = str(HOME)


def tearDownModule():  # noqa: N802 - unittest hook
    _hygiene.assert_pristine()
    # the children a hook subprocess started run with its working directory, under the temp dir
    alive = _hygiene.wait_for_no_serving_child(cwd_root=_isolate.TMP)
    if alive:
        raise AssertionError(f"value-serving children still run after the module: {alive}")

# captured at import, before another module replaces hooks._clipboard with a lambda
_CLIPBOARD = hooks._clipboard
_CLIPBOARD_READ = hooks._clipboard_read

BASH = shutil.which("bash")
PLAIN = "paths-plain-value-" + "3141"
NASTY = "pa$s'w\"ord`x $(echo no) y\\z"
GLPAT = "glpat-" + "Pq7Rs8Tu9Vw0Xy1Za2Bc"


def _cfg(extra: dict | None = None) -> None:
    cfg = json.loads(JSONFILE_CFG)
    cfg.update(extra or {})
    Path(_TMP, "config.json").write_text(json.dumps(cfg))


def _reset() -> None:
    _cfg()
    for f in ("index.json", "vault.json", "audit.log", "hooks.log"):
        try:
            os.unlink(Path(_TMP, f))
        except FileNotFoundError:
            pass
    shutil.rmtree(Path(_TMP, "pending"), ignore_errors=True)
    hooks._live_cache.clear()


def _marked(payload: dict, extra: dict) -> dict:
    """The payload with its client marker: the caller's prompt_id or turn_id, else Claude's."""
    if not {"prompt_id", "turn_id"} & extra.keys():
        payload.update(CLAUDE)
    payload.update(extra)
    return payload


def _bash_pre(command: str, session: str = "S1", **extra) -> dict:
    return hooks.pre_tool(_marked({"tool_name": "Bash", "tool_input": {"command": command}, "session_id": session},
                                  extra))


def _run(command: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.run([BASH, "-c", command], capture_output=True, text=True, env=env, timeout=30)


def _hso(out: dict) -> dict:
    return out.get("hookSpecificOutput") or {}


# ------------------------------------------------------------------ fail closed --
class FailClosedAnswerTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_fail_closed_answer_per_event_and_client(self):
        for client, payload in (("claude", {"prompt_id": "p"}), ("codex", {"turn_id": "t"})):
            with self.subTest(client=client):
                up = hooks._fail_closed("user-prompt", payload, "x")
                self.assertEqual(up["decision"], "block")
                # the person reads it: no event id, no "tell the user", one next step
                self.assertTrue(up["reason"].startswith("maisecrets could not check this prompt: x It was not sent. "
                                                        "Send it again. If this comes again, "), up["reason"])
                self.assertNotIn("user-prompt", up["reason"])
                self.assertNotIn("tell the user", up["reason"])
                if client == "claude":
                    self.assertTrue(up["hookSpecificOutput"]["suppressOriginalPrompt"])
                else:
                    self.assertNotIn("hookSpecificOutput", up, "Codex rejects a Claude-only field")
                up = hooks._fail_closed("user-prompt", payload, "x", hint=False)
                self.assertIn("It was not sent. Fix the cause, then send it again.", up["reason"])
                pre = hooks._fail_closed("pre-tool", payload, "x", hint=False)["hookSpecificOutput"]
                self.assertEqual(pre["permissionDecision"], "deny")
                self.assertIn("did NOT run. Tell the user; do not retry", pre["permissionDecisionReason"])
                post = hooks._fail_closed("post-tool", payload, "x")
                if client == "claude":
                    self.assertIn("withheld", post["hookSpecificOutput"]["updatedToolOutput"])
                else:
                    self.assertEqual(post["decision"], "block")
                    self.assertIn("withheld", post["reason"])

    def _main(self, event: str, stdin: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(hooks.sys, "stdin", io.StringIO(stdin)), \
                mock.patch.object(hooks.sys, "stdout", out), mock.patch.object(hooks.sys, "stderr", err):
            rc = hooks.main(["hook", event])
        return rc, out.getvalue(), err.getvalue()

    def test_a_handler_exception_answers_with_its_type_only(self):
        def boom(payload):
            raise RuntimeError("argv carried " + PLAIN)
        for event in ("user-prompt", "pre-tool"):
            with self.subTest(event), mock.patch.dict(hooks.HANDLERS, {event: boom}):
                rc, out, _err = self._main(event, '{"prompt_id": "p"}')
                self.assertEqual(rc, 0)
                self.assertIn("an internal error (RuntimeError)", out)
                self.assertNotIn(PLAIN, out, "an exception message may carry a value")
                json.loads(out)

    def test_a_config_error_in_pre_tool_names_the_key_and_says_do_not_retry(self):
        def bad(payload):
            raise ConfigError("ttl_seconds must be an object")
        with mock.patch.dict(hooks.HANDLERS, {"pre-tool": bad}):
            rc, out, _err = self._main("pre-tool", '{"prompt_id": "p"}')
        reason = json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("configuration error: ttl_seconds", reason)
        self.assertIn("do not retry", reason)

    def test_post_tool_guard_withholds_on_config_error_and_on_any_exception(self):
        with mock.patch.object(hooks, "post_tool", side_effect=ConfigError("scrub_transcript")):
            out = hooks._post_tool_guarded({"prompt_id": "p"})
        self.assertIn("configuration error: scrub_transcript", out["hookSpecificOutput"]["updatedToolOutput"])
        with mock.patch.object(hooks, "post_tool", side_effect=KeyError(PLAIN)):
            out = hooks._post_tool_guarded({"turn_id": "t"})
        self.assertEqual(out["decision"], "block")
        self.assertIn("an internal error (KeyError)", out["reason"])
        self.assertNotIn(PLAIN, json.dumps(out))

    def test_the_watchdog_withholds_a_slow_post_tool_and_denies_a_slow_pre_tool(self):
        def slow(payload):
            time.sleep(0.6)
            return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": "late"}}
        for event, check in (("post-tool", lambda o: self.assertIn("withheld", _hso(o)["updatedToolOutput"])),
                             ("pre-tool", lambda o: self.assertEqual(_hso(o)["permissionDecision"], "deny"))):
            with self.subTest(event), mock.patch.dict(hooks.HANDLERS, {event: slow}), \
                    mock.patch.dict(hooks.WATCHDOG_SECONDS, {event: 0.2}), \
                    mock.patch.object(hooks.os, "_exit", lambda code: None):
                _rc, out, _err = self._main(event, '{"prompt_id": "p"}')
                obj = json.loads(out)      # exactly one object: the late handler answer is dropped
                check(obj)
                self.assertIn("took longer", json.dumps(obj))

    def test_no_watchdog_thread_outlives_a_hook_run(self):
        # a daemon timer thread still running at interpreter shutdown can crash the process; a hook
        # ended with signal 11 after its answer on a macOS runner (2026-09-27)
        import threading
        bash = '{"tool_name": "Bash", "tool_input": {"command": "true"}, "prompt_id": "p"}'
        for event, payload in (("pre-tool", bash), ("user-prompt", '{"prompt": "hi", "prompt_id": "p"}')):
            with self.subTest(event), mock.patch.dict(hooks.HANDLERS, {event: lambda p: {}}):
                self._main(event, payload)
                timers = [t for t in threading.enumerate() if isinstance(t, threading.Timer) and t.is_alive()]
                self.assertEqual(timers, [])

    def test_a_wrong_event_name_is_a_usage_error(self):
        for argv in (["hook"], ["hook", "session-end"], ["hook", "pre-tool", "x"]):
            with self.subTest(argv), mock.patch.object(hooks.sys, "stderr", io.StringIO()) as err:
                self.assertEqual(hooks.main(argv), 2)
                self.assertIn("usage", err.getvalue())

    def test_the_run_log_word_for_every_answer_shape(self):
        cases = [({}, "pass"), ({"decision": "block"}, "block"),
                 (hooks._deny("x"), "deny"), ({"hookSpecificOutput": {"updatedInput": {}}}, "rewrite"),
                 ({"hookSpecificOutput": {"updatedToolOutput": "x"}}, "redact"),
                 ({"hookSpecificOutput": {"additionalContext": "x"}}, "context"),
                 ({"systemMessage": "x"}, "answer")]
        for obj, word in cases:
            with self.subTest(word):
                self.assertEqual(hooks._decision_of("pre-tool", obj), word)

    def test_the_run_log_keeps_the_newest_2000_lines_and_truncates_the_tool_name(self):
        log = Path(_TMP, "hooks.log")
        log.write_text("".join(f"old-line-{i:05d} " + "x" * 90 + "\n" for i in range(2100)), encoding="utf-8")
        hooks._run_log("pre-tool", {"tool_name": "mcp__" + "t" * 80, "session_id": "session-long-id",
                                    "prompt_id": "p"}, "ok", "pass", 3)
        lines = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2000)
        self.assertTrue(lines[0].startswith("old-line-00101"), lines[0][:20])
        last = lines[-1].split("\t")
        self.assertEqual(last[1:4], ["pre-tool", "claude", "session-"])
        self.assertEqual(len(last[4]), 40)
        self.assertEqual(last[5:], ["pass", "3ms", "ok"])
        if os.name != "nt":  # Windows keeps no POSIX mode (st_mode & 0o777 is 0o666)
            self.assertEqual(os.stat(log).st_mode & 0o777, 0o600)


# ------------------------------------------------------------- answer shapes --
class ClientShapeTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _hygiene.watch_children(self)
        _reset()
        self.e = Vault().put(PLAIN, "SECRET", "manual", session="S1")

    def test_user_prompt_block_per_client_and_a_typed_reference_gets_the_primer(self):
        with mock.patch.object(hooks, "_clipboard", lambda t: True):
            claude = hooks.user_prompt({"prompt": "use " + GLPAT, "session_id": "U1", "prompt_id": "p",
                                        "transcript_path": ""})
            codex = hooks.user_prompt({"prompt": "use " + GLPAT, "session_id": "U2", "turn_id": "t",
                                       "transcript_path": ""})
        self.assertTrue(claude["hookSpecificOutput"]["suppressOriginalPrompt"])
        self.assertIn("pastes the cleaned prompt. Then send it, or type /maisecrets:send", claude["reason"])
        self.assertNotIn("hookSpecificOutput", codex)
        self.assertIn("pastes the cleaned prompt. Then send it.", codex["reason"])
        self.assertIn("maisecrets by mcpgate.de", codex["reason"])
        for out in (claude, codex):
            self.assertNotIn(GLPAT, json.dumps(out))
        typed = hooks.user_prompt({"prompt": "print " + self.e.ref, "session_id": "U3", "prompt_id": "p"})
        self.assertEqual(typed["hookSpecificOutput"]["additionalContext"], hooks.primer())
        self.assertEqual(Vault().status(self.e.key, "U3"), "ok", "a typed reference admits the session")
        self.assertEqual(hooks.user_prompt({"prompt": "hello", "session_id": "U3", **CLAUDE}), {})

    def test_the_notice_names_the_kind_and_the_step_per_client(self):
        v = Vault()

        class E:
            def __init__(self, t, ref):
                self.type, self.ref = t, ref
        cards = "\n".join(hooks.block_notice([E("CARD", "⟦CARD_c1⟧"), E("ODD", "⟦ODD_c1⟧")], "x", True, False, {}, v))
        self.assertIn("personal data was found", cards, "every type that is not SECRET is personal data")
        both = "\n".join(hooks.block_notice([E("SECRET", "⟦SECRET_c1⟧"), E("CARD", "⟦CARD_c1⟧")], "x", True, False,
                                              {}, v))
        self.assertIn("a secret and personal data were found", both)
        codex_no_clip = hooks.block_notice([E("SECRET", "⟦SECRET_c1⟧")], "the prompt", False, True,
                                           {"report_url": None}, v)
        self.assertIn("    Copy the cleaned prompt from here and send it:", codex_no_clip)
        self.assertIn("    the prompt", codex_no_clip)
        self.assertFalse(any("/maisecrets:" in line or "Something wrong" in line for line in codex_no_clip))
    def test_pre_tool_bash_is_auto_approved_only_on_codex(self):
        claude = _hso(_bash_pre("printf '%s' " + self.e.ref, prompt_id="p"))
        codex = _hso(_bash_pre("printf '%s' " + self.e.ref, turn_id="t"))
        self.assertNotIn("permissionDecision", claude)
        # Codex for Windows runs PowerShell: a command with a placeholder is refused there
        self.assertEqual(codex["permissionDecision"], "deny" if os.name == "nt" else "allow")
        for out in (claude, codex):
            self.assertNotIn(PLAIN, json.dumps(out))
        for out in (claude,) if os.name == "nt" else (claude, codex):   # a Codex deny has no command
            if BASH:
                self.assertEqual(_run(out["updatedInput"]["command"]).stdout, PLAIN)

    def test_post_tool_answers_codex_with_a_block_that_carries_the_redacted_text(self):
        for response in ("pw " + PLAIN, {"stdout": "pw " + PLAIN, "code": 0}):
            with self.subTest(type(response).__name__):
                out = hooks.post_tool({"tool_name": "Bash", "session_id": "S1", "turn_id": "t",
                                       "transcript_path": "", "tool_response": response})
                self.assertEqual(out["decision"], "block")
                self.assertIn("this is not an error", out["reason"])
                self.assertIn(self.e.ref, out["reason"])
                self.assertNotIn(PLAIN, out["reason"])
                self.assertNotIn("hookSpecificOutput", out)

    def test_post_tool_redacts_nested_strings_and_keeps_other_types(self):
        response = {"content": [{"type": "text", "text": "a " + PLAIN}, {"n": 5, "ok": True, "none": None}],
                    "meta": {"deep": [["x", PLAIN + " tail"]]}, "exit": 0}
        out = hooks.post_tool({"tool_name": "mcp__x__y", "session_id": "S1", "prompt_id": "p",
                               "tool_response": response})
        new = out["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(new["content"][0]["text"], "a " + self.e.ref)
        self.assertEqual(new["content"][1], {"n": 5, "ok": True, "none": None})
        self.assertEqual(new["meta"]["deep"], [["x", self.e.ref + " tail"]])
        self.assertEqual(new["exit"], 0)
        self.assertIn("masked 2 value(s) in this mcp__x__y result", out["systemMessage"])
        self.assertEqual(hooks.post_tool({"tool_name": "Bash", "session_id": "S1", "tool_response": None,
                                          **CLAUDE}), {})
        self.assertEqual(hooks.post_tool({"tool_name": "Bash", "session_id": "S1", "tool_response": [1, 2.5],
                                          **CLAUDE}), {})


# ---------------------------------------------------------------- redaction --
class ExactRedactionTests(unittest.TestCase):
    def setUp(self):
        _reset()
        self.v = Vault()

    def _post(self, text: str, session: str = "S1") -> str:
        out = hooks.post_tool({"tool_name": "Bash", "session_id": session, "prompt_id": "p",
                               "tool_response": {"stdout": text}})
        return out["hookSpecificOutput"]["updatedToolOutput"]["stdout"] if out else text

    def test_a_stored_value_is_found_url_decoded_and_json_unescaped(self):
        e1 = self.v.put("Zq7k@P2mX9vR4tL8", "SECRET", "manual", session="S1")
        e2 = self.v.put("Secr/et-Value-77", "SECRET", "manual", session="S1")
        out = self._post("url https://h.example/?t=Zq7k%40P2mX9vR4tL8 and json \"Secr\\/et-Value-77\"")
        self.assertNotIn("Zq7k%40P2mX9vR4tL8", out)
        self.assertNotIn("Secr\\/et-Value-77", out)
        self.assertIn(e1.ref, out)
        self.assertIn(e2.ref, out)
        self.assertEqual(Vault().status(e1.key, "S1"), "ok")

    def test_a_resolved_value_is_found_in_every_derived_form(self):
        raw = "Wv3~Kp9/Lq+Zt8=Mn"
        e = self.v.put(raw, "SECRET", "manual", session="S1")
        self.assertEqual(self.v.record_resolve(e.key, "S1", "mcp__x__y", "{}"), "ok")
        from urllib.parse import quote
        b = raw.encode()
        forms = {"b64url-nopad": base64.urlsafe_b64encode(b).decode().rstrip("="), "HEX": b.hex().upper(),
                 "quote": quote(raw, safe=""), "b64": base64.b64encode(b).decode()}
        for name, form in forms.items():
            with self.subTest(name):
                out = self._post("x" + form + "y")
                self.assertNotIn(form, out)
                self.assertIn(e.ref, out)
        self.assertEqual(self._post("nothing of it here 1234"), "nothing of it here 1234")

    def test_resolved_values_are_read_in_one_call_when_the_backend_offers_it(self):
        e = self.v.put(PLAIN, "SECRET", "manual", session="S1")
        self.v.record_resolve(e.key, "S1", "mcp__x__y", "{}")
        v = Vault()
        calls = []

        def get_many(keys):
            calls.append(list(keys))
            return {k: v.backend.get(k) for k in keys}
        with mock.patch.object(v.backend, "get_many", get_many, create=True):
            got = hooks._resolved_values(v, "S1")
        self.assertEqual(calls, [[e.key]])
        self.assertEqual(got, [(PLAIN, e.ref)])
        self.assertEqual(hooks._resolved_values(v, "S-other"), [])


# ---------------------------------------------------------------- transcript --
class TranscriptScrubTests(unittest.TestCase):
    def setUp(self):
        _reset()
        self.path = Path(_TMP, "scrub.jsonl")

    def test_short_and_all_digit_values_are_not_scrubbed(self):
        self.path.write_text('{"n": 1234567890, "t": "abc"}\n', encoding="utf-8")
        self.assertFalse(hooks._scrub_transcript(str(self.path), ["1234567890", "abc", ""], ["⟦X⟧"]))
        self.assertEqual(self.path.read_text(encoding="utf-8"), '{"n": 1234567890, "t": "abc"}\n')
        self.assertFalse(hooks._scrub_transcript("", [PLAIN], ["⟦X⟧"]))
        self.assertFalse(hooks._scrub_transcript(str(Path(_TMP, "absent.jsonl")), [PLAIN], ["⟦X⟧"]))

    def test_an_all_digit_value_is_scrubbed_inside_strings_and_json_numbers_stay(self):
        # external review, 2026-09-28: every all-digit value was skipped, so a detected tax ID stayed in the transcript
        recs = [{"message": {"content": "Steuer-ID: 12345678901 bitte"}, "ts": 12345678901},
                {"text": "id 912345678901, x12345678901y, \\u0031", "num": [12345678901]}, {"k": "12345678901"}]
        self.path.write_text("\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
        self.assertTrue(hooks._scrub_transcript(str(self.path), ["12345678901"], ["⟦ID_c1⟧"]))
        lines = self.path.read_text(encoding="utf-8").splitlines()
        got = [json.loads(line) for line in lines]          # every record is still valid JSON
        self.assertEqual(got[0]["message"]["content"], "Steuer-ID: *********** bitte")
        self.assertEqual(got[0]["ts"], 12345678901, "a JSON number is not a detected value")
        self.assertEqual(got[1]["text"], "id 912345678901, x***********y, \\u0031", "a longer digit run stays")
        self.assertEqual(got[1]["num"], [12345678901])
        self.assertEqual(got[2]["k"], "***********")

    def test_an_all_digit_value_after_a_record_longer_than_the_window_is_scrubbed(self):
        # Codex review, 2026-09-28: a string over 8 MiB moved the value into the next window, which began
        # mid-string without its opening quote, and the value stayed
        recs = [{"a": "x" * (9 * 1024 * 1024) + " id 123456 end", "n": 123456}, {"k": "tail 123456"}]
        self.path.write_text("\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
        self.assertTrue(hooks._scrub_transcript(str(self.path), ["123456"], ["⟦X⟧"]))
        got = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(got[0]["a"].endswith(" id ****** end"))
        self.assertEqual(got[0]["n"], 123456)
        self.assertEqual(got[1]["k"], "tail ******")

    def test_malformed_lines_are_scrubbed_in_place_keeping_inode_and_mode(self):
        self.path.write_text("not json " + PLAIN + "\n{\"broken\": \"" + PLAIN + "\n\n", encoding="utf-8")
        os.chmod(self.path, 0o600)
        ino = os.stat(self.path).st_ino
        self.assertTrue(hooks._scrub_transcript(str(self.path), [PLAIN], ["⟦X⟧"]))
        data = self.path.read_text(encoding="utf-8")
        self.assertNotIn(PLAIN, data)
        self.assertEqual(data, "not json " + "*" * len(PLAIN) + "\n{\"broken\": \"" + "*" * len(PLAIN) + "\n\n")
        st = os.stat(self.path)
        self.assertEqual(st.st_ino, ino)
        if os.name != "nt":  # Windows keeps no POSIX mode (st_mode & 0o777 is 0o666)
            self.assertEqual(st.st_mode & 0o777, 0o600)

    def test_a_value_on_the_window_boundary_of_a_large_transcript_is_scrubbed(self):
        chunk = 8 * 1024 * 1024
        rec = json.dumps({"type": "tool", "content": "y" * 1000}) + "\n"
        head = rec * (chunk // len(rec))
        prefix = '{"type": "user", "content": "'
        pad = chunk - len(head) - len(prefix) - 1 - 10   # the value starts 10 bytes before the 8 MiB edge
        line = json.dumps({"type": "user", "content": "z" * pad + " " + PLAIN + " end"}) + "\n"
        self.assertTrue(line.startswith(prefix))
        self.assertEqual((head + line).index(PLAIN), chunk - 10)
        huge = json.dumps({"type": "tool", "content": "w" * (2 * 1024 * 1024) + PLAIN}) + "\n"
        self.path.write_text(head + line + huge + rec, encoding="utf-8")
        self.assertTrue(hooks._scrub_transcript(str(self.path), [PLAIN], ["⟦X⟧"]))
        data = self.path.read_bytes()
        self.assertNotIn(PLAIN.encode(), data)
        for raw in data.splitlines():
            json.loads(raw)

    def test_the_delayed_scrub_waits_for_the_record_and_takes_values_on_stdin(self):
        self.assertIsNone(hooks._scrub_transcript_later("", [PLAIN], ["⟦X⟧"]))
        late = Path(_TMP, "late.jsonl")
        late.unlink(missing_ok=True)
        dbg = Path(_TMP, "debug.log")
        dbg.unlink(missing_ok=True)
        with mock.patch.dict(os.environ, {"MAISECRETS_DEBUG_LOG": str(dbg)}):
            real_popen = subprocess.Popen
            argvs, children = [], []

            def spy(argv, **kw):
                argvs.append(argv)
                children.append(real_popen(argv, **kw))
                return children[-1]
            with mock.patch.object(hooks.subprocess, "Popen", spy):
                hooks._scrub_transcript_later(str(late), [PLAIN], ["⟦X⟧"], seconds=5.0)
            time.sleep(0.5)
            late.write_text(json.dumps({"content": "later " + PLAIN}) + "\n", encoding="utf-8")
            deadline = time.time() + 5
            while time.time() < deadline and PLAIN in late.read_text(encoding="utf-8"):
                time.sleep(0.1)
            self.assertNotIn(PLAIN, late.read_text(encoding="utf-8"))
            self.assertNotIn(PLAIN, " ".join(argvs[0]), "the value never is an argument")
            deadline = time.time() + 3
            while time.time() < deadline and "scrub-later: done" not in (dbg.read_text() if dbg.exists() else ""):
                time.sleep(0.1)
            self.assertIn("scrub-later: done", dbg.read_text())
            self.assertEqual(children[0].wait(timeout=5), 0, "the child ends once the record is scrubbed")
            with mock.patch.object(hooks.subprocess, "Popen", side_effect=OSError("no fork")):
                hooks._scrub_transcript_later(str(late), [PLAIN], ["⟦X⟧"])
            self.assertIn("scrub-later: could not start", dbg.read_text())


# -------------------------------------------------------------- user prompt --
class MentionAndPendingTests(unittest.TestCase):
    def setUp(self):
        _reset()
        self.dir = Path(tempfile.mkdtemp(dir=_TMP))
        (self.dir / "notes.env").write_text("K=v\n")

    def test_an_at_mention_of_an_existing_file_is_blocked_absolute_or_relative_to_cwd(self):
        for prompt, cwd in ((f"see @{self.dir / 'notes.env'}.", ""), ("see @notes.env, please", str(self.dir))):
            with self.subTest(prompt):
                out = hooks.user_prompt({"prompt": prompt, "cwd": cwd, "session_id": "M1", "prompt_id": "p"})
                self.assertEqual(out["decision"], "block")
                self.assertIn("would send the whole file to the AI before maisecrets can check it", out["reason"])
                self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        self.assertEqual(hooks.user_prompt({"prompt": "see @nothing-here.env", "cwd": str(self.dir), **CLAUDE}), {})
        self.assertEqual(hooks.user_prompt({"prompt": "mail me@example", "cwd": str(self.dir), **CLAUDE}), {})
        _cfg({"block_at_mentions": False})
        self.assertEqual(hooks.user_prompt({"prompt": "see @notes.env", "cwd": str(self.dir), **CLAUDE}), {})

    def test_a_pending_prompt_expires_after_15_minutes_and_two_sessions_are_not_mixed(self):
        hooks._save_pending("text of A ⟦SECRET_c1⟧", "A")
        p = hooks._pending_path("A")
        if os.name != "nt":  # Windows keeps no POSIX mode (st_mode & 0o777 is 0o666)
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
        old = time.time() - 16 * 60
        os.utime(p, (old, old))
        self.assertIsNone(hooks.take_pending("A"), "a stale prompt is never sent")
        self.assertIsNone(hooks.take_pending(None))
        hooks._save_pending("text of B", "B")
        self.assertEqual(hooks.take_pending(None), "text of B", "one fresh prompt, no session id: the newest")
        self.assertIsNone(hooks.take_pending(None))
        hooks._save_pending("text of C", "C")
        hooks._save_pending("text of D", None)
        both = hooks.take_pending(None)
        self.assertIn("two sessions are waiting", both)
        self.assertNotIn("text of", both)
        self.assertEqual(hooks.take_pending("C"), "text of C")

    def test_saving_a_pending_prompt_never_raises(self):
        shutil.rmtree(Path(_TMP, "pending"), ignore_errors=True)
        Path(_TMP, "pending").write_text("a file where the directory belongs")
        try:
            hooks._save_pending("x", "S")          # no exception, no prompt kept
            self.assertTrue(Path(_TMP, "pending").is_file())
        finally:
            Path(_TMP, "pending").unlink()


class ClipboardTests(unittest.TestCase):
    def test_the_clipboard_command_per_system_and_a_missing_tool_is_false(self):
        ps_read = ["powershell", "-NoProfile", "-Command",
                   "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; Get-Clipboard -Raw"]
        text = "x ⟦SECRET_c1⟧"
        for system, write, sent, read in (
                ("Darwin", ["pbcopy"], text.encode(), ["pbpaste"]),
                # clip.exe takes UTF-16 as Unicode, UTF-8 in the code page; a byte order mark stays in
                ("Windows", ["clip"], text.encode("utf-16-le"), ps_read),
                ("Linux", ["xclip", "-selection", "clipboard"], text.encode(),
                 ["xclip", "-selection", "clipboard", "-o"])):
            with self.subTest(system):
                calls = []

                def fake_run(cmd, **kw):
                    calls.append((cmd, kw.get("input")))
                    return subprocess.CompletedProcess(cmd, 0, stdout="from clipboard ⟦K⟧".encode())
                with mock.patch.object(hooks.platform, "system", return_value=system), \
                        mock.patch.object(hooks.subprocess, "run", fake_run):
                    self.assertTrue(_CLIPBOARD(text))
                    self.assertEqual(_CLIPBOARD_READ(), "from clipboard ⟦K⟧", "the read is UTF-8")
                self.assertEqual(calls, [(write, sent), (read, None)])
        with mock.patch.object(hooks.subprocess, "run", side_effect=OSError("absent")):
            self.assertFalse(_CLIPBOARD("x"))
            self.assertEqual(_CLIPBOARD_READ(), "")
        with mock.patch.object(hooks.subprocess, "run", side_effect=subprocess.TimeoutExpired("x", 3)):
            self.assertFalse(_CLIPBOARD("x"))


# --------------------------------------------------------------- file tools --
class FileToolTests(unittest.TestCase):
    def setUp(self):
        _reset()
        self.e = Vault().put(PLAIN, "SECRET", "manual", session="S1")
        self.work = tempfile.mkdtemp(prefix="maisecrets-work-", dir=str(Path(_TMP).parent))

    def _pre(self, tool: str, tool_input: dict, **extra) -> dict:
        return hooks.pre_tool(_marked({"tool_name": tool, "session_id": "S1", "tool_input": tool_input}, extra))

    def test_multiedit_and_notebookedit_resolve_nested_and_codex_allows(self):
        out = _hso(self._pre("MultiEdit", {"file_path": "/w/a.env", "edits": [
            {"old_string": "K=", "new_string": "K=" + self.e.ref}, {"old_string": "x", "new_string": "y"}]}))
        self.assertEqual(out["updatedInput"]["edits"][0]["new_string"], "K=" + PLAIN)
        self.assertNotIn("permissionDecision", out)
        nb = _hso(self._pre("NotebookEdit", {"notebook_path": "/w/n.ipynb", "new_source": "t = '" + self.e.ref + "'"},
                            turn_id="t"))
        self.assertEqual(nb["permissionDecision"], "allow")
        self.assertEqual(nb["updatedInput"]["new_source"], "t = '" + PLAIN + "'")
        self.assertIn("\tNotebookEdit\tNotebookEdit /w/n.ipynb", Path(_TMP, "audit.log").read_text(encoding="utf-8"))

    def test_the_home_is_refused_also_as_a_relative_path_from_the_client_cwd(self):
        for tool_input, cwd in (({"file_path": "config.json", "content": "{}"}, _TMP),
                                ({"file_path": "../" + Path(_TMP).name + "/index.json", "content": "{}"},
                                 str(Path(_TMP).parent / "x")),
                                ({"file_path": "~/.MaiSecrets/config.json", "content": "{}"}, "")):
            with self.subTest(tool_input["file_path"]):
                out = _hso(self._pre("Write", tool_input, cwd=cwd))
                self.assertEqual(out["permissionDecision"], "deny")
                self.assertIn("maisecrets home is changed by the human only", out["permissionDecisionReason"])
        self.assertEqual(self._pre("Write", {"file_path": "config.json", "content": "{}"}, cwd=self.work), {})

    def test_a_path_the_os_cannot_resolve_is_not_taken_for_the_home(self):
        out = _hso(self._pre("Write", {"file_path": "/w/a\0b", "content": self.e.ref}))
        self.assertEqual(out["updatedInput"]["content"], PLAIN)

    def test_a_failed_resolve_in_a_file_tool_says_nothing_was_written(self):
        out = _hso(self._pre("Write", {"file_path": "/w/a", "content": "⟦SECRET_c77⟧"}))
        self.assertEqual(out["permissionDecision"], "deny")
        reason = out["permissionDecisionReason"]
        self.assertIn("SECRET_c77 (no such placeholder)", reason)
        self.assertIn("Nothing was written.", reason)
        self.assertNotIn("The command did not run", reason)


# ---------------------------------------------------------------------- MCP --
class McpAskTests(unittest.TestCase):
    def setUp(self):
        _reset()
        self.e = Vault().put(PLAIN, "SECRET", "manual", session="S1")

    def _pre(self, tool_input, **extra) -> dict:
        return hooks.pre_tool(_marked({"tool_name": "mcp__svc__act", "session_id": "S1", "tool_input": tool_input,
                                       "transcript_path": ""}, extra))

    def test_the_ask_names_the_fields_the_tool_and_never_the_value(self):
        params = json.dumps({"body": "hi " + self.e.ref}, ensure_ascii=False)
        with mock.patch.object(hooks, "load_config", return_value={**hooks.load_config(), "rehydration": "confirm"}):
            out = _hso(self._pre({"to": self.e.ref, "params": params}, prompt_id="p"))
        self.assertEqual(out["permissionDecision"], "ask")
        reason = out["permissionDecisionReason"]
        self.assertIn(f"the real value of {self.e.ref} in to, params.body of mcp__svc__act", reason)
        self.assertIn("WARNING: params.body is text", reason)
        self.assertNotIn(PLAIN, reason)
        self.assertEqual(out["updatedInput"]["to"], PLAIN)
        self.assertEqual(json.loads(out["updatedInput"]["params"])["body"], "hi " + PLAIN)

    def test_a_placeholder_as_a_field_name_or_without_a_value_is_refused(self):
        out = _hso(self._pre({self.e.ref: "x", "y": self.e.ref}))
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("used as a field name", out["permissionDecisionReason"])
        self.assertEqual(self._pre({"q": "no placeholder", "n": 3}), {})
        out = _hso(self._pre({"to": "⟦SECRET_c55⟧"}))
        self.assertIn("SECRET_c55 (no such placeholder)", out["permissionDecisionReason"])
        self.assertIn("do not guess other keys", out["permissionDecisionReason"])

    def test_field_paths_and_text_field_words(self):
        self.assertEqual(hooks._ref_fields({"p": "{not json " + self.e.ref}), ["p"])
        self.assertEqual(hooks._ref_fields(self.e.ref), ["(input)"])
        self.assertEqual(hooks._ref_fields({"a": [{"b": self.e.ref}, self.e.ref]}), ["a[0].b", "a[1]"])
        for path, want in (("messageText", True), ("text_body", True), ("Body", True), ("x.HTML", True),
                           ("context", False), ("plaintext", False), ("httpStatus", False), ("[0]", False),
                           ("", False), ("to", False)):
            with self.subTest(path):
                self.assertEqual(hooks.is_text_field(path), want)


# --------------------------------------------------------------------- Bash --
class BashPathTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _hygiene.watch_children(self)
        _reset()
        self.e = Vault().put(NASTY, "SECRET", "manual", session="S1")
        self.p = Vault().put(PLAIN, "SECRET", "manual", session="S1")

    @unittest.skipIf(BASH is None, "no bash")
    def test_contexts_the_old_tests_did_not_reach_place_the_value(self):
        for name, cmd, want in [
            ("escaped quote inside double quotes", 'printf \'%s\' "a\\"b' + self.e.ref + '"', 'a"b' + NASTY),
            ("backslash in a plain word", "printf '%s' \\x" + self.p.ref, "x" + PLAIN),
            ("command substitution", "printf '%s' $(printf '%s' " + self.p.ref + ")", PLAIN),
            ("subshell", "(printf '%s' " + self.e.ref + ")", NASTY),
            ("backtick after a closed one in double quotes", 'printf \'%s\' "`echo a`-' + self.e.ref + '"',
             "a-" + NASTY),
        ]:
            with self.subTest(name):
                out = _hso(_bash_pre(cmd))
                self.assertIn("updatedInput", out, out)
                new = out["updatedInput"]["command"]
                self.assertNotIn(NASTY, new)
                r = _run(new)
                self.assertEqual(r.stdout, want, r.stderr)

    def test_more_refused_contexts_and_command_words(self):
        ref = self.p.ref
        for cmd, why in [
            ('echo "$(( 1 + ' + ref + ' ))"', "$((…)) a value is not a number"),
            ("echo $(( (1) + " + ref + " ))", "$((…)) a value is not a number"),
            ('echo "`echo ' + ref + '`"', "inside `…`"),
            ("openssl enc -aes-256-cbc -k " + ref, "openssl enc would encode"),
            ("set -o xtrace; echo " + ref, "set -o xtrace would trace"),
            ("PS4='+ ' echo " + ref, "a custom PS4 would trace"),
            ("nice -n 5 base64 <<< " + ref, "base64 would encode"),
            ("timeout 5s xxd <<< " + ref, "xxd would encode"),
            ("(base64 <<< " + ref + ")", "base64 would encode"),
        ]:
            with self.subTest(cmd):
                out = _hso(_bash_pre(cmd))
                self.assertEqual(out.get("permissionDecision"), "deny", out)
                self.assertIn(why, out["permissionDecisionReason"])
        self.assertIn("updatedInput", _hso(_bash_pre("sudo -u nobody printf '%s' " + ref)))

    def test_each_failure_status_gets_its_one_next_step(self):
        v = Vault()
        v._index["entries"][self.p.key]["expires"] = time.time() - 10
        v._save_index()
        out = _hso(_bash_pre("echo " + self.p.ref))
        self.assertIn(f"{self.p.key} (expired)", out["permissionDecisionReason"])
        self.assertIn("/maisecrets:put", out["permissionDecisionReason"])
        _cfg({"max_keys_per_session": 1})
        out = _hso(_bash_pre("echo " + self.e.ref))
        self.assertIn("updatedInput", out)
        if BASH:
            _run(out["updatedInput"]["command"])
        third = Vault().put("third-" + PLAIN, "SECRET", "manual", session="S1")
        out = _hso(_bash_pre("echo " + third.ref))
        self.assertIn("limit: 1 different placeholders", out["permissionDecisionReason"])
        self.assertIn("do not change maisecrets settings yourself", out["permissionDecisionReason"])
        # 0.6.9: the person learns how to raise the cap (a typed prompt; the model may not type it for them)
        self.assertIn("/maisecrets:settings max_keys_per_session NUMBER", out["permissionDecisionReason"])
        _cfg()
        with mock.patch.object(Vault, "_record", return_value=False):
            out = _hso(_bash_pre("echo " + third.ref))
        self.assertIn("(audit log not writable)", out["permissionDecisionReason"])
        self.assertIn("The audit log could not be written", out["permissionDecisionReason"])

    def test_codex_on_windows_is_refused_and_claude_on_windows_reads_under_a_grant(self):
        with mock.patch.object(hooks.platform, "system", return_value="Windows"):
            codex = _hso(_bash_pre("echo " + self.e.ref, turn_id="t"))
            claude = _hso(_bash_pre("printf '%s' " + self.e.ref, prompt_id="p"))
        self.assertEqual(codex["permissionDecision"], "deny")
        self.assertIn("Codex for Windows", codex["permissionDecisionReason"])
        cmd = claude["updatedInput"]["command"]
        self.assertIn("/hooks/resolve.py\" " + self.e.key + " --grant ", cmd)
        self.assertNotIn(NASTY, cmd)
        self.assertEqual(len(Vault()._index.get("grants", {})), 1, "one grant for one key")
        if BASH and os.name != "nt":
            r = _run(cmd)
            self.assertEqual(r.stdout, NASTY, r.stderr)
        with mock.patch.object(hooks.platform, "system", return_value="Windows"), \
                mock.patch.object(Vault, "_record", return_value=False):
            out = _hso(_bash_pre("echo " + self.e.ref))
        self.assertIn("(audit log not writable)", out["permissionDecisionReason"])


@unittest.skipIf(os.name == "nt", "POSIX run dir")
class RunDirTests(unittest.TestCase):
    def test_the_run_dir_under_xdg_is_private_and_a_file_in_its_place_is_refused(self):
        xdg = tempfile.mkdtemp(dir=_TMP)
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": xdg}):
            d = hooks._run_dir()
            self.assertEqual(d, os.path.join(xdg, "maisecrets"))
            self.assertEqual(os.stat(d).st_mode & 0o777, 0o700)
            os.rmdir(d)
            fd = os.open(d, os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(fd)
            with self.assertRaises(RuntimeError):
                hooks._run_dir()
            os.unlink(d)
            os.symlink(tempfile.mkdtemp(dir=_TMP), d)
            with self.assertRaises(RuntimeError):
                hooks._run_dir()

    def test_on_windows_the_run_dir_is_named_after_the_user(self):
        with mock.patch.object(hooks.platform, "system", return_value="Windows"), \
                mock.patch.dict(os.environ, {"USERNAME": "tester"}):
            self.assertEqual(hooks._run_dir(), os.path.join(tempfile.gettempdir(), "maisecrets-tester"))

    def test_a_stale_fifo_is_swept_and_a_fresh_one_is_kept(self):
        d = hooks._run_dir()
        stale, fresh, other = (os.path.join(d, n) for n in ("v-stale-x", "v-fresh-x", "keep-me"))
        for f in (stale, fresh, other):
            Path(f).write_text("")
        old = time.time() - 600
        os.utime(stale, (old, old))
        os.utime(other, (old, old))
        path = hooks._fifo_path("nonce1")
        self.assertEqual(path, os.path.join(d, "v-nonce1"))
        self.assertFalse(os.path.exists(stale))
        self.assertTrue(os.path.exists(fresh) and os.path.exists(other))
        for f in (fresh, other):
            os.unlink(f)

    @unittest.skipIf(os.name == "nt", "POSIX FIFO path")
    def test_a_value_taken_back_ends_its_serving_child_at_once(self):
        """_unserve deletes the FIFO of a refused command; the child retried the open for its full
        120 s with the value in memory (suite review, 2026-09-27). Now it ends at once, served or
        taken back, and a served value arrives once."""
        children = []
        real = subprocess.Popen

        def keep(*a, **kw):
            children.append(real(*a, **kw))
            return children[-1]
        self.addCleanup(lambda: [(c.kill(), c.wait()) for c in children if c.poll() is None])
        for take_back in (True, False):
            with self.subTest(take_back=take_back):
                fifo = hooks._fifo_path(hooks.key_nonce())
                with mock.patch.object(hooks.subprocess, "Popen", keep):
                    self.assertTrue(hooks._serve_value_later(fifo, PLAIN, seconds=30.0))
                if take_back:
                    hooks._unserve([fifo])
                else:
                    with open(fifo, encoding="utf-8") as f:
                        self.assertEqual(f.read(), PLAIN)
                self.assertEqual(children[-1].wait(timeout=2), 0)
                self.assertFalse(os.path.exists(fifo))


# ------------------------------------------------------ payload shape matrix --
_FAKEBIN = tempfile.mkdtemp(prefix="fakebin-", dir=_TMP)
for _tool in ("pbcopy", "pbpaste", "xclip", "clip"):
    Path(_FAKEBIN, _tool).write_text("#!/bin/sh\ncat >/dev/null 2>&1\nexit 0\n")
    os.chmod(Path(_FAKEBIN, _tool), 0o755)


def _dispatch(event: str, stdin: str, home: str | None = None, **extra_env: str) -> subprocess.CompletedProcess:
    """One hook event through the real entry point, as the client starts it. The home has a
    jsonfile config.json before the process starts; the real clipboard is replaced by a sink."""
    home = home or _TMP
    cfg = json.loads(Path(home, "config.json").read_text())
    assert cfg.get("backend") == "jsonfile", "a subprocess must never reach the Keychain backend"
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GIT_", "CODEX_")) and k not in ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT",
                                                                  "XDG_RUNTIME_DIR", "MAISECRETS_DEBUG_LOG")}
    # the run dir of the child is the one of this process; its serving children inherit the cwd,
    # which is how tearDownModule finds one that outlived its FIFO
    # MS_TEST_CLIP: on Windows clip.exe is found in System32 before PATH, and tests/_platform_fakes.py
    # writes the sink file instead
    env.update({"MAISECRETS_HOME": home, "TMPDIR": tempfile.gettempdir(),
                "PATH": _FAKEBIN + os.pathsep + env.get("PATH", ""),
                "MS_TEST_CLIP": os.path.join(_FAKEBIN, "clipboard")})
    env.update(extra_env)
    return subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), event], input=stdin,
                          capture_output=True, text=True, env=env, timeout=60, cwd=tempfile.gettempdir())


class PayloadMatrixTests(unittest.TestCase):
    """Each event x Claude payload / Codex payload / missing fields / wrong field type / a broken
    store / garbage stdin / JSON that is not an object. The answer is one JSON object the client
    accepts (or, for a guard, exit 2 with nothing on stdout, which blocks), and no answer carries
    the stored value."""

    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _hygiene.watch_children(self)
        _reset()
        self.e = Vault().put(PLAIN, "SECRET", "manual", session="SM")
        self.broken = tempfile.mkdtemp(prefix="broken-", dir=_TMP)
        Path(self.broken, "config.json").write_text(JSONFILE_CFG)
        Path(self.broken, "index.json").write_text("{not json")
        # the value is still in the store; only the index that names it is damaged
        Path(self.broken, "vault.json").write_text(json.dumps({"SECRET_c1": PLAIN}))

    def _one(self, r: subprocess.CompletedProcess) -> dict:
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(PLAIN, r.stdout)
        self.assertNotIn(GLPAT, r.stdout)
        return json.loads(r.stdout)          # exactly one object

    def _blocks_by_exit(self, r: subprocess.CompletedProcess) -> None:
        """A refusal is JSON on stdout with exit 0, which both clients read; Codex runs the tool when a
        hook exits 2 (Codex review, 2026-09-28)."""
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        refused = out.get("decision") == "block" or \
            (out.get("hookSpecificOutput") or {}).get("permissionDecision") == "deny"
        self.assertTrue(refused, out)

    def test_user_prompt_matrix(self):
        base = {"transcript_path": "", "cwd": _TMP}
        claude = self._one(_dispatch("user-prompt", json.dumps(
            dict(base, prompt="deploy " + GLPAT, session_id="SM", prompt_id="p"))))
        self.assertEqual(claude["decision"], "block")
        self.assertEqual(claude["hookSpecificOutput"], {"hookEventName": "UserPromptSubmit",
                                                        "suppressOriginalPrompt": True})
        codex = self._one(_dispatch("user-prompt", json.dumps(
            dict(base, prompt="deploy " + GLPAT, session_id="SC", turn_id="t", model="gpt"))))
        self.assertEqual(set(codex), {"decision", "reason"})
        self.assertEqual(self._one(_dispatch("user-prompt", '{"session_id": "SM"}')), {})
        wrong = self._one(_dispatch("user-prompt", '{"prompt": 42, "prompt_id": "p"}'))
        self.assertEqual(wrong["decision"], "block")
        self.assertIn("an internal error (TypeError)", wrong["reason"])
        broken = self._one(_dispatch("user-prompt", json.dumps({"prompt": "x " + GLPAT, "prompt_id": "p",
                                                                "transcript_path": ""}), home=self.broken))
        self.assertEqual(broken["decision"], "block")
        for garbage in ("{not json", ""):
            with self.subTest(garbage):
                self._blocks_by_exit(_dispatch("user-prompt", garbage))

    def test_pre_tool_matrix(self):
        cmd = "printf '%s' " + self.e.ref
        claude = self._one(_dispatch("pre-tool", json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": "SM", "prompt_id": "p"})))
        self.assertEqual(set(claude["hookSpecificOutput"]), {"hookEventName", "updatedInput"})
        codex = self._one(_dispatch("pre-tool", json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": "SM", "turn_id": "t", "model": "m"})))
        self.assertEqual(codex["hookSpecificOutput"]["permissionDecision"], "deny" if os.name == "nt" else "allow")
        for out in (claude,) if os.name == "nt" else (claude, codex):   # each rewrite waits for one read
            if BASH:
                self.assertEqual(_run(out["hookSpecificOutput"]["updatedInput"]["command"]).stdout, PLAIN)
        self.assertEqual(self._one(_dispatch("pre-tool", '{"tool_name": "Bash", "prompt_id": "p"}')), {})
        self.assertEqual(self._one(_dispatch("pre-tool", '{"prompt_id": "p"}')), {})
        wrong = self._one(_dispatch("pre-tool", '{"tool_name": "Bash", "tool_input": "echo hi", "prompt_id": "p"}'))
        self.assertEqual(wrong["hookSpecificOutput"]["permissionDecision"], "deny")
        broken = self._one(_dispatch("pre-tool", json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": "SM", "prompt_id": "p"}),
            home=self.broken))
        self.assertEqual(broken["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("did NOT run", broken["hookSpecificOutput"]["permissionDecisionReason"])
        for garbage in ("{not json", ""):
            with self.subTest(garbage):
                self._blocks_by_exit(_dispatch("pre-tool", garbage))

    def test_post_tool_matrix(self):
        resp = {"stdout": "pw " + PLAIN, "stderr": ""}
        claude = self._one(_dispatch("post-tool", json.dumps(
            {"tool_name": "Bash", "tool_response": resp, "session_id": "SM", "prompt_id": "p"})))
        self.assertEqual(claude["hookSpecificOutput"]["updatedToolOutput"]["stdout"], "pw " + self.e.ref)
        codex = self._one(_dispatch("post-tool", json.dumps(
            {"tool_name": "Bash", "tool_response": resp, "session_id": "SM", "turn_id": "t", "transcript_path": ""})))
        self.assertEqual(codex["decision"], "block")
        self.assertIn(self.e.ref, codex["reason"])
        self.assertEqual(self._one(_dispatch("post-tool", '{"tool_name": "Bash", "prompt_id": "p"}')), {})
        for garbage in ("{not json", ""):
            with self.subTest(garbage):
                out = self._one(_dispatch("post-tool", garbage))
                self.assertIn("withheld", out["hookSpecificOutput"]["updatedToolOutput"])

    def test_json_that_is_not_an_object_fails_closed_on_every_guard(self):
        """`null`, a list, a number or a string parse as JSON but are no payload. Before the fix
        the handler and then the fail-closed path itself raised (`"prompt_id" in None`), the
        process exited 1 and the client went on as if no hook existed."""
        for garbage in ("null", "[1]", "7", '"text"'):
            with self.subTest(garbage):
                self._blocks_by_exit(_dispatch("user-prompt", garbage))
                self._blocks_by_exit(_dispatch("pre-tool", garbage))
                out = self._one(_dispatch("post-tool", garbage))
                self.assertIn("withheld", out["hookSpecificOutput"]["updatedToolOutput"])

    def test_a_damaged_index_withholds_the_tool_output_instead_of_passing_it(self):
        """The index names the stored values; when it is unreadable the redaction cannot know
        them. Before the fix the pre-check read the damage as "nothing stored" and the raw
        output, stored value included, reached the model."""
        resp = {"stdout": "pw " + PLAIN, "stderr": ""}
        for client in ({"prompt_id": "p"}, {"turn_id": "t", "transcript_path": ""}):
            with self.subTest(client=client):
                out = self._one(_dispatch("post-tool", json.dumps(
                    dict(client, tool_name="Bash", tool_response=resp, session_id="SM")), home=self.broken))
                self.assertIn("withheld", json.dumps(out))

    def test_session_start_matrix(self):
        codex_home = Path(_TMP, "codex-home")
        claude = self._one(_dispatch("session-start", json.dumps(
            {"session_id": "SM", "transcript_path": str(Path(_TMP, "claude", "t.jsonl")), "source": "startup"})))
        codex = self._one(_dispatch("session-start", json.dumps(
            {"session_id": "SC", "transcript_path": str(codex_home / "sessions" / "r.jsonl"), "model": "m"}),
            CODEX_HOME=str(codex_home)))
        self.assertIn("/maisecrets:status", claude["systemMessage"])
        self.assertNotIn("/maisecrets:", codex["systemMessage"], "Codex has no plugin slash commands")
        for garbage in ("{}", "{not json", "", "null", "[1]", "7"):
            with self.subTest(garbage):
                out = self._one(_dispatch("session-start", garbage))
                self.assertIn("maisecrets", out["systemMessage"])
        for out in (claude, codex):
            self.assertEqual(out["hookSpecificOutput"], {"hookEventName": "SessionStart",
                                                         "additionalContext": hooks.primer()})


if __name__ == "__main__":
    unittest.main()
