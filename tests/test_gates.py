"""The gates around a resolve: session rule, one-time grant, quoting contexts, limiter,
store-read backstop, MCP arguments, exact-match redaction, keyed fingerprint.

Every test that claims "the value arrives" runs the rewritten command through a real
bash and compares bytes; every test that claims "the value does not leak" searches the
artefact for the literal value.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# the vault home is fixed at the first import of maisecrets.vault (another test module may have
# imported it first); the resolve subprocess must see the same home, so it is taken from there
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS_HOME"], "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import HOME, INDEX, Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

_TMP = str(HOME)
# the value FIFOs live under the temp dir _isolate made, without $XDG_RUNTIME_DIR: the tests never
# touch the directory the installed plugin uses on this machine


def tearDownModule():  # noqa: N802 - unittest hook
    _hygiene.assert_pristine()
    alive = _hygiene.wait_for_no_serving_child()
    if alive:
        raise AssertionError(f"value-serving children still run after the module: {alive}")

BASH = shutil.which("bash")
# quotes, a command substitution, a backtick, a backslash and spaces: everything a splice would break on
NASTY = "pa$s'w\"ord`x $(echo no) y\\z"
PLAIN = "plain-secret-value-" + "42"


def _reset() -> None:
    for f in ("index.json", "vault.json", "audit.log"):
        try:
            os.unlink(Path(_TMP, f))
        except FileNotFoundError:
            pass
    shutil.rmtree(Path(_TMP, "pending"), ignore_errors=True)
    hooks._live_cache.clear()


def _bash_pre(command: str, session: str = "S1", client: dict = CLAUDE) -> dict:
    return hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": command}, "session_id": session, **client})


def _run(command: str) -> subprocess.CompletedProcess:
    return subprocess.run([BASH, "-c", command], capture_output=True, text=True)


def _config(**keys):
    """The config the hooks read, with these keys on top (the policy file wins over the user file,
    so a patched load_config is the one place a test sets a key for one call)."""
    from unittest import mock
    return mock.patch.object(hooks, "load_config", return_value={**hooks.load_config(), **keys})


class GrantTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _hygiene.watch_children(self)
        _reset()
        self.e = Vault().put(NASTY, "SECRET", "manual", session="S1")

    @unittest.skipIf(BASH is None, "no bash")
    def test_value_arrives_byte_for_byte_in_every_quoting_context(self):
        for name, cmd, want in [
            ("unquoted", "printf '%s' " + self.e.ref, NASTY),
            ("single", "printf '%s' 'a-" + self.e.ref + "-b'", "a-" + NASTY + "-b"),
            ("double", 'printf \'%s\' "a-' + self.e.ref + '-b"', "a-" + NASTY + "-b"),
            ("two refs", "printf '%s|%s' " + self.e.ref + " '" + self.e.ref + "'", NASTY + "|" + NASTY),
        ]:
            with self.subTest(name):
                out = _bash_pre(cmd)["hookSpecificOutput"]
                new = out["updatedInput"]["command"]
                self.assertNotIn("permissionDecision", out)
                self.assertNotIn(NASTY, new, "the value must not be spliced into the command")
                self.assertNotIn(NASTY[:6], new)
                r = _run(new)
                self.assertEqual(r.stdout, want, r.stderr)

    @unittest.skipIf(BASH is None, "no bash")
    def test_value_is_delivered_once_and_a_missing_delivery_fails_the_whole_command(self):
        out = _bash_pre("printf '%s' " + self.e.ref + " | tr a-z A-Z; echo tail")["hookSpecificOutput"]
        cmd = out["updatedInput"]["command"]
        self.assertTrue(cmd.startswith('__ms_1="$('), cmd)             # read up front, in the main shell
        self.assertNotIn(NASTY, cmd)
        r = _run(cmd)
        self.assertEqual(r.stdout, NASTY.upper() + "tail\n", r.stderr)   # the value reached a pipeline element
        if sys.platform == "win32":
            return   # Git Bash reads through the resolver script under a grant (up to 3 reads), not a FIFO
        # the FIFO delivered once and is gone: the same command again fails closed as a whole,
        # no "" reaches the pipeline, nothing after it runs
        r2 = _run(cmd)
        self.assertEqual(r2.returncode, 97)
        self.assertEqual(r2.stdout, "")
        self.assertIn("not delivered", r2.stderr)

    def test_two_references_to_one_key_share_one_delivery(self):
        out = _bash_pre("echo " + self.e.ref + " and '" + self.e.ref + "'")["hookSpecificOutput"]
        cmd = out["updatedInput"]["command"]
        self.assertEqual(cmd.count("__ms_1="), 1)
        self.assertEqual(cmd.count("${__ms_1}"), 2)
        if BASH:
            self.assertEqual(_run(cmd).stdout, NASTY + " and " + NASTY + "\n")

    def test_a_model_written_grant_or_resolver_call_is_denied(self):
        for cmd in ('python3 /x/hooks/resolve.py SECRET_c1 --grant abc', 'resolve.py SECRET_c1 --grant abc'):
            with self.subTest(cmd):
                self.assertEqual(_bash_pre(cmd)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_blocked_prompt_is_kept_for_send_and_taken_once(self):
        _hygiene.patch(self, hooks, "_clipboard", lambda text: False)     # SSH: no clipboard
        token = "glpat-" + "PendingProbeAbc123456789x"
        out = hooks.user_prompt({"prompt": f"deploy with {token} now", "session_id": "S7", "transcript_path": "",
                                 **CLAUDE})
        self.assertIn("/maisecrets:send", out["reason"])
        self.assertNotIn(token, out["reason"])
        text = hooks.take_pending("S7")
        self.assertEqual(text, "deploy with ⟦SECRET_c2⟧ now")
        self.assertIsNone(hooks.take_pending("S7"))                 # taken once

    def test_reference_resolves_only_in_a_session_that_saw_it(self):
        out = _bash_pre("echo " + self.e.ref, session="S2")["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("(not given in this session)", out["permissionDecisionReason"])
        self.assertIn("paste", out["permissionDecisionReason"])
        # no session id at all: nothing resolves
        out = hooks.pre_tool({"tool_name": "Bash", "tool_input": {"command": "echo " + self.e.ref}, **CLAUDE})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        # a human types the reference into S2: from now on S2 may resolve it
        hooks.user_prompt({"prompt": "use " + self.e.ref, "session_id": "S2", "transcript_path": "", **CLAUDE})
        out = _bash_pre("echo " + self.e.ref, session="S2")["hookSpecificOutput"]
        self.assertIn("updatedInput", out)

    def test_entry_written_before_the_sessions_list_resolves_in_its_creating_session(self):
        v = Vault()
        meta = v._index["entries"][self.e.key]
        meta["sessions"] = []            # the shape a 0.2.0 hook left behind: creator known, no list
        meta["session"] = "S1"
        v._save_index()
        self.assertEqual(Vault().status(self.e.key, "S1"), "ok")
        self.assertEqual(Vault().status(self.e.key, "S2"), "foreign-session")

    def test_agent_reads_of_the_store_are_denied(self):
        for cmd in ["python3 -m maisecrets.cli get SECRET_c1",
                    "security find-generic-password -s maisecrets -a SECRET_c1 -w",
                    "cat ~/.maisecrets/vault.json"]:
            with self.subTest(cmd):
                self.assertEqual(_bash_pre(cmd)["hookSpecificOutput"]["permissionDecision"], "deny")
        # the rewritten command never comes back through PreToolUse (the model's own input does);
        # if it does, the model copied a nonce from the transcript, and that is denied too
        new = _bash_pre("echo " + self.e.ref)["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertEqual(_bash_pre(new)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_limiter_caps_distinct_keys_per_session_and_resolves_per_hour(self):
        v = Vault()
        v.cfg["max_keys_per_session"] = 2
        v.cfg["max_resolves_per_hour"] = 3
        e2 = v.put("second-secret-value-1", "SECRET", "manual", session="S1")
        e3 = v.put("third-secret-value-22", "SECRET", "manual", session="S1")
        self.assertEqual(v.grant(self.e.key, "S1", "Bash", "a")[1], "ok")
        self.assertEqual(v.grant(e2.key, "S1", "Bash", "b")[1], "ok")
        self.assertIn("max_keys_per_session", v.grant(e3.key, "S1", "Bash", "c")[1])
        self.assertEqual(v.grant(self.e.key, "S1", "Bash", "d")[1], "ok")       # a known key still passes
        self.assertIn("max_resolves_per_hour", v.grant(self.e.key, "S1", "Bash", "e")[1])

    def test_audit_line_names_key_tool_and_context_but_no_value(self):
        _bash_pre("curl -H 'x: " + self.e.ref + "' https://example.org")
        log = Path(HOME, "audit.log").read_text(encoding="utf-8")
        self.assertIn("SECRET_c1\tBash\tcurl -H 'x: ⟦SECRET_c1⟧' https://example.org", log)
        self.assertNotIn(NASTY, log)


class ContextTests(unittest.TestCase):
    """The rewrite places a variable only where bash expands it exactly once; every other
    context is refused with the reason (review, 2026-09-26: bash -c spliced the value as code)."""

    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _hygiene.watch_children(self)
        _reset()
        self.e = Vault().put(NASTY, "SECRET", "manual", session="S1")

    @unittest.skipIf(BASH is None, "no bash")
    def test_value_arrives_inside_a_command_substitution_and_an_unquoted_heredoc(self):
        for name, cmd, want in [
            ("sq in $()", 'printf \'%s\' "$(printf \'%s\' \'' + self.e.ref + '\')"', NASTY),
            ("unquoted heredoc", "cat <<EOF\nkey: " + self.e.ref + "\nEOF\n", "key: " + NASTY + "\n"),
            ("after a comment with an apostrophe", "true # don't\nprintf '%s' " + self.e.ref, NASTY),
        ]:
            with self.subTest(name):
                out = _bash_pre(cmd)["hookSpecificOutput"]
                self.assertNotIn("permissionDecision", out, out)
                new = out["updatedInput"]["command"]
                self.assertNotIn(NASTY[:6], new)
                r = _run(new)
                self.assertEqual(r.stdout, want, r.stderr)

    def test_contexts_the_rewrite_cannot_place_are_refused_with_the_reason(self):
        before = set(os.listdir(hooks._run_dir()))
        marker_value = "x$(touch " + str(Path(_TMP, "MARKER")) + ")y"
        e2 = Vault().put(marker_value, "SECRET", "manual", session="S1")
        for name, cmd in [
            ("bash -c", "bash -c 'printf \"%s\" \"" + e2.ref + "\"'"),
            ("sh -lc", "sh -lc \"echo " + e2.ref + "\""),
            ("ssh", "ssh host \"cmd " + e2.ref + "\""),
            ("eval", "eval \"echo " + e2.ref + "\""),
            ("quoted heredoc", "cat <<'EOF'\nkey: " + e2.ref + "\nEOF\n"),
            ("ansi-c", "printf '%s' $'it\\'s " + e2.ref + "'"),
            ("backtick", "echo `cat " + e2.ref + "`"),
        ]:
            with self.subTest(name):
                out = _bash_pre(cmd)["hookSpecificOutput"]
                self.assertEqual(out.get("permissionDecision"), "deny", out)
                self.assertIn("did not run", out["permissionDecisionReason"])
        self.assertFalse(Path(_TMP, "MARKER").exists(), "a value must never run as code")
        self.assertEqual(set(os.listdir(hooks._run_dir())) - before, set(), "a refused command leaves no value waiting")

    def test_a_command_that_would_transform_the_value_is_refused(self):
        for cmd in ("printf '%s' " + self.e.ref + " | base64", "x=" + self.e.ref + "; echo ${x:0:4}",
                    "PS4='+$x '; x=" + self.e.ref + "; set -x; true", "bash -x run.sh; echo " + self.e.ref,
                    "printf '%s' " + self.e.ref + " | xxd -p"):
            with self.subTest(cmd[:30]):
                out = _bash_pre(cmd)["hookSpecificOutput"]
                self.assertEqual(out.get("permissionDecision"), "deny", out)
                self.assertIn("cannot be placed in this command", out["permissionDecisionReason"])
        # a plain pipeline stays allowed
        plain = _bash_pre("curl -H 'X-Token: " + self.e.ref + "' h | jq .")["hookSpecificOutput"]
        self.assertNotIn("permissionDecision", plain)

    @unittest.skipIf(os.name == "nt", "POSIX FIFO path")
    def test_a_refused_key_leaves_no_value_waiting(self):
        before = set(os.listdir(hooks._run_dir()))
        out = _bash_pre("echo " + self.e.ref + " ⟦SECRET_c99⟧")["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("(no such placeholder)", out["permissionDecisionReason"])
        self.assertIn("do not guess", out["permissionDecisionReason"])
        self.assertEqual(set(os.listdir(hooks._run_dir())) - before, set())

    @unittest.skipIf(os.name == "nt", "POSIX FIFO path")
    def test_the_run_dir_is_private_and_refused_when_it_is_not(self):
        d = hooks._run_dir()
        st = os.stat(d)
        self.assertEqual(st.st_mode & 0o777, 0o700)
        os.chmod(d, 0o755)
        try:
            out = _bash_pre("echo " + self.e.ref)["hookSpecificOutput"]
            self.assertEqual(out.get("permissionDecision"), "deny", out)
        finally:
            os.chmod(d, 0o700)

    def test_client_is_read_from_the_payload_before_the_environment(self):
        from unittest import mock
        with mock.patch.dict(os.environ, {"CODEX_HOME": "/tmp/x"}):
            self.assertEqual(hooks.client_of({"prompt_id": "p"}), "claude")
            self.assertEqual(hooks.client_of({"turn_id": "t"}), "codex")
            self.assertEqual(hooks.client_of({}), "codex")
            out = hooks.pre_tool({"tool_name": "Bash", "prompt_id": "p", "session_id": "S1",
                                  "tool_input": {"command": "echo " + self.e.ref}})["hookSpecificOutput"]
            self.assertNotIn("permissionDecision", out, "a Claude payload is never auto-approved")
        with _hygiene.without_client_env():
            self.assertEqual(hooks.client_of({}), "claude")

    def test_the_run_log_label_names_the_desktop_entry_point(self):
        """The Claude desktop app starts Cowork sessions with CLAUDE_CODE_ENTRYPOINT=local-agent;
        a terminal session sets cli or nothing. Only the label changes, never the client."""
        from unittest import mock
        with _hygiene.without_client_env():
            self.assertEqual(hooks._client_label({"prompt_id": "p"}), "claude")
            os.environ["CLAUDE_CODE_ENTRYPOINT"] = "cli"
            self.assertEqual(hooks._client_label({"prompt_id": "p"}), "claude")
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "local-agent"}):
            self.assertEqual(hooks._client_label({"prompt_id": "p"}), "claude/local-agent")
            self.assertEqual(hooks._client_label({"turn_id": "t"}), "codex",
                             "a Codex run carries no Claude entry point")

    def test_file_tools_resolve_like_mcp_and_the_home_is_off_limits(self):
        out = hooks.pre_tool({"tool_name": "Write", "session_id": "S1", **CLAUDE,
                              "tool_input": {"file_path": "/tmp/x.env", "content": "K=" + self.e.ref}})
        self.assertNotIn("permissionDecision", out["hookSpecificOutput"])
        self.assertEqual(out["hookSpecificOutput"]["updatedInput"]["content"], "K=" + NASTY)
        audit = Path(_TMP, "audit.log").read_text(encoding="utf-8")
        self.assertIn("Write /tmp/x.env", audit)
        self.assertNotIn(NASTY, audit)
        out = hooks.pre_tool({"tool_name": "Edit", "session_id": "S2", **CLAUDE,
                              "tool_input": {"file_path": "/tmp/x.env", "old_string": "a", "new_string": self.e.ref}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("Nothing was written", out["hookSpecificOutput"]["permissionDecisionReason"])
        Path(_TMP, "config.json").write_text(
            '{"backend": "jsonfile", "allow_plaintext_store": true, "resolve_in_files": false}')
        try:
            out = hooks.pre_tool({"tool_name": "Write", "session_id": "S1", **CLAUDE,
                                  "tool_input": {"file_path": "/tmp/x.env", "content": "K=" + self.e.ref}})
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
            self.assertIn("resolve_in_files", out["hookSpecificOutput"]["permissionDecisionReason"])
        finally:
            Path(_TMP, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        out = hooks.pre_tool({"tool_name": "Edit", "session_id": "S1", **CLAUDE,
                              "tool_input": {"file_path": str(Path(_TMP, "config.json")),
                                             "old_string": "a", "new_string": "b"}})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        harmless = {"tool_name": "Write", "tool_input": {"file_path": "/tmp/y", "content": "hi"}, **CLAUDE}
        self.assertEqual(hooks.pre_tool(harmless), {})
        out = _bash_pre("echo x > ~/.maisecrets/config.json")["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("home directory", out["permissionDecisionReason"])

    def test_an_encoder_is_refused_only_where_the_value_can_reach_it(self):
        r = Vault().put(PLAIN, "SECRET", "manual", session="S1").ref
        # the value reaches the encoder: through a pipe, a group, a variable, a file, a heredoc, a function
        for cmd in ("printf %s " + r + " | base64", "base64 <<< " + r, "echo " + r + " | tr a b | base64",
                    "X=" + r + "; echo $X | base64", "export X=" + r + "; echo $X | base64",
                    "X=$(printf %s " + r + "); echo $X | base64", 'X="$(printf %s ' + r + ')"; echo "$X" | base64',
                    "X+=" + r + "; echo $X | base64", "declare X=" + r + "; echo $X | base64",
                    "printf %s " + r + " > /tmp/f; base64 /tmp/f", "printf %s " + r + " | tee /tmp/f; base64 /tmp/f",
                    "base64 < <(printf %s " + r + ")", "base64 <<EOF\n" + r + "\nEOF",
                    "{ printf %s " + r + "; } | base64", "(printf %s " + r + ") | base64",
                    "echo $(printf %s " + r + ") | base64", "for i in 1; do printf %s " + r + "; done | base64",
                    "f(){ base64; }; printf %s " + r + " | f", "function f { base64; }; printf %s " + r + " | f",
                    "read X <<< " + r + "; echo $X | base64", "mapfile a <<< " + r + "; echo $a | base64",
                    "printf %s " + r + " | openssl enc -base64", "printf %s " + r + " | xxd",
                    "printf %s " + r + " | . /dev/stdin", "printf %s " + r + " | source /dev/stdin"):
            with self.subTest(cmd[:40]):
                self.assertEqual(_bash_pre(cmd)["hookSpecificOutput"].get("permissionDecision"), "deny", cmd)
        # the encoder works on another part that never holds the value
        for cmd in ("S=$(printf %s 'grep x' | base64); curl -H 'X: " + r + "' https://example.org",
                    "base64 -d < s.b64 > s.sh; curl -H 'X: " + r + "' https://example.org",
                    "openssl base64 -in a -out b && curl -H 'X: " + r + "' https://example.org"):
            with self.subTest(cmd[:40]):
                self.assertNotEqual(_bash_pre(cmd)["hookSpecificOutput"].get("permissionDecision"), "deny", cmd)

    def test_the_codex_review_shapes_are_refused(self):
        # Codex review of 0.5.3+ (2026-09-28): ANSI-C words, a redirection before the command word, a shell
        # reading redirected input, a long trace option, and an argument heredoc that ends early
        r = Vault().put(PLAIN, "SECRET", "manual", session="S1").ref
        for cmd in ("$'ssh' host echo " + r, "<<< " + r + " base64", "< /dev/null ssh host echo " + r,
                    "2>/dev/null base64 <<< " + r, "bash < <(printf '%s' " + r + ")", "bash < script.sh " + r,
                    "bash -o xtrace script.sh " + r, "bash -v script.sh " + r, "bash --verbose script.sh " + r,
                    # second review round, redirection on an outer construct, and trace settings from elsewhere
                    "exec <<< " + r + "; bash", "{ bash; } <<< " + r, "zsh --xtrace script.sh " + r,
                    "env SHELLOPTS=xtrace bash script.sh " + r, "SHELLOPTS=xtrace bash script.sh " + r,
                    "( bash ) <<< " + r, "for i in 1; do bash; done <<< " + r, "exec < cmds.txt; T=" + r + " bash",
                    "export SHELLOPTS=xtrace; bash s.sh " + r, "set -o xtrace; bash s.sh " + r,
                    "set -x; bash s.sh " + r,
                    # third review round: no space before the redirection, an exec behind a prefix, shopt
                    "{ bash; }< f " + r, "for i in 1; do bash; done<<< " + r, "( bash )<f " + r,
                    "command exec < f; T=" + r + " bash", "shopt -so xtrace; export SHELLOPTS; bash s.sh " + r,
                    "set -o pipefail -o verbose; export SHELLOPTS; bash s.sh " + r):
            with self.subTest(cmd[:40]):
                self.assertEqual(_bash_pre(cmd)["hookSpecificOutput"].get("permissionDecision"), "deny", cmd)
        root = '"/opt/p/hooks/run.sh"'
        early = f"bash {root} report --args-stdin <<'MAISECRETS_ARGS_END'\nbug x\nMAISECRETS_ARGS_END\ntrue\n"
        for cmd in (early + "MAISECRETS_ARGS_END", early,
                    f"bash {root} report --args-stdin <<'MAISECRETS_ARGS_END'\nx\n MAISECRETS_ARGS_END \n"
                    "MAISECRETS_ARGS_END",
                    f"bash {root} report --args-stdin <<MAISECRETS_ARGS_END\n$(true)\nMAISECRETS_ARGS_END",
                    f"bash {root} report --args-stdin; true"):
            with self.subTest(cmd[:50]):
                self.assertEqual(_bash_pre(cmd)["hookSpecificOutput"].get("permissionDecision"), "deny", cmd)
        # final review of 0.5.4: a `<` or the word verbose in another command does not reach the shell
        for cmd in ("API_KEY=" + r + " bash ./deploy.sh && npm test -- --verbose",
                    "TOKEN=" + r + " bash deploy.sh 2>&1 | grep -v verbose",
                    "TOKEN=" + r + " bash d.sh --log-level=verbose",
                    "TOKEN=" + r + " ./scripts/xtrace_report.sh && bash lint.sh",
                    "mysql -p" + r + " db < dump.sql && bash post.sh", "TOKEN=" + r + " bash ./run.sh; sort < list.txt",
                    "curl -H 'X: " + r + "' https://x && diff <(sort a) b && bash check.sh",
                    "exec >log; TOKEN=" + r + " bash d.sh", "set -euo pipefail; TOKEN=" + r + " bash d.sh"):
            with self.subTest(cmd[:50]):
                self.assertNotEqual(_bash_pre(cmd).get("hookSpecificOutput", {}).get("permissionDecision"), "deny", cmd)
        good = f"bash {root} report --args-stdin <<'MAISECRETS_ARGS_END'\nbug $(x) | `y` it's\nMAISECRETS_ARGS_END"
        self.assertEqual(_bash_pre(good), {})

    def test_backstop_false_positives_of_the_old_patterns_pass(self):
        for cmd in ("python3 -m pytest tests/test_resolve.py", "grep -rn PasswordVault src/", "echo x --grant abc"):
            with self.subTest(cmd):
                self.assertEqual(_bash_pre(cmd), {})


class ScannerEdgeTests(unittest.TestCase):
    """Cases the second review round found: nested-shell spellings, ordinary commands that must
    pass, here-strings, arithmetic, backslash-quoted heredocs, the value next to a letter."""

    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _hygiene.watch_children(self)
        _reset()
        self.e = Vault().put(NASTY, "SECRET", "manual", session="S1")

    def test_nested_shell_spellings_are_refused_and_a_value_never_runs(self):
        marker = Path(_TMP, "MARKER2")
        e2 = Vault().put("x$(touch " + str(marker) + ")y", "SECRET", "manual", session="S1")
        for cmd in ("/bin/bash -c 'echo " + e2.ref + "'", "bash --norc -c 'echo " + e2.ref + "'",
                    "bash -o pipefail -c 'echo " + e2.ref + "'", "bash <<EOF\necho " + e2.ref + "\nEOF\n",
                    "echo 'echo " + e2.ref + "' | sh", "/usr/bin/ssh host echo " + e2.ref,
                    "sudo bash -c 'echo " + e2.ref + "'", "docker run img sh -c \"echo " + e2.ref + "\"",
                    "python3 -c 'print(\"" + e2.ref + "\")'", "set -euxo pipefail; echo " + e2.ref,
                    "bash -xe run.sh " + e2.ref, "/usr/bin/base64 <<< " + e2.ref, "x=" + e2.ref + "; echo ${x^^}",
                    "awk -v v=" + e2.ref + " 'BEGIN{print v}'", "echo $((" + e2.ref + "))"):
            with self.subTest(cmd[:40]):
                out = _bash_pre(cmd)["hookSpecificOutput"]
                self.assertEqual(out.get("permissionDecision"), "deny", out)
        self.assertFalse(marker.exists())

    def test_a_command_word_hidden_by_quotes_a_variable_or_a_runner_is_still_refused(self):
        # review, 2026-09-27: \ssh, s''sh and b''ash '-c' were not recognised as command words, and
        # passed every rule on them; a variable as the command word and xargs are only known at run time
        r = self.e.ref
        for cmd in ("\\ssh host 'echo " + r + "'", "s''sh host echo " + r, "'s'sh host echo " + r,
                    "b''ash -c 'echo " + r + "'", "bash '-c' 'echo " + r + "'", "ba\\sh -c 'echo " + r + "'",
                    "printf '%s' " + r + " | xargs -0 ssh host echo", "printf '%s' " + r + " | xargs -I{} sh -c {}",
                    "find . -exec bash -c 'echo " + r + "' \\;", "printf '%s' " + r + " | parallel sh -c"):
            with self.subTest(cmd[:40]):
                out = _bash_pre(cmd)["hookSpecificOutput"]
                self.assertEqual(out.get("permissionDecision"), "deny", out)
        # the real words, not a word inside quotes: these pass
        # ssh anywhere in the command with a value, also as a plain word: the safety net refuses it
        for cmd in ("watch -n 5 grep " + r + " /tmp/x", "parallel grep " + r + " ::: a b",
                    "{ ssh host 'echo " + r + "'; }", "f(){ ssh \"$@\"; }; f host 'echo " + r + "'",
                    "if true; then ssh host 'echo " + r + "'; fi", "! ssh host 'echo " + r + "'",
                    "env -i ssh host 'echo " + r + "'", "command -p ssh host 'echo " + r + "'",
                    "exec -a x ssh host 'echo " + r + "'", "time -p ssh host 'echo " + r + "'",
                    "printf '%s' " + r + " | scp /dev/stdin host:/tmp/x", "rsync -e ssh " + r + " host:/tmp/",
                    "GIT_SSH_COMMAND='ssh -o SetEnv=X=" + r + "' git push",
                    "export GIT_SSH_COMMAND='ssh -o SendEnv=X'; X=" + r + " git push",
                    "printf '%s' " + r + " |& bash",
                    "printf '%s' " + r + " | env -S 'ssh aux01 bash'",
                    "printf '%s' " + r + " | env --split-string=bash",
                    "printf '%s' " + r + " | env -u HOME -S bash",
                    "printf '%s' " + r + " | xargs -0 scp x host:/tmp",
                    "printf '%s' " + r + " | git -c core.sshCommand=ssh push",
                    # env -S in its real words: a path, quotes, a backslash, a long-option prefix, genv, a runner
                    "printf '%s' " + r + " | /usr/bin/env -S 'ssh h bash'", "printf '%s' " + r + " | \\env -S x",
                    "printf '%s' " + r + " | e''nv -S x", "printf '%s' " + r + " | env '-S' x",
                    "printf '%s' " + r + " | env --sp x", "printf '%s' " + r + " | genv -S x",
                    "printf '%s' " + r + " | xargs /usr/bin/env -S 'bash -s'",
                    # a backslash before a newline continues the line: the word after it is still a flag
                    "bash \\\n-c 'echo " + r + "'", "python3 \\\n-c 'print(1)' " + r,
                    "printf '%s' " + r + " | env \\\n-S x"):
            with self.subTest(cmd[:40]):
                self.assertEqual(_bash_pre(cmd)["hookSpecificOutput"].get("permissionDecision"), "deny", cmd)
        # a command word from a variable is not read, as in 0.5.2: like a script file, the hook cannot see what
        # runs, and the client's permission prompt shows the command (THREAT-MODEL, C6)
        for cmd in ("grep 'bash -c' " + r, "printf '%s' " + r + " | xargs -0 echo", 'echo "the ssh key is ' + r + '"',
                    "echo 'ssh host' " + r, '"$PYTHON" script.py ' + r, "${KUBECTL:-kubectl} get " + r,
                    "RSYNC_PASSWORD=" + r + " rsync -av rsync://backup@nas/mod ./out",
                    "ansible-playbook site.yml -c ssh -e db_pass=" + r, "curl -d " + r + " https://x/api/rsync",
                    'case "$1" in start) curl -H "X: ' + r + '" https://x ;; esac',
                    "rsync -av ./dist/ web01:/srv/ && curl -H 'X-Key: " + r + "' https://example.org",
                    '"$HOME/bin/tool" --token ' + r, "${REPO}/bin/deploy " + r, "watch -x grep " + r + " /tmp/x",
                    "env A=1 sort -S 1G " + r, "env -uS cmd " + r, "echo 'a\\\nb' " + r, "echo a \\\nb " + r):
            with self.subTest(cmd[:40]):
                self.assertNotEqual(_bash_pre(cmd)["hookSpecificOutput"].get("permissionDecision"), "deny", cmd)

    @unittest.skipIf(BASH is None, "no bash")
    def test_ordinary_commands_pass_and_the_value_arrives(self):
        for cmd, want in [
            ("printf '%s' " + self.e.ref + " # watch out for eval", NASTY),
            ("printf '%s' \"${PORT:-8080}-" + self.e.ref + "\"", "8080-" + NASTY),
            ("printf '%s' \"" + self.e.ref + "b\"", NASTY + "b"),
            ("cat <<<x >/dev/null; printf '%s' " + self.e.ref, NASTY),
            ("echo $((1<<2)) >/dev/null; printf '%s' '" + self.e.ref + "'", NASTY),
            ("cat <<-EOF\n\tk: " + self.e.ref + "\n\tEOF\n", "k: " + NASTY + "\n"),
        ]:
            with self.subTest(cmd[:40]):
                out = _bash_pre(cmd)["hookSpecificOutput"]
                self.assertNotIn("permissionDecision", out, out)
                r = _run(out["updatedInput"]["command"])
                self.assertEqual(r.stdout, want, r.stderr)
        for cmd in ("python3 script.py --token " + self.e.ref, "docker run --rm -e TOKEN=" + self.e.ref + " alpine env",
                    "git clone https://oauth2:" + self.e.ref + "@host/x.git ssh-keys",
                    "npm run watch -- --token " + self.e.ref,
                    "grep eval file.txt; curl -H 'X: " + self.e.ref + "' h", "bash script.sh " + self.e.ref):
            with self.subTest(cmd[:40]):
                self.assertNotIn("permissionDecision", _bash_pre(cmd)["hookSpecificOutput"])

    def test_an_env_prefix_into_sh_c_is_refused(self):
        # sh -c parses $VAR a second time as code; the answer is a deny that names sh, never a rewrite
        out = _bash_pre("VAR=" + self.e.ref + " sh -c 'printf %s \"$VAR\"'")["hookSpecificOutput"]
        self.assertEqual(out.get("permissionDecision"), "deny", out)
        self.assertNotIn("updatedInput", out)
        self.assertIn("sh would parse the value a second time", out["permissionDecisionReason"])

    @unittest.skipIf(BASH is None or os.name == "nt", "POSIX rewrite through bash")
    def test_a_crlf_heredoc_is_rewritten_exactly_and_the_value_arrives(self):
        # bash takes "EOF\r" as the tag, and the "EOF\r" line closes it; the \r stays in the body
        cmd = "cat <<EOF\r\nk: " + self.e.ref + "\r\nEOF\r\n"
        out = _bash_pre(cmd)["hookSpecificOutput"]
        self.assertNotIn("permissionDecision", out, out)
        got = out["updatedInput"]["command"]
        prelude = re.escape('__ms_1="$(cat ') + r"[^)\s]+" + re.escape(
            ')" || { echo "maisecrets: the value for ' + self.e.key + ' was not delivered (served for 120 s, or '
            'read by another process); the command did not run. Run it again once; if it fails again, stop and '
            'tell the user" >&2; exit 97; }; ')
        self.assertRegex(got, "^" + prelude + re.escape("cat <<EOF\r\nk: ${__ms_1}\r\nEOF\r\n") + r"\Z")
        self.assertNotIn(NASTY, got)
        r = subprocess.run([BASH, "-c", got], capture_output=True)   # bytes: text mode would eat the \r
        self.assertEqual(r.stdout, ("k: " + NASTY + "\r\n").encode(), r.stderr)

    def test_backslash_quoted_heredoc_is_refused_like_a_quoted_one(self):
        for cmd in ("cat <<\\EOF\nk: " + self.e.ref + "\nEOF\n", "cat <<E\"O\"F\nk: " + self.e.ref + "\nEOF\n",
                    "cat <<EOF\nv=$(date) " + self.e.ref + "\nEOF\n"):
            with self.subTest(cmd[:20]):
                self.assertEqual(_bash_pre(cmd)["hookSpecificOutput"].get("permissionDecision"), "deny")

    @unittest.skipIf(os.name == "nt", "Windows uses the resolver and its grant")
    def test_no_grant_is_redeemable_after_a_posix_rewrite(self):
        _bash_pre("printf '%s' " + self.e.ref)
        v = Vault()
        self.assertEqual(v._index.get("grants", {}), {}, "POSIX mints no grant")
        for cmd in ("python3 -m maisecrets.cli resolve SECRET_c1 --grant abc", "resolve SECRET_c1 --grant abc",
                    "python3 -c 'from maisecrets.cli import cmd_resolve'", "ls \"$XDG_RUNTIME_DIR/maisecrets\"",
                    "security dump-keychain -d login.keychain", "cat ~/.MAISECRETS/index.json"):
            with self.subTest(cmd):
                self.assertEqual(_bash_pre(cmd)["hookSpecificOutput"]["permissionDecision"], "deny")

    @unittest.skipIf(os.name == "nt", "POSIX FIFO path")
    def test_a_second_key_that_cannot_be_served_takes_the_first_back(self):
        from unittest import mock
        e2 = Vault().put(PLAIN, "SECRET", "manual", session="S1")
        before = set(os.listdir(hooks._run_dir()))
        calls = {"n": 0}
        real = hooks._serve_value_later

        def flaky(fifo, value, seconds=120.0, **kw):
            calls["n"] += 1
            return real(fifo, value, seconds, **kw) if calls["n"] == 1 else False
        with mock.patch.object(hooks, "_serve_value_later", flaky):
            out = _bash_pre("echo " + self.e.ref + " " + e2.ref)["hookSpecificOutput"]
        self.assertEqual(out.get("permissionDecision"), "deny")
        import time as _t
        _t.sleep(0.3)
        self.assertEqual(set(os.listdir(hooks._run_dir())) - before, set(), "the first value must not wait")

    def test_a_refused_command_writes_no_audit_line(self):
        audit = Path(_TMP, "audit.log")
        _bash_pre("echo " + self.e.ref + " ⟦SECRET_c99⟧")
        self.assertFalse(audit.exists() and self.e.key in audit.read_text(encoding="utf-8"))

    def test_hooks_log_records_every_run_without_values(self):
        import io
        from unittest import mock
        buf = io.StringIO()
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "printf '%s' " + self.e.ref},
                              "session_id": "S1", "prompt_id": "p"})
        with mock.patch.object(hooks.sys, "stdin", io.StringIO(payload)), mock.patch.object(hooks.sys, "stdout", buf):
            hooks.main(["hook", "pre-tool"])
        log = Path(_TMP, "hooks.log").read_text(encoding="utf-8")
        self.assertIn("pre-tool\tclaude\tS1\tBash\trewrite", log)
        self.assertNotIn(NASTY, log)
        self.assertNotIn("printf", log)


class FailClosedTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_exactly_one_answer_leaves_the_process_when_the_watchdog_fires(self):
        import io
        from unittest import mock
        def slow(payload):
            import time as _t
            _t.sleep(0.6)
            return {"decision": "block", "reason": "handler"}
        buf = io.StringIO()
        with mock.patch.dict(hooks.HANDLERS, {"user-prompt": slow}), \
                mock.patch.dict(hooks.WATCHDOG_SECONDS, {"user-prompt": 0.2}), \
                mock.patch.object(hooks.os, "_exit", lambda code: None), \
                mock.patch.object(hooks.sys, "stdin", io.StringIO('{"prompt": "x", "prompt_id": "p"}')), \
                mock.patch.object(hooks.sys, "stdout", buf):
            hooks.main(["hook", "user-prompt"])
        out = buf.getvalue()
        obj = json.loads(out)      # one object, not two concatenated
        self.assertIn("took longer", obj["reason"])

    def test_fail_closed_texts_say_whether_the_tool_ran(self):
        pre = hooks._fail_closed("pre-tool", CLAUDE, "x")["hookSpecificOutput"]
        self.assertIn("did NOT run", pre["permissionDecisionReason"])
        post = hooks._fail_closed("post-tool", CLAUDE, "x")["hookSpecificOutput"]
        self.assertIn("ran and finished", post["updatedToolOutput"])
        self.assertIn("ran and finished", hooks._fail_closed("post-tool", {"turn_id": "t"}, "x")["reason"])

    def test_config_error_in_the_policy_names_the_key_in_the_answer(self):
        import io
        from unittest import mock
        from maisecrets import vault as vmod
        buf = io.StringIO()
        with mock.patch.dict(vmod.POLICY_PATHS, {__import__("platform").system(): Path(_TMP, "policy.json")}):
            Path(_TMP, "policy.json").write_text('{"max_ttl_seconds": "x"}')
            try:
                with mock.patch.object(hooks.sys, "stdin", io.StringIO('{"prompt": "hi", "prompt_id": "p"}')), \
                        mock.patch.object(hooks.sys, "stdout", buf):
                    hooks.main(["hook", "user-prompt"])
            finally:
                Path(_TMP, "policy.json").unlink()
        out = json.loads(buf.getvalue())
        self.assertEqual(out["decision"], "block")
        self.assertIn("max_ttl_seconds", out["reason"])
        self.assertNotIn("locked store", out["reason"])

    def test_policy_keys_win_over_the_user_file(self):
        from unittest import mock
        from maisecrets import vault as vmod
        with mock.patch.dict(vmod.POLICY_PATHS, {__import__("platform").system(): Path(_TMP, "policy.json")}):
            Path(_TMP, "policy.json").write_text('{"max_keys_per_session": 3, "scrub_transcript": false}')
            Path(_TMP, "config.json").write_text(
                '{"backend": "jsonfile", "allow_plaintext_store": true, "max_keys_per_session": 99}')
            try:
                cfg = vmod.load_config()
            finally:
                Path(_TMP, "policy.json").unlink()
                Path(_TMP, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        self.assertEqual(cfg["max_keys_per_session"], 3)
        self.assertFalse(cfg["scrub_transcript"])
        self.assertEqual(sorted(cfg["policy_keys"]), ["max_keys_per_session", "scrub_transcript"])

    def test_post_tool_with_a_broken_payload_withholds_instead_of_failing_open(self):
        import io
        from unittest import mock
        buf = io.StringIO()
        # a broken stdin carries no client marker: the client is Claude Code by the environment
        with mock.patch.object(hooks.sys, "stdin", io.StringIO("{not json")), \
                mock.patch.object(hooks.sys, "stdout", buf), _hygiene.without_client_env():
            rc = hooks.main(["hook", "post-tool"])
        self.assertEqual(rc, 0)
        self.assertIn("withheld", json.loads(buf.getvalue())["hookSpecificOutput"]["updatedToolOutput"])

    def test_damaged_index_stays_damaged_until_repaired(self):
        Vault().put(PLAIN, "SECRET", "manual", session="S1")
        INDEX.write_text("{not json", encoding="utf-8")
        for _ in range(2):
            with self.assertRaises(RuntimeError):
                Vault().put("second-value-9876", "SECRET", "manual", session="S1")
        self.assertEqual(json.loads(Path(_TMP, "vault.json").read_text())["SECRET_c1"], PLAIN,
                         "the first value is never overwritten")
        from maisecrets.vault import make_backend
        v = Vault.__new__(Vault)
        v.cfg = hooks.load_config()
        v.backend = make_backend(v.cfg)
        info = v.repair()
        self.assertEqual(info["counters"].get("SECRET"), 1)

        class Opaque:
            test_mode = True

            def get(self, k):
                return None
        v2 = Vault.__new__(Vault)
        v2.cfg, v2.backend = v.cfg, Opaque()
        with self.assertRaises(RuntimeError):
            v2.repair()
        e = Vault().put("third-value-5555", "SECRET", "manual", session="S1")
        self.assertEqual(e.key, "SECRET_c2", "counters continue after a repair")

    def test_config_with_a_wrong_type_names_the_key_and_defaults_stay_untouched(self):
        from maisecrets import vault as vmod
        before = json.dumps(vmod.DEFAULT_CONFIG, sort_keys=True)
        Path(_TMP, "config.json").write_text(
            '{"backend": "jsonfile", "allow_plaintext_store": true, "ttl_seconds": 3600}')
        try:
            # a wrong type in the USER file never locks the user out: the strict defaults apply and
            # the warning names the key (it reaches the user at session start and in `status`)
            cfg = vmod.load_config()
            self.assertIn("ttl_seconds", cfg["config_warning"])
            self.assertEqual(cfg["ttl_seconds"], vmod.DEFAULT_CONFIG["ttl_seconds"])
            Path(_TMP, "config.json").write_text(
                '{"backend": "jsonfile", "allow_plaintext_store": true, "shortcutt": 1, "colour": 1}')
            # a typo of a real key is named; any other key is only counted, it may be a pasted value
            warning = vmod.load_config()["config_warning"]
            self.assertIn("shortcutt", warning)
            self.assertNotIn("colour", warning)
            self.assertIn("1 more", warning)
            self.assertEqual(vmod.load_config()["backend"], "jsonfile")
        finally:
            Path(_TMP, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        os.environ["CLAUDE_PLUGIN_OPTION_TTL_HOURS"] = "1"
        try:
            vmod.load_config()
        finally:
            del os.environ["CLAUDE_PLUGIN_OPTION_TTL_HOURS"]
        self.assertEqual(json.dumps(vmod.DEFAULT_CONFIG, sort_keys=True), before)

    def test_transcript_scrub_keeps_every_record_valid_json(self):
        cases = ["Secr3tValue\\", 'pässwörd"123', "plain-value-0001", "a\"b\\c"]
        path = Path(_TMP, "t.jsonl")
        lines = [json.dumps({"type": "user", "message": {"content": "token " + v + " end"}}, ensure_ascii=asc)
                 for v in cases for asc in (True, False)]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertTrue(hooks._scrub_transcript(str(path), cases, ["⟦X⟧"] * len(cases)))
        data = path.read_text(encoding="utf-8")
        for line in data.splitlines():
            rec = json.loads(line)
            content = rec["message"]["content"]
            for v in cases:
                self.assertNotIn(v, content)
                self.assertNotIn(v, line)


class McpTests(unittest.TestCase):
    def setUp(self):
        _reset()
        self.e = Vault().put(PLAIN, "SECRET", "manual", session="S1")

    def test_mcp_arguments_are_resolved_in_place_keeping_the_shape(self):
        payload = {"tool_name": "mcp__x__y", "session_id": "S1", **CLAUDE,
                   "tool_input": {"to": "a " + self.e.ref, "n": 1, "list": [self.e.ref, 2]}}
        out = hooks.pre_tool(payload)["hookSpecificOutput"]
        self.assertEqual(out["updatedInput"], {"to": "a " + PLAIN, "n": 1, "list": [PLAIN, 2]})
        # rehydration "automatic" (the default): no ask of ours, the client's own permission rules decide
        self.assertNotIn("permissionDecision", out)
        _reset()
        self.e = Vault().put(PLAIN, "SECRET", "manual", session="S1")
        payload["tool_input"] = {"to": "a " + self.e.ref, "n": 1, "list": [self.e.ref, 2]}
        with _config(rehydration="confirm"):
            out = hooks.pre_tool(payload)["hookSpecificOutput"]
        self.assertEqual(out["updatedInput"], {"to": "a " + PLAIN, "n": 1, "list": [PLAIN, 2]})
        self.assertEqual(out["permissionDecision"], "ask")
        self.assertIn("to, list", out["permissionDecisionReason"])
        self.assertNotIn(PLAIN, out["permissionDecisionReason"])

    def test_a_value_in_a_message_body_goes_out_by_default_and_is_confirmed_with_a_warning_on_confirm(self):
        # the user asked the agent to send the value: maisecrets keeps it out of the model, not out of the post
        tool_input = {"channel": "C1", "text": "the key is " + self.e.ref}
        out = hooks.pre_tool({"tool_name": "mcp__slack__post", "session_id": "S1", "prompt_id": "p",
                              "tool_input": tool_input})["hookSpecificOutput"]
        self.assertNotIn("permissionDecision", out)
        self.assertEqual(out["updatedInput"]["text"], "the key is " + PLAIN)
        codex = hooks.pre_tool({"tool_name": "mcp__slack__post", "session_id": "S1", "turn_id": "t",
                                "tool_input": tool_input})["hookSpecificOutput"]
        self.assertEqual(codex["permissionDecision"], "allow")
        self.assertEqual(codex["updatedInput"]["text"], "the key is " + PLAIN)
        with _config(rehydration="confirm"):
            out = hooks.pre_tool({"tool_name": "mcp__slack__post", "session_id": "S1", "prompt_id": "p",
                                  "tool_input": tool_input})["hookSpecificOutput"]
            self.assertEqual(out["permissionDecision"], "ask")
            self.assertIn("WARNING: text is text that other people can read", out["permissionDecisionReason"])
            # nested, listed, camel-case, suffixed and JSON-string text fields (review, 2026-09-27)
            for ti in ({"messages": [{"text": self.e.ref}]}, {"items": [{"Text": self.e.ref}]},
                       {"children": [{"paragraph": {"rich_text": [{"text": {"content": self.e.ref}}]}}]},
                       {"messageText": self.e.ref}, {"text_body": self.e.ref}, {"msg": self.e.ref},
                       {"params": json.dumps({"text": self.e.ref}, ensure_ascii=False)}):
                got = hooks.pre_tool({"tool_name": "mcp__x__post", "session_id": "S1", "prompt_id": "p",
                                      "tool_input": ti})["hookSpecificOutput"]
                self.assertIn("WARNING", got["permissionDecisionReason"], ti)
            # whole words: these fields carry values a tool needs, not published text
            for ti in ({"context": self.e.ref}, {"plaintext": self.e.ref}, {"httpStatus": self.e.ref}):
                got = hooks.pre_tool({"tool_name": "mcp__x__post", "session_id": "S1", "prompt_id": "p",
                                      "tool_input": ti})["hookSpecificOutput"]
                self.assertNotIn("WARNING", got["permissionDecisionReason"], ti)
            # Codex cannot ask with a rewritten input: confirm refuses there, before anything is resolved
            got = hooks.pre_tool({"tool_name": "mcp__mail__send", "session_id": "S1", "turn_id": "t",
                                  "tool_input": {"to": self.e.ref}})["hookSpecificOutput"]
            self.assertEqual(got["permissionDecision"], "deny")
            self.assertNotIn("updatedInput", got)
            self.assertIn("Codex cannot ask", got["permissionDecisionReason"])
        self.assertEqual(hooks._ref_fields({"messages": [{"text": self.e.ref}]}), ["messages[0].text"])

    def test_mcp_foreign_session_is_denied_and_nothing_is_partially_resolved(self):
        out = hooks.pre_tool({"tool_name": "mcp__x__y", "session_id": "S9", **CLAUDE,
                              "tool_input": {"to": self.e.ref}})["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertNotIn("updatedInput", out)


class NoticeTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_the_notice_names_the_kind_and_one_step_and_nothing_more(self):
        from unittest import mock
        _hygiene.patch(self, hooks, "_clipboard", lambda t: True)
        mail = hooks.user_prompt({"prompt": "write to anna.schmidt@firma-xyz.de", "session_id": "K1",
                                  "transcript_path": "", "prompt_id": "p"})["reason"].split("\n")
        self.assertEqual(mail[0], "maisecrets: personal data was found and kept from the AI.")
        self.assertEqual(mail[1], "", "the step stands apart")
        self.assertRegex(mail[2], r"^    (⌘V|Ctrl\+V)  pastes the cleaned prompt\.")
        self.assertEqual(mail[-1], "Something wrong? /maisecrets:report · maisecrets by mcpgate.de")
        self.assertNotIn("github.com", "\n".join(mail))
        self.assertNotIn("EMAIL_c", "\n".join(mail), "no masked forms without the prompt around them")
        both = hooks.user_prompt({"prompt": "mail anna.schmidt@firma-xyz.de token glpat-" + "Q" * 3
                                  + "abcdefghij1234567890", "session_id": "K2", "transcript_path": "",
                                  "prompt_id": "p"})["reason"]
        self.assertIn("a secret and personal data were found", both)
        for system, key in (("Darwin", "⌘V"), ("Windows", "Ctrl+V"), ("Linux", "Ctrl+V")):
            with mock.patch.object(hooks.platform, "system", return_value=system):
                self.assertEqual(hooks._paste_key(), key)

    def test_without_a_clipboard_the_whole_prompt_is_shown_and_codex_gets_no_empty_line(self):
        long_tail = " and more words" * 40
        prompt = "check glpat-" + "Q" * 3 + "abcdefghij1234567890" + long_tail + " end-marker"
        _hygiene.patch(self, hooks, "_clipboard", lambda t: False)
        for payload, codex in (({"prompt": prompt, "session_id": "N1", "transcript_path": "", "prompt_id": "p"}, False),
                               ({"prompt": prompt, "session_id": "N2", "transcript_path": "", "turn_id": "t"}, True)):
            reason = hooks.user_prompt(payload)["reason"]
            with self.subTest(codex=codex):
                self.assertIn("end-marker", reason, "the text to copy is the whole prompt")
                self.assertNotIn("Wrong detection?\n", reason + "\n") if codex else None
                self.assertFalse(reason.rstrip().endswith("Wrong detection?"))


class RedactionTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_shapeless_value_is_redacted_by_exact_match(self):
        e = Vault().put(NASTY, "SECRET", "manual", session="S1")
        out = hooks.post_tool({"tool_name": "Bash", "session_id": "S1", **CLAUDE,
                               "tool_response": {"stdout": "PW=" + NASTY + "\ngot:" + NASTY + "\n", "stderr": ""}})
        text = json.dumps(out)
        self.assertNotIn(NASTY, text)
        self.assertEqual(out["hookSpecificOutput"]["updatedToolOutput"]["stdout"], f"PW={e.ref}\ngot:{e.ref}\n")
        self.assertIn(f"masked 2 value(s) in this Bash result before the AI saw it: {e.ref}", out["systemMessage"])

    def test_index_carries_no_reversible_fingerprint(self):
        import hashlib
        Vault().put(PLAIN, "SECRET", "manual", session="S1")
        idx = INDEX.read_text()
        self.assertNotIn(hashlib.sha256(PLAIN.encode()).hexdigest()[:12], idx)
        self.assertNotIn(PLAIN, idx)
        # the key lives in the backend, not in the index
        self.assertNotIn(Vault().fp_key().hex(), idx)

    def test_output_without_live_entries_is_untouched(self):
        out = hooks.post_tool({"tool_name": "Bash", "session_id": "S1", **CLAUDE,
                               "tool_response": {"stdout": "nothing here 12345678", "stderr": ""}})
        self.assertEqual(out, {})


class StorePathTests(unittest.TestCase):
    """External review, 2026-09-28: Read, Grep and Glob were not checked at all, so the agent could read the
    key and the ciphertext of the file store and decode them outside every gate around a resolve."""

    def pre(self, tool: str, tool_input: dict, cwd: str = "/tmp") -> str:
        out = hooks.pre_tool({"tool_name": tool, "tool_input": tool_input, "session_id": "S1", **CLAUDE, "cwd": cwd})
        return out.get("hookSpecificOutput", {}).get("permissionDecision", "pass")

    def test_the_read_tools_are_in_the_matcher(self):
        hooks_json = json.loads((Path(__file__).resolve().parent.parent / "hooks" / "hooks.json").read_text())
        matcher = hooks_json["hooks"]["PreToolUse"][0]["matcher"]
        for tool in ("Read", "Grep", "Glob"):
            self.assertRegex(tool, "^(?:" + matcher + ")$")

    def test_a_read_of_the_store_or_its_value_directory_is_refused(self):
        home = str(hooks.HOME) if hasattr(hooks, "HOME") else os.environ["MAISECRETS_HOME"]
        link = Path(tempfile.mkdtemp(prefix="maisecrets-link-")) / "l"
        self.addCleanup(shutil.rmtree, link.parent, True)
        os.symlink(home, link)
        for tool, ti in (("Read", {"file_path": home + "/key"}), ("Read", {"file_path": str(link) + "/vault.enc.json"}),
                         ("Grep", {"pattern": "x", "path": home}), ("Glob", {"pattern": home + "/*"}),
                         ("Grep", {"pattern": "x", "glob": home + "/*.json"}),
                         ("Read", {"file_path": os.path.join("..", os.path.basename(home), "key"),
                                   "__cwd": os.path.join(os.path.dirname(home), "x")}),
                         ("mcp__fs__read_file", {"path": home + "/vault.enc.json"})):
            with self.subTest(tool=tool, ti=ti):
                ti = dict(ti)
                cwd = ti.pop("__cwd", "/tmp")
                self.assertEqual(self.pre(tool, ti, cwd=cwd), "deny")

    def test_another_spelling_or_a_grep_over_a_parent_is_refused(self):
        # Codex review, 2026-09-28: an uppercase spelling passed on a case-insensitive file system, and a Grep
        # over the store's parent directory searched the store
        home = os.environ["MAISECRETS_HOME"]
        Path(home, "key").write_text("x", encoding="utf-8")
        self.addCleanup(lambda: Path(home, "key").unlink(missing_ok=True))
        mixed = home[:-3] + home[-3:].swapcase()
        if os.path.exists(mixed):                      # a case-insensitive file system (macOS by default)
            self.assertEqual(self.pre("Read", {"file_path": mixed + "/key"}), "deny")
        self.assertEqual(self.pre("Grep", {"pattern": "x", "path": os.path.dirname(home)}), "deny")
        self.assertEqual(self.pre("Glob", {"pattern": "*", "path": os.path.dirname(home)}), "pass", "names only")
        self.assertEqual(self.pre("Grep", {"pattern": "x"}, cwd=os.path.dirname(home)), "deny", "no path: the cwd")

    def test_ordinary_reads_pass(self):
        # a folder that does not hold the store: on Linux the test home lies in /tmp, so a Grep over /tmp is
        # rightly refused there
        elsewhere = tempfile.mkdtemp(prefix="maisecrets-elsewhere-")
        self.addCleanup(shutil.rmtree, elsewhere, True)
        for tool, ti in (("Read", {"file_path": "/etc/hosts"}), ("Glob", {"pattern": "**/*.py"}),
                         ("Grep", {"pattern": "maisecrets", "path": elsewhere}),
                         ("mcp__x__y", {"text": "the store is in ~/.maisecrets"})):
            with self.subTest(tool=tool, ti=ti):
                self.assertEqual(self.pre(tool, ti), "pass")


class ResolvedValueRedactionTests(unittest.TestCase):
    def setUp(self):
        _reset()
        self.v = Vault()
        self.e = self.v.put("Zq7kP2mX9vR4tL8w", "SECRET", "manual", session="S1")
        # the session resolved it (an MCP call), so it is expected back in any position
        self.assertEqual(self.v.record_resolve(self.e.key, "S1", "mcp__x__y", "{}"), "ok")

    def _post(self, text: str) -> str:
        out = hooks.post_tool({"tool_name": "Bash", "session_id": "S1", "prompt_id": "p",
                               "tool_response": {"stdout": text}})
        return out["hookSpecificOutput"]["updatedToolOutput"]["stdout"] if out else text

    def test_value_in_url_path_query_prefix_and_encodings_is_redacted(self):
        import base64
        raw = "Zq7kP2mX9vR4tL8w"
        for text in ("https://x.example/?k=" + raw + "&z=1", "path/" + raw + "/x", "x" + raw,
                     base64.b64encode(raw.encode()).decode(), raw.encode().hex(), "+" + raw + " :",
                     '{"pw": "' + raw + '"}'):
            with self.subTest(text[:20]):
                out = self._post(text)
                self.assertNotIn(raw, out)
                self.assertNotIn(base64.b64encode(raw.encode()).decode(), out)
                self.assertIn(self.e.ref, out)

    def test_a_short_value_the_session_put_in_comes_back_masked(self):
        # external review, 2026-09-28: a password shorter than 8 characters stored with `put` came back to the
        # model in plain text after it was used, because every exact match started at 8 characters
        for raw in ("A7x!42", "Kq9#vT", "8812"):
            with self.subTest(raw):
                e = self.v.put(raw, "SECRET", "manual", session="S1")
                self.assertEqual(self.v.record_resolve(e.key, "S1", "Bash", "{}"), "ok")
                for text in ("pw=" + raw + " done", "x" + raw + "y"):
                    out = self._post(text)
                    self.assertNotIn(raw, out)
                    self.assertIn(e.ref, out)

    def test_a_value_of_one_to_three_characters_does_not_break_the_words_around_it(self):
        # Codex review: a resolved `a` turned `status: a database` into masks inside every word
        e = self.v.put("a", "SECRET", "manual", session="S1")
        self.assertEqual(self.v.record_resolve(e.key, "S1", "Bash", "{}"), "ok")
        self.assertEqual(self._post("status: a database"), "status: " + e.ref + " database")
        e2 = self.v.put("i", "SECRET", "manual", session="S1")
        self.assertEqual(self.v.record_resolve(e2.key, "S1", "Bash", "{}"), "ok")
        self.assertEqual(self._post("çiğ and i ok"), "çiğ and " + e2.ref + " ok", "a letter is a letter in any script")

    def test_a_result_above_the_cap_is_masked_without_storing(self):
        _reset()
        emails = " ".join(f"user{i}@corp-example.org" for i in range(130))
        res = hooks.post_tool({"tool_name": "Bash", "session_id": "S1", "prompt_id": "p",
                               "tool_response": {"stdout": emails}})
        out = res["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        self.assertNotIn("@corp-example.org", out)
        self.assertIn("⟦EMAIL⟧", out)
        self.assertLessEqual(len([e for e in Vault().list() if not e.purged]), 100)


class ShortcutTests(unittest.TestCase):
    @unittest.skipIf(BASH is None, "no bash")
    def test_shortcut_installs_command_and_wrapper_that_finds_the_newest_copy(self):
        from unittest import mock
        from maisecrets import cli
        home = Path(tempfile.mkdtemp(prefix="maisecrets-shortcut-"))
        cfg_dir = home / ".claude"
        # two installed copies; the wrapper must pick 0.3.10 over 0.3.9 (numeric, not lexical)
        for v in ("0.3.9", "0.3.10"):
            d = home / ".claude" / "plugins" / "cache" / "mp" / "maisecrets" / v
            (d / ".claude-plugin").mkdir(parents=True)
            (d / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": "maisecrets", "version": v}))
            (d / "hooks").mkdir()
            (d / "hooks" / "run.sh").write_text('#!/usr/bin/env bash\necho "ran $0 $*"\n')
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(cfg_dir), "HOME": str(home)}):
            self.assertEqual(cli.cmd_shortcut([]), 0)
            cmd = (cfg_dir / "commands" / "ms.md").read_text(encoding="utf-8")
            self.assertIn("allowed-tools: Bash(bash ~/.maisecrets/bin/ms.sh*)", cmd)
            self.assertIn("!`bash ~/.maisecrets/bin/ms.sh`", cmd)
            self.assertIn("Sent: ", cmd)
            wrapper = Path(_TMP, "bin", "ms.sh")
            self.assertTrue(wrapper.exists())
            r = subprocess.run([BASH, str(wrapper)], capture_output=True, text=True,
                               env={**os.environ, "HOME": str(home)})
        self.assertIn("/0.3.10/hooks/run.sh pending", r.stdout.replace("\\", "/"), r.stderr)
        self.assertNotIn("$(", cmd.split("---")[2].split("\n")[1], "the ! line is a fixed path, never a substitution")

    def test_session_start_offers_the_shortcut_once_and_installs_nothing(self):
        """Writing ~/.claude/commands without a question was a change behind the user's back, and
        Codex cannot use /ms (UX review, 2026-09-27): the session start only names the command."""
        cfg_dir = Path(tempfile.mkdtemp(prefix="maisecrets-cfg-"))
        marker = Path(_TMP, ".shortcut")
        marker.unlink(missing_ok=True)
        base = {k: v for k, v in os.environ.items() if not k.startswith("CODEX_")}
        claude = {**base, "CLAUDE_CONFIG_DIR": str(cfg_dir), "CLAUDE_PLUGIN_ROOT": str(ROOT), "CLAUDECODE": "1"}

        def start(env):
            r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "session-start"],
                               input="{}", capture_output=True, text=True, env=env)
            return json.loads(r.stdout).get("systemMessage", "")
        first = start(claude)
        self.assertIn("/maisecrets:shortcut adds /ms", first)
        self.assertFalse((cfg_dir / "commands" / "ms.md").exists(), "nothing is installed")
        self.assertEqual(marker.read_text().strip(), "offered")
        self.assertNotIn("/maisecrets:shortcut", start(claude), "offered once")
        marker.unlink()
        codex = {k: v for k, v in claude.items() if k != "CLAUDECODE"}
        codex["CODEX_HOME"] = str(cfg_dir)
        msg = start(codex)
        self.assertNotIn("/maisecrets:", msg, "Codex has no slash commands for plugins")
        self.assertFalse(marker.exists())

    def test_the_first_session_start_speaks_plainly(self):
        Path(_TMP, ".announced").unlink(missing_ok=True)
        env = {k: v for k, v in os.environ.items() if not k.startswith("CODEX_")}
        env.update({"CLAUDE_PLUGIN_ROOT": str(ROOT), "CLAUDECODE": "1"})
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), "session-start"],
                           input="{}", capture_output=True, text=True, env=env)
        msg = json.loads(r.stdout)["systemMessage"]
        self.assertIn("is on. It keeps passwords, keys and personal data out of the AI", msg)
        for jargon in ("config.json", "Metadata:", '{"backend"', "mcpgate.de"):
            self.assertNotIn(jargon, msg)

    def test_shortcut_can_be_removed_and_stays_removed(self):
        from unittest import mock
        cfg_dir = Path(tempfile.mkdtemp(prefix="maisecrets-cfg-"))
        env = {"CLAUDE_CONFIG_DIR": str(cfg_dir), "CLAUDE_PLUGIN_ROOT": str(ROOT)}
        from maisecrets import cli
        with mock.patch.dict(os.environ, env):
            self.assertEqual(cli.cmd_shortcut([]), 0)
            self.assertTrue((cfg_dir / "commands" / "ms.md").exists())
            self.assertEqual(cli.cmd_shortcut(["--remove"]), 0)
        self.assertFalse((cfg_dir / "commands" / "ms.md").exists())
        self.assertEqual(Path(_TMP, ".shortcut").read_text().strip(), "removed")


class ReportTests(unittest.TestCase):
    def setUp(self):
        _reset()
        try:
            os.unlink(Path(HOME, "events.log"))
        except FileNotFoundError:
            pass
        _hygiene.patch(self, hooks, "_clipboard", lambda text: True)

    def test_block_records_an_event_and_the_issue_link_carries_no_value(self):
        from maisecrets import events
        token = "glpat-" + "ReportProbeAbc123456789x"
        out = hooks.user_prompt({"prompt": f"token {token}", "session_id": "S1", "transcript_path": "", **CLAUDE})
        self.assertIn("/maisecrets:report", out["reason"])
        ev = events.load()[-1]
        self.assertEqual(ev["hook"], "UserPromptSubmit")
        self.assertEqual(ev["hits"][0]["kind"], "gitlab-pat")
        self.assertNotIn(token, json.dumps(ev))
        url = events.issue_url(ev, "a build id")
        self.assertTrue(url.startswith(events.ISSUES_URL + "?"))
        self.assertNotIn("ReportProbe", url)
        self.assertIn("gitlab-pat", url)
        self.assertIn("a+build+id", url)


    def test_bug_and_feature_links_carry_the_text_and_no_event(self):
        from maisecrets import events
        url = events.generic_issue_url("feature", "ask before a persistent value resolves")
        self.assertIn("labels=enhancement", url)
        self.assertIn("Feature%3A+ask+before", url)
        url = events.generic_issue_url("bug", "the block notice hides the clipboard hint")
        self.assertIn("labels=bug", url)
        self.assertNotIn("hits", url)


class ConcurrencyTests(unittest.TestCase):
    def test_parallel_hook_processes_do_not_lose_the_index_or_each_other(self):
        _reset()
        # each child waits up to 60 s for the lock, not the 6 s of a hook: twelve processes on a loaded windows-latest
        # runner queued past 6 s and failed with LockTimeout (2026-10-20). The test asks whether the lock loses
        # nothing; whether one lock comes within a hook's deadline is asked by other tests
        code = ("import sys; sys.path.insert(0, sys.argv[1]); from maisecrets.home import _Lock; "
                "_Lock.LOCK_DEADLINE = 60.0; from maisecrets.vault import Vault; "
                "e = Vault().put('parallel-value-' + sys.argv[2] + '-abcdef', 'SECRET', 'manual', session='S1'); "
                "print(e.key)")
        procs = [subprocess.Popen([sys.executable, "-c", code, str(ROOT), str(i)], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, env=dict(os.environ)) for i in range(12)]
        outs = [p.communicate(timeout=120) for p in procs]
        errors = [err for _o, err in outs if err.strip()]
        self.assertEqual(errors, [], errors[:2])
        keys = sorted(o.strip() for o, _e in outs)
        self.assertEqual(len(set(keys)), 12, keys)                        # twelve distinct references
        live = [e for e in Vault().list() if not e.purged]
        self.assertEqual(len(live), 12)                                    # nothing lost in the index


class DocumentRouteTests(unittest.TestCase):
    """A value for a document: the refusal of inline code and of a quoted heredoc names the route that works
    (field report, Codex, 2026-10-16: the model asked the user to type the address into the PDF by hand)."""

    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _hygiene.watch_children(self)
        _reset()
        self.e = Vault().put(NASTY, "SECRET", "manual", session="S1")

    def _reason(self, cmd: str, client: dict) -> str:
        # the POSIX text: on Windows, Codex gets its own refusal before the route (test_windows_codex_keeps_its_own)
        from unittest import mock
        with mock.patch.object(hooks.platform, "system", return_value="Linux"):
            out = _bash_pre(cmd, client=client)["hookSpecificOutput"]
        self.assertEqual(out.get("permissionDecision"), "deny", out)
        return out["permissionDecisionReason"]

    def test_inline_code_and_a_quoted_heredoc_name_the_script_file_route(self):
        r = self.e.ref
        forms = {"python3 -c": "python3 -c \"open('a.html','w').write('" + r + "')\"",
                 "node -e": "node -e \"require('fs').writeFileSync('a.html','" + r + "')\"",
                 "python3 heredoc": "python3 - <<'PY'\nopen('a.html','w').write('" + r + "')\nPY\n",
                 "cat heredoc": "cat > a.html <<'EOF'\n<p>" + r + "</p>\nEOF\n"}
        for client, tool in ((CLAUDE, "Write or Edit"), (_hygiene.CODEX, "apply_patch")):
            for name, cmd in forms.items():
                with self.subTest(name, client=client):
                    why = self._reason(cmd, client)
                    self.assertIn("did not run", why)
                    script = "node make_doc.js" if name == "node -e" else "python3 make_doc.py"
                    self.assertIn(f"run it with the placeholder as its argument: {script} ⟦{self.e.key}⟧", why)
                    self.assertIn(f"Or write the file with {tool}: the placeholder in the content gets the value", why)
                    self.assertIn("Do not ask the user to type the value in", why)

    def test_without_values_in_files_the_route_names_only_the_argument(self):
        with _config(resolve_in_files=False):
            why = self._reason("python3 -c 'print(1)' " + self.e.ref, CLAUDE)
        self.assertIn("python3 make_doc.py", why)
        self.assertNotIn("Write or Edit", why)

    def test_a_policy_that_refuses_the_route_gets_no_route(self):
        # block refuses every path, and confirm on Codex refuses both routes: the text must not send the model
        # to a route that is refused next, nor forbid it to ask the user, which the policy's refusal asks for
        cmd = "python3 -c 'print(1)' " + self.e.ref
        for name, keys, client in (("block", {"rehydration": "block"}, CLAUDE),
                                   ("block codex", {"rehydration": "block"}, _hygiene.CODEX),
                                   ("confirm codex", {"rehydration": "confirm"}, _hygiene.CODEX)):
            with self.subTest(name), _config(**keys):
                why = self._reason(cmd, client)
                self.assertIn("inline code would parse the value as program text", why)
                self.assertNotIn("make_doc", why)
                self.assertNotIn("Do not ask the user", why)
        with _config(rehydration="confirm"):
            self.assertIn("Write or Edit", self._reason(cmd, CLAUDE))   # Claude Code asks: the route works

    def test_deno_gets_its_run_word(self):
        self.assertIn("deno run make_doc.js", self._reason("deno --eval 'x' " + self.e.ref, CLAUDE))

    def test_windows_codex_keeps_its_own_refusal(self):
        from unittest import mock
        with mock.patch.object(hooks.platform, "system", return_value="Windows"):
            out = _bash_pre("python3 -c 'print(1)' " + self.e.ref, client=_hygiene.CODEX)["hookSpecificOutput"]
        self.assertEqual(out.get("permissionDecision"), "deny", out)
        self.assertIn("cannot be placed in a shell command on Codex for Windows", out["permissionDecisionReason"])
        # the argument route is refused there too: only the file route (tests/test_windows_document_route.py)
        self.assertNotIn("with the placeholder as its argument", out["permissionDecisionReason"])
        self.assertIn("write a text file with apply_patch", out["permissionDecisionReason"])

    def test_the_route_names_the_refused_interpreter_and_every_key(self):
        e2 = Vault().put(PLAIN, "SECRET", "manual", session="S1")
        why = self._reason("node -e 'x' " + self.e.ref + " " + e2.ref, CLAUDE)
        self.assertIn(f"node make_doc.js \u27e6{self.e.key}\u27e7 \u27e6{e2.key}\u27e7.", why)

    def test_other_refusals_keep_their_own_next_step(self):
        why = self._reason("bash -c 'echo " + self.e.ref + "'", CLAUDE)
        self.assertNotIn("make_doc.py", why)
        self.assertIn("run its inner command directly", why)

    @unittest.skipIf(BASH is None or os.name == "nt", "a POSIX shell runs the rewritten command")
    def test_the_route_the_refusal_names_puts_the_value_into_the_file(self):
        work = Path(tempfile.mkdtemp(prefix="ms-doc-"))   # outside the vault home: a command there is refused
        self.addCleanup(shutil.rmtree, work, True)
        (work / "make_doc.py").write_text("import sys\nopen(sys.argv[2], 'w').write('<p>' + sys.argv[1] + '</p>')\n")
        cmd = f"cd '{work}' && '{sys.executable}' make_doc.py {self.e.ref} doc.html"
        out = _bash_pre(cmd)["hookSpecificOutput"]
        self.assertNotIn("permissionDecision", out, out)
        new = out["updatedInput"]["command"]
        self.assertNotIn(NASTY[:6], new)
        r = _run(new)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((work / "doc.html").read_text(), "<p>" + NASTY + "</p>")

    def test_the_primer_names_the_document_route(self):
        self.assertIn("python3 make_pdf.py ⟦KEY⟧", hooks.PRIMER)
        self.assertIn("Write, Edit or apply_patch", hooks.PRIMER)


class TipTests(unittest.TestCase):
    def test_one_tip_per_day_rotating_and_switchable_off(self):
        from maisecrets import tips
        try:
            os.unlink(Path(HOME, ".tip"))
        except FileNotFoundError:
            pass
        first = tips.tip_of_the_day()
        self.assertTrue(first and first.startswith("maisecrets:"))
        self.assertIsNone(tips.tip_of_the_day())          # same day: silent
        Path(HOME, ".tip").write_text("2000-01-01 0\n")   # another day: the next tip
        self.assertEqual(tips.tip_of_the_day(), tips.TIPS[1])
        cfg = Path(HOME, "config.json")
        old = cfg.read_text()
        cfg.write_text('{"backend": "jsonfile", "allow_plaintext_store": true, "tips": false}')
        try:
            Path(HOME, ".tip").write_text("2000-01-01 0\n")
            self.assertIsNone(tips.tip_of_the_day())
        finally:
            cfg.write_text(old)


if __name__ == "__main__":
    unittest.main()
