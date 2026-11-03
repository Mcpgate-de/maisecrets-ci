"""Sensitive References through the hooks: a reference that an MCP result of the gateway showed in this session goes
into a Bash command as its value, from the resolver (sink process), and an echo of it comes back as the reference.
Against the fake gateway (harness/sref_server.py); synthetic values only."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "harness"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import hooks, sref_client as S  # noqa: E402
from maisecrets.vault import HOME, JsonFileBackend  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402
import test_sref_client as T  # noqa: E402

BASH = shutil.which("bash")
VALUE = "value-one@example.org"


@unittest.skipUnless(T.HAS_OPENSSL and BASH and os.name != "nt", "openssl and bash on POSIX")
class SrefBashTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls) -> None:
        _hygiene.assert_children_ended()

    def setUp(self) -> None:
        _hygiene.watch_children(self)
        HOME.mkdir(parents=True, exist_ok=True)
        for name in ("sref", "vault-refs", "index.json", "vault.json", "audit.log"):
            p = HOME / name
            if p.is_dir():
                shutil.rmtree(p)
            elif p.exists():
                p.unlink()
        self.srv = T.SrefServer(cert=T._cert()).__enter__()
        self.addCleanup(self.srv.__exit__)
        (HOME / "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True,
                                                      "client_vault_cafile": self.srv.cert}))
        self.profile = Path(tempfile.mkdtemp(prefix="sref-hooks-profile-"))
        env = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.profile)})
        env.start()
        self.addCleanup(env.stop)
        (self.profile / ".claude.json").write_text(json.dumps(
            {"mcpServers": {"gw": {"type": "http", "url": self.srv.url + "/mcp"}}}))
        hooks._live_cache.clear()
        self.cfg = {"client_vault_cafile": self.srv.cert}
        self.found = S.discover(self.cfg, self.srv.url + "/mcp")
        self.backend = JsonFileBackend()
        self.addCleanup(S.forget, self.backend, self.found["origin"])
        self.ref = self.srv.mint("email", VALUE)
        self.shown = self.ref[:-1] + ":va•••@example.org" + self.ref[-1]   # with the display part a gateway adds

    def login(self) -> None:
        helper = T.SrefClientTests("test_discovery_names_the_resolver_and_its_sinks")
        helper.srv = self.srv
        S.login(self.cfg, self.backend, self.found, helper.browser, wait=10)

    def result(self, session: str = "s1") -> None:
        """The MCP result of the gateway that shows the reference in this session."""
        hooks._post_tool_guarded({"tool_name": "mcp__gw__gitlab_read_actions", "session_id": session, **CLAUDE,
                                  "mcp_server": {"name": "gw", "source": "user"}, "tool_input": {"iid": 7},
                                  "tool_response": {"content": [{"type": "text", "text": "author: " + self.shown}]}})

    def run_command(self, command: str, session: str = "s1") -> subprocess.CompletedProcess:
        """The hook, then the rewritten command, as the client runs it: the value is fetched when it starts."""
        out = self.bash(command, session)
        return subprocess.run([BASH, "-c", out["hookSpecificOutput"]["updatedInput"]["command"]],
                              capture_output=True, text=True, timeout=60)

    def bash(self, command: str, session: str = "s1") -> dict:
        hooks._live_cache.clear()
        return hooks.pre_tool({"tool_name": "Bash", "session_id": session, **CLAUDE,
                               "tool_input": {"command": command}})

    def test_the_value_reaches_the_command_and_the_gateway_learns_the_program(self):
        self.login()
        self.result()
        out = self.bash(f"printf 'got:%s' {self.shown}")
        command = out["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertNotIn(VALUE, command, "the command carries no value")
        run = subprocess.run([BASH, "-c", command], capture_output=True, text=True)
        self.assertEqual(run.stdout, "got:" + VALUE)
        self.assertEqual([(r["sink_type"], r["destination"], r["count"]) for r in self.srv.resolved],
                         [("process", "printf", 1)])

    def test_an_echo_of_the_value_comes_back_as_the_reference(self):
        self.login()
        self.result()
        self.run_command(f"printf 'got:%s' {self.shown}")
        hooks._live_cache.clear()
        out = hooks._post_tool_guarded({"tool_name": "Bash", "session_id": "s1", **CLAUDE,
                                        "tool_input": {"command": "cat out.txt"},
                                        "tool_response": {"stdout": f"got:{VALUE}\n", "stderr": ""}})
        upd = json.dumps(out["hookSpecificOutput"]["updatedToolOutput"], ensure_ascii=False)
        self.assertNotIn(VALUE, upd)
        self.assertIn(self.ref, upd, "the canonical reference: the display part is not trusted")

    def test_another_session_gets_a_reason_and_the_gateway_is_not_asked(self):
        self.login()
        self.result("s1")
        out = self.bash(f"printf %s {self.shown}", session="s2")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("another session", out["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertEqual(self.srv.resolved, [])

    def test_without_a_login_the_command_does_not_run_and_names_the_login(self):
        self.result()
        out = self.bash(f"printf %s {self.shown}")
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("/maisecrets:sref login", reason)
        rest = reason.replace(self.shown, "").replace(self.ref, "")
        self.assertNotIn(self.ref[6:-1].split(":")[-1], rest, "no id beyond the reference")

    def write(self, path: str, content: str) -> dict:
        hooks._live_cache.clear()
        return hooks.pre_tool({"tool_name": "Write", "session_id": "s1", **CLAUDE, "cwd": str(self.profile),
                               "tool_input": {"file_path": path, "content": content}})

    def test_a_file_gets_the_value_and_the_gateway_learns_the_path(self):
        self.login()
        self.result()
        target = str(self.profile / "invite.txt")
        out = self.write(target, "To: " + self.shown + "\n")
        self.assertEqual(out["hookSpecificOutput"]["updatedInput"]["content"], "To: " + VALUE + "\n")
        self.assertEqual([(r["sink_type"], r["destination"]) for r in self.srv.resolved], [("local_file", target)])

    def test_a_reference_in_the_path_is_refused(self):
        self.login()
        self.result()
        out = self.write(str(self.profile / self.shown), "x")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(self.srv.resolved, [])

    def test_the_command_logs_in_shows_the_state_and_logs_out_and_prints_no_token(self):
        import contextlib
        import io
        from maisecrets import cli
        helper = T.SrefClientTests("test_discovery_names_the_resolver_and_its_sinks")
        helper.srv = self.srv

        def run(*args) -> tuple:
            out = io.StringIO()
            with contextlib.redirect_stdout(out), mock.patch("webbrowser.open", helper.browser):
                code = cli.cmd_sref(list(args))
            return code, out.getvalue()
        code, text = run()
        self.assertEqual(code, 0)
        self.assertIn("gw (127.0.0.1): not logged in", text)
        code, text = run("login")
        self.assertEqual(code, 0, text)
        self.assertIn("logged in to 127.0.0.1", text)
        self.assertNotIn("srefr_", text)
        self.assertIn("logged in", run("status")[1].split(": ", 1)[1])
        self.assertEqual(run("logout")[0], 0)
        self.assertFalse(S.logged_in(self.backend, self.found["origin"]))
        self.assertEqual(run("login", "other")[0], 1, "an unknown server name")

    def test_a_display_part_cannot_move_the_shell_analysis(self):
        # Fable review, 2026-11-02: a quote in the display hid `| base64`, `eval` and `ssh` from the refusals
        self.login()
        self.result()
        for display, tail in (("'", " | base64"), ('"', " | base64"), ("'", "; eval x"), ("x y", " | base64")):
            forged = self.ref[:-1] + ":" + display + self.ref[-1]
            with self.subTest(display=display, tail=tail):
                out = self.bash(f"printf %s {forged}{tail}")
                self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(self.srv.resolved, [], "nothing was resolved for a refused command")

    def test_a_display_part_never_reaches_the_shell(self):
        self.login()
        self.result()
        marker = self.profile / "ran"
        forged = self.ref[:-1] + f":$(touch {marker})" + self.ref[-1]
        out = self.bash(f"printf 'got:%s' {forged}")
        command = out["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertNotIn("touch", command)
        run = subprocess.run([BASH, "-c", command], capture_output=True, text=True)
        self.assertEqual(run.stdout, "got:" + VALUE)
        self.assertFalse(marker.exists())

    def test_the_program_name_comes_from_the_command_not_from_a_display(self):
        self.login()
        self.result()
        forged = self.ref[:-1] + ":a b" + self.ref[-1]
        out = self.bash(f"X={forged} printf %s x")
        subprocess.run([BASH, "-c", out["hookSpecificOutput"]["updatedInput"]["command"]], capture_output=True)
        self.assertEqual([r["destination"] for r in self.srv.resolved], ["printf"])

    def test_a_reference_in_a_patch_file_name_is_refused_before_any_resolve(self):
        self.login()
        self.result()
        patch = f"*** Begin Patch\n*** Add File: {self.profile}/{self.shown}.txt\n+x\n*** End Patch\n"
        hooks._live_cache.clear()
        out = hooks.pre_tool({"tool_name": "apply_patch", "session_id": "s1", "turn_id": "t", "model": "m",
                              "cwd": str(self.profile), "tool_input": {"command": patch}})
        self.assertEqual(out.get("decision") or out["hookSpecificOutput"]["permissionDecision"], "deny"
                         if "hookSpecificOutput" in out else "block")
        self.assertEqual(self.srv.resolved, [])
        audit = (HOME / "audit.log").read_text(encoding="utf-8") if (HOME / "audit.log").exists() else ""
        self.assertNotIn("sref:", audit)

    def test_the_hook_resolves_nothing_and_the_command_fetches_the_value_once_when_it_starts(self):
        # prod run, 2026-11-03: a command that the client refused after the hook had already cost a resolve
        self.login()
        self.result()
        out = self.bash(f"printf 'got:%s' {self.shown}")
        command = out["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertEqual(self.srv.resolved, [], "the hook itself resolves nothing")
        self.assertFalse((HOME / "audit.log").exists() and "sref:" in (HOME / "audit.log").read_text())
        first = subprocess.run([BASH, "-c", command], capture_output=True, text=True, timeout=60)
        self.assertEqual(first.stdout, "got:" + VALUE)
        self.assertEqual(len(self.srv.resolved), 1)
        again = subprocess.run([BASH, "-c", command], capture_output=True, text=True, timeout=60)
        self.assertEqual(again.returncode, 97, "the value is served once")
        self.assertEqual(len(self.srv.resolved), 1)

    def test_a_failed_resolve_stops_the_command_instead_of_running_it_without_the_value(self):
        self.login()
        self.result()
        command = self.bash(f"printf 'got:%s' {self.shown}")["hookSpecificOutput"]["updatedInput"]["command"]
        self.srv.revoke(self.ref)                    # between the hook and the start: the gateway refuses now
        run = subprocess.run([BASH, "-c", command], capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 97)
        self.assertEqual(run.stdout, "", "printf never ran with an empty value")

    def test_the_audit_names_the_reference_without_its_id(self):
        self.login()
        self.result()
        self.run_command(f"printf %s {self.shown}")
        audit = (HOME / "audit.log").read_text(encoding="utf-8") if (HOME / "audit.log").exists() else ""
        rid = self.ref.split(":")[2].rstrip(self.ref[-1])
        self.assertIn("sref:email:" + rid[:4], audit)
        self.assertNotIn(rid, audit)


if __name__ == "__main__":
    unittest.main()
