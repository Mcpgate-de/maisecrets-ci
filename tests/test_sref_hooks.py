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

from maisecrets import exit_wrap, hooks, sref_client as S  # noqa: E402
from maisecrets.vault import HOME, JsonFileBackend  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402
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

    def test_a_command_that_prints_the_value_and_fails_ends_with_0_so_its_output_is_masked(self):
        # Claude Code answers a non-zero exit with PostToolUseFailure, which cannot replace the output
        # (anthropics/claude-code#97278): the value reached the model. Now the shell ends with 0 and names the code
        self.login()
        self.result()
        run = self.run_command(f"printf 'got:%s' {self.shown}; exit 4")
        self.assertEqual(run.returncode, 0)
        self.assertEqual(run.stdout, "got:" + VALUE)
        self.assertIn("the command ended with exit code 4", run.stderr)
        hooks._live_cache.clear()
        out = hooks._post_tool_guarded({"tool_name": "Bash", "session_id": "s1", **CLAUDE,
                                        "tool_input": {"command": "x"},
                                        "tool_response": {"stdout": run.stdout, "stderr": run.stderr}})
        self.assertNotIn(VALUE, json.dumps(out, ensure_ascii=False))
        ok = self.run_command(f"printf 'got:%s' {self.shown}")
        self.assertEqual((ok.returncode, ok.stderr), (0, ""), "a command that succeeds prints nothing more")

    def test_only_a_claude_code_command_with_a_server_value_gets_the_exit_trap(self):
        self.login()
        self.result()
        trap = exit_wrap.trap()
        self.assertIn("; " + trap + "; printf ",
                      self.bash(f"printf %s {self.shown}")["hookSpecificOutput"]["updatedInput"]["command"])
        hooks._live_cache.clear()
        codex = hooks.pre_tool({"tool_name": "Bash", "session_id": "s1", **CODEX,
                                "tool_input": {"command": f"printf %s {self.shown}"}})
        command = codex["hookSpecificOutput"]["updatedInput"]["command"]     # an allow with a rewrite, no deny
        self.assertIn("__ms_1", command)
        self.assertNotIn(trap, command, "Codex sends PostToolUse for a failed command")

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

    def echo(self, given: list, printed: str) -> tuple[str, list, dict]:
        """The gateway shows each (kind, value) of `given` as a reference, a command resolves each one in turn, and a
        later command prints `printed`: the redacted output, the tokens, and the local index."""
        refs = [self.srv.mint(kind, value) for kind, value in given]
        self.login()
        for ref in refs:
            hooks._post_tool_guarded({"tool_name": "mcp__gw__gitlab_read_actions", "session_id": "s1", **CLAUDE,
                                      "mcp_server": {"name": "gw", "source": "user"}, "tool_input": {"iid": 8},
                                      "tool_response": {"content": [{"type": "text", "text": "author: " + ref}]}})
            self.run_command(f"printf 'got:%s' {ref}")
        hooks._live_cache.clear()
        out = hooks._post_tool_guarded({"tool_name": "Bash", "session_id": "s1", **CLAUDE,
                                        "tool_input": {"command": "printf 'from: %s' x"},
                                        "tool_response": {"stdout": f"from: {printed}\n", "stderr": ""}})
        # no rewrite at all: the output went out as it was
        upd = json.dumps(out.get("hookSpecificOutput", {}).get("updatedToolOutput", printed), ensure_ascii=False)
        index = json.loads((HOME / "index.json").read_text()) if (HOME / "index.json").exists() else {}
        return upd, refs, index.get("entries") or {}

    def test_an_echo_of_an_address_the_rules_find_comes_back_as_the_reference_and_is_not_stored(self):
        # the gateway pilot (2026-11-06): an address the email rule finds came back as a new local EMAIL placeholder,
        # stored on this computer, where the gateway's audit and sink check do not reach it. example.org is no
        # address to the rules, so the test above never took that way
        found = "jana." + "weber" + "@" + "nordwind" + "-post.de"
        upd, refs, entries = self.echo([("email", found)], found)
        self.assertNotIn(found, upd)
        self.assertIn(refs[0], upd, "the reference the gateway sent, not a placeholder of this computer")
        self.assertNotIn("EMAIL_c", upd)
        self.assertEqual([k for k in entries if k.startswith("EMAIL")], [],
                         "no local entry for a value the gateway holds")

    def test_a_server_value_inside_a_longer_one_does_not_cut_the_longer_one(self):
        # Codex review (2026-11-06): the domain, released first, was replaced first inside the address, and the rest
        # of the address went out in clear
        domain = "post" + "-k7Qx92ab.de"           # no word: the exact redaction hunts it
        found = "jana." + "weber" + "@" + domain
        upd, refs, _ = self.echo([("domain", domain), ("email", found)], found)
        self.assertNotIn("jana.", upd)
        self.assertIn(refs[1], upd)

    def test_a_short_server_value_the_rules_find_comes_back_as_the_reference(self):
        # Codex review (2026-11-06): a value under 8 characters is not hunted as a substring, so the rule hit made it
        # a local IP placeholder
        ip = "9.8." + "7.6"
        upd, refs, entries = self.echo([("ip", ip)], f"host {ip} up")
        self.assertNotIn(ip, upd)
        self.assertIn(refs[0], upd)
        self.assertEqual([k for k in entries if k.startswith("IP")], [])

    def test_a_server_name_a_name_service_finds_comes_back_as_the_reference(self):
        # Codex review, round 2 (2026-11-06): a word such as a first name is not hunted as a substring either, so a hit
        # of the name service made it a local NAME placeholder. The name service stands in as an extra hit here
        import dataclasses
        from maisecrets import detect
        name = "Alex" + "andra"
        template = detect.scan("author: Ann " + "Testerin", channel="tool")[0]
        real = detect.scan

        def with_name(s, *a, **k):
            at = s.find(name)
            extra = [dataclasses.replace(template, kind="name", value=name, start=at, end=at + len(name))]
            return real(s, *a, **k) + (extra if at >= 0 else [])
        with mock.patch.object(detect, "scan", with_name):
            upd, refs, entries = self.echo([("name", name)], f"by {name} today")
        self.assertTrue(detect.reads_as_word(name), "the premise: the exact redaction does not hunt it")
        self.assertNotIn(name, upd)
        self.assertIn(refs[0], upd)
        self.assertEqual([k for k in entries if k.startswith("NAME")], [])

    def test_a_short_server_value_in_base64_comes_back_as_the_reference(self):
        # Codex review, round 3 (2026-11-06): the encoded forms of a short value were not hunted either
        import base64
        ip = "9.8." + "7.6"
        b64 = base64.b64encode(ip.encode()).decode()
        upd, refs, _ = self.echo([("ip", ip)], f"blob {b64} end")
        self.assertNotIn(b64.rstrip("="), upd)
        self.assertIn(refs[0], upd)

    def test_a_short_server_value_inside_a_longer_one_does_not_cut_the_longer_one(self):
        # Codex review, round 4 (2026-11-06): the IP rule hit inside the longer value took the IP's token first, and
        # the rest of the longer value went out in clear
        ip = "9.8." + "7.6"
        longer = "hostq7Z-" + ip + "-k2Wx"
        upd, refs, _ = self.echo([("ip", ip), ("host", longer)], longer)
        self.assertNotIn("hostq7Z", upd)
        self.assertNotIn("k2Wx", upd)
        self.assertIn(refs[1], upd)

    def test_a_hit_that_reaches_into_a_server_value_takes_the_whole_value(self):
        # Codex review, round 5 (2026-11-06): a hit from the middle of the value past its end cut it, and the exact
        # redaction found the first part no more
        import dataclasses
        from maisecrets import detect
        value = "k7Qx92ab" + "-hostq"
        cross = "hostq:tail9"
        template = detect.scan("author: Ann " + "Testerin", channel="tool")[0]
        real = detect.scan

        def with_cross(s, *a, **k):
            at = s.find(cross)
            extra = [dataclasses.replace(template, kind="name", value=cross, start=at, end=at + len(cross))]
            return real(s, *a, **k) + (extra if at >= 0 else [])
        with mock.patch.object(detect, "scan", with_cross):
            upd, _, _ = self.echo([("host", value)], f"id {value}:tail9 end")
        self.assertNotIn("k7Qx92ab", upd)
        self.assertNotIn("tail9", upd)

    def test_a_short_server_value_that_touches_a_longer_one_does_not_cut_it(self):
        # Codex review, round 6 (2026-11-06): the IP hit at the end of a longer value took its token, and the start of
        # the longer value went out in clear
        ip = "9.8." + "7.6"
        longer = "k7Qx92ab-" + "9.8."
        upd, _, _ = self.echo([("ip", ip), ("host", longer)], "k7Qx92ab-" + ip)
        self.assertNotIn("k7Qx92ab", upd)
        self.assertNotIn("7.6", upd)

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

    def gateway_result(self, session: str = "s1") -> dict:
        return hooks._post_tool_guarded({"tool_name": "mcp__gw__gitlab_read_actions", "session_id": session, **CLAUDE,
                                         "mcp_server": {"name": "gw", "source": "user"}, "tool_input": {"iid": 7},
                                         "tool_response": {"content": [{"type": "text",
                                                                        "text": "author: " + self.shown}]}})

    def test_without_a_login_the_first_result_tells_the_person_once_per_session(self):
        first = self.gateway_result("s1").get("systemMessage") or ""
        self.assertIn("offers Sensitive References", first)
        self.assertIn("/maisecrets:sref login", first)
        self.assertNotIn("offers Sensitive References", self.gateway_result("s1").get("systemMessage") or "")
        self.assertIn("offers Sensitive References", self.gateway_result("s2").get("systemMessage") or "")
        self.assertEqual(self.srv.resolved, [])          # a hint resolves nothing and opens no browser

    def test_with_a_login_no_hint(self):
        self.login()
        self.assertNotIn("offers Sensitive References", self.gateway_result("s1").get("systemMessage") or "")

    def test_a_reference_no_session_received_is_refused_with_its_cause(self):
        # the gateway pilot (2026-11-05): a command with a reference the plugin cannot resolve ran with its text
        for logged_in in (False, True):
            if logged_in:
                self.login()
            out = self.bash(f"printf %s {self.shown}")
            with self.subTest(logged_in=logged_in):
                self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
                reason = out["hookSpecificOutput"]["permissionDecisionReason"]
                self.assertIn("did not receive", reason)
                self.assertIn("/maisecrets:sref login", reason)
        self.assertEqual(self.srv.resolved, [])

    def test_a_file_with_a_reference_no_session_received_is_not_written(self):
        out = self.write(str(self.profile / "x.txt"), "author: " + self.shown)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("did not receive", out["hookSpecificOutput"]["permissionDecisionReason"])

    def write(self, path: str, content: str) -> dict:
        hooks._live_cache.clear()
        return hooks.pre_tool({"tool_name": "Write", "session_id": "s1", **CLAUDE, "cwd": str(self.profile),
                               "tool_input": {"file_path": path, "content": content}})

    def test_a_file_gets_the_value_and_the_gateway_is_sent_the_path(self):
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
        self.assertIn("logged in to 127.0.0.1 (the account is shown to you only)", text)
        self.assertNotIn("ope\u2026@example.com", text, "the AI reads this output: no account in it")
        self.assertNotIn("srefr_", text)
        state = run("status")[1].split(": ", 1)[1]
        self.assertIn("logged in", state)
        self.assertIn("; account shown to you only", state)
        self.assertNotIn("@example.com", state)
        if os.name != "nt":
            self.assertIn("values go into files, commands, the screen", state)
            self.assertNotIn("log in again", state)
        # a login from before 0.9.0 kept no scope: files only, and the status says how to allow more
        rec = S._load(self.backend, self.found["origin"])
        S._keep(self.backend, self.found["origin"], {k: v for k, v in rec.items() if k != "scope"})
        state = run("status")[1].split(": ", 1)[1]
        self.assertIn("values go into files (log in again to allow", state)
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

    def test_a_login_without_commands_names_the_reason_and_runs_nothing(self):
        # mcpgate 2.0.3815: the process sink needs its own scope; a login without it (Windows, an old login) is
        # refused, and the command says why instead of a delivery timeout
        self.found = {**self.found, "scope": S.SCOPE}
        self.login()
        self.result()
        run = self.run_command(f"printf 'got:%s' {self.shown}")
        self.assertEqual(run.returncode, 97)
        self.assertEqual(run.stdout, "", "printf never ran")
        self.assertIn("does not allow real values in commands", run.stderr)
        self.assertIn("/maisecrets:sref login", run.stderr)
        self.assertNotIn("served for 120 s", run.stderr)
        self.assertNotIn(VALUE, run.stderr)
        self.assertEqual(self.srv.resolved, [], "the gateway gave no value")

    def test_a_value_that_starts_with_the_refusal_marker_is_never_printed(self):
        # Opus review: the prelude printed what follows the marker, before the exit trap, so the model saw it
        self.login()
        planted = "maisecrets-refused:" + "PlantedValue" + "7Kq2"
        ref = self.srv.mint("secret", planted)
        hooks._post_tool_guarded({"tool_name": "mcp__gw__gitlab_read_actions", "session_id": "s1", **CLAUDE,
                                  "mcp_server": {"name": "gw", "source": "user"}, "tool_input": {"iid": 8},
                                  "tool_response": {"content": [{"type": "text", "text": "token: " + ref}]}})
        run = self.run_command(f"printf 'got:%s' {ref}")
        self.assertEqual(run.returncode, 97)
        self.assertNotIn("PlantedValue", run.stdout + run.stderr)

    def test_a_click_on_the_screen_shows_a_noted_reference_once_through_the_display_sink(self):
        # #30: the gateway resolves it for the screen (sink display); the value is released, so a paste or an echo
        # of it in a tool output comes back as the reference
        from maisecrets import show_values
        self.login()
        self.result()
        key = self.ref[1:-1]
        cfg = {**hooks.load_config(), "show_values": "always"}
        got = show_values.reveal({"ref": key, "session_id": "s1"}, cfg)
        self.assertEqual(got, {"value": VALUE})
        self.assertEqual([(r["sink_type"], r["destination"]) for r in self.srv.resolved], [("display", "screen")])
        hooks._live_cache.clear()
        out = hooks._post_tool_guarded({"tool_name": "Bash", "session_id": "s1", **CLAUDE,
                                        "tool_input": {"command": "cat note.txt"},
                                        "tool_response": {"stdout": "pasted: " + VALUE, "stderr": ""}})
        upd = json.dumps(out["hookSpecificOutput"]["updatedToolOutput"], ensure_ascii=False)
        self.assertNotIn(VALUE, upd)
        self.assertIn(self.ref, upd, "the released value comes back as its reference")

    def test_a_reference_this_session_did_not_get_or_show_values_off_resolves_nothing(self):
        from maisecrets import show_values
        self.login()
        self.result(session="other")
        key = self.ref[1:-1]
        cfg = {**hooks.load_config(), "show_values": "always"}
        got = show_values.reveal({"ref": key, "session_id": "s1"}, cfg)
        self.assertIn("reason", got)
        self.assertNotIn(VALUE, json.dumps(got))
        self.result()
        self.assertIn("reason", show_values.reveal({"ref": key, "session_id": "s1"}, {**cfg, "show_values": "off"}))
        self.assertEqual(self.srv.resolved, [], "no resolve without a note of this session, and none under off")

    def test_a_login_without_the_display_scope_names_the_reason(self):
        from maisecrets import show_values
        self.found = {**self.found, "scope": S.SCOPE}
        self.login()
        self.result()
        cfg = {**hooks.load_config(), "show_values": "always"}
        got = show_values.reveal({"ref": self.ref[1:-1], "session_id": "s1"}, cfg)
        self.assertIn("does not allow showing values on the screen", got.get("reason", ""))
        self.assertEqual(self.srv.resolved, [])

    def test_the_audit_names_the_reference_without_its_id(self):
        self.login()
        self.result()
        self.run_command(f"printf %s {self.shown}")
        audit = (HOME / "audit.log").read_text(encoding="utf-8") if (HOME / "audit.log").exists() else ""
        rid = self.ref.split(":")[2].rstrip(self.ref[-1])
        self.assertIn("sref:email:" + rid[:4], audit)
        self.assertNotIn(rid, audit)



class ServerFormTests(unittest.TestCase):
    def test_an_encoded_form_of_a_short_server_value_is_not_encoded_again(self):
        # Codex review, round 5: each form was taken for a value and encoded once more (base64 of base64)
        from maisecrets import tool_output
        form = tool_output._Form("OS44Ljcu" + "Ng==")
        self.assertEqual(tool_output._resolved_forms(form), [str(form)])


class OverlapTests(unittest.TestCase):
    """tool_output._exact_redact on values that overlap in the text (Codex review, round 6)."""

    class NoStore:
        def live_fingerprints(self, prompt=False):
            return {}

    def redact(self, text: str, resolved: list) -> str:
        from maisecrets import tool_output
        return tool_output._exact_redact(text, self.NoStore(), "s1", {"n": 0}, [], resolved, [])

    def test_two_values_that_overlap_leave_no_part_in_clear(self):
        a, b = "AA11BB" + "22CC", "22CC" + "DD33EE"
        out = self.redact(f"x {a}DD33EE y", [(a, "<A>"), (b, "<B>")])
        self.assertEqual(out, "x <A><B> y")

    def test_a_value_inside_a_longer_one_gives_the_longer_one_only(self):
        a, b = "q7Zk" + "-AA11BB22CC-w", "AA11BB" + "22CC"
        self.assertEqual(self.redact(f"x {a} y", [(b, "<B>"), (a, "<A>")]), "x <A> y")

    def test_one_value_that_overlaps_itself_leaves_no_part_in_clear(self):
        v = "abab" + "abab"
        self.assertEqual(self.redact("x ababababab y", [(v, "<V>")]), "x <V> y")


class PutServerTokensTests(unittest.TestCase):
    """hooks._put_server_tokens: a server token goes at the place of the rule hit, and no part of a hit stays in
    clear (Codex review, round 3: a whole-word search found no word in xNAMEy, and the dropped hit went out)."""

    def hit(self, text: str, value: str, kind: str = "name"):
        import dataclasses
        from maisecrets import detect
        template = detect.scan("author: Ann " + "Testerin", channel="tool")[0]
        at = text.index(value)
        return dataclasses.replace(template, kind=kind, value=value, start=at, end=at + len(value))

    def test_a_hit_between_letters_gets_its_token(self):
        name = "Alex" + "andra"
        text = f"x{name}y"
        out, rest, put = hooks._put_server_tokens(text, [], [(self.hit(text, name), "<REF>")])
        self.assertEqual(out, "x<REF>y")
        self.assertEqual((rest, put), ([], [name]))

    def test_the_other_hits_move_to_their_place_in_the_new_text(self):
        name, other = "Alex" + "andra", "Bern" + "hardine"
        text = f"{name} and {other}"
        out, rest, _ = hooks._put_server_tokens(text, [self.hit(text, other)], [(self.hit(text, name), "<REF>")])
        self.assertEqual([out[m.start:m.end] for m in rest], [other])

    def test_a_taken_hit_that_overlaps_another_becomes_one_hit_with_it(self):
        text = "id Alexandra" + "Bern end"
        a, b = self.hit(text, "Alexandra"), self.hit(text, "andraBern")
        out, rest, put = hooks._put_server_tokens(text, [b], [(a, "<REF>")])
        self.assertEqual((out, put), (text, []))
        self.assertEqual([(m.start, m.end) for m in rest], [(3, 3 + len("AlexandraBern"))])

if __name__ == "__main__":
    unittest.main()


class AccountNoticeTests(unittest.TestCase):
    """The account of a gateway login goes to the person only: the AI reads the output of /maisecrets:sref."""

    def test_after_the_sref_command_the_person_gets_the_account_and_other_commands_get_nothing(self):
        from maisecrets import sref_client, sref_hooks, vault_refs
        origin = "https://gw.example.com"
        command = 'bash "/p/hooks/run.sh" sref --args-' + "stdin <<'X'\nstatus\nX"
        with mock.patch.object(vault_refs, "user_servers", return_value={"gw": origin + "/mcp"}), \
                mock.patch.object(sref_client, "logged_in", return_value=True), \
                mock.patch.object(sref_client, "account", return_value="ope\u2026@example.com"):
            run = {"tool_name": "Bash", "session_id": "s1", "tool_input": {"command": command}}
            note = sref_hooks.account_notice(run)
            self.assertIn("gw as ope\u2026@example.com", note)
            self.assertIn("for you only", note)
            other = {**run, "tool_input": {"command": "echo sref status"}}
            self.assertIsNone(sref_hooks.account_notice(other))
