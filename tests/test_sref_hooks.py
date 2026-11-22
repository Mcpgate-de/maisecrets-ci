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

from maisecrets import exit_wrap, hooks, hub, sref_client as S, sref_hooks  # noqa: E402
from maisecrets.vault import HOME, JsonFileBackend  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402
import test_sref_client as T  # noqa: E402
from maisecrets.vault_refs import server_key as vault_refs_server_key  # noqa: E402

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
        for name in ("sref", "vault-refs", "index.json", "vault.json", "audit.log", "sref-pairing.json"):
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
        self.assertIn("/maisecrets sref login", reason)
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
        self.assertIn("/maisecrets sref login", first)
        self.assertNotIn("offers Sensitive References", self.gateway_result("s1").get("systemMessage") or "")
        self.assertIn("offers Sensitive References", self.gateway_result("s2").get("systemMessage") or "")
        self.assertEqual(self.srv.resolved, [])          # a hint resolves nothing and opens no browser

    def test_the_hint_names_the_server_and_why_the_browser_opens(self):
        first = self.gateway_result("s1").get("systemMessage") or ""
        self.assertIn("send /maisecrets sref login gw once", first)
        self.assertIn("your browser opens, and you give your consent at the gateway", first)

    def test_the_login_offer_comes_once_per_session_after_the_hint_and_never_with_a_login(self):
        self.assertIsNone(sref_hooks.login_offer("s1"))          # no reference yet: no offer
        self.gateway_result("s1")
        self.assertEqual(sref_hooks.login_offer("s1"), "/maisecrets sref login gw")
        # asking records nothing: only a fill that happened (login_offered) ends the offer
        self.assertEqual(sref_hooks.login_offer("s1"), "/maisecrets sref login gw")
        self.assertEqual(hub.mod_answer({"action": "login_offered", "session_id": "s1",
                                         "fill": "/maisecrets:sref login gw"}), {"recorded": True})
        self.assertIsNone(sref_hooks.login_offer("s1"))          # once per session and gateway
        self.assertFalse(sref_hooks.login_offered("s1", "/maisecrets:sref login gw; x"))
        self.assertIsNone(sref_hooks.login_offer("s2"))          # s2 got no reference
        self.gateway_result("s2")
        self.login()
        self.assertIsNone(sref_hooks.login_offer("s2"))          # logged in meanwhile
        self.assertEqual(self.srv.resolved, [])
        self.assertEqual(hub.mod_answer({"action": "login_offer", "session_id": "s3"}), {"fill": None})

    def test_a_text_with_sref_in_it_or_a_reference_the_model_sent_gives_no_hint_and_no_offer(self):
        out = hooks._post_tool_guarded({"tool_name": "mcp__gw__notes", "session_id": "s1", **CLAUDE,
                                        "mcp_server": {"name": "gw", "source": "user"}, "tool_input": {},
                                        "tool_response": {"content": [{"type": "text",
                                                                       "text": "the docs say: use sref: links"}]}})
        self.assertNotIn("offers Sensitive References", out.get("systemMessage") or "")
        # the model sent the reference and the server echoed it: the gateway did not send it
        out = hooks._post_tool_guarded({"tool_name": "mcp__gw__echo", "session_id": "s1", **CLAUDE,
                                        "mcp_server": {"name": "gw", "source": "user"},
                                        "tool_input": {"text": self.ref},
                                        "tool_response": {"content": [{"type": "text", "text": self.ref}]}})
        self.assertNotIn("offers Sensitive References", out.get("systemMessage") or "")
        self.assertIsNone(sref_hooks.login_offer("s1"))

    def test_the_offer_names_the_server_that_sent_the_references_and_only_an_ascii_name(self):
        cfg = json.loads((self.profile / ".claude.json").read_text())
        url = cfg["mcpServers"]["gw"]["url"]
        cfg["mcpServers"]["aa-other"] = {"type": "http", "url": url.replace("/mcp", "/other/mcp")}
        cfg["mcpServers"]["g\u00e4tew\u00e4y"] = {"type": "http", "url": url.replace("/mcp", "/third/mcp")}
        (self.profile / ".claude.json").write_text(json.dumps(cfg))
        self.gateway_result("s1")                                 # sent by gw, the same origin as aa-other
        self.assertEqual(sref_hooks.login_offer("s1"), "/maisecrets sref login gw")
        hooks._post_tool_guarded({"tool_name": "mcp__g\u00e4tew\u00e4y__read", "session_id": "s2", **CLAUDE,
                                  "mcp_server": {"name": "g\u00e4tew\u00e4y", "source": "user"}, "tool_input": {},
                                  "tool_response": {"content": [{"type": "text", "text": "author: " + self.shown}]}})
        self.assertIsNone(sref_hooks.login_offer("s2"))          # a name the box cannot take: the hint line only

    def connector_result(self, name: str = "claude.ai Team GW", session: str = "s1", source: str = "claudeai") -> dict:
        """A result of the gateway reached through a claude.ai connector: its URL is in no config of the client."""
        cfg = json.loads((self.profile / ".claude.json").read_text())
        cfg["mcpServers"].pop("gw", None) if name != "claude.ai gw" else None
        (self.profile / ".claude.json").write_text(json.dumps(cfg))
        return hooks._post_tool_guarded({"tool_name": "mcp__claude_ai_Team_GW__gitlab_read_actions",
                                         "session_id": session, **CLAUDE,
                                         "mcp_server": {"name": name, "source": source}, "tool_input": {"iid": 7},
                                         "tool_response": {"content": [{"type": "text",
                                                                        "text": "author: " + self.shown}]}})

    def answer(self, url: str = "") -> str:
        return json.dumps({"resource": url or self.srv.url + "/mcp"})

    def test_a_claude_ai_connector_is_proposed_by_its_tool_and_bound_only_by_the_login(self):
        from maisecrets import vault_refs
        self.connector_result()                                        # before the binding: nothing is noted
        self.assertEqual(self.bash(f"printf %s {self.shown}")["hookSpecificOutput"]["permissionDecision"], "deny")
        out = sref_hooks.connector_answer("s1", "claude_ai_Team_GW", self.answer())
        self.assertEqual(out["fill"], "/maisecrets sref login Team_GW")
        self.assertIn("your claude.ai connector Team_GW names 127.0.0.1", out["note"])
        self.assertEqual(vault_refs.connectors(), {})                  # a proposal only
        self.assertEqual(vault_refs.connectors(pending=True), {"Team_GW": self.srv.url + "/mcp"})
        self.connector_result(session="s2")                            # still not noted
        self.assertEqual(self.bash(f"printf %s {self.shown}", session="s2")["hookSpecificOutput"]["permissionDecision"],
                         "deny")
        # the person's login binds it (cli sref login does both)
        self.login()
        self.assertTrue(vault_refs.bind_connector("Team_GW", self.srv.url + "/mcp"))
        self.assertEqual(vault_refs.connectors(), {"Team_GW": self.srv.url + "/mcp"})
        self.assertEqual(vault_refs.connectors(pending=True), {})
        self.connector_result(session="s3")
        res = self.bash(f"printf %s {self.shown}", session="s3")
        self.assertNotEqual(res.get("hookSpecificOutput", {}).get("permissionDecision"), "deny", res)
        self.assertEqual(sref_hooks.connector_answer("s4", "claude_ai_Team_GW", self.answer()),
                         {"fill": None, "note": None})                 # bound: no offer
        # logout of the connector undoes the binding
        self.assertTrue(vault_refs.forget_connector("Team_GW"))
        self.assertEqual(vault_refs.connectors(), {})

    def test_a_proposal_is_refused_for_a_configured_name_a_held_gateway_a_bad_answer_or_another_url(self):
        from maisecrets import vault_refs
        # gw (a server of the config) holds the gateway's origin: no connector may propose it
        self.assertEqual(vault_refs.propose_connector("claude_ai_Other", self.answer())[2],
                         "a server of your configuration or another connector holds that gateway")
        cfg = json.loads((self.profile / ".claude.json").read_text())
        cfg["mcpServers"] = {"claude_ai_Team_GW": {"type": "http", "url": "https://mine.example/mcp"}}
        cfg["projects"] = {"/w": {"mcpServers": {"claude_ai_Local": {"type": "http", "url": "https://l.example/mcp"}}}}
        (self.profile / ".claude.json").write_text(json.dumps(cfg))
        for server, answer, why in [
                ("claude_ai_Team_GW", self.answer(), "a server of your own configuration has that name"),
                ("claude_ai_Local", self.answer(), "a server of your own configuration has that name"),
                ("claude_ai_X", "not json", "the connector named no https URL"),
                ("claude_ai_X", json.dumps({"resource": "http://x.example/mcp"}), "the connector named no https URL"),
                ("Team_GW", self.answer(), "not a claude.ai connector"),
                ("claude.ai X", self.answer(), "not a claude.ai connector")]:
            with self.subTest(server=server, answer=answer[:30]):
                self.assertEqual(vault_refs.propose_connector(server, answer)[2], why)
        self.assertEqual(vault_refs.connectors(pending=True), {})
        proj = Path(tempfile.mkdtemp(prefix="sref-proj-"))
        (proj / ".mcp.json").write_text(json.dumps({"mcpServers": {"claude_ai_Proj": {"url": "https://p.example"}}}))
        self.assertEqual(vault_refs.propose_connector("claude_ai_Proj", self.answer(), str(proj))[2],
                         "a server of your own configuration has that name")
        # two proposals of one gateway: the first login binds, the second never
        self.assertIsNone(vault_refs.propose_connector("claude_ai_X", self.answer())[2])
        self.assertIsNone(vault_refs.propose_connector("claude_ai_Z", self.answer())[2])
        self.assertTrue(vault_refs.bind_connector("X", self.srv.url + "/mcp"))
        self.assertFalse(vault_refs.bind_connector("Z", self.srv.url + "/mcp"))
        self.assertEqual(set(vault_refs.connectors()), {"X"})
        self.assertEqual(vault_refs.propose_connector("claude_ai_X", json.dumps({"resource": "https://e.example/m"}))[2],
                         "this connector is bound to another URL")
        # a second connector cannot take the bound one's gateway
        self.assertEqual(vault_refs.propose_connector("claude_ai_Y", self.answer())[2],
                         "a server of your configuration or another connector holds that gateway")
        self.assertFalse(vault_refs.bind_connector("Y", self.srv.url + "/mcp"))

    def test_a_connector_with_the_name_of_a_user_server_never_takes_its_references(self):
        # the person is logged in to gw; a claude.ai connector "gw" shows a reference: it is not noted, so it resolves
        # nowhere (review of the connector source, HIGH-2)
        self.login()
        self.connector_result(name="claude.ai gw")
        self.assertEqual(self.bash(f"printf %s {self.shown}")["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIsNone(vault_refs_server_key({"mcp_server": {"name": "claude.ai gw", "source": "claudeai"}}))

    def test_a_user_server_added_later_with_the_name_of_a_bound_connector_takes_the_name_back(self):
        from maisecrets import vault_refs
        self.connector_result()
        vault_refs.propose_connector("claude_ai_Team_GW", self.answer())
        vault_refs.bind_connector("Team_GW", self.srv.url + "/mcp")
        self.assertEqual(vault_refs_server_key({"mcp_server": {"name": "claude.ai Team GW", "source": "claudeai"}}),
                         "Team_GW")
        cfg = json.loads((self.profile / ".claude.json").read_text())
        cfg["mcpServers"]["Team_GW"] = {"type": "http", "url": "https://other.example/mcp"}
        (self.profile / ".claude.json").write_text(json.dumps(cfg))
        self.assertIsNone(vault_refs_server_key({"mcp_server": {"name": "claude.ai Team GW", "source": "claudeai"}}))

    def test_a_reference_that_two_gateways_showed_resolves_at_neither(self):
        import time as _t
        from maisecrets import sref_notes
        k = sref_notes.ref_key(self.ref)
        now = _t.time()
        sref_notes.DIR.mkdir(parents=True, exist_ok=True)
        one = {"https://a.example": {k: {"t": now - 60, "sessions": ["s1"], "url": "https://a.example/mcp"}}}
        sref_notes.NOTES.write_text(json.dumps({sref_notes.profile(): one}))
        self.assertEqual(sref_notes.noted([self.ref], "s1"), {self.ref: ("https://a.example", "https://a.example/mcp")})
        two = {**one, "https://b.example": {k: {"t": now - 5, "sessions": ["s1"], "url": "https://b.example/mcp"}}}
        sref_notes.NOTES.write_text(json.dumps({sref_notes.profile(): two}))
        self.assertEqual(sref_notes.noted([self.ref], "s1"), {})

    def test_only_a_login_the_person_typed_binds_a_proposed_connector(self):
        from maisecrets import cli, events, vault_refs
        self.connector_result()
        vault_refs.propose_connector("claude_ai_Team_GW", self.answer())
        self.login()                                  # the browser login itself (stands in for sref_client.login)
        run = mock.patch.object(S, "login", lambda *a, **k: None)
        env = mock.patch.dict(os.environ, {"CLAUDE_CODE_SESSION_ID": "s1"})
        self.srv.pairing = False                      # a gateway without a pairing proof: the typed login binds
        with run, env, mock.patch.object(cli, "_ROUTE", {"v": "slash command"}), \
                mock.patch("sys.stdout", new_callable=__import__("io").StringIO) as out:
            self.assertEqual(cli.cmd_sref(["login", "Team_GW"]), 1)     # a command the AI ran: no typed note
            self.assertIn("because you did not type this login", out.getvalue())
            self.assertEqual(vault_refs.connectors(), {})
            # the person typed it (the prompt hook notes it, also for the mod and its pane button)
            events.note_typed_login("/maisecrets:sref login Team_GW", {"session_id": "s1"}, True)
            self.assertEqual(cli.cmd_sref(["login", "Team_GW"]), 0, out.getvalue())
            self.assertEqual(vault_refs.connectors(), {"Team_GW": self.srv.url + "/mcp"})
            self.assertIn("127.0.0.1 gives no pairing proof, so your typed login bound the claude.ai connector "
                          "Team_GW", out.getvalue())
        self.assertFalse(sref_hooks.pair_due("Team_GW"))              # nothing waits for a proof
        # a note serves once, and a subagent's or an untyped prompt makes none
        self.assertFalse(events.take_typed_login("Team_GW", ["s1"]))
        events.note_typed_login("/maisecrets:sref login Team_GW", {"session_id": "s1", "agent_id": "a"}, True)
        events.note_typed_login("/maisecrets:sref login Team_GW", {"session_id": "s1"}, False)
        self.assertFalse(events.take_typed_login("Team_GW", ["s1"]))

    # ---- #91: the pairing proof of a connector, for a gateway whose metadata names pairing_endpoint
    NONCE = "n" * 21 + "_" + "A1-b" * 5 + "z"            # 43 characters of the base64url alphabet, as the mod makes

    def typed_login(self, key: str = "Team_GW", login=None, propose: bool = True) -> tuple:
        """A proposed connector and the person's typed login for it, as cli sref login runs it: (exit code, output)."""
        from maisecrets import cli, events, vault_refs
        if propose:
            self.connector_result()
            vault_refs.propose_connector("claude_ai_" + key, self.answer())
        self.login()                                  # the browser login itself (stands in for sref_client.login)
        events.note_typed_login(f"/maisecrets:sref login {key}", {"session_id": "s1"}, True)
        with mock.patch.object(S, "login", login or (lambda *a, **k: None)), \
                mock.patch.dict(os.environ, {"CLAUDE_CODE_SESSION_ID": "s1"}), \
                mock.patch.object(cli, "_ROUTE", {"v": "slash command"}), \
                mock.patch("sys.stdout", new_callable=__import__("io").StringIO) as out:
            code = cli.cmd_sref(["login", key])
        return code, out.getvalue()

    def pair(self, answer: object, key: str = "Team_GW", nonce: str = "") -> dict:
        text = answer if isinstance(answer, str) else json.dumps(answer)
        return hub.mod_answer({"action": "pair", "key": key, "nonce": nonce or self.NONCE, "answer": text})

    def test_with_a_pairing_endpoint_the_login_only_marks_and_the_connector_s_own_proof_binds(self):
        from maisecrets import vault_refs
        code, out = self.typed_login()
        self.assertEqual(code, 0, out)                # the mod pairs only after a login that succeeded
        self.assertIn("The claude.ai connector Team_GW is bound only when it proves that it reaches 127.0.0.1 with "
                      "your account", out)
        self.assertIn("Without the mod (claude -p, Codex) nothing binds it.", out)
        self.assertEqual(vault_refs.connectors(), {})                  # the login alone binds nothing
        self.assertEqual(hub.mod_answer({"action": "pair_due", "key": "Team_GW"}), {"due": True})
        url = self.srv.url + "/mcp"
        got = self.pair({"resource": url, "proof": self.srv.proof(self.NONCE)})
        self.assertTrue(got["bound"], got)
        self.assertIn("is bound to 127.0.0.1: it proved that it reaches that gateway with your account", got["note"])
        self.assertEqual(vault_refs.connectors(), {"Team_GW": url})
        self.assertEqual(self.srv.pairings, [self.NONCE])             # the gateway got the nonce with the token
        self.assertNotIn(self.NONCE, got["note"])
        self.assertNotIn(self.srv.proof(self.NONCE), json.dumps(got))
        stored = (HOME / "sref" / "connectors.json").read_text()
        self.assertNotIn(self.srv.proof(self.NONCE), stored)          # the proof is never kept
        self.assertNotIn(self.NONCE, stored)
        self.assertEqual(hub.mod_answer({"action": "pair_due", "key": "Team_GW"}), {"due": False})

    def test_a_wrong_proof_binds_nothing_and_uses_the_login_mark(self):
        from maisecrets import vault_refs
        self.assertEqual(self.typed_login()[0], 0)
        url = self.srv.url + "/mcp"
        # another gateway (or another account) has another key: its proof for the same nonce differs
        got = self.pair({"resource": url, "proof": self.srv.proof(self.NONCE, key=b"k" * 32)})
        self.assertFalse(got["bound"])
        self.assertIn("its proof does not match your login at 127.0.0.1", got["note"])
        self.assertIn("To try again, send /maisecrets:sref login Team_GW.", got["note"])
        self.assertEqual(vault_refs.connectors(), {})
        # the mark served once: the right proof now needs a new typed login
        got = self.pair({"resource": url, "proof": self.srv.proof(self.NONCE)})
        self.assertIn("no login of yours for it in the last 15 minutes", got["note"])
        self.assertEqual(vault_refs.connectors(), {})

    def test_a_missing_proof_or_another_resource_binds_nothing_and_asks_the_gateway_nothing(self):
        from maisecrets import vault_refs
        url = self.srv.url + "/mcp"
        for answer, why in [({"resource": url}, "it gave no pairing proof"),
                            ({"resource": url, "proof": "short"}, "it gave no pairing proof"),
                            ("", "no longer names 127.0.0.1 as its gateway"),
                            ({"resource": "https://other.example/mcp", "proof": self.srv.proof(self.NONCE)},
                             "no longer names 127.0.0.1 as its gateway")]:
            with self.subTest(answer=str(answer)[:40]):
                vault_refs.forget_connector("Team_GW")
                self.assertEqual(self.typed_login()[0], 0)
                got = self.pair(answer)
                self.assertFalse(got["bound"])
                self.assertIn(why, got["note"])
                self.assertEqual(vault_refs.connectors(), {})
        self.assertEqual(self.srv.pairings, [])

    def test_no_login_mark_a_stale_one_or_a_bad_nonce_binds_nothing(self):
        from maisecrets import vault_refs
        url = self.srv.url + "/mcp"
        right = {"resource": url, "proof": self.srv.proof(self.NONCE)}
        # a proposal and a login, but no typed login for the connector: no mark
        self.connector_result()
        vault_refs.propose_connector("claude_ai_Team_GW", self.answer())
        self.login()
        self.assertFalse(sref_hooks.pair_due("Team_GW"))
        self.assertIn("no login of yours for it in the last 15 minutes", self.pair(right)["note"])
        self.assertEqual(vault_refs.connectors(), {})
        # a mark older than 15 minutes
        self.assertEqual(self.typed_login()[0], 0)
        later = vault_refs.time.time() + vault_refs.LOGIN_MARK_TTL + 5
        with mock.patch.object(vault_refs.time, "time", lambda: later):
            self.assertFalse(sref_hooks.pair_due("Team_GW"))
            self.assertIn("no login of yours for it in the last 15 minutes", self.pair(right)["note"])
        self.assertEqual(vault_refs.connectors(), {})
        # a nonce of another form is refused before the mark is used
        self.assertEqual(self.typed_login()[0], 0)
        self.assertIn("the proof request had no valid form", self.pair(right, nonce="short")["note"])
        self.assertTrue(sref_hooks.pair_due("Team_GW"))
        self.assertTrue(self.pair(right)["bound"])
        self.assertEqual(self.srv.pairings, [self.NONCE])

    def test_each_reason_of_the_gateway_for_no_proof_gets_its_own_line_and_binds_nothing(self):
        from maisecrets import vault_refs
        url = self.srv.url + "/mcp"
        # the connector's tool answers a refusal as JSON text (ai-gateway 2.0.4024: error_code, isError false)
        for code, words in [("DELEGATED_CALL", "a delegated call"), ("NOT_ENABLED", "a service account"),
                            ("NOT_CONFIGURED", "no pairing key set up yet")]:
            with self.subTest(tool=code):
                vault_refs.forget_connector("Team_GW")
                self.assertEqual(self.typed_login()[0], 0)
                got = self.pair({"success": False, "error_code": code, "error": "text of the gateway"})
                self.assertFalse(got["bound"])
                self.assertIn("127.0.0.1 gave the connector no proof: ", got["note"])
                self.assertIn(words, got["note"])
                self.assertNotIn("text of the gateway", got["note"])
        # the pairing endpoint's refusals
        for answer, words in [((403, {"error": "NOT_ENABLED"}), "a service account"),
                              ((403, {"error_code": "DELEGATED_CALL"}), "a delegated call"),
                              ((503, {"error": "unavailable"}), "no pairing key set up yet")]:
            with self.subTest(endpoint=answer):
                vault_refs.forget_connector("Team_GW")
                self.assertEqual(self.typed_login()[0], 0)
                self.srv.pair_answer = answer
                got = self.pair({"resource": url, "proof": self.srv.proof(self.NONCE)})
                self.assertFalse(got["bound"])
                self.assertIn("127.0.0.1 gives no proof: ", got["note"])
                self.assertIn(words, got["note"])
        self.assertEqual(vault_refs.connectors(), {})

    def test_the_gateway_s_refusal_of_the_pairing_binds_nothing(self):
        from maisecrets import vault_refs
        self.assertEqual(self.typed_login()[0], 0)
        self.srv.pair_answer = (403, {"error": "insufficient_scope"})
        got = self.pair({"resource": self.srv.url + "/mcp", "proof": self.srv.proof(self.NONCE)})
        self.assertFalse(got["bound"])
        self.assertIn("127.0.0.1 refused the pairing", got["note"])
        self.assertEqual(vault_refs.connectors(), {})

    def test_a_discovery_record_that_does_not_say_whether_the_gateway_pairs_binds_nothing(self):
        from maisecrets import vault_refs
        self.assertEqual(self.found["pairing"], self.srv.url + "/sensitive-references/pairing")
        for old in ({k: v for k, v in self.found.items() if k != "pairing"},     # the cache of an older version
                    {**self.found, "pairing": None}):                          # a cache that names no endpoint
            with self.subTest(keys=len(old)):
                vault_refs.forget_connector("Team_GW")
                with mock.patch.object(S, "discover_typed",
                                       lambda *a, **k: (old, "the gateway did not answer in time")):
                    code, out = self.typed_login()
                self.assertEqual(code, 1)
                self.assertIn("could not check whether the gateway gives a pairing proof", out)
                self.assertEqual(vault_refs.connectors(), {})
                self.assertFalse(sref_hooks.pair_due("Team_GW"))

    def test_a_broken_pairing_endpoint_binds_nothing(self):
        from maisecrets import vault_refs
        for named in ("https://other.example/sensitive-references/pairing", 7, "http://127.0.0.1/p"):
            with self.subTest(named=named):
                vault_refs.forget_connector("Team_GW")
                self.srv.pairing_named = named
                code, out = self.typed_login()
                self.assertEqual(code, 1)
                self.assertIn("its pairing endpoint is not an https URL on its own origin", out)
                self.assertEqual(vault_refs.connectors(), {})
                self.assertFalse(sref_hooks.pair_due("Team_GW"))

    def test_a_gateway_that_named_a_pairing_endpoint_once_never_binds_without_a_proof_again(self):
        from maisecrets import vault_refs
        self.assertEqual(self.typed_login()[0], 0)           # a live discovery saw the endpoint
        self.assertTrue(S.pairing_seen(self.found["origin"]))
        vault_refs.forget_connector("Team_GW")
        self.srv.pairing = False                              # the endpoint is gone (or an answer hides it)
        code, out = self.typed_login()
        self.assertEqual(code, 1)
        self.assertIn("it named a pairing endpoint before and names none now", out)
        self.assertEqual(vault_refs.connectors(), {})

    def test_the_login_mark_takes_the_url_of_the_login_and_goes_when_the_pairing_cannot_run(self):
        from maisecrets import vault_refs
        url = self.srv.url + "/mcp"
        self.connector_result()
        vault_refs.propose_connector("claude_ai_Team_GW", self.answer())
        self.assertFalse(vault_refs.mark_login("Team_GW", "https://other.example/mcp"))
        self.assertFalse(sref_hooks.pair_due("Team_GW"))
        self.assertTrue(vault_refs.mark_login("Team_GW", url))
        self.assertTrue(sref_hooks.pair_due("Team_GW"))
        # the mod's pairing could not run: the mark goes
        self.assertEqual(hub.mod_answer({"action": "pair_cancel", "key": "Team_GW"}), {"cancelled": True})
        self.assertFalse(sref_hooks.pair_due("Team_GW"))
        # a new login clears an earlier mark before it starts, also when it then fails
        self.assertTrue(vault_refs.mark_login("Team_GW", url))

        def refused(*a, **k):
            raise S.Refused("the person declined it")
        code, out = self.typed_login(login=refused, propose=False)
        self.assertEqual(code, 1, out)
        self.assertFalse(sref_hooks.pair_due("Team_GW"))
        self.assertIn("no login of yours", self.pair({"resource": url, "proof": self.srv.proof(self.NONCE)})["note"])

    def test_a_proposal_that_expired_after_the_login_says_so(self):
        from maisecrets import vault_refs
        self.assertEqual(self.typed_login()[0], 0)
        later = vault_refs.time.time() + vault_refs.PROPOSAL_TTL + 5
        # the mark is still fresh (its clock), the proposal is not: only the proposal's age moves
        data = json.loads((HOME / "sref" / "connectors.json").read_text())
        for mine in data.values():
            mine["pending"]["Team_GW"]["t"] -= vault_refs.PROPOSAL_TTL + 5
        (HOME / "sref" / "connectors.json").write_text(json.dumps(data))
        self.assertLess(vault_refs.time.time(), later)
        got = self.pair({"resource": self.srv.url + "/mcp", "proof": self.srv.proof(self.NONCE)})
        self.assertFalse(got["bound"])
        self.assertIn("its proposal expired", got["note"])
        self.assertEqual(vault_refs.connectors(), {})

    def test_the_run_plan_of_a_login_names_a_proposed_connector_for_the_pairing(self):
        from maisecrets import prompt_commands, vault_refs
        self.assertNotIn("pair", prompt_commands.run_plan("/maisecrets:sref login Team_GW"))
        self.connector_result()
        vault_refs.propose_connector("claude_ai_Team_GW", self.answer())
        self.assertEqual(prompt_commands.run_plan("/maisecrets:sref login Team_GW")["pair"], "Team_GW")
        self.assertNotIn("pair", prompt_commands.run_plan("/maisecrets:sref login other"))
        self.assertNotIn("pair", prompt_commands.run_plan("/maisecrets:sref login"))

    def test_a_proposal_expires_and_status_names_it_without_asking_its_url(self):
        from maisecrets import cli, vault_refs
        self.connector_result()
        vault_refs.propose_connector("claude_ai_Team_GW", self.answer())
        with mock.patch("sys.stdout", new_callable=__import__("io").StringIO) as out:
            cli.cmd_sref(["status"])
        self.assertIn("Team_GW (127.0.0.1): a claude.ai connector that names this gateway; not bound", out.getvalue())
        self.assertNotIn("Team_GW (127.0.0.1): logged in", out.getvalue())
        later = vault_refs.time.time() + vault_refs.PROPOSAL_TTL + 5
        with mock.patch.object(vault_refs.time, "time", lambda: later):
            self.assertEqual(vault_refs.connectors(pending=True), {})

    def test_the_ai_cannot_run_the_sref_command(self):
        # a login it started could bind a connector; and only the person logs in (review of the connector source)
        head = (Path(__file__).resolve().parent.parent / "commands" / "sref.md").read_text(encoding="utf-8")
        self.assertIn("\ndisable-model-invocation: true\n", head.split("\n---", 1)[0] + "\n")

    def test_a_configured_server_named_like_a_connector_is_never_one(self):
        from maisecrets import vault_refs
        cfg = json.loads((self.profile / ".claude.json").read_text())
        cfg["mcpServers"] = {"claude.ai Foo": {"type": "http", "url": "https://mine.example/mcp"}}
        (self.profile / ".claude.json").write_text(json.dumps(cfg))
        self.assertEqual(vault_refs.propose_connector("claude_ai_Foo", self.answer())[2],
                         "a server of your own configuration has that name")
        self.assertIsNone(vault_refs_server_key({"mcp_server": {"name": "claude.ai Foo", "source": "claudeai"}}))

    def test_the_connector_key_is_the_same_from_its_hook_name_and_its_tool_name(self):
        from maisecrets.vault_refs import connector_key
        for hook, tool in (("claude.ai Team GW", "claude_ai_Team_GW"), ("claude.ai phase6-ai-gateway",
                                                                       "claude_ai_phase6-ai-gateway")):
            self.assertEqual(connector_key(hook), connector_key(tool))
        self.assertEqual(connector_key("claude.ai Team GW"), "Team_GW")
        self.assertNotEqual(connector_key("claude.ai Team-GW"), connector_key("claude.ai Team GW"))
        self.assertIsNone(connector_key("Team GW"))         # not a claude.ai connector name

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
                self.assertIn("/maisecrets sref login", reason)
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
        self.assertIn("/maisecrets sref login", run.stderr)
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

    def audit_lines(self) -> list:
        path = HOME / "audit.log"
        return [x.split("\t") for x in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []

    def audit_output(self) -> str:
        import contextlib
        import io

        from maisecrets import cli
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.cmd_audit([]), 0)
        return out.getvalue()

    def test_the_audit_line_and_the_audit_output_name_the_gateway_audit_id(self):
        # RESOLVER-PROFILE 12.4 (SC-28): the person finds the same release in the gateway's audit
        self.login()
        self.result()
        run = self.run_command(f"printf %s {self.shown}")
        self.assertEqual(run.stdout, VALUE)
        self.assertEqual(len(self.srv.audit_ids), 1)
        gid = self.srv.audit_ids[0]
        lines = [x for x in self.audit_lines() if x[2].startswith("sref:email:")]
        self.assertEqual(len(lines), 1)
        self.assertEqual(len(lines[0]), 6)
        self.assertEqual(lines[0][5], gid)
        self.assertIn(f"(gateway audit {gid})", self.audit_output())

    def test_a_file_write_names_the_gateway_audit_id_too(self):
        self.login()
        self.result()
        self.write(str(self.profile / "invite.txt"), "To: " + self.shown + "\n")
        lines = [x for x in self.audit_lines() if x[2].startswith("sref:email:")]
        self.assertEqual([x[3] for x in lines], ["Write"])
        self.assertEqual(lines[0][5:], self.srv.audit_ids)

    def test_without_a_gateway_audit_id_the_audit_line_keeps_its_five_fields(self):
        # an older gateway, or an id maisecrets ignores: the line is as before, and the output shows it
        for gid in (None, "evt 1"):
            with self.subTest(gid=gid):
                (HOME / "audit.log").unlink(missing_ok=True)
                self.srv.audit_id = gid
                self.login()
                self.result()
                run = self.run_command(f"printf %s {self.shown}")
                self.assertEqual(run.stdout, VALUE)
                lines = [x for x in self.audit_lines() if x[2].startswith("sref:email:")]
                self.assertEqual([len(x) for x in lines], [5])
                out = self.audit_output()
                self.assertIn("sref:email:", out)
                self.assertNotIn("gateway audit", out)


class AuditIdLineTests(unittest.TestCase):
    """vault.record_server writes the gateway's audit id only with the charset of sref_client.AUDIT_ID_RE, whoever
    calls it."""

    def setUp(self) -> None:
        HOME.mkdir(parents=True, exist_ok=True)
        (HOME / "audit.log").unlink(missing_ok=True)
        self.addCleanup((HOME / "audit.log").unlink, missing_ok=True)

    def record(self, gid: object) -> list:
        from maisecrets.vault import Vault
        key = "sref:email:abcd\u2026@gw.example"
        (HOME / "audit.log").unlink(missing_ok=True)
        self.assertEqual(Vault({"backend": "jsonfile", "allow_plaintext_store": True}).record_server(
            [key], "s1", "Bash", "printf x", {key: gid}), "ok")
        return (HOME / "audit.log").read_text(encoding="utf-8").splitlines()[-1].split("\t")

    def test_a_valid_id_is_the_sixth_field_and_any_other_is_left_out(self):
        self.assertEqual(self.record("evt_7.a-B")[5:], ["evt_7.a-B"])
        for bad in (None, 7, "", "e" * 129, "evt 7", "evt_7\tx", "evt_7\n"):
            with self.subTest(bad=bad):
                self.assertEqual(len(self.record(bad)), 5)


    def test_the_audit_view_shows_a_sixth_field_only_with_the_id_charset(self):
        import contextlib
        import io
        from maisecrets import cli
        (HOME / "audit.log").write_text("t\ts1\tsref:x\tBash\tprintf x\tevt_7.a-B\n"
                                        "t\ts1\tsref:y\tBash\tprintf y\tevil text\x1b[31m\n", encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.cmd_audit([]), 0)
        self.assertIn("(gateway audit evt_7.a-B)", out.getvalue())
        self.assertNotIn("evil text", out.getvalue())
        self.assertNotIn("\x1b", out.getvalue())
        self.assertIn("printf y", out.getvalue(), "the line shows, without the field")


class PairingCallTests(unittest.TestCase):
    """#91: the AI never calls a connector's pairing tool with a nonce; only the mod's own call (toolu_plugin_) runs."""

    def pre(self, tool: str, tool_input: dict, tool_use_id: str) -> dict:
        hooks._live_cache.clear()
        return hooks.pre_tool({"tool_name": tool, "session_id": "s1", **CLAUDE, "tool_input": tool_input,
                               "tool_use_id": tool_use_id, "mcp_server": {"name": "claude.ai Real GW"}})

    def test_the_ai_s_call_of_a_pairing_tool_with_a_nonce_is_refused(self):
        nonce = "n" * 43
        for tool in ("mcp__claude_ai_Real_GW__sensitive_references_resource", "mcp__gw__sensitive_references_resource"):
            out = self.pre(tool, {"nonce": nonce}, "toolu_01abc")
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny", tool)
            self.assertIn("pairing proof is only for the maisecrets mod", out["hookSpecificOutput"]
                          ["permissionDecisionReason"])
            self.assertNotIn(nonce, json.dumps(out))

    def test_a_nonce_in_another_shape_is_refused_too(self):
        # review of MR !628: only the key `nonce` was refused; the AI needs no argument for this tool at all
        nonce = "n" * 43
        tool = "mcp__claude_ai_Real_GW__sensitive_references_resource"
        for tool_input in ({"Nonce": nonce}, {"args": {"nonce": nonce}}, {"n": nonce}):
            with self.subTest(keys=sorted(tool_input)):
                out = self.pre(tool, tool_input, "toolu_01abc")
                self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
                self.assertNotIn(nonce, json.dumps(out))

    def test_the_mod_s_own_call_and_a_call_without_a_nonce_are_not_refused_for_it(self):
        tool = "mcp__claude_ai_Real_GW__sensitive_references_resource"
        for tool_input, tool_use_id in (({"nonce": "n" * 43}, "toolu_plugin_0123"), ({}, "toolu_01abc")):
            out = self.pre(tool, tool_input, tool_use_id)
            self.assertNotIn("pairing proof", json.dumps(out))
        self.assertIsNone(sref_hooks.pairing_call_refusal({"tool_name": "Bash", "tool_input": {"nonce": "x"}}))


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

class UnboundReferenceIsMaskedWholeTests(unittest.TestCase):
    """Field case 2026-11-22: a claude.ai connector that was not bound yet showed `api_key: <a reference>`. The rule
    after the label took the id and the closing bracket for a secret, and the model saw the reference cut: its opening
    part, a placeholder, and no closing bracket. An untrusted id stays masked (a server can wrap a secret in a
    reference), but as the whole reference, with its brackets."""

    RID = "Qm7Rv2Kd9TfLw4HbN8cPz3sT6yUa1eQo"     # 32 characters, the shape of a gateway's reference id

    def post(self, text: str) -> str:
        hooks._live_cache.clear()
        out = hooks._post_tool_guarded({
            "tool_name": "mcp__claude_ai_phase6_ai-gateway__gitlab_read_actions", "session_id": "s-unbound", **CLAUDE,
            "mcp_server": {"name": "claude.ai phase6 ai-gateway", "source": "claudeai"},
            "tool_input": {"action": "get_issue_details"}, "tool_response": [{"type": "text", "text": text}]})
        shown = (out.get("hookSpecificOutput") or {}).get("updatedToolOutput")
        return shown[0]["text"] if shown else text

    def test_an_unbound_reference_after_a_label_is_masked_whole(self):
        ref = "\u27e6sref:secret:" + self.RID + "\u27e7"
        shown = self.post(f"title: deploy\napi_key: {ref}\nend")
        self.assertNotIn(self.RID, shown, "the id of an untrusted reference stays masked")
        self.assertNotIn("sref:", shown, "no part of the reference is left: the mask took it whole")
        self.assertRegex(shown, "^title: deploy\napi_key: \u27e6SECRET_c\\d+\u27e7\nend$")
        self.assertEqual(shown.count("\u27e6"), shown.count("\u27e7"), "no bracket is left open")

    def test_two_hits_in_one_reference_are_one_value_and_a_trusted_one_stays(self):
        from maisecrets import placeholder
        from maisecrets.detection.core import Match
        ref = "\u27e6sref:secret:" + self.RID + ":ke\u2022\u2022\u2022\u27e7"
        text = "token: " + ref + " end"
        a = text.index(self.RID)
        hits = [Match("x", "SECRET", text[a:a + 10], a, a + 10),
                Match("y", "SECRET", text[a + 12:a + 20], a + 12, a + 20)]
        out = placeholder.whole_references(text, hits)
        self.assertEqual([(m.start, m.end, m.value) for m in out], [(7, 7 + len(ref), ref)])
        self.addCleanup(placeholder.TRUSTED.clear)
        placeholder.TRUSTED.add("\u27e6sref:secret:" + self.RID + "\u27e7")
        self.assertEqual(placeholder.whole_references(text, hits), hits, "a reference a gateway gave is not widened")


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
