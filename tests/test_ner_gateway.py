"""The gateway of /maisecrets:sref login as the source of names (#33) against a fake gateway (harness/sref_server.py
with the name endpoint of ai-gateway #1819): the command, discovery, the login that asks for the name scope only while
the source is set, the token at each tool result, the gateway's refusals by name, its own wait, and a prompt only
after `/maisecrets:ner prompts on` for this source, with the rules' findings as filler (C30a). Synthetic values
only.

Run: python3 -m unittest tests.test_ner_gateway -v
"""
from __future__ import annotations

import json
import os
import shutil
import ssl
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "harness"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import ner_gateway, ner_setup, remote_layer, sref_client as S  # noqa: E402
from maisecrets.vault import JsonFileBackend  # noqa: E402

HAS_OPENSSL = shutil.which("openssl") is not None
if HAS_OPENSSL:
    from sref_server import NER_SCOPE, SrefServer  # noqa: E402
    from vault_server import make_cert  # noqa: E402

_CERT: tuple | None = None
TEXT = "the ticket of Dana " + "Okafor is open"


def _cert() -> tuple:
    global _CERT
    if _CERT is None:
        _CERT = make_cert(tempfile.mkdtemp(prefix="ner-gw-cert-"))
    return _CERT


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


class CommandTests(unittest.TestCase):
    def test_the_command_names_a_gateway_and_keeps_the_tuning(self):
        word = ner_setup.parse("/maisecrets:ner gateway https://gw.example.com/mcp")
        self.assertEqual(word, "gateway:https://gw.example.com/mcp")
        self.assertEqual(ner_setup.parse("maisecrets: ner gateway https://gw.example.com"), "gateway:https://gw.example.com")
        new = ner_setup.updated({"url": ner_setup.LOCAL_URL, "timeout_ms": 900}, word)
        self.assertEqual(new, {"timeout_ms": 900, "gateway": "https://gw.example.com",
                               "gateway_url": "https://gw.example.com/mcp", "url": "https://gw.example.com",
                               "format": "hf", "allow_network": True})
        self.assertIn("the gateway https://gw.example.com", ner_setup.describe(new))
        # another source takes the gateway keys away
        self.assertNotIn("gateway", ner_setup.updated(new, "local"))

    def test_prompts_on_for_a_network_source_and_withhold_off_are_weakenings(self):
        from maisecrets import settings
        gw = ner_setup.updated({}, "gateway:https://gw.example.com/mcp")
        self.assertTrue(settings.loosens("remote_detector", gw, ner_setup.updated(gw, "prompts:on")))
        held = ner_setup.updated(gw, "unavailable:withhold")
        self.assertFalse(settings.loosens("remote_detector", gw, held))
        self.assertTrue(settings.loosens("remote_detector", held, ner_setup.updated(held, "unavailable:rules")))

    def test_sref_without_a_name_takes_the_server_of_the_ner_gateway(self):
        import io
        from contextlib import redirect_stdout
        from unittest import mock
        from maisecrets import cli, vault_refs
        servers = {"team-gw": "https://gw.example.com/mcp", "other-gw": "https://other.example.com/mcp"}
        found = {"team-gw": {"origin": "https://gw.example.com"}, "other-gw": {"origin": "https://other.example.com"}}
        conf = ner_setup.updated({}, "gateway:https://gw.example.com/mcp")
        with mock.patch.object(vault_refs, "user_servers", return_value=servers), \
                mock.patch.object(S, "discover", side_effect=lambda cfg, url, *a: found[
                    next(k for k, v in servers.items() if v == url)]), \
                mock.patch.object(S, "forget") as forget:
            self.assertEqual(ner_setup.gateway_server(conf), "team-gw")
            for setting, code in (({"remote_detector": conf}, 0), ({}, 2)):
                with self.subTest(gateway=bool(setting)), \
                        mock.patch.object(cli, "load_config", return_value={"backend": "jsonfile",
                                                                            "allow_plaintext_store": True,
                                                                            **setting}), \
                        redirect_stdout(io.StringIO()):
                    self.assertEqual(cli.cmd_sref(["logout"]), code)
            forget.assert_called_once()
            self.assertEqual(forget.call_args[0][1], "https://gw.example.com")

    def test_a_tool_call_that_carries_the_sentence_is_refused_like_the_others(self):
        import re
        self.assertTrue(re.search(ner_setup.IN_A_COMMAND, "echo '/maisecrets:ner gateway https://gw.example.com'"))


@unittest.skipUnless(HAS_OPENSSL and os.name != "nt", "openssl on POSIX")
class GatewaySourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.srv = SrefServer(cert=_cert()).__enter__()
        self.addCleanup(self.srv.__exit__)
        self.srv.ner = True
        self.backend = JsonFileBackend()           # the store of the temp home of tests/_isolate.py
        conf = ner_setup.updated({}, "gateway:" + self.srv.url + "/mcp")
        self.cfg = {"client_vault_cafile": self.srv.cert, "remote_detector": conf, "backend": "jsonfile",
                    "allow_plaintext_store": True}
        self.origin = conf["gateway"]
        self.addCleanup(S.forget, self.backend, self.origin)
        self.addCleanup(lambda: ner_gateway.CACHE.unlink(missing_ok=True))

    def browser(self, url: str) -> None:
        ctx = ssl.create_default_context(cafile=self.srv.cert)
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect())
        try:
            opener.open(url)
        except urllib.error.HTTPError as exc:
            location = exc.headers["Location"]
            exc.close()
        with urllib.request.urlopen(location, timeout=5) as answer:
            answer.read()

    def login(self, cfg: dict) -> None:
        S.login(cfg, self.backend, S.discover(cfg, self.srv.url + "/mcp"), self.browser, wait=10)

    def ask(self, text: str = TEXT, prompt: bool = False) -> tuple:
        cfg = self.cfg
        if prompt:     # the prompt path builds its detector with allow_network False (remote_layer.prompt_names)
            cfg = {**cfg, "remote_detector": {**cfg["remote_detector"], "allow_network": False}}
        det, why = remote_layer.from_config(cfg)
        if det is None:
            return None, why
        return det.ask(text, [])

    def test_discovery_names_the_endpoint_and_a_login_asks_for_its_scope_only_while_the_source_is_set(self):
        found = S.discover(self.cfg, self.srv.url + "/mcp")
        self.assertEqual(found["ner"]["endpoint"], self.srv.url + "/sensitive-references/ner")
        self.assertIn(NER_SCOPE, found["scope"].split())
        other = S.discover({"client_vault_cafile": self.srv.cert}, self.srv.url + "/mcp")
        self.assertNotIn(NER_SCOPE, other["scope"].split(), "no source set: the login does not ask for it")

    def test_a_logged_in_source_finds_the_name_and_the_gateway_got_the_text(self):
        self.login(self.cfg)
        spans, status = self.ask()
        self.assertEqual(status.state, "ok", status)
        self.assertEqual([TEXT[s:e] for s, e, _t, _sc in spans], ["Okafor"])
        self.assertEqual(self.srv.ner_texts, [TEXT])

    def test_a_login_without_the_name_scope_gives_the_reason_and_sends_nothing(self):
        self.login({"client_vault_cafile": self.srv.cert})        # logged in before the source was set
        det, why = remote_layer.from_config(self.cfg)
        self.assertIsNone(det)
        self.assertIn("/maisecrets:sref login", why)
        self.assertEqual(self.srv.ner_texts, [])

    def test_a_source_that_cannot_be_asked_leaves_its_results_unchecked_on_the_screen_and_withheld(self):
        conf = self.cfg["remote_detector"]           # no login: from_config gives a reason, no detector
        out = self.post_tool(conf)
        self.assertIn("names not checked: the name service cannot be asked", out.get("systemMessage", ""))
        out = self.post_tool(ner_setup.updated(conf, "unavailable:withhold"))
        self.assertNotIn("Okafor", json.dumps(out["hookSpecificOutput"]["updatedToolOutput"]))
        self.assertEqual(self.srv.ner_texts, [])
        # no source at all: nothing to say
        self.assertNotIn("names not checked", self.post_tool({}).get("systemMessage", ""))

    def test_a_prompt_of_a_program_never_goes_to_a_service_on_the_network(self):
        self.login(self.cfg)
        on = ner_setup.updated(self.cfg["remote_detector"], "prompts:on")
        names, why = remote_layer.prompt_names({**self.cfg, "remote_detector": on}, TEXT, [], lambda: None,
                                               typed=False)
        self.assertEqual((names, why, self.srv.ner_texts), ([], "", []))

    def test_the_mod_sends_only_a_typed_prompt_to_the_gateway(self):
        import json as _json
        from maisecrets import hooks
        from maisecrets.home import CONFIG
        self.login(self.cfg)
        old = CONFIG.read_text(encoding="utf-8") if CONFIG.exists() else None
        self.addCleanup(lambda: CONFIG.write_text(old, encoding="utf-8") if old is not None
                        else CONFIG.unlink(missing_ok=True))
        on = ner_setup.updated(self.cfg["remote_detector"], "prompts:on")
        CONFIG.write_text(_json.dumps({**self.cfg, "remote_detector": on}), encoding="utf-8")
        for origin, sent in (("sdk", 0), ("composer", 1)):
            with self.subTest(origin=origin):
                hooks.rewrite_prompt({"prompt": TEXT, "origin": origin, "session_id": "s-ner-gw",
                                      "cwd": tempfile.gettempdir()})
                self.assertEqual(len(self.srv.ner_texts), sent)

    def test_the_status_asks_for_a_login_only_when_one_is_needed(self):
        import json as _json
        from maisecrets.home import CONFIG
        old = CONFIG.read_text(encoding="utf-8") if CONFIG.exists() else None
        self.addCleanup(lambda: CONFIG.write_text(old, encoding="utf-8") if old is not None
                        else CONFIG.unlink(missing_ok=True))
        CONFIG.write_text(_json.dumps(self.cfg), encoding="utf-8")
        conf = self.cfg["remote_detector"]
        code, lines = ner_setup.report(conf)
        self.assertEqual(code, 4, lines)
        self.assertTrue(any(x.startswith("login: run.sh sref login") for x in lines), lines)
        self.login({"client_vault_cafile": self.srv.cert})        # a login without the name scope
        self.assertEqual(ner_setup.report(conf)[0], 4)
        self.login(self.cfg)
        code, lines = ner_setup.report(conf)
        self.assertEqual(code, 0, lines)
        self.assertFalse(any(x.startswith("login:") for x in lines))
        self.srv.ner_answer = (503, {"error": "busy"})
        self.assertEqual(ner_setup.report(conf)[0], 1, "a busy gateway needs no login")

    def test_no_login_and_a_switched_off_gateway_give_reasons(self):
        det, why = remote_layer.from_config(self.cfg)
        self.assertIsNone(det)
        self.assertIn("login", why)
        self.srv.ner = False
        ner_gateway.CACHE.unlink(missing_ok=True)
        det, why = remote_layer.from_config(self.cfg)
        self.assertIsNone(det)
        self.assertIn("names no name detection", why)

    def prompt(self, conf: dict) -> tuple:
        from maisecrets.detection.core import Match
        text = "deploy with " + "testpass-" + "x" * 12 + " for Dana " + "Okafor"
        start = text.index("testpass")
        secret = Match("rule", "SECRET", text[start:start + 21], start, start + 21, 1.0)
        names, why = remote_layer.prompt_names({**self.cfg, "remote_detector": conf}, text, [secret], lambda: None)
        return text, start, [text[m.start:m.end] for m in names], why

    def test_a_prompt_goes_to_the_gateway_only_after_prompts_on_for_this_source(self):
        self.login(self.cfg)
        conf = self.cfg["remote_detector"]
        _text, _start, names, why = self.prompt(conf)
        self.assertEqual((names, why, self.srv.ner_texts), ([], "", []), "no prompts on: the rules alone")
        on = ner_setup.updated(conf, "prompts:on")
        self.assertIs(on["prompts"], True)
        text, start, names, why = self.prompt(on)
        self.assertEqual((names, why), (["Okafor"], ""))
        self.assertEqual(len(self.srv.ner_texts), 1)
        sent = self.srv.ner_texts[0]
        self.assertNotIn("testpass", sent, "the rules' finding goes out as filler")
        self.assertEqual(sent[:start], text[:start])
        # the choice belongs to this source: another source and back, and the prompt stays here again
        again = ner_setup.updated(ner_setup.updated(on, "local"), "gateway:" + self.srv.url + "/mcp")
        self.assertNotIn("prompts", again)
        self.assertEqual(self.prompt(again)[2], [])
        self.assertEqual(len(self.srv.ner_texts), 1)
        # off stays off across a change of the source
        off = ner_setup.updated(ner_setup.updated(on, "prompts:off"), "gateway:" + self.srv.url + "/mcp")
        self.assertIs(off["prompts"], False)

    def test_a_prompt_to_a_local_service_needs_no_switch_and_never_opens_the_network(self):
        on = ner_setup.updated(ner_setup.updated({}, "local"), "prompts:on")
        self.assertNotIn("prompts", on, "on this computer prompts are on by default; nothing to record")

    def post_tool(self, conf: dict, tool: str = "Bash") -> dict:
        import json
        from maisecrets import hooks
        from maisecrets.home import CONFIG
        old = CONFIG.read_text(encoding="utf-8") if CONFIG.exists() else None
        self.addCleanup(lambda: CONFIG.write_text(old, encoding="utf-8") if old is not None
                        else CONFIG.unlink(missing_ok=True))
        CONFIG.write_text(json.dumps({**self.cfg, "remote_detector": conf}), encoding="utf-8")
        response = ({"stdout": TEXT, "stderr": "", "interrupted": False, "isImage": False} if tool == "Bash"
                    else {"type": "text", "file": {"filePath": "/w/notes.txt", "content": TEXT}})
        return hooks._post_tool_guarded_rest({"hook_event_name": "PostToolUse", "session_id": "s-ner-gw",
                                               "tool_name": tool, "tool_input": {"command": "cat notes.txt"},
                                               "tool_response": response})

    def test_each_result_whose_names_were_not_checked_says_so_on_the_screen(self):
        self.login(self.cfg)
        self.srv.ner_answer = (503, {"error": "busy"})
        conf = self.cfg["remote_detector"]
        for _ in range(2):                   # each time, not once per session
            out = self.post_tool(conf)
            self.assertIn("⚠ names not checked: the name service was busy", out.get("systemMessage", ""))
            self.assertNotIn("updatedToolOutput", out.get("hookSpecificOutput") or {}, "the output stays as it is")
        self.assertIn("did not check the names", out["hookSpecificOutput"]["additionalContext"], "the AI knows too")
        self.srv.ner_answer = None
        out = self.post_tool(conf)
        self.assertNotIn("names not checked", out.get("systemMessage", ""))
        self.assertNotIn("did not check the names", json.dumps(out))

    def test_withhold_keeps_an_unchecked_result_from_the_ai(self):
        self.login(self.cfg)
        conf = ner_setup.updated(self.cfg["remote_detector"], "unavailable:withhold")
        self.assertEqual(conf["unavailable"], "withhold")
        self.srv.ner_answer = (503, {"error": "busy"})
        for tool in ("Bash", "Read"):
            with self.subTest(tool=tool):
                out = self.post_tool(conf, tool)
                given = json.dumps(out["hookSpecificOutput"]["updatedToolOutput"])
                self.assertNotIn("Okafor", given)
                self.assertIn("withheld this tool result", given)
                self.assertIn("withheld this result from the AI", out["systemMessage"])
                self.assertNotIn("the rules alone masked", out["hookSpecificOutput"].get("additionalContext", ""))
        self.srv.ner_answer = None
        out = self.post_tool(conf)
        self.assertNotIn("withheld", json.dumps(out), "an answered result passes")
        self.assertNotIn("unavailable", ner_setup.updated(conf, "unavailable:rules"))

    def test_a_tool_result_waits_the_gateways_own_time_not_the_rate_of_this_computer(self):
        self.login(self.cfg)
        self.srv.ner_delay = 0.9           # well under 3 s, well over the 300 ms base of a service on this computer
        layer = remote_layer.prepare(self.cfg, [TEXT], lambda s: [])
        self.assertEqual(layer.status.state, "ok", layer.status)
        self.assertEqual([m.value for m in layer.found[TEXT]], ["Okafor"])

    def test_the_gateways_refusals_have_their_names(self):
        self.login(self.cfg)
        for code, reason in ((403, "forbidden"), (413, "too_long"), (429, "rate_limited"), (503, "busy"),
                             (500, "http")):
            with self.subTest(code=code):
                self.srv.ner_answer = (code, {"error": "x"})
                spans, status = self.ask()
                self.assertEqual((spans, status.state, status.reason), ([], "unavailable", reason))


class TokenTests(unittest.TestCase):
    def test_a_token_goes_only_over_https_and_holds_only_token_characters(self):
        from maisecrets.detection import remote
        good = "srefr_" + "a" * 30
        remote.RemoteDetector("https://gw.example.com/x", allow_network=True, token=good)
        for url, tok in (("http://127.0.0.1:9/x", good), ("https://gw.example.com/x", good + "\r\nX: y"),
                         ("https://gw.example.com/x", "short")):
            with self.subTest(n=len(tok), url=url[:5]):
                with self.assertRaises(ValueError):
                    remote.RemoteDetector(url, allow_network=True, token=tok)
        with self.assertRaises(ValueError):
            remote.RemoteDetector("https://gw.example.com/x", allow_network=True, token=good, bearer="a" * 64)
        det = remote.RemoteDetector("https://gw.example.com/x", allow_network=True, token=good)
        self.assertNotIn(good, repr(det))
        self.assertNotIn(good, str(det.status("unavailable", "http")))
        with self.assertRaises(ValueError) as caught:
            remote.RemoteDetector("https://gw.example.com/x", allow_network=True, token=good + "\n")
        self.assertNotIn(good, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
