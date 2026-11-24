"""The gateway of /maisecrets:sref login as the source of names (#33) against a fake gateway (harness/sref_server.py
with the name endpoint of ai-gateway #1819): the command, discovery, the one login that asks for every scope the
gateway offers (the name scope too), text only while the person chose the gateway as the source, the token at each
tool result, the gateway's refusals by name, its own wait, and a prompt only
as from any source that is set, with the rules' findings as filler (C30a). Synthetic values
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
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "harness"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import ner_gateway, ner_health, ner_setup, remote_layer, sref_client as S  # noqa: E402
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

    def test_the_gateway_source_and_withhold_off_are_weakenings(self):
        from maisecrets import settings
        gw = ner_setup.updated({}, "gateway:https://gw.example.com/mcp")
        self.assertTrue(settings.loosens("remote_detector", ner_setup.updated({}, "local"), gw))
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

    def test_a_login_without_a_name_and_several_servers_lists_one_command_per_server(self):
        import io
        from contextlib import redirect_stdout
        from unittest import mock
        from maisecrets import cli, vault_refs
        servers = {"team-gw": "https://gw.example.com/mcp", "other-gw": "https://other.example.com/mcp"}
        found = {"team-gw": {"origin": "https://gw.example.com"}, "other-gw": {"origin": "https://other.example.com"}}
        out = io.StringIO()
        with mock.patch.object(vault_refs, "user_servers", return_value=servers), \
                mock.patch.object(S, "discover", side_effect=lambda cfg, url, *a: found[
                    next(k for k, v in servers.items() if v == url)]), \
                mock.patch.object(S, "login") as login, \
                mock.patch.object(cli, "load_config", return_value={"backend": "jsonfile",
                                                                    "allow_plaintext_store": True}), \
                redirect_stdout(out):
            self.assertEqual(cli.cmd_sref(["login"]), 2)
        login.assert_not_called()
        lines = out.getvalue().splitlines()
        self.assertIn("  /maisecrets sref login team-gw", lines)
        self.assertIn("  /maisecrets sref login other-gw", lines)

    def test_a_login_whose_name_service_was_not_granted_says_so_in_one_line(self):
        import io
        from contextlib import redirect_stdout
        from unittest import mock
        from maisecrets import cli, vault_refs
        servers = {"team-gw": "https://gw.example.com/mcp"}
        out = io.StringIO()
        with mock.patch.object(vault_refs, "user_servers", return_value=servers), \
                mock.patch.object(S, "discover", return_value={"origin": "https://gw.example.com"}), \
                mock.patch.object(S, "login", return_value=S.NER_NOT_GRANTED), \
                mock.patch.object(cli, "load_config", return_value={"backend": "jsonfile",
                                                                    "allow_plaintext_store": True}), \
                redirect_stdout(out):
            cli.cmd_sref(["login", "team-gw"])
        self.assertIn(S.NER_NOT_GRANTED, out.getvalue().splitlines())

    def test_the_ready_command_quotes_a_server_name_as_the_argument_parser_reads_it(self):
        import io
        import shlex
        from contextlib import redirect_stdout
        from unittest import mock
        from maisecrets import cli, vault_refs
        servers = {"team gw": "https://gw.example.com/mcp", "other;gw": "https://other.example.com/mcp"}
        found = {"team gw": {"origin": "https://gw.example.com"}, "other;gw": {"origin": "https://other.example.com"}}
        out = io.StringIO()
        with mock.patch.object(vault_refs, "user_servers", return_value=servers), \
                mock.patch.object(S, "discover", side_effect=lambda cfg, url, *a: found[
                    next(k for k, v in servers.items() if v == url)]), \
                mock.patch.object(S, "login"), \
                mock.patch.object(cli, "load_config", return_value={"backend": "jsonfile",
                                                                    "allow_plaintext_store": True}), \
                redirect_stdout(out):
            self.assertEqual(cli.cmd_sref(["login"]), 2)
        names = [shlex.split(line.split("/maisecrets sref ", 1)[1])
                 for line in out.getvalue().splitlines() if "/maisecrets sref " in line]
        self.assertEqual(sorted(names), [["login", "other;gw"], ["login", "team gw"]])

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
        # first of all (cleanups run last in, first out): a renewal in the background ends before its login goes
        self.addCleanup(lambda: [p.wait(30) for p in S._renewals])
        for f in (ner_health.STATE, ner_health._WARNED, S._ended_path()):
            f.unlink(missing_ok=True)
            self.addCleanup(f.unlink, missing_ok=True)

    def browser(self, url: str) -> None:
        ctx = ssl.create_default_context(cafile=self.srv.cert)
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect())
        try:
            opener.open(url)
        except urllib.error.HTTPError as exc:
            location = exc.headers["Location"]
            exc.close()
        try:
            with urllib.request.urlopen(location, timeout=5) as answer:
                answer.read()
        except urllib.error.HTTPError as exc:     # an error the gateway sent back: the loopback page says 400
            exc.close()

    def login(self, cfg: dict) -> None:
        S.login(cfg, self.backend, S.discover(cfg, self.srv.url + "/mcp"), self.browser, wait=10)

    def older_login(self) -> None:
        """A login of maisecrets 0.9.24 or older, made before the gateway was the name source: no name scope."""
        found = S.discover(self.cfg, self.srv.url + "/mcp")
        found = {**found, "scope": " ".join(w for w in found["scope"].split() if w != NER_SCOPE)}
        S.login(self.cfg, self.backend, found, self.browser, wait=10)

    def ask(self, text: str = TEXT, prompt: bool = False) -> tuple:
        cfg = self.cfg
        if prompt:     # the prompt path builds its detector with allow_network False (remote_layer.prompt_names)
            cfg = {**cfg, "remote_detector": {**cfg["remote_detector"], "allow_network": False}}
        det, why = remote_layer.from_config(cfg)
        if det is None:
            return None, why
        return det.ask(text, [])

    def test_one_login_asks_for_the_name_scope_whether_or_not_the_source_is_set(self):
        found = S.discover(self.cfg, self.srv.url + "/mcp")
        self.assertEqual(found["ner"]["endpoint"], self.srv.url + "/sensitive-references/ner")
        self.assertIn(NER_SCOPE, found["scope"].split())
        other = S.discover({"client_vault_cafile": self.srv.cert}, self.srv.url + "/mcp")
        self.assertIn(NER_SCOPE, other["scope"].split(), "no source set: the one login asks for it too")
        self.srv.ner = False
        off = S.discover({"client_vault_cafile": self.srv.cert}, self.srv.url + "/mcp")
        self.assertNotIn(NER_SCOPE, off["scope"].split(), "a gateway without name detection: no name scope")

    def test_a_login_before_the_source_is_set_needs_no_second_consent(self):
        self.login({"client_vault_cafile": self.srv.cert})        # the sref login first, no name source yet
        self.assertEqual(self.srv.ner_texts, [], "no source: the gateway gets no text")
        exchanges = self.srv.code_exchanges
        spans, status = self.ask()                                 # then the person chooses the gateway
        self.assertEqual(status.state, "ok", status)
        self.assertEqual([TEXT[s:e] for s, e, _t, _sc in spans], ["Okafor"])
        self.assertEqual(self.srv.code_exchanges, exchanges, "no new login, no browser consent")

    def test_a_gateway_that_refuses_the_name_scope_still_logs_in_once_more_without_it(self):
        for step in ("authorize", "token"):
            with self.subTest(step=step):
                S.forget(self.backend, self.origin)
                self.srv.refuse_ner = step
                found = S.discover({"client_vault_cafile": self.srv.cert}, self.srv.url + "/mcp")
                self.assertIn(NER_SCOPE, found["scope"].split())
                note = S.login(self.cfg, self.backend, found, self.browser, wait=10)
                self.assertEqual(note, S.NER_NOT_GRANTED)
                self.assertIn("did not grant its name service", note)
                granted = str(S._load(self.backend, self.origin).get("scope") or "").split()
                self.assertNotIn(NER_SCOPE, granted)
                self.assertIn("sensitive-references.resolve", granted, "the login holds the other scopes")
                det, why = remote_layer.from_config(self.cfg)
                self.assertIsNone(det)
                self.assertIn("lacks the name scope", why)
        self.srv.refuse_ner = None
        S.forget(self.backend, self.origin)
        self.assertEqual(S.login(self.cfg, self.backend, S.discover(self.cfg, self.srv.url + "/mcp"), self.browser,
                                 wait=10), "", "a gateway that grants it: no line")

    def test_a_refused_scope_without_the_name_scope_asked_fails_as_before(self):
        self.srv.ner = False                     # no name scope in the login: nothing to drop, no second try
        self.srv.refuse_ner = "token"
        found = S.discover({"client_vault_cafile": self.srv.cert}, self.srv.url + "/mcp")
        found = {**found, "scope": found["scope"] + " " + NER_SCOPE, "ner": None}
        with self.assertRaises(S.Refused):
            S.login(self.cfg, self.backend, found, self.browser, wait=10)

    def test_a_gateway_whose_name_detection_is_off_is_no_name_service_and_asks_for_no_login(self):
        # ai-gateway: POST /sensitive-references/ner answers 404 ner_not_enabled while the operator has it off
        self.login(self.cfg)
        self.srv.ner_answer = (404, {"error": "ner_not_enabled"})
        spans, status = self.ask()
        self.assertEqual((spans, status.state, status.reason), ([], "unavailable", "not_enabled"))
        out = self.post_tool(self.cfg["remote_detector"])
        said = out.get("systemMessage", "")
        self.assertIn("names are NOT checked \u2014 the gateway offers no name detection \u2192 /maisecrets ner", said)
        self.assertNotIn("sref login", said, "no login helps here")
        self.assertIn("the gateway offers no name service", out["hookSpecificOutput"]["additionalContext"])
        self.assertIn("Okafor", json.dumps(out["hookSpecificOutput"].get("updatedToolOutput", TEXT)),
                      "the rules alone: a name no rule finds stays")
        self.assertEqual(ner_health.cause_of(self.cfg["remote_detector"], "not_enabled"), "no_ner")

    def test_a_login_with_the_name_scope_sends_no_text_while_the_gateway_is_not_the_source(self):
        self.login({"client_vault_cafile": self.srv.cert})
        self.assertIn(NER_SCOPE, str(S._load(self.backend, self.origin).get("scope") or "").split())
        for conf in (None, ner_setup.updated(self.cfg["remote_detector"], "off")):
            with self.subTest(source=conf):
                cfg = {k: v for k, v in self.cfg.items() if k != "remote_detector"}
                if conf is not None:
                    cfg["remote_detector"] = conf
                self.assertEqual(remote_layer.from_config(cfg), (None, ""), "no source: no detector, no reason")
                self.assertEqual(remote_layer.prompt_names(cfg, TEXT, [], lambda: None, typed=True), ([], ""))
                self.assertIsNone(remote_layer.prepare(cfg, [TEXT], lambda s: [], lambda s: []))
        self.assertEqual(self.srv.ner_texts, [], "the name scope alone sends no text")

    def test_a_logged_in_source_finds_the_name_and_the_gateway_got_the_text(self):
        self.login(self.cfg)
        spans, status = self.ask()
        self.assertEqual(status.state, "ok", status)
        self.assertEqual([TEXT[s:e] for s, e, _t, _sc in spans], ["Okafor"])
        self.assertEqual(self.srv.ner_texts, [TEXT])

    def test_a_text_over_max_chars_is_not_sent_in_pieces_to_the_gateway(self):
        # #105: pieces would spend the person's quota of the minute; off until the gateway shares it (ai-gateway #2141)
        self.login(self.cfg)
        det, _why = remote_layer.from_config(self.cfg)
        self.assertFalse(det.pieces)
        spans, status = det.ask("a" * (det.max_chars + 1), [])
        self.assertEqual((spans, status.state, self.srv.ner_texts), ([], "too_long", []))

    def test_a_login_without_the_name_scope_gives_the_reason_and_sends_nothing(self):
        self.older_login()
        det, why = remote_layer.from_config(self.cfg)
        self.assertIsNone(det)
        self.assertIn("/maisecrets sref login", why)
        self.assertIn("0.9.24 or older", why, "the reason says why one new consent is needed")
        self.assertEqual(self.srv.ner_texts, [])

    def test_a_source_that_cannot_be_asked_leaves_its_results_unchecked_on_the_screen_and_withheld(self):
        conf = self.cfg["remote_detector"]           # no login: from_config gives a reason, no detector
        out = self.post_tool(conf)
        self.assertEqual(out.get("systemMessage"), "\u26a0\ufe0f maisecrets: names are NOT checked \u2014 not logged "
                         "in at the gateway \u2192 /maisecrets sref login", "the cause and the step")
        note = out["hookSpecificOutput"]["additionalContext"]
        self.assertIn("did not check the names", note, "the AI knows")
        self.assertIn("may stand in clear text", note)
        self.assertNotIn("for each", note, "no claim of a warning under each result: the person hears it once")
        for claim in ("screen", "told the person", "warning"):
            self.assertNotIn(claim, note, "nothing of the screen: a subagent or a headless run shows no line")
        out = self.post_tool(conf)
        self.assertNotIn("NOT checked", out.get("systemMessage", ""), "once per session")
        self.assertIn("did not check the names", out["hookSpecificOutput"]["additionalContext"], "AI: each time")
        out = self.post_tool(ner_setup.updated(conf, "unavailable:withhold"))
        self.assertNotIn("Okafor", json.dumps(out["hookSpecificOutput"]["updatedToolOutput"]))
        self.assertEqual(self.srv.ner_texts, [])
        # no source at all: nothing to say
        self.assertNotIn("names not checked", self.post_tool({}).get("systemMessage", ""))

    def test_a_prompt_of_a_program_never_goes_to_a_service_on_the_network(self):
        self.login(self.cfg)
        names, why = remote_layer.prompt_names(self.cfg, TEXT, [], lambda: None, typed=False)
        self.assertEqual((names, why, self.srv.ner_texts), ([], "", []))

    def test_the_mod_sends_only_a_typed_prompt_to_the_gateway(self):
        import json as _json
        from maisecrets import hooks
        from maisecrets.home import CONFIG
        self.login(self.cfg)
        old = CONFIG.read_text(encoding="utf-8") if CONFIG.exists() else None
        self.addCleanup(lambda: CONFIG.write_text(old, encoding="utf-8") if old is not None
                        else CONFIG.unlink(missing_ok=True))
        CONFIG.write_text(_json.dumps(self.cfg), encoding="utf-8")
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
        self.older_login()                                         # a login without the name scope
        self.assertEqual(ner_setup.report(conf)[0], 4)
        self.login(self.cfg)
        code, lines = ner_setup.report(conf)
        self.assertEqual(code, 0, lines)
        self.assertFalse(any(x.startswith("login:") for x in lines))
        self.srv.ner_answer = (503, {"error": "busy"})
        self.assertEqual(ner_setup.report(conf)[0], 1, "a busy gateway needs no login")

    def test_the_status_shows_the_gateways_load_and_the_quota(self):
        import json as _json
        from maisecrets.home import CONFIG
        old = CONFIG.read_text(encoding="utf-8") if CONFIG.exists() else None
        self.addCleanup(lambda: CONFIG.write_text(old, encoding="utf-8") if old is not None
                        else CONFIG.unlink(missing_ok=True))
        CONFIG.write_text(_json.dumps(self.cfg), encoding="utf-8")
        self.login(self.cfg)
        code, lines = ner_setup.report(self.cfg["remote_detector"])
        self.assertEqual(code, 0, lines)
        load = [x for x in lines if x.startswith("load:")]
        self.assertEqual(load, ["load: 4 workers, 25 % in use; 0 waiting; your quota this minute: 59 of 60 "
                                "requests, 199,951 of 200,000 characters"])
        self.srv.ner_status = {"service": None, "client_path": {"free": False}, "quota": {}}
        ner_gateway.CACHE.unlink(missing_ok=True)
        load = [x for x in ner_setup.report(self.cfg["remote_detector"])[1] if x.startswith("load:")]
        self.assertEqual(load, ["load: the client slot is busy now (a text is answered busy)"])
        self.assertEqual(ner_gateway.status_line({"service": {"workers": 4, "in_use_share": None}}), "load: 4 workers")
        self.assertEqual(ner_gateway.status_line("x"), "load: no load data")
        # Infinity and 1e999 are JSON numbers; they must not stop the status (Gate A)
        self.assertEqual(ner_gateway.status_line({"service": {"workers": float("inf")},
                                                  "quota": {"requests_left": 1e999, "requests_per_minute": 60}}),
                         "load: no load data")
        # a cache from before the status endpoint: one discovery more, not an hour without load data
        import json as _j
        ner_gateway.CACHE.write_text(_j.dumps({self.origin: {"at": __import__("time").time(), "found": {
            **S.discover(self.cfg, self.srv.url + "/mcp"), "ner": {k: v for k, v in S.discover(
                self.cfg, self.srv.url + "/mcp")["ner"].items() if k != "status"}}}}), encoding="utf-8")
        self.srv.ner_status = {"service": {"workers": 4, "in_use_share": 0.5}}
        self.assertEqual(ner_gateway.status_line(ner_gateway.status(self.cfg, self.cfg["remote_detector"])[0]),
                         "load: 4 workers, 50 % in use")

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

    def test_a_prompt_goes_to_the_gateway_with_no_switch(self):
        self.login(self.cfg)
        conf = self.cfg["remote_detector"]
        text, start, names, why = self.prompt(conf)
        self.assertEqual((names, why), (["Okafor"], ""))
        self.assertEqual(len(self.srv.ner_texts), 1)
        sent = self.srv.ner_texts[0]
        self.assertNotIn("testpass", sent, "the rules' finding goes out as filler")
        self.assertEqual(sent[:start], text[:start])
        # a policy's "prompts": false (the only place it is still read) leaves the prompt to the rules
        self.assertEqual(self.prompt({**conf, "prompts": False})[2], [])
        self.assertEqual(len(self.srv.ner_texts), 1)

    def test_a_prompt_waits_two_seconds_in_total_discovery_and_token_included(self):
        # Gate A of the prompt change: a slow discovery or token took its own 2 s, and then the request got a fresh
        # full wait. One end, set before the discovery, bounds all three
        self.login(self.cfg)
        self.srv.ner_delay = 2.5
        real = S.discover

        def slow(seconds):
            def discover(*a, **k):
                time.sleep(seconds)
                return real(*a, **k)
            return discover
        # (name, extra setting, discovery delay, token refresh delay, the longest wait)
        cases = (("cached", {}, 0.0, 0.0, 2.4),
                 ("a timeout_ms of 3 s is for tool results", {"timeout_ms": 3000}, 0.0, 0.0, 2.4),
                 ("slow discovery", {}, 1.2, 0.0, 2.4),
                 ("discovery past the end", {}, 2.3, 0.0, None),
                 ("slow token, a shorter prompt wait", {"prompt_timeout_ms": 1000}, 0.0, 1.5, 1.3))
        for name, extra, discovery, refresh, longest in cases:
            with self.subTest(name):
                if discovery:
                    ner_gateway.CACHE.unlink(missing_ok=True)
                if refresh:
                    rec = S._load(self.backend, self.origin)
                    S._keep(self.backend, self.origin, {**rec, "expires": 0})      # the next call refreshes
                self.srv.refresh_delay = refresh
                cfg = {**self.cfg, "remote_detector": {**self.cfg["remote_detector"], **extra}}
                with mock.patch.object(S, "discover", slow(discovery)):
                    t0 = time.monotonic()
                    names, why = remote_layer.prompt_names(cfg, TEXT, [], lambda: None)
                    took = time.monotonic() - t0
                # a setup that ends after the wait: no answer in time, as for a slow service
                self.assertEqual((names, why), ([], "timeout"))
                if longest is not None:
                    self.assertLess(took, longest)

    def test_the_prompts_switch_is_no_form_of_the_command_any_more(self):
        for text in ("/maisecrets:ner prompts on", "/maisecrets:ner prompts off"):
            self.assertEqual(ner_setup.parse(text), "other:" + text[16:])

    def post_tool(self, conf: dict, tool: str = "Bash", **extra) -> dict:
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
                                               "tool_response": response, **extra})

    def test_each_result_whose_names_were_not_checked_says_so_on_the_screen(self):
        self.login(self.cfg)
        self.srv.ner_answer = (503, {"error": "busy"})
        conf = self.cfg["remote_detector"]
        line = "names are NOT checked \u2014 the gateway's name service is busy \u2192 /maisecrets ner"
        for shown in (True, False):          # once per session, when the state turns bad
            out = self.post_tool(conf)
            self.assertEqual(line in out.get("systemMessage", ""), shown, out.get("systemMessage"))
            self.assertNotIn("updatedToolOutput", out.get("hookSpecificOutput") or {}, "the output stays as it is")
            self.assertIn("did not check the names", out["hookSpecificOutput"]["additionalContext"], "AI: each time")
        self.assertEqual(ner_health.recorded(conf), "busy", "the status can name it")
        self.srv.ner_answer = None
        out = self.post_tool(conf)
        self.assertNotIn("NOT checked", out.get("systemMessage", ""))
        self.assertNotIn("did not check the names", json.dumps(out))
        self.assertIsNone(ner_health.recorded(conf), "names checked again: the status names no cause")
        self.srv.ner_answer = (503, {"error": "busy"})
        self.assertNotIn("NOT checked", self.post_tool(conf).get("systemMessage", ""), "the same cause: not again")
        self.srv.ner_answer = (429, {"error": "rate_limited"})
        self.assertIn("limit per minute was reached", self.post_tool(conf).get("systemMessage", ""), "a new cause")

    def test_codex_gives_its_model_the_note_at_each_unchecked_result(self):
        # Codex sends only additionalContext to the model; a systemMessage is a warning for the person (CLIENTS.md)
        self.login(self.cfg)
        self.srv.ner_answer = (503, {"error": "busy"})
        conf = self.cfg["remote_detector"]
        for _ in range(2):
            out = self.post_tool(conf, turn_id="t-1", session_id="s-ner-codex")
            hso = out.get("hookSpecificOutput") or {}
            self.assertIn("did not check the names", hso.get("additionalContext", ""), out)
            self.assertEqual(hso.get("hookEventName"), "PostToolUse")

    def test_a_failed_discovery_has_its_own_cause_and_only_a_read_document_without_ner_is_no_ner(self):
        self.login(self.cfg)
        conf = self.cfg["remote_detector"]
        real = S._request

        def answer(result):
            def request(cfg, method, url, *a, **kw):
                if "/.well-known/" in url:
                    if isinstance(result, BaseException):
                        raise result
                    return result
                return real(cfg, method, url, *a, **kw)
            return request
        cases = (("timeout", TimeoutError("slow"), "slow"), ("refused", ConnectionRefusedError("down"), "no_answer"),
                 ("http 500", (500, {}, b""), "no_answer"),
                 ("bad json", (200, {"content-type": "application/json"}, b"{not json"), "other"),
                 ("no sensitive references", (200, {"content-type": "application/json"}, b"{}"), "no_ner"))
        for name, result, cause in cases:
            with self.subTest(name):
                ner_gateway.CACHE.unlink(missing_ok=True)
                with mock.patch.object(S, "_request", answer(result)):
                    det, why = ner_gateway.detector(self.cfg, conf, lambda *a: object())
                self.assertIsNone(det)
                self.assertEqual(ner_gateway.LAST["cause"], cause, why)
        ner_gateway.CACHE.unlink(missing_ok=True)
        self.srv.ner = False                  # the document is read and names no name detection
        det, _why = ner_gateway.detector(self.cfg, conf, lambda *a: object())
        self.assertEqual((det, ner_gateway.LAST["cause"]), (None, "no_ner"))

    def test_withhold_keeps_an_unchecked_result_from_the_ai(self):
        self.login(self.cfg)
        conf = ner_setup.updated(self.cfg["remote_detector"], "unavailable:withhold")
        self.assertEqual(conf["unavailable"], "withhold")
        self.srv.ner_answer = (503, {"error": "busy"})
        cause = "names are NOT checked \u2014 the gateway's name service is busy \u2192 /maisecrets ner"
        for first, tool in ((True, "Bash"), (False, "Read")):
            with self.subTest(tool=tool):
                out = self.post_tool(conf, tool)
                given = json.dumps(out["hookSpecificOutput"]["updatedToolOutput"])
                self.assertNotIn("Okafor", given)
                self.assertIn("withheld this tool result", given)
                self.assertIn("withheld this result from the AI", out["systemMessage"], "under each withheld result")
                self.assertEqual(cause in out["systemMessage"], first, "the cause and the step: once per session")
                self.assertNotIn("the rules alone masked", out["hookSpecificOutput"].get("additionalContext", ""))
        self.assertEqual(ner_health.recorded(conf), "busy", "the status learns the cause of a withheld result too")
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
        cases = ((403, "x", "forbidden"), (413, "x", "too_long"), (429, "rate_limited", "rate_limited"),
                 (503, "temporarily_unavailable", "unavailable"), (503, "ner_unavailable", "unavailable"),
                 (429, "busy", "busy"), (503, "busy", "busy"), (500, "x", "http"))
        for code, body, reason in cases:
            # 429 {"error": "busy"}: the gateway's one client slot since it stopped answering busy with 503
            with self.subTest(code=code, error=body):
                self.srv.ner_answer = (code, {"error": body, "retry_after": 1})
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
