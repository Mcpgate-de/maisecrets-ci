"""maisecrets/sref_client.py against a fake gateway (harness/sref_server.py): discovery, the loopback login with PKCE,
the token in the store, the resolve into a file or a command, the whole-batch rule with counts, the refresh, a
withdrawn consent, the quota and a sink the gateway does not offer. The values are synthetic; no answer of the client
names a value or a reference id.

Run: python3 -m unittest tests.test_sref_client -v
"""
from __future__ import annotations

import json
import os
import shutil
import ssl
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "harness"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import sref_client as S  # noqa: E402
from maisecrets.vault import JsonFileBackend  # noqa: E402

HAS_OPENSSL = shutil.which("openssl") is not None
if HAS_OPENSSL:
    from sref_server import SrefServer  # noqa: E402
    from vault_server import make_cert  # noqa: E402

VALUE_MAIL, VALUE_NAME = "value-one@example.org", "Value Two"
_CERT: tuple | None = None


def _cert() -> tuple:
    global _CERT
    if _CERT is None:
        _CERT = make_cert(tempfile.mkdtemp(prefix="sref-cert-"))
    return _CERT


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


@unittest.skipUnless(HAS_OPENSSL and os.name != "nt", "openssl on POSIX")
class SrefClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.srv = SrefServer(cert=_cert()).__enter__()
        self.addCleanup(self.srv.__exit__)
        self.cfg = {"client_vault_cafile": self.srv.cert}
        self.backend = JsonFileBackend()           # the store of the temp home of tests/_isolate.py
        self.found = S.discover(self.cfg, self.srv.url + "/mcp")
        self.addCleanup(S.forget, self.backend, self.found["origin"])

    def browser(self, url: str, state: str | None = None) -> None:
        """The person in the browser: the authorize URL answers with a redirect to the loopback, which the browser
        follows. With `state`, the redirect is forged to carry another state."""
        ctx = ssl.create_default_context(cafile=self.srv.cert)
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect())
        try:
            opener.open(url)
        except urllib.error.HTTPError as exc:
            location = exc.headers["Location"]
            exc.close()
        if state is not None:
            location = location.split("state=")[0] + "state=" + state
        try:
            with urllib.request.urlopen(location, timeout=5) as answer:
                answer.read()
        except urllib.error.HTTPError as exc:
            exc.close()

    def login(self) -> None:
        S.login(self.cfg, self.backend, self.found, self.browser, wait=10)

    def test_discovery_names_the_resolver_and_its_sinks(self):
        self.assertIsNotNone(self.found)
        self.assertEqual(self.found["resolve"], self.srv.url + "/sensitive-references/resolve")
        self.assertEqual(sorted(self.found["sinks"]), ["local-file-1", "mcpgate-process-1"])

    def test_the_login_keeps_the_tokens_in_the_store(self):
        self.assertFalse(S.logged_in(self.backend, self.found["origin"]))
        self.login()
        self.assertTrue(S.logged_in(self.backend, self.found["origin"]))
        stored = self.backend.get(S._entry(self.found["origin"]))
        self.assertIn("srefr_", stored)

    def test_a_forged_state_ends_the_login_without_a_token(self):
        with self.assertRaises(S.Refused):
            S.login(self.cfg, self.backend, self.found, lambda url: self.browser(url, state="forged"), wait=10)
        self.assertFalse(S.logged_in(self.backend, self.found["origin"]))

    def test_a_file_and_a_command_get_their_values_and_the_gateway_learns_the_sink(self):
        self.login()
        mail, name = self.srv.mint("email", VALUE_MAIL), self.srv.mint("name", VALUE_NAME)
        got = S.resolve(self.cfg, self.backend, self.found, [mail, name], "local_file", "/tmp/invite.txt")
        self.assertEqual(got, {mail: VALUE_MAIL, name: VALUE_NAME})
        S.resolve(self.cfg, self.backend, self.found, [mail], "process", "curl")
        self.assertEqual([(r["sink_type"], r["destination"], r["count"]) for r in self.srv.resolved],
                         [("local_file", "/tmp/invite.txt", 2), ("process", "curl", 1)])

    def test_one_bad_reference_refuses_the_whole_batch_with_counts_only(self):
        self.login()
        good, gone = self.srv.mint("email", VALUE_MAIL), self.srv.mint("name", VALUE_NAME)
        self.srv.revoke(gone)
        unknown = "⟦sref:email:" + "x" * 24 + "⟧"
        with self.assertRaises(S.Refused) as cm:
            S.resolve(self.cfg, self.backend, self.found, [good, gone, unknown], "local_file", "/tmp/a.txt")
        msg = str(cm.exception)
        self.assertIn("1 revoked", msg)
        self.assertIn("1 unknown", msg)
        for leak in (VALUE_MAIL, VALUE_NAME, good, gone, unknown):
            self.assertNotIn(leak, msg)
        self.assertEqual(self.srv.resolved, [], "nothing released")

    def test_an_expired_access_token_is_refreshed_once_and_the_refresh_token_rotates(self):
        self.login()
        old = json.loads(self.backend.get(S._entry(self.found["origin"])))["refresh"]
        self.srv.access.clear()                      # the access token died early on the server
        ref = self.srv.mint("email", VALUE_MAIL)
        self.assertEqual(S.resolve(self.cfg, self.backend, self.found, [ref], "process", "mail"), {ref: VALUE_MAIL})
        new = json.loads(self.backend.get(S._entry(self.found["origin"])))["refresh"]
        self.assertNotEqual(old, new, "a new refresh token is kept")
        self.assertNotIn(old, self.srv.refresh, "the old refresh token is spent")
        self.assertIn(new, self.srv.refresh)

    def test_only_a_400_invalid_grant_ends_the_login(self):
        ref = self.srv.mint("email", VALUE_MAIL)
        for answer, kept in (((500, {"error": "invalid_grant"}), True), ((503, {"error": "busy"}), True),
                             ((400, {"error": "invalid_grant"}), False)):
            with self.subTest(status=answer[0]):
                self.login()
                self.srv.access.clear()
                self.srv.token_answer = answer
                with self.assertRaises(S.Refused):
                    S.resolve(self.cfg, self.backend, self.found, [ref], "process", "mail")
                self.assertEqual(S.logged_in(self.backend, self.found["origin"]), kept)
                self.srv.token_answer = None

    def test_an_unknown_sink_type_is_named_in_fixed_text(self):
        self.login()
        sentinel = "⟦sref:email:" + "u" * 24 + "⟧"
        with self.assertRaises(S.Refused) as cm:
            S.resolve(self.cfg, self.backend, self.found, [self.srv.mint("email", VALUE_MAIL)], sentinel, "x")
        self.assertEqual(str(cm.exception), "unknown sink type")

    def test_a_timeout_on_the_refresh_keeps_the_login(self):
        self.login()
        self.srv.access.clear()
        real = S._request

        def slow(cfg, method, url, *a, **kw):
            if url == self.found["token"]:
                raise TimeoutError("the server took too long")
            return real(cfg, method, url, *a, **kw)
        with mock.patch.object(S, "_request", slow):
            with self.assertRaises(S.Refused):
                S.resolve(self.cfg, self.backend, self.found, [self.srv.mint("email", VALUE_MAIL)], "process", "mail")
        self.assertTrue(S.logged_in(self.backend, self.found["origin"]))

    def test_many_silent_local_connections_hold_few_threads_and_the_login_goes_on(self):
        # a process of the same user can always disturb its own login (C22); what the listener must not do is grow
        # without bound or end: at most 16 connections hold a thread, and the login completes once they are gone
        import socket
        import threading
        import time as clock
        seen = {"threads": 0}

        def handlers(port: int) -> int:
            # the request threads of this listener only, not those of the fake gateway
            n = 0
            for t in threading.enumerate():
                args = getattr(t, "_args", ())
                if getattr(getattr(t, "_target", None), "__name__", "") == "process_request_thread" and args:
                    try:
                        n += args[0].getsockname()[1] == port
                    except OSError:
                        pass
            return n

        def browser(url):
            port = int(url.split("127.0.0.1%3A")[1].split("%2F")[0])
            conns = []
            try:
                for _ in range(64):                # sampled from the first one, so no handler expires unseen
                    conns.append(socket.create_connection(("127.0.0.1", port), timeout=10))
                    seen["threads"] = max(seen["threads"], handlers(port))
                end = clock.monotonic() + 2
                while clock.monotonic() < end:     # the highest count the listener reaches while all 64 are open
                    seen["threads"] = max(seen["threads"], handlers(port))
                    clock.sleep(0.05)
            finally:
                for c in conns:
                    c.close()
            self.browser(url)
        S.login(self.cfg, self.backend, self.found, browser, wait=20)
        self.assertGreater(seen["threads"], 0, "the count sees the handler threads")
        self.assertLessEqual(seen["threads"], 16, "the connections beyond 16 hold no thread")
        self.assertTrue(S.logged_in(self.backend, self.found["origin"]))

    def test_a_thread_that_does_not_start_gives_its_slot_back(self):
        import socket
        import socketserver
        real = socketserver.ThreadingMixIn.process_request
        fails = {"n": 0}

        def no_thread(server, request, client_address):
            # only the login listener on plain http; the fake gateway serves over TLS
            if fails["n"] < 20 and not isinstance(server.socket, ssl.SSLSocket):   # more than the 16 slots
                fails["n"] += 1
                raise RuntimeError("can't start new thread")
            return real(server, request, client_address)

        def browser(url):
            port = int(url.split("127.0.0.1%3A")[1].split("%2F")[0])
            end = __import__("time").monotonic() + 15      # generous for a loaded CI runner; the login waits 20 s
            while fails["n"] < 20 and __import__("time").monotonic() < end:
                with socket.create_connection(("127.0.0.1", port), timeout=10) as c:
                    c.recv(1)                      # the server closes it after the failed start
            self.browser(url)
        with mock.patch.object(socketserver.ThreadingMixIn, "process_request", no_thread), \
                mock.patch.object(socketserver.BaseServer, "handle_error", lambda *a: None):
            S.login(self.cfg, self.backend, self.found, browser, wait=20)
        self.assertEqual(fails["n"], 20)
        self.assertTrue(S.logged_in(self.backend, self.found["origin"]))

    def test_a_string_of_the_token_endpoint_or_the_callback_never_reaches_an_error(self):
        self.login()
        sentinel = "⟦sref:email:" + "s" * 24 + "⟧"
        self.srv.access.clear()
        self.srv.token_answer = (400, {"error": sentinel})
        with self.assertRaises(S.Refused) as cm:
            S.resolve(self.cfg, self.backend, self.found, [self.srv.mint("email", VALUE_MAIL)], "process", "mail")
        self.assertNotIn(sentinel, str(cm.exception))
        self.srv.token_answer = None

        def refusing_browser(url):
            port = url.split("127.0.0.1%3A")[1].split("%2F")[0]
            state = url.split("state=")[1].split("&")[0]
            try:
                from urllib.parse import quote
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/callback?state={state}&error={quote(sentinel)}",
                                            timeout=5) as answer:
                    answer.read()
            except urllib.error.HTTPError as exc:
                exc.close()
        with self.assertRaises(S.Refused) as cm:
            S.login(self.cfg, self.backend, self.found, refusing_browser, wait=2)
        self.assertNotIn(sentinel, str(cm.exception))

    def test_a_withdrawn_consent_asks_for_a_new_login_and_forgets_the_old_one(self):
        self.login()
        ref = self.srv.mint("email", VALUE_MAIL)
        self.srv.withdraw()
        with self.assertRaises(S.Refused) as cm:
            S.resolve(self.cfg, self.backend, self.found, [ref], "local_file", "/tmp/a.txt")
        self.assertIn("run the login again", str(cm.exception))
        self.assertFalse(S.logged_in(self.backend, self.found["origin"]), "a refused refresh token is not kept")

    def test_a_string_of_the_gateway_never_reaches_an_error_message(self):
        self.login()
        ref = self.srv.mint("email", VALUE_MAIL)
        self.srv.evil = True
        for sink, dest in (("local_file", "/tmp/a.txt"), ("process", "curl")):
            with self.subTest(sink=sink):
                with self.assertRaises(S.Refused) as cm:
                    S.resolve(self.cfg, self.backend, self.found, [ref], sink, dest)
                msg = str(cm.exception)
                self.assertNotIn(ref, msg)
                self.assertNotIn(ref.split(":")[2], msg)

    def test_another_local_request_does_not_end_the_login(self):
        def browser(url):
            port = url.split("127.0.0.1%3A")[1].split("%2F")[0]
            import socket
            silent = socket.create_connection(("127.0.0.1", int(port)))   # sends nothing, holds one thread
            self.addCleanup(silent.close)
            for path in ["/favicon.ico", "/callback?code=x&state=wrong"] * 20:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as answer:
                        answer.read()
                except urllib.error.HTTPError as exc:
                    exc.close()
            self.browser(url)
        S.login(self.cfg, self.backend, self.found, browser, wait=10)
        self.assertTrue(S.logged_in(self.backend, self.found["origin"]))

    def test_an_authorize_endpoint_with_a_query_keeps_it_and_adds_the_parameters(self):
        from urllib.parse import parse_qs, urlsplit
        found = dict(self.found, authorize="https://gw.example/authorize?tenant=a&state=old&redirect_uri=x")
        q = parse_qs(urlsplit(S.authorize_url(found, "cid", "http://127.0.0.1:1/callback", "ch", "st")).query)
        self.assertEqual((q["tenant"], q["response_type"], q["state"], q["redirect_uri"]),
                         (["a"], ["code"], ["st"], ["http://127.0.0.1:1/callback"]))

    def test_the_daily_quota_is_named(self):
        self.login()
        self.srv.quota = 1
        refs = [self.srv.mint("email", VALUE_MAIL), self.srv.mint("name", VALUE_NAME)]
        with self.assertRaises(S.Refused) as cm:
            S.resolve(self.cfg, self.backend, self.found, refs, "local_file", "/tmp/a.txt")
        self.assertIn("daily limit", str(cm.exception))

    def test_a_sink_the_gateway_does_not_offer_is_refused_before_a_request(self):
        self.srv.sinks = ["local-file-1"]
        found = S.discover(self.cfg, self.srv.url + "/mcp")
        self.login()
        ref = self.srv.mint("email", VALUE_MAIL)
        with self.assertRaises(S.Refused) as cm:
            S.resolve(self.cfg, self.backend, found, [ref], "process", "curl")
        self.assertIn("does not resolve into a command", str(cm.exception))
        self.assertEqual(self.srv.resolved, [])

    def test_no_login_no_request(self):
        ref = self.srv.mint("email", VALUE_MAIL)
        with self.assertRaises(S.Refused) as cm:
            S.resolve(self.cfg, self.backend, self.found, [ref], "local_file", "/tmp/a.txt")
        self.assertIn("not logged in", str(cm.exception))


class FindTests(unittest.TestCase):
    def test_a_reference_with_a_display_part_resolves_by_its_id(self):
        rid = "a" * 24
        text = f"mail to ⟦sref:email:{rid}:ma•••@x.de⟧ and ⟦sref:name:{rid}⟧"
        got = [(c, s, e) for _r, c, s, e in S.find(text)]
        self.assertEqual([c for c, _s, _e in got], [f"⟦sref:email:{rid}⟧", f"⟦sref:name:{rid}⟧"])
        self.assertEqual(text[got[0][1]:got[0][2]], f"⟦sref:email:{rid}:ma•••@x.de⟧")

    def test_a_short_id_is_no_reference(self):
        self.assertEqual(S.find("⟦sref:email:short⟧"), [])

    def test_the_display_part_follows_the_contract_of_the_gateway(self):
        # 1 to 256 characters, colons allowed, no line break (ai-gateway pii_display.SREF_TOKEN_RE, 2026-11-02)
        rid = "b" * 24
        for display in ("2001:db8::•", "x" * 256):
            with self.subTest(display=display[:12]):
                self.assertEqual([c for _r, c, _s, _e in S.find(f"⟦sref:ip:{rid}:{display}⟧")], [f"⟦sref:ip:{rid}⟧"])
        for display in ("x" * 257, "two\nlines", "", "a b"):
            with self.subTest(display=repr(display[:12])):
                self.assertEqual(S.find(f"⟦sref:ip:{rid}:{display}⟧"), [])


if __name__ == "__main__":
    unittest.main()
