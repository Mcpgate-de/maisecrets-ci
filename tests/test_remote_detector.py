"""The remote detector (maisecrets/detection/remote.py): a named-entity service the library asks after its rules. Each
test runs a fake service on a loopback port (or a Unix socket) that answers in one wire format, slowly, not at all
or with nonsense, and checks the promises: the service only adds, a failing service leaves the deterministic result
as it is and the status says why, the service never sees a deterministic finding, and no text leaves the computer
unless the caller allows it."""
from __future__ import annotations

import json
import re
import os
import socket
import socketserver
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets.detection import (  # noqa: E402
    NO_REFERENCES, NO_SOURCES, Active, Detector, Host, ScanIncomplete, contract)
from maisecrets.detection import remote as rm  # noqa: E402
from test_detection_entry_point import problems  # noqa: E402

NAME = "Anna Kowalczyk"                       # a name no deterministic rule takes
PHONE = "+49 171 " + "4829173"                # a finding of the rules (the number of docs/DETECTION.md)
J = "".join
TEXT = f"Please ask {NAME} about the build; call her at {PHONE} today."


def detector() -> Detector:
    return Detector(regions=Active(regions=["generic"], languages=["en"], source="test"), sources=NO_SOURCES,
                    references=NO_REFERENCES, host=Host(user="", year=2026))


class Service:
    """A fake service. `answer(text)` returns the JSON it sends; `received` keeps each request body."""

    def __init__(self, fmt: str = "hf", answer=None, delay: float = 0.0, status: int = 200, unix: str = "",
                 drip: float = 0.0, bearer: str = ""):
        self.fmt, self.delay, self.status, self.received, self.paths = fmt, delay, status, [], []
        self.bearer, self.headers = bearer, []     # a service that wants this bearer answers 401 without it
        self.secret, self.challenges, self.proof_for = "", [], None   # GET /health?challenge= as mcpgate/ner (#1699)
        self.drip = drip            # seconds between the bytes of the body: a service that dribbles its answer
        self.answer = answer or self.names
        svc = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - http.server API
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                svc.received.append(json.loads(body))
                svc.paths.append(self.path)
                svc.headers.append({k.lower(): v for k, v in self.headers.items()})
                if svc.bearer and self.headers.get("Authorization") != "Bearer " + svc.bearer:
                    self.send_response(401)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if svc.delay:
                    time.sleep(svc.delay)
                text = svc.received[-1]["inputs" if svc.fmt == "hf" else "text"]
                answer = svc.answer(text)
                out = answer if isinstance(answer, bytes) else json.dumps(answer).encode()
                self.send_response(svc.status)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                try:
                    for i in range(len(out)) if svc.drip else [None]:
                        self.wfile.write(out if i is None else out[i:i + 1])
                        if i is not None:
                            self.wfile.flush()
                            time.sleep(svc.drip)
                except OSError:
                    pass

            def do_GET(self):  # noqa: N802 - http.server API
                import hashlib
                import hmac
                import urllib.parse
                parts = urllib.parse.urlsplit(self.path)
                nonce = urllib.parse.parse_qs(parts.query).get("challenge", [""])[0]
                svc.challenges.append(nonce)
                secret = svc.secret
                import re
                if secret and not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", nonce):     # as ner-sidecar/serve.py
                    self.send_response(400)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if parts.path.rstrip("/") != "/health" or not secret:
                    out = b'{"status": "ok"}'           # a service without the secret gives no proof
                else:
                    signed = svc.proof_for(nonce) if svc.proof_for else nonce
                    proof = hmac.new(secret.encode(), ("health:" + signed).encode(), hashlib.sha256).hexdigest()
                    out = json.dumps({"status": "ok", "proof": proof}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                try:
                    for i in range(len(out)) if svc.drip else [None]:
                        self.wfile.write(out if i is None else out[i:i + 1])
                        if i is not None:
                            self.wfile.flush()
                            time.sleep(svc.drip)
                except OSError:
                    pass

            def log_message(self, *args):
                pass

            def address_string(self):
                return "local"

        if unix:
            class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
                daemon_threads = True
            self.server = UnixServer(unix, Handler)
            self.url = "unix:" + unix
        else:
            self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            self.server.daemon_threads = True
            self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()

    def names(self, text: str):
        at = text.find(NAME)
        if at < 0:
            return []
        if self.fmt == "hf":
            return [{"entity_group": "PER", "start": at, "end": at + len(NAME), "score": 0.98, "word": NAME}]
        return [{"entity_type": "PERSON", "start": at, "end": at + len(NAME), "score": 0.85}]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def bearer_of(secret: str) -> str:
    # the derivation of mcpgate/ner (NER_CLIENT_SECRET) and of the gateway: hmac_sha256(secret, "bearer")
    import hashlib
    import hmac
    return hmac.new(secret.encode(), b"bearer", hashlib.sha256).hexdigest()


class BearerTests(unittest.TestCase):
    """A service that wants a bearer (ai-gateway !2965): the derived token goes out as a header and nowhere else."""

    TOKEN = bearer_of("test-client-secret-value")      # the test vector both sides use

    def ask(self, svc: Service, **kw):
        self.addCleanup(svc.close)
        det = rm.RemoteDetector(svc.url, **kw)
        spans, status = det.ask(TEXT, [])
        return det, spans, status

    def test_the_bearer_goes_out_as_a_header_and_the_service_answers(self):
        svc = Service(bearer=self.TOKEN)
        _det, spans, status = self.ask(svc, bearer=self.TOKEN)
        self.assertEqual((status.state, len(spans)), ("ok", 1))
        self.assertEqual(svc.headers[0]["authorization"], "Bearer " + self.TOKEN)

    def test_without_the_keyword_the_request_is_as_before(self):
        plain, with_token = Service(), Service()
        self.ask(plain)
        self.ask(with_token, bearer=self.TOKEN)
        self.assertNotIn("authorization", plain.headers[0])
        self.assertEqual(set(plain.headers[0]), set(with_token.headers[0]) - {"authorization"})
        self.assertEqual(plain.received, with_token.received)

    def test_a_missing_or_wrong_bearer_is_unauthorized_and_the_token_is_nowhere(self):
        for kw in ({}, {"bearer": bearer_of("another-test-secret")}):
            with self.subTest(sent=bool(kw)):
                det, spans, status = self.ask(Service(bearer=self.TOKEN), **kw)
                self.assertEqual((spans, status.state, status.reason), ([], "unavailable", "unauthorized"))
                for shown in (repr(det), str(vars(status)), repr(status)):
                    self.assertNotIn(self.TOKEN, shown)
                    self.assertNotIn(kw.get("bearer", self.TOKEN), shown)

    def test_only_the_derived_hex_is_taken_and_the_error_names_no_value(self):
        for bad in ("test-client-secret-value", self.TOKEN.upper(), self.TOKEN[:-1], self.TOKEN + "0",
                    self.TOKEN[:62] + "\r\n", None, 7):
            with self.subTest(bad=repr(bad)[:12]):
                with self.assertRaises(ValueError) as cm:
                    rm.RemoteDetector("http://127.0.0.1:9/", bearer=bad)
                self.assertEqual(str(cm.exception), "bearer: 64 lowercase hex characters")


class ChallengeTests(unittest.TestCase):
    """A service maisecrets started proves its secret before each text (#1699); a listener that cannot gets none."""

    SHARED = "".join(("test", "-container-", "x" * 26))     # NER_CLIENT_SECRET of the fake container

    def service(self, secret="", **kw) -> Service:
        svc = Service(bearer=bearer_of(self.SHARED) if secret == self.SHARED else "", **kw)
        svc.secret = secret
        self.addCleanup(svc.close)
        return svc

    def test_the_container_proves_the_secret_and_gets_the_text_with_the_bearer(self):
        svc = self.service(self.SHARED)
        det = rm.RemoteDetector(svc.url, secret=self.SHARED)
        for _ in range(2):
            spans, status = det.ask(TEXT, [])
            self.assertEqual((status.state, len(spans)), ("ok", 1))
        self.assertEqual(len(svc.received), 2)
        self.assertEqual(len(set(svc.challenges)), 2, "a fresh nonce for each text")
        self.assertTrue(all(re.fullmatch(r"[A-Za-z0-9_-]{32,128}", c) for c in svc.challenges), "128 bits and more")
        self.assertEqual(svc.headers[-1]["authorization"], "Bearer " + bearer_of(self.SHARED))
        seen = json.dumps([svc.received, svc.headers, svc.challenges])
        self.assertNotIn(self.SHARED, seen, "the secret itself never travels")
        for shown in (repr(det), repr(status)):
            self.assertNotIn(self.SHARED, shown)

    def test_a_listener_without_the_secret_or_with_another_gets_no_text(self):
        for name, svc in (("no secret", self.service("")),
                          ("another secret", self.service("another-container-secret-" + "y" * 16))):
            with self.subTest(listener=name):
                spans, status = rm.RemoteDetector(svc.url, secret=self.SHARED).ask(TEXT, [])
                self.assertEqual((spans, status.state, status.reason), ([], "unavailable", "not_ours"))
                self.assertEqual(svc.received, [], "no text before the proof")

    def test_a_dribbled_proof_ends_at_the_deadline_and_sends_no_text(self):
        # one byte every 50 ms: each read stays under the socket timeout, the whole proof takes about 4 s
        svc = self.service(self.SHARED, drip=0.05)
        t0 = time.monotonic()
        spans, status = rm.RemoteDetector(svc.url, secret=self.SHARED, timeout=0.3).ask(TEXT, [])
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertEqual(status.state, "unavailable")
        time.sleep(5.0)
        self.assertEqual(svc.received, [], "the late proof sent no text")

    def test_a_text_held_up_after_the_proof_is_not_sent_once_the_caller_gave_up(self):
        # the proof in time, then the connection for the text slow: after ask() said timeout, nothing goes out (codex)
        svc = self.service(self.SHARED)
        det = rm.RemoteDetector(svc.url, secret=self.SHARED, timeout=0.3)
        real, calls = det._connection, []

        def slow_second(left, pin=None):
            calls.append(left)
            if len(calls) == 2:              # the connection for the text
                time.sleep(0.6)
            return real(left, pin)
        det._connection = slow_second
        spans, status = det.ask(TEXT, [])
        self.assertEqual((status.state, status.reason), ("unavailable", "timeout"))
        time.sleep(1.0)
        self.assertEqual((len(calls), svc.received), (2, []), "the text was not sent after the timeout")

    def test_the_text_goes_to_the_address_that_gave_the_proof(self):
        # a name whose second lookup points elsewhere (codex review of #1699): one lookup for both
        ours, other = self.service(self.SHARED), self.service(self.SHARED)
        port_of = lambda svc: svc.server.server_address[1]    # noqa: E731
        answers = [port_of(ours), port_of(other)]
        lookups = []

        def resolve(host, port, *a, **k):
            lookups.append(host)
            return [(2, 1, 6, "", ("127.0.0.1", answers[min(len(lookups), 2) - 1]))]
        with mock.patch.object(rm.socket, "getaddrinfo", resolve):
            spans, status = rm.RemoteDetector(f"http://localhost:{port_of(ours)}/", secret=self.SHARED).ask(TEXT, [])
        self.assertEqual((status.state, len(lookups)), ("ok", 1))
        self.assertEqual((len(ours.received), other.received), (1, []))

    def test_a_proof_of_an_old_nonce_is_refused(self):
        svc = self.service(self.SHARED)
        svc.proof_for = lambda nonce: "a-nonce-from-an-earlier-probe-0123"
        spans, status = rm.RemoteDetector(svc.url, secret=self.SHARED).ask(TEXT, [])
        self.assertEqual((status.state, status.reason, svc.received), ("unavailable", "not_ours", []))

    def test_only_a_url_safe_secret_and_not_both_secret_and_bearer(self):
        for kw in ({"secret": "short"}, {"secret": "has space " * 5}, {"secret": None},
                   {"secret": self.SHARED, "bearer": bearer_of(self.SHARED)}):
            with self.subTest(kw=sorted(kw)):
                with self.assertRaises(ValueError) as cm:
                    rm.RemoteDetector("http://127.0.0.1:9/", **kw)
                self.assertNotIn(self.SHARED, str(cm.exception))


class RemoteDetectorTests(unittest.TestCase):
    def setUp(self):
        self.det = detector()
        self.base = self.det.findings(TEXT, channel="tool")
        self.assertTrue(any(m.type == "PHONE" for m in self.base), "premise: the rules find the number")
        self.assertFalse(any(m.type == "NAME" for m in self.base), "premise: the rules leave the name")

    def run_with(self, svc: Service, **kw) -> rm.Result:
        self.addCleanup(svc.close)
        return self.det.findings_with(TEXT, channel="tool", remote=rm.RemoteDetector(svc.url, format=svc.fmt, **kw))

    def test_a_product_word_alone_is_no_name_and_a_full_name_with_one_stays(self):
        # ghissues dev, 2026-11-01: 141 of 1,670 name spans were a product word alone (rm.PRODUCT_WORDS)
        full = NAME + " Jenkins"
        text = f"Ask {full} about it; Claude wrote the patch and jenkins ran it."

        def answer(t):
            out = []
            for word in (full, "Claude", "jenkins"):
                at = t.find(word)
                out.append({"entity_group": "PER", "start": at, "end": at + len(word), "score": 0.9, "word": word})
            return out
        svc = Service(answer=answer)
        self.addCleanup(svc.close)
        spans, status = rm.RemoteDetector(svc.url).ask(text, [])
        self.assertEqual(status.state, "ok")
        self.assertEqual([text[s:e] for s, e, _t, _sc in spans], [full])

    def test_a_product_name_is_no_name_and_a_person_with_a_product_surname_stays(self):
        # mcpgate/ner v2.0.3584, 2026-11-03: "Claude Code" came back as one PER span; only a product word alone was
        # dropped
        person, first = NAME + " Docker", "Claude " + NAME.split()[-1]
        text = f"Claude Code ran it, GitHub Actions too, then {person}, {first} and Docker Desktop. Claude Opus too."
        phrases = ("Claude Code", "GitHub Actions", person, first, "Docker Desktop", "Claude Opus")

        def answer(t):
            out = []
            for word in phrases:
                at = t.find(word)
                out.append({"entity_group": "PER", "start": at, "end": at + len(word), "score": 0.9, "word": word})
            return out
        svc = Service(answer=answer)
        self.addCleanup(svc.close)
        spans, status = rm.RemoteDetector(svc.url).ask(text, [])
        self.assertEqual(status.state, "ok")
        self.assertEqual([text[s:e] for s, e, _t, _sc in spans], [person, first])

    def test_is_product_name_is_the_rule_a_caller_applies_itself(self):
        # the gateway applies the spans itself and asks this function (public since 0.8.15)
        for span in ("Claude", " claude code ", "GitHub Actions", "Docker Desktop", "Claude Opus", "GitHub Copilot"):
            self.assertTrue(rm.is_product_name(span), span)
        for span in ("", "Hallo", NAME, NAME + " Docker", "Claude " + NAME.split()[-1], "Code", "Desktop Claude",
                     "Claude Server", "GitHub Api"):
            self.assertFalse(rm.is_product_name(span), span)

    def test_a_greeting_alone_is_no_name_and_the_name_after_it_stays(self):
        # a corpus of gateway responses, 2026-11-02: 88 of 117 false names were "Hallo" before a name
        text = f"Hallo {NAME}, Moin! Dear team, hi."

        def answer(t):
            out = []
            for word in ("Hallo", NAME, "Moin", "Dear", "hi"):
                at = t.find(word)
                out.append({"entity_group": "PER", "start": at, "end": at + len(word), "score": 0.9, "word": word})
            return out
        svc = Service(answer=answer)
        self.addCleanup(svc.close)
        spans, status = rm.RemoteDetector(svc.url).ask(text, [])
        self.assertEqual(status.state, "ok")
        self.assertEqual([text[s:e] for s, e, _t, _sc in spans], [NAME])

    def test_a_button_word_alone_is_no_name(self):
        # #41: the reference service marks "Allow" and "Deny" before "buttons" as persons (0.91 to 0.999)
        text = f"the warning and the Allow and Deny buttons, then {NAME} pressed Submit or Reset."

        def answer(t):
            out = []
            for word in ("Allow", "Deny", NAME, "Submit", "Reset"):
                at = t.find(word)
                out.append({"entity_group": "PER", "start": at, "end": at + len(word), "score": 0.99, "word": word})
            return out
        svc = Service(answer=answer)
        self.addCleanup(svc.close)
        spans, status = rm.RemoteDetector(svc.url).ask(text, [])
        self.assertEqual(status.state, "ok")
        self.assertEqual([text[s:e] for s, e, _t, _sc in spans], [NAME])

    def test_is_no_person_is_the_whole_rule_a_caller_applies_itself(self):
        # the gateway applies the spans itself and asks this function (#41, devs/ai-gateway#1808)
        for span in ("Allow", " deny ", "Submit", "Lieben", "Hallo", "hoi", "Claude Code", "GitHub", "Ran", "Skipped"):
            self.assertTrue(rm.is_no_person(span), span)
        # a button word that is also a given name or a surname stays a name: Edit (Hungarian), Ok (Korean)
        for span in ("", NAME, NAME.split()[0], NAME.split()[-1], "Allow " + NAME.split()[-1], "Allowance", "Edit",
                     "Ok"):
            self.assertFalse(rm.is_no_person(span), span)

    def _kept(self, text: str, words: tuple) -> list:
        def answer(t):
            out = []
            for word in words:
                at = t.find(word)
                out.append({"entity_group": "PER", "start": at, "end": at + len(word), "score": 0.95, "word": word})
            return out
        svc = Service(answer=answer)
        self.addCleanup(svc.close)
        spans, status = rm.RemoteDetector(svc.url).ask(text, [])
        self.assertEqual(status.state, "ok")
        return [text[s:e] for s, e, _t, _sc in spans]

    def test_the_tail_of_a_product_name_is_no_name(self):
        # 2026-11-17: the gateway's service gave "Code" of "Claude Code" alone, and it was stored as a name
        for product, tail in (("Claude", "Code"), ("GitHub", "Actions"), ("Docker", "Desktop")):
            text = f"I use {product} {tail} with {NAME} today."
            for words in ((tail,), (f"{product} {tail}",), (product,)):
                with self.subTest(words=words):
                    self.assertEqual(self._kept(text, words + (NAME,)), [NAME])
        self.assertEqual(self._kept(f"Open Claude Code Desktop, {NAME}.", ("Desktop", NAME)), [NAME])

    def test_a_name_after_a_product_word_stays_a_name(self):
        first, last = NAME.split()[0], NAME.split()[-1]
        self.assertEqual(self._kept(f"Claude {NAME} wrote it.", (NAME,)), [NAME])
        self.assertEqual(self._kept(f"Claude {first} wrote it.", (first,)), [first])
        self.assertEqual(self._kept(f"Claude Code {last} wrote it.", (last,)), [last])
        # a tail that is a given name or a surname stays a name after a product word: Server is a Turkish given name
        for words, kept in ((("Server",), ["Server"]), (("Claude Server",), ["Claude Server"]), (("Api",), ["Api"]),
                            (("Claude Api",), ["Claude Api"])):
            with self.subTest(words=words):
                self.assertEqual(self._kept("Ask Claude Server and Claude Api about it.", words), kept)

    def test_a_word_that_is_a_name_somewhere_stays_a_name_without_context(self):
        # Gate A: code, bash, home, edit are surnames or given names; only a context in the text frees them
        for word in ("Code", "Bash", "Home", "Edit", "Read", "Desktop", "Server", "Opus", "Library"):
            with self.subTest(word=word):
                self.assertEqual(self._kept(f"Ask {word} about it.", (word,)), [word])
        # a word that is never a name goes alone
        self.assertEqual(self._kept("WebFetch, PostToolUse, Users and GitLab", ("WebFetch", "PostToolUse", "Users",
                                                                                  "GitLab")), [])

    def test_a_tool_name_in_a_hook_label_or_a_tool_context_is_no_name(self):
        # 2026-11-17: "PostToolUse:Bash says: …" made "Bash" a stored name, masked in every later text
        line = "PostToolUse:Bash says: maisecrets masked 2 values. Then PreToolUse:Edit ran."
        for words in (("PostToolUse:Bash",), ("Bash",), ("PostToolUse",), ("Edit",), ("PreToolUse:Edit",)):
            with self.subTest(words=words):
                self.assertEqual(self._kept(line + f" {NAME} saw it.", words + (NAME,)), [NAME])
        self.assertEqual(self._kept(f"I ran Bash and then {NAME} used the Edit tool, Read(x) and via Task.",
                                    ("Bash", NAME, "Edit", "Read", "Task")), [NAME])
        self.assertEqual(self._kept(f"Stop:{NAME.split()[0]} and Edit and Bash.", (NAME.split()[0], "Edit", "Bash")),
                         [NAME.split()[0], "Edit", "Bash"])

    def test_the_hook_and_tool_rules_a_caller_applies_itself(self):
        for span in ("PostToolUse:Bash", "Stop:Edit", " sessionstart:read "):
            self.assertTrue(rm.is_hook_label(span), span)
            self.assertTrue(rm.is_no_person(span), span)
        for span in ("", "Bash", "Edit", "PostToolUse", "PostToolUse:" + NAME.split()[0], "Foo:Bash",
                     "PostToolUse:Bash hook", ":"):
            self.assertFalse(rm.is_hook_label(span), span)
        for text, span in (("PostToolUse:Edit", "Edit"), ("x Stop:Bash", "Bash")):
            at = text.rindex(span)
            self.assertTrue(rm.is_hook_label_tail(text, at, at + len(span)), (text, span))
            self.assertTrue(rm.is_no_person_in(text, at, at + len(span)), (text, span))
        for text, span in (("Edit", "Edit"), ("Note:Edit", "Edit"), ("PostToolUse: Edit", "Edit"),
                           ("PostToolUse:Edit it", "Edit it"), ("PostToolUseX:Edit", "Edit"),
                           ("PostToolUse-Edit", "Edit"), ("Edit PostToolUse:", "Edit"),
                           ("Stop:" + NAME.split()[0], NAME.split()[0]), ("PostToolUse :Edit", "Edit")):
            at = text.rindex(span)
            self.assertFalse(rm.is_hook_label_tail(text, at, at + len(span)), (text, span))
        for text, span in (("Bash(ls)", "Bash"), ("the Edit tool", "Edit"), ("two Read  tools", "Read"),
                           ("I ran Bash", "Bash"), ("run  Write", "Write"), ("runs Grep", "Grep"), ("via Task", "Task"),
                           ("ran\tBash", "Bash")):
            at = text.rindex(span)
            self.assertTrue(rm.is_tool_in_context(text, at, at + len(span)), (text, span))
        for text, span in (("Bash (ls)", "Bash"), ("Edit toolbox", "Edit"), ("called Bash", "Bash"),
                           ("ranBash", "Bash"),
                           ("Bash", "Bash"), (NAME + "(x)", NAME), ("ran " + NAME, NAME), ("the Bash\ntool", "Bash")):
            at = text.rindex(span)
            self.assertFalse(rm.is_tool_in_context(text, at, at + len(span)), (text, span))

    def test_a_folder_name_or_a_product_word_in_a_path_is_no_name_and_a_login_name_stays(self):
        # 2026-11-17: "Users" and "Claude" in paths of an audit report were masked as names
        login = NAME.split()[0].lower()
        text = (f"read /Users/{login}/.claude/settings.json and C:\\Users\\{login}\\AppData\\Roaming\\Codex "
                f"and /home/{login}/Library/Shared/x, Library/Documents.")
        words = ("Users", "claude", "AppData", "Roaming", "Codex", "home", "Library", "Library/Documents", login)
        self.assertEqual(self._kept(text, words), [login])
        self.assertEqual(self._kept(f"/Users/{login}/Documents", (f"Users/{login}",)), [f"Users/{login}"])

    def test_the_path_rules_a_caller_applies_itself(self):
        for span in ("Library/Documents", "AppData\\Roaming", "/var/tmp/", "/opt/claude", "Documents/Users"):
            self.assertTrue(rm.is_path_words(span), span)
        for span in ("", "/", "Users", "Users/" + NAME.split()[0], "Users Library", "Library " + NAME, "Users/Home",
                     "home/claude", "/Users/Shared"):
            self.assertFalse(rm.is_path_words(span), span)
        for text, span in (("/home/x", "home"), ("Library/", "Library"), ("x\\Local", "Local"), ("/.claude", ".claude"),
                           ("/.claude", "claude"), ("C:\\Opt", "Opt"), ("/x/home/y", "home"), ("/home/a/Opt", "Opt"),
                           ("Users-x/Home", "Home"), ("myusers//Home", "Home"), ("usersLibrary/", "Library"),
                           ("x-users/Home", "Home"),
                           ("/myusers/Library", "Library")):
            at = text.rindex(span)
            self.assertTrue(rm.is_path_segment(text, at, at + len(span)), (text, span))
        for text, span in (("home", "home"), ("go home now", "home"), ("/x/" + NAME.split()[0], NAME.split()[0]),
                           ("a.home", "home"), ("-home-", "home"), (".home", "home"), ("/Users/Home/file", "Home"),
                           ("/home/home/file", "home"), ("/Users//Home/", "Home"), ("/home//Home/", "Home"),
                           ("C:\\\\Users\\\\Home\\\\", "Home"),
                           ("C:\\Users\\Opt\\x", "Opt"), ("Users/Library", "Library")):
            at = text.rindex(span)
            self.assertFalse(rm.is_path_segment(text, at, at + len(span)), (text, span))

    def test_is_never_stored_name_holds_only_words_that_are_never_a_name(self):
        for value in ("Users", "PostToolUse", "WebFetch", "GitLab", "Codex", "Actions", "Users/AppData", " grep ",
                      "PostToolUse:WebFetch", "AppData\\Users"):
            self.assertTrue(rm.is_never_stored_name(value), value)
        # a word that is a name somewhere is stored when the filter keeps it: the filter has the context
        for value in ("", "/", NAME, NAME.split()[0], "Claude", "Code", "Server", "Bash", "Edit", "Home", "Desktop",
                      "PostToolUse:Bash", "Users/" + NAME.split()[0], "Claude Code"):
            self.assertFalse(rm.is_never_stored_name(value), value)

    def test_is_product_tail_and_is_no_person_in_are_the_rule_a_caller_applies_itself(self):
        for text, span in (("Claude Code", "Code"), ("GitHub  Actions", "Actions"), ("Docker Desktop", "Desktop"),
                           ("Claude Code Desktop", "Desktop"), ("Claude Code Desktop", "Code Desktop")):
            at = text.rindex(span)
            self.assertTrue(rm.is_product_tail(text, at, at + len(span)), (text, span))
            self.assertTrue(rm.is_no_person_in(text, at, at + len(span)), (text, span))
        for text, span in (("Code", "Code"), ("my Code", "Code"), ("Claude\nCode", "Code"),
                           ("Claude-Code", "Code"), ("Claude " + NAME, NAME), ("Claude Code", " "),
                           (".Code", "Code"), ("Claude Code " + NAME, "Code " + NAME),
                           ("ClaudeCode", "Code"), ("Claude my Code", "Code"), ("Claude ", ""),
                           ("Claude Server", "Server"), ("Claude Code Server", "Code Server")):
            at = text.rindex(span)
            self.assertFalse(rm.is_product_tail(text, at, at + len(span)), (text, span))
        self.assertTrue(rm.is_no_person_in("Kessler GmbH", 0, len("Kessler")))
        self.assertTrue(rm.is_no_person_in("Hallo", 0, 5))
        self.assertFalse(rm.is_no_person_in("x " + NAME, 2, 2 + len(NAME)))

    def test_a_company_with_a_legal_form_is_no_name(self):
        # #46: the name service took company names of the Mendeley sample for persons; invented companies
        text = f"Invoice from Varga Orbek Ltd, then Lindqvist-Haro LLC paid. {NAME} called Kessler GmbH."

        def answer(t):
            out = []
            # the model takes the legal form into the span, or stops before it
            for word in ("Varga Orbek Ltd", "Lindqvist-Haro", NAME, "Kessler"):
                at = t.find(word)
                out.append({"entity_group": "PER", "start": at, "end": at + len(word), "score": 0.95, "word": word})
            return out
        svc = Service(answer=answer)
        self.addCleanup(svc.close)
        spans, status = rm.RemoteDetector(svc.url).ask(text, [])
        self.assertEqual(status.state, "ok")
        self.assertEqual([text[s:e] for s, e, _t, _sc in spans], [NAME])

    def test_is_company_name_reads_the_unambiguous_legal_forms_only(self):
        for form in ("GmbH", "mbH", "LLC", "LLP", "Ltd", "Ltd.", "Inc", "Inc.", "Corp", "Corp.", "Limited", "PLC",
                     "plc"):
            text = f"Kessler {form} paid"
            with self.subTest(text=text):
                self.assertTrue(rm.is_company_name(text, 0, len("Kessler")), "a legal form follows")
                self.assertTrue(rm.is_company_name(text, 0, len(text) - len(" paid")), "a legal form ends the span")
        # persons (Gate A of #46): a job title or a word after a comma, an initial, a hyphen, a short form of another
        # meaning, a word that starts with a form, a plain name
        for text, end in (("Jane Doe, SE at Acme", 8), ("Tom Berg, PLC programmer", 8), ("Hi Tom, Group chat", 6),
                          ("Dear Tom, Inc. forms are attached", 8), ("Raghav N.V. Rao joined", 6),
                          ("Raghav N.V. Rao joined", 11), ("Herr Mueller AG-Leiter", 12), ("Ola Berg SE-Team", 8),
                          ("Kessler Ltd-branded mugs", 7), ("Letitia Vance AG of the state", 13),
                          ("Kessler Incorporated the files", 7), ("Kessler limited the access", 7), ("Kessler", 7),
                          ("Mary S.A. Jones", 4), ("Kessler Group", 7), ("Kessler and Sons", 7)):
            with self.subTest(text=text, end=end):
                self.assertFalse(rm.is_company_name(text, 0, end))

    def test_the_hf_format_adds_a_name_with_its_score(self):
        r = self.run_with(Service("hf"), model="d3@test")
        names = [m for m in r.findings if m.type == "NAME"]
        self.assertEqual([(m.value, m.kind, m.score) for m in names], [(NAME, "remote:hf", 0.98)])
        self.assertEqual((r.remote.state, r.remote.added, r.remote.model), ("ok", 1, "d3@test"))
        self.assertEqual([m for m in r.findings if m.type != "NAME"], self.base, "the rules' findings as they were")
        self.assertTrue(all(m.score is None for m in self.base), "a deterministic finding has no score")

    def test_the_presidio_format_posts_to_analyze_with_its_language(self):
        svc = Service("presidio")
        r = self.run_with(svc, language="de")
        self.assertEqual([m.value for m in r.findings if m.type == "NAME"], [NAME])
        self.assertEqual(svc.paths, ["/analyze"])
        self.assertEqual(svc.received[0]["language"], "de")

    def test_names_only_sends_no_parameters_and_more_classes_ask_for_their_labels(self):
        # the multi-label contract of examples/ner_service.py: an old service and the Hugging Face API never see
        # the new key unless the person maps a class beyond names
        svc = Service("hf")
        self.run_with(svc)
        self.assertEqual(svc.received[-1].keys(), {"inputs"})
        more = {"PER": "NAME", "PERSON": "NAME", "ORG": "ORGANIZATION", "LOC": "LOCATION"}
        # the Hugging Face API has no `labels`: without ask_labels the request stays as it was (codex review)
        self.det.findings_with(TEXT, channel="tool", remote=rm.RemoteDetector(svc.url, classes=more))
        self.assertEqual(svc.received[-1].keys(), {"inputs"})
        self.det.findings_with(TEXT, channel="tool", remote=rm.RemoteDetector(svc.url, classes=more, ask_labels=True))
        self.assertEqual(svc.received[-1]["parameters"], {"labels": ["PER", "ORG", "LOC"]})
        # a service whose person class is PERSON keeps it
        self.det.findings_with(TEXT, channel="tool", remote=rm.RemoteDetector(
            svc.url, classes={"PERSON": "NAME", "ORG": "ORGANIZATION"}, ask_labels=True))
        self.assertEqual(svc.received[-1]["parameters"], {"labels": ["PERSON", "ORG"]})

    def test_port_0_is_refused_not_taken_for_the_default_port(self):
        with self.assertRaises(ValueError):
            rm.RemoteDetector("http://127.0.0.1:0/")

    def test_the_service_never_sees_a_deterministic_finding_and_offsets_still_fit(self):
        svc = Service("hf")
        self.run_with(svc)
        sent = svc.received[0]["inputs"]
        self.assertNotIn(PHONE, sent)
        self.assertEqual(len(sent), len(TEXT))
        m = next(m for m in self.base if m.type == "PHONE")
        self.assertEqual(sent[m.start:m.end], rm.FILLER * (m.end - m.start))
        self.assertEqual(sent[:m.start] + sent[m.end:], TEXT[:m.start] + TEXT[m.end:])

    def test_a_span_over_a_deterministic_finding_is_dropped_and_the_finding_stays(self):
        m = next(m for m in self.base if m.type == "PHONE")

        def over(text):
            return [{"entity_group": "PER", "start": m.start - 3, "end": m.start + 4, "score": 0.9}]
        r = self.run_with(Service("hf", answer=over))
        self.assertEqual(r.findings, self.base)
        self.assertEqual((r.remote.state, r.remote.added), ("ok", 0))
        # a span of letters only over a finding: a span with a digit is no person anyway (#93), so the number above
        # alone no longer shows the overlap rule
        text = "Write to mara.feld" + "@" + "nordwerk.internal today."
        base = self.det.findings(text, channel="tool")
        mail = next(m for m in base if m.type == "EMAIL")

        def over_mail(t):
            return [{"entity_group": "PER", "start": mail.start - 3, "end": mail.start + 4, "score": 0.9}]
        svc = Service("hf", answer=over_mail)
        self.addCleanup(svc.close)
        r = self.det.findings_with(text, channel="tool", remote=rm.RemoteDetector(svc.url, format=svc.fmt))
        self.assertEqual(r.findings, base)
        self.assertEqual((r.remote.state, r.remote.added), ("ok", 0))

    def test_a_slow_service_leaves_the_rules_result_and_says_timeout(self):
        t = time.monotonic()
        r = self.run_with(Service("hf", delay=1.0), timeout=0.2)
        self.assertLess(time.monotonic() - t, 0.9)
        self.assertEqual(r.findings, self.base)
        self.assertEqual((r.remote.state, r.remote.reason), ("unavailable", "timeout"))

    def test_a_service_that_dribbles_its_answer_cannot_hold_the_caller(self):
        t = time.monotonic()
        r = self.run_with(Service("hf", drip=0.05), timeout=0.3)
        self.assertLess(time.monotonic() - t, 0.8, "the deadline holds over the whole answer, not per read")
        self.assertEqual((r.findings, r.remote.state, r.remote.reason), (self.base, "unavailable", "timeout"))

    def test_a_name_that_resolves_off_this_computer_is_refused_before_a_byte_is_sent(self):
        svc = Service("hf")
        self.addCleanup(svc.close)
        port = svc.server.server_address[1]
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))]
        with mock.patch.object(rm.socket, "getaddrinfo", return_value=fake), \
                mock.patch.object(rm.socket.socket, "connect") as connect:
            r = self.det.findings_with(TEXT, channel="tool", remote=rm.RemoteDetector(f"http://localhost:{port}/"))
        self.assertEqual((r.findings, r.remote.reason, svc.received), (self.base, "policy", []))
        connect.assert_not_called()
        real = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        with mock.patch.object(rm.socket, "getaddrinfo", return_value=real):
            r = self.det.findings_with(TEXT, channel="tool", remote=rm.RemoteDetector(f"http://localhost:{port}/"))
        self.assertEqual(r.remote.state, "ok", "premise: the same name on loopback is asked")

    def test_an_answer_with_more_items_than_words_is_refused_at_once(self):
        def flood(text):
            return [{"entity_group": "PER", "start": 0, "end": 1, "score": 0.5}] * 5000
        t = time.monotonic()
        r = self.run_with(Service("hf", answer=flood), timeout=5)
        self.assertLess(time.monotonic() - t, 2.0)
        self.assertEqual((r.findings, r.remote.reason), (self.base, "answer"))

    def test_a_stored_value_inside_a_finding_still_covers_the_whole_finding(self):
        text = "-" * 71 + " end"          # no letters: the span is not widened, the merge alone decides
        ner = rm.RemoteDetector("http://127.0.0.1:1/")
        ner._request = lambda body, deadline, gate=None: json.dumps(
            [{"entity_group": "PER", "start": 65, "end": 70, "score": 0.9}]).encode()
        spans, status = ner.ask(text, [(56, 71), (60, 63)])
        self.assertEqual((spans, status.state), ([], "ok"))

    def test_a_costly_answer_ends_at_the_deadline_too(self):
        text = "a" * 20000
        ner = rm.RemoteDetector("http://127.0.0.1:1/", timeout=0.05, max_chars=10 ** 6)
        ner._request = lambda body, deadline, gate=None: json.dumps(
            [{"entity_group": "PER", "start": i, "end": i + 1, "score": 0.9} for i in range(0, 20000, 2)]).encode()
        t = time.monotonic()
        spans, status = ner.ask(text, [])
        self.assertLess(time.monotonic() - t, 1.0)
        self.assertIn(status.state, ("ok", "unavailable"))

    def test_the_fast_widening_is_the_plain_one(self):
        import random
        rnd = random.Random(7)
        for _ in range(200):
            text = "".join(rnd.choice("ab  1.\n_é") for _ in range(rnd.randint(1, 40)))
            words = rm._Words(text)
            for _ in range(20):
                s = rnd.randint(0, len(text) - 1)
                e = rnd.randint(s + 1, len(text))
                plain = rm.whole_words(text, s, e)
                fast = words.widen(s, e)
                self.assertEqual(fast if fast[0] < fast[1] else "empty", plain if plain[0] < plain[1] else "empty",
                                 (text, s, e))

    def test_offsets_are_code_points(self):
        text = "\U0001f600\U0001f600 please ask " + NAME + " today"
        svc = Service("hf")
        self.addCleanup(svc.close)
        r = self.det.findings_with(text, channel="tool", remote=rm.RemoteDetector(svc.url))
        self.assertEqual([m.value for m in r.findings if m.score is not None], [NAME])

    def test_a_setting_it_cannot_use_is_refused_when_made(self):
        with self.assertRaises(ValueError):
            rm.RemoteDetector("http://127.0.0.1:abc/")
        for flag in ("false", 1, "yes", None):
            with self.subTest(allow_network=flag), self.assertRaises(ValueError):
                rm.RemoteDetector("https://ner.example.com/", allow_network=flag)
        for kw in ({"classes": {"PER": []}}, {"classes": {"PER": "name"}}, {"min_score": {"NAME": 2}},
                   {"min_score": {"NAME": "x"}}, {"timeout": 0}, {"timeout": float("nan")}, {"max_chars": 0},
                   {"max_chars": True}):
            with self.subTest(kw), self.assertRaises(ValueError):
                rm.RemoteDetector("http://127.0.0.1:1/", **kw)

    def test_white_space_alone_is_no_name(self):
        def blank(text):
            at = text.find(" about")
            return [{"entity_group": "PER", "start": at, "end": at + 1, "score": 0.9}]
        r = self.run_with(Service("hf", answer=blank))
        self.assertEqual((r.findings, r.remote.added), (self.base, 0))

    def test_a_dead_service_leaves_the_rules_result_and_says_refused(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        # Windows answers a closed port only after its SYN retries (about 2 s): a timeout of 5 s lets the refusal come
        r = self.det.findings_with(TEXT, channel="tool",
                                   remote=rm.RemoteDetector(f"http://127.0.0.1:{port}/", timeout=5))
        self.assertEqual(r.findings, self.base)
        self.assertEqual((r.remote.state, r.remote.reason), ("unavailable", "refused"))

    def test_a_service_that_took_the_connection_and_is_slow_says_timeout(self):
        s = Service("hf", delay=1.0)
        self.addCleanup(s.close)
        r = self.det.findings_with(TEXT, channel="tool", remote=rm.RemoteDetector(s.url, timeout=0.3))
        self.assertEqual((r.remote.state, r.remote.reason), ("unavailable", "timeout"))

    def test_nonsense_leaves_the_rules_result_and_says_answer(self):
        for name, answer in (("no json", lambda t: b"<html>"), ("no list", lambda t: {"x": 1}),
                             ("out of range", lambda t: [{"entity_group": "PER", "start": -5, "end": 10 ** 7,
                                                          "score": 1.0}]),
                             ("a wrong item beside a good one", lambda t: [
                                 {"entity_group": "PER", "start": t.find(NAME), "end": t.find(NAME) + len(NAME),
                                  "score": 0.9}, "x"]),
                             ("a score over 1", lambda t: [{"entity_group": "PER", "start": 0, "end": 3,
                                                            "score": 7}]),
                             ("a start as text beside a good item", lambda t: [
                                 {"entity_group": "PER", "start": t.find(NAME), "end": t.find(NAME) + len(NAME),
                                  "score": 0.9}, {"entity_group": "PER", "start": "3", "end": 9, "score": 0.9}])):
            with self.subTest(name):
                r = self.run_with(Service("hf", answer=answer))
                self.assertEqual(r.findings, self.base)
                self.assertEqual((r.remote.state, r.remote.reason), ("unavailable", "answer"))

    def test_an_http_error_leaves_the_rules_result(self):
        r = self.run_with(Service("hf", status=500))
        self.assertEqual(r.findings, self.base)
        self.assertEqual((r.remote.state, r.remote.reason), ("unavailable", "http"))

    def test_a_text_over_the_limit_is_not_sent_without_pieces(self):
        svc = Service("hf")
        r = self.run_with(svc, max_chars=10, pieces=False)
        self.assertEqual((r.findings, r.remote.state, svc.received), (self.base, "too_long", []))

    def test_a_deadline_that_has_passed_sends_nothing(self):
        # since 0.9.4 the deadline bounds the rules too: they raise ScanIncomplete, and the service is not asked
        svc = Service("hf")
        self.addCleanup(svc.close)
        with self.assertRaises(ScanIncomplete):
            self.det.findings_with(TEXT, channel="tool", remote=rm.RemoteDetector(svc.url),
                                   deadline=time.monotonic() - 1)
        self.assertEqual(svc.received, [])

    def test_a_request_that_starts_past_the_deadline_sends_nothing(self):
        # the rules ended in time and the deadline passed before the request: a timeout, nothing sent
        svc = Service("hf")
        self.addCleanup(svc.close)
        spans, status = rm.RemoteDetector(svc.url).ask(TEXT, [], time.monotonic() - 1)
        self.assertEqual((spans, status.reason, svc.received), ([], "timeout", []))

    def test_only_a_loopback_or_unix_address_without_allow_network(self):
        for url in ("http://127.0.0.1:1/", "http://localhost:1/", "http://[::1]:1/", "unix:/tmp/x.sock"):
            rm.RemoteDetector(url)
        for url in ("http://10.0.0.5:8000/", "https://ner.example.com/", "http://127.0.0.1.example.com/"):
            with self.subTest(url), self.assertRaises(ValueError):
                rm.RemoteDetector(url)
            rm.RemoteDetector(url, allow_network=True)
        for url in ("ftp://127.0.0.1/", "127.0.0.1:80", "http:///x"):
            with self.subTest(url), self.assertRaises(ValueError):
                rm.RemoteDetector(url, allow_network=True)

    def test_names_only_by_default_more_classes_and_a_least_score_by_choice(self):
        def two(text):
            at, city = text.find(NAME), text.find("build")
            return [{"entity_group": "PER", "start": at, "end": at + len(NAME), "score": 0.6},
                    {"entity_group": "LOC", "start": city, "end": city + 5, "score": 0.99}]
        r = self.run_with(Service("hf", answer=two))
        self.assertEqual([m.type for m in r.findings if m.score is not None], ["NAME"])
        r = self.run_with(Service("hf", answer=two), classes={"PER": "NAME", "LOC": "ADDRESS"},
                          min_score={"NAME": 0.7})
        self.assertEqual([m.type for m in r.findings if m.score is not None], ["ADDRESS"])

    def test_a_span_inside_a_word_is_widened_and_a_word_piece_label_is_read(self):
        def piece(text):
            at = text.find(NAME)
            return [{"entity": "B-PER", "start": at + 1, "end": at + 3, "score": 0.9},
                    {"entity": "I-PER", "start": at + 6, "end": at + 9, "score": 0.9}]
        r = self.run_with(Service("hf", answer=piece))
        self.assertEqual([m.value for m in r.findings if m.score is not None], ["Anna", "Kowalczyk"])

    @unittest.skipIf(not hasattr(socket, "AF_UNIX") or os.name == "nt", "a Unix socket")
    def test_a_unix_socket(self):
        d = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(lambda: os.path.exists(d + "/s") and os.unlink(d + "/s"))
        r = self.run_with(Service("hf", unix=d + "/s"))
        self.assertEqual([m.value for m in r.findings if m.score is not None], [NAME])

    def test_without_a_remote_detector_the_result_is_the_findings(self):
        r = self.det.findings_with(TEXT, channel="tool")
        self.assertEqual((r.findings, r.remote), (self.base, rm.OFF))

    def test_the_response_of_a_host_fits_the_schema_and_names_the_remote_detector(self):
        r = self.run_with(Service("hf"), model="d3@test")
        doc = contract.result_response(self.det, r)
        self.assertEqual(problems(doc, contract.json.loads(contract.SCHEMA.read_text())["$defs"]["response"]), [])
        self.assertEqual(doc["engine"]["remote"], {"format": "hf", "model": "d3@test", "state": "ok"})
        name = next(f for f in doc["findings"] if f["type"] == "NAME")
        self.assertEqual((name["score"], name["provenance"]["origin"], name["provenance"]["layer"]),
                         (0.98, "model", "model"))
        self.assertTrue(all("score" not in f for f in doc["findings"] if f["type"] != "NAME"))
        off = contract.result_response(self.det, self.det.findings_with(TEXT, channel="tool"))
        self.assertNotIn("remote", off["engine"])
        req = {"contract": contract.CONTRACT, "text": TEXT, "channel": "tool", "regions": ["generic"],
               "languages": ["en"], "path": ""}
        self.assertEqual(off["findings"], contract.detect(req)["findings"], "the same rows as the entry point")
        down = self.det.findings_with(TEXT, channel="tool", remote=rm.RemoteDetector("http://127.0.0.1:1/"))
        doc = contract.result_response(self.det, down)
        self.assertEqual(problems(doc, contract.json.loads(contract.SCHEMA.read_text())["$defs"]["response"]), [])
        self.assertEqual(doc["engine"]["remote"]["state"], "unavailable")

    def test_every_reason_of_an_unavailable_service_fits_the_schema(self):
        # a host that embeds the library serialises each reason: network and policy came with 0.8.7 (codex review)
        schema = contract.json.loads(contract.SCHEMA.read_text())["$defs"]["response"]
        base = self.det.findings_with(TEXT, channel="tool")
        for reason in ("timeout", "refused", "network", "policy", "unauthorized", "not_ours", "http", "answer"):
            with self.subTest(reason=reason):
                r = rm.Result(base.findings, rm.RemoteStatus("hf", "m", "unavailable", reason))
                self.assertEqual(problems(contract.result_response(self.det, r), schema), [])



class JsonEscapedTextTests(unittest.TestCase):
    """The name service reads a JSON-escaped text with its escapes as the characters they stand for, and each span
    comes back in the offsets of the original text, whole escapes included (#39: a calendar guest list arrived as
    `\r\nAlexander`, which the service read as the word nAlexander)."""
    FIRST = "Alexander " + "Demo"
    SECOND = "Oleg " + "Beispiel"
    THIRD = "Ren" + "\\u00e9 " + "Musterfrau"      # an escaped letter inside the name

    @staticmethod
    def tokenizer_names(*names):
        def answer(text):
            out = []
            for name in names:
                # a name glued to a letter is no word of its own, as a tokenizer reads `nAlexander`
                for m in re.finditer(r"(?<![A-Za-z])" + re.escape(name) + r"(?![A-Za-z])", text):
                    out.append({"entity_group": "PER", "start": m.start(), "end": m.end(), "score": 0.97})
            return out
        return answer

    def found(self, text, svc):
        self.addCleanup(svc.close)
        r = detector().findings_with(text, channel="tool", remote=rm.RemoteDetector(svc.url))
        return r, [text[m.start:m.end] for m in r.findings if m.kind.startswith("remote:")]

    def test_a_name_after_an_escaped_line_break_is_found_at_its_place_in_the_text(self):
        plain_third = "René Musterfrau"
        for crlf in ("\\r\\n", "\\\\r\\\\n", "\\n"):
            text = J(["Guests", crlf, "- organiser", crlf, self.FIRST, crlf, self.SECOND, crlf, self.THIRD, crlf,
                      "end"])
            svc = Service("hf", answer=self.tokenizer_names(self.FIRST, self.SECOND, plain_third))
            with self.subTest(crlf=crlf):
                r, names = self.found(text, svc)
                self.assertEqual(names, [self.FIRST, self.SECOND, self.THIRD])
                self.assertNotIn("\\", svc.received[-1]["inputs"])     # the service read the characters
                self.assertEqual(r.remote.state, "ok")

    def test_an_escaped_emoji_next_to_a_name_and_a_lone_surrogate_do_not_stop_the_request(self):
        # review of the branch: an emoji arrives as two \uXXXX escapes (a surrogate pair); as two lone surrogates the
        # body could not be encoded, and the whole result lost its name detection ("answer")
        emoji = "\\ud83d" + "\\ude00"
        for text, want in ((J(["Danke ", emoji, " ", self.FIRST, "\\n"]), [self.FIRST]),
                           (J(["x \\ud83d y\\n", self.FIRST, "\\n"]), [self.FIRST]),      # a lone high surrogate
                           (J(["\\ude00", "\\n", self.FIRST]), [self.FIRST])):         # a lone low surrogate
            svc = Service("hf", answer=self.tokenizer_names(self.FIRST))
            with self.subTest(text=text):
                r, names = self.found(text, svc)
                self.assertEqual((r.remote.state, names), ("ok", want))
        plain, starts, ends = rm.unescape_json("a " + emoji + " b")
        self.assertEqual(plain, "a \U0001F600 b")
        self.assertEqual(J(["a ", emoji, " b"])[starts[2]:ends[2]], emoji)   # one character for both escapes

    def test_a_finding_of_the_rules_inside_an_escaped_text_still_goes_out_as_filler(self):
        text = J(["Call\\n", self.FIRST, "\\nat ", PHONE, "\\n"])
        svc = Service("hf", answer=self.tokenizer_names(self.FIRST))
        _r, names = self.found(text, svc)
        self.assertEqual(names, [self.FIRST])
        sent = svc.received[-1]["inputs"]
        self.assertNotIn(PHONE, sent)
        self.assertIn(rm.FILLER * len(PHONE), sent)

    def test_the_map_covers_whole_escapes_and_a_text_without_one_is_sent_as_it_is(self):
        text = "a\\u00e9b\\\\nc"
        plain, starts, ends = rm.unescape_json(text)
        self.assertEqual(plain, "aéb\nc")
        self.assertEqual([text[a:b] for a, b in zip(starts, ends)], ["a", "\\u00e9", "b", "\\\\n", "c"])
        self.assertEqual(rm.unescape_json("no escape here"), ("no escape here", None, None))
        self.assertEqual(rm.unescape_json("a \\ b")[1], None)     # a backslash before no escape letter stays


class Scripted:
    """A fake service whose answers follow a script, one entry per POST: (status, body, headers, delay); past the
    script it finds each NAME in the piece it got. `received` keeps each request body. `by_text(inputs)`, when given,
    gives the entry of a request by its text instead: pieces in flight at once arrive in no fixed order (#105).
    `in_flight` and `most_at_once` count the requests the service holds at the same time."""

    def __init__(self, script=(), secret: str = "", answer=None, by_text=None):
        self.script, self.received, self.challenges, self.secret = list(script), [], [], secret
        self.answer, self.by_text = answer, by_text
        self.in_flight = self.most_at_once = 0
        self.lock = threading.Lock()
        svc = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - http.server API
                doc = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                with svc.lock:
                    n = len(svc.received)
                    svc.received.append(doc)
                    svc.in_flight += 1
                    svc.most_at_once = max(svc.most_at_once, svc.in_flight)
                try:
                    status, body, headers, delay = svc.by_text(doc["inputs"]) if svc.by_text else \
                        svc.script[n] if n < len(svc.script) else (200, None, {}, 0.0)
                    if delay:
                        time.sleep(delay)
                finally:
                    with svc.lock:
                        svc.in_flight -= 1
                if body is None and svc.answer is not None:
                    body = svc.answer(doc["inputs"])
                if body is None:
                    body = [{"entity_group": "PER", "start": m.start(), "end": m.end(), "score": 0.97}
                            for m in re.finditer(re.escape(NAME), doc["inputs"])]
                out = json.dumps(body).encode()
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                try:
                    self.wfile.write(out)
                except OSError:
                    pass

            def do_GET(self):  # noqa: N802 - http.server API
                import hashlib
                import hmac
                import urllib.parse
                nonce = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("challenge", [""])[0]
                svc.challenges.append(nonce)
                proof = hmac.new(svc.secret.encode(), ("health:" + nonce).encode(), hashlib.sha256).hexdigest()
                out = json.dumps({"status": "ok", "proof": proof}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


BUSY = (429, {"error": "busy", "retry_after": 0.2}, {}, 0.0)
SIZE = 1000                                   # max_chars of these tests: a core of at most 800, an overlap of 200


def dots(n: int) -> str:
    return "." * n                            # no letter, no space, no line break: the cut lands where a test puts it


class PiecesTests(unittest.TestCase):
    """A text longer than max_chars goes in pieces (#105): cut on the unescaped text at a line break or a space, with
    an overlap; a span belongs to the piece whose core holds its start; one deadline for the whole text; Retry-After
    once per piece for `busy`; the status says how far the text was checked."""

    def svc(self, script=(), secret: str = "") -> Scripted:
        s = Scripted(script, secret)
        self.addCleanup(s.close)
        return s

    def ask(self, svc, text, occupied=(), wait=3.0, kind=None, **kw):
        det = rm.RemoteDetector(svc.url, max_chars=SIZE, **kw)
        return det.ask(text, list(occupied), time.monotonic() + wait, kind=kind)

    def test_the_plan_cuts_at_a_line_break_then_a_space_and_every_piece_fits(self):
        text = J([dots(700), "\n", dots(50), " ", dots(1500)])
        plan = rm.plan_pieces(text, SIZE)
        self.assertEqual(plan[0][2], 701, "after the line break, not at the later space")
        self.assertEqual([c0 for _p, c0, _c1, _e in plan[1:]], [c1 for _p, _c0, c1, _e in plan[:-1]], "no gap")
        self.assertEqual((plan[0][1], plan[-1][2]), (0, len(text)))
        self.assertTrue(all(e - p <= SIZE and p == max(0, c0 - 200) for p, c0, _c1, e in plan))
        self.assertEqual(rm.plan_pieces(dots(SIZE), SIZE), [(0, 0, SIZE, SIZE)], "a text that fits is one piece")

    def test_a_name_exactly_on_a_cut_is_found_once_and_whole(self):
        # the space inside the name is the only one in the room of the first cut: the cut falls inside the name
        text = J([dots(780), NAME, dots(900)])
        plan = rm.plan_pieces(text, SIZE)
        at = text.index(NAME)
        self.assertTrue(at < plan[0][2] < at + len(NAME), "premise: the cut is inside the name")
        svc = self.svc()
        spans, status = self.ask(svc, text)
        self.assertEqual([(s, e) for s, e, _t, _sc in spans], [(at, at + len(NAME))], "once, whole")
        self.assertEqual(len(svc.received), len(plan))
        self.assertTrue(all(NAME in r["inputs"] for r in svc.received[:2]), "premise: both pieces read it whole")
        self.assertEqual((status.state, status.checked_to, status.total), ("ok", len(text), len(text)))

    def test_a_name_that_the_end_of_a_piece_cuts_belongs_to_the_next_piece_and_is_masked_whole(self):
        # the first piece ends after the given name: a model reads that word alone as a name. Kept first, it would
        # leave the surname of the next piece unmasked (Fable review of revision 3: _keep keeps the first span)
        first = NAME.split()[0]
        text = J([dots(700), "\n", dots(200 - len(first) - 1), NAME, dots(900)])
        plan = rm.plan_pieces(text, SIZE)
        at = text.index(NAME)
        self.assertEqual((plan[0][2], plan[0][3]), (701, at + len(first) + 1), "premise: piece 1 ends in the name")

        def answer(piece):
            spans = [{"entity_group": "PER", "start": m.start(), "end": m.end(), "score": 0.97}
                     for m in re.finditer(re.escape(NAME), piece)]
            if piece.endswith(first + " "):
                spans.append({"entity_group": "PER", "start": len(piece) - len(first) - 1, "end": len(piece) - 1,
                              "score": 0.9})
            return spans
        svc = Scripted(answer=answer)
        self.addCleanup(svc.close)
        spans, status = self.ask(svc, text)
        self.assertEqual(status.state, "ok")
        self.assertEqual([(s, e) for s, e, _t, _sc in spans], [(at, at + len(NAME))], "whole, from the next piece")

    def test_a_name_past_checked_to_is_not_reported_as_checked(self):
        text = J([dots(780), NAME, dots(400), NAME, dots(300)])
        first, second = text.index(NAME), text.rindex(NAME)
        plan = rm.plan_pieces(text, SIZE)
        self.assertEqual(len(plan), 2)
        svc = self.svc([(200, None, {}, 0.0), (200, None, {}, 3.0)])     # the second piece is too slow
        spans, status = self.ask(svc, text, wait=1.0)
        self.assertEqual((status.state, status.reason), ("partial", "timeout"))
        self.assertEqual((status.checked_to, status.total), (plan[0][2], len(text)))
        self.assertTrue(first < status.checked_to <= second)
        self.assertEqual([s for s, _e, _t, _sc in spans], [first], "the name of the unchecked rest is no span")
        self.assertTrue(all(s < status.checked_to for s, _e, _t, _sc in spans))

    def test_escapes_across_a_cut_are_cut_as_characters_and_map_back(self):
        line = "row of the export" + "\\r\\n"
        text = J([line * 40, NAME, "\\n", line * 40])
        plain, starts, _ends = rm.unescape_json(text)
        self.assertGreater(len(plain), SIZE)
        self.assertEqual(len(rm.plan_pieces(plain, SIZE)), 2)
        svc = self.svc([(200, None, {}, 0.0), (200, None, {}, 3.0)])      # the second piece is too slow
        spans, status = self.ask(svc, text, wait=1.0)
        self.assertTrue(all("\\" not in r["inputs"] and len(r["inputs"]) <= SIZE for r in svc.received))
        self.assertEqual([text[s:e] for s, e, _t, _sc in spans], [NAME])
        self.assertEqual(status.state, "partial")
        # checked_to is an offset of the original text, at a whole escape: the rest unescapes to the rest of plain
        cut = rm.plan_pieces(plain, SIZE)[0][2]
        self.assertEqual(text[starts[cut] - 4:starts[cut]], "\\r\\n", "premise: the cut follows an escaped break")
        self.assertEqual(status.checked_to, starts[cut])
        self.assertEqual(rm.unescape_json(text[status.checked_to:])[0], plain[cut:])

    def test_occupied_across_a_cut_goes_out_as_filler_in_both_pieces(self):
        text = J([dots(700), "\n", dots(900)])
        cut = rm.plan_pieces(text, SIZE)[0][2]
        occ = (cut - 30, cut + 30)
        plan = rm.plan_pieces(text, SIZE)
        # piece 2 starts 200 before the cut: a span at 205 lies on the occupied part, one at 300 past it
        on = {"entity_group": "PER", "start": 205, "end": 215, "score": 0.9}
        past = {"entity_group": "PER", "start": 300, "end": 310, "score": 0.9}
        svc = self.svc([(200, [], {}, 0.0), (200, [on, past], {}, 0.0)])
        spans, status = self.ask(svc, text, occupied=[occ])
        self.assertEqual(status.state, "ok")
        shared = 0
        for (p, _c0, _c1, e), req in zip(plan, svc.received):
            got = req["inputs"]
            self.assertEqual(len(got), e - p)
            inside = [got[j - p] for j in range(max(p, occ[0]), min(e, occ[1]))]
            if inside:
                shared += 1
                self.assertEqual(set(inside), {rm.FILLER}, "each piece gets its part as filler")
        self.assertEqual(shared, 2, "premise: the occupied span lies in two pieces")
        p2 = plan[1][0]
        self.assertEqual([(s, e) for s, e, _t, _sc in spans], [(p2 + 300, p2 + 310)],
                         "the span on the occupied part is dropped, the one past it kept")

    def test_a_retry_that_fits_the_deadline_is_made(self):
        svc = self.svc([BUSY])
        spans, status = self.ask(svc, f"ask {NAME} now", wait=0.6)
        self.assertEqual((status.state, len(spans), len(svc.received)), ("ok", 1, 2))

    def test_a_retry_that_does_not_fit_with_the_first_estimate_is_not_made(self):
        # the wait (0.2 s) fits, but the wait and the estimate of a first piece (1.5 x 60 ms per 1,000 characters,
        # 90 ms for 1,000) do not
        text = J([dots(495), NAME, dots(SIZE - 495 - len(NAME))])
        svc = self.svc([BUSY])
        spans, status = self.ask(svc, text, wait=0.25)
        self.assertEqual((status.state, status.reason, len(svc.received)), ("unavailable", "busy", 1))
        svc = self.svc([BUSY])
        spans, status = self.ask(svc, text, wait=0.45)
        self.assertEqual((status.state, len(spans), len(svc.received)), ("ok", 1, 2))

    def test_the_estimate_after_the_first_piece_is_its_measured_time(self):
        # the first piece took 0.4 s: a retry of 0.1 s does not fit 0.3 s more, though the first estimate would
        text = J([dots(700), "\n", dots(900)])
        busy = (429, {"error": "busy", "retry_after": 0.1}, {}, 0.0)
        svc = self.svc([(200, [], {}, 0.4), busy])
        _spans, status = self.ask(svc, text, wait=0.4 + 0.3, timeout=2.0)
        self.assertEqual((status.state, status.reason, len(svc.received)), ("partial", "busy", 2))

    def test_retry_after_comes_from_the_header_or_from_the_body(self):
        for name, script in (("header", (503, {"error": "busy"}, {"Retry-After": "0.1"}, 0.0)),
                             ("body", (429, {"error": "busy", "retry_after": 0.1}, {}, 0.0))):
            with self.subTest(name):
                svc = self.svc([script])
                spans, status = self.ask(svc, f"ask {NAME} now", wait=1.0)
                self.assertEqual((status.state, len(spans), len(svc.received)), ("ok", 1, 2))
        svc = self.svc([(503, {"error": "busy"}, {}, 0.0)])
        _spans, status = self.ask(svc, f"ask {NAME} now", wait=1.0)
        self.assertEqual((status.reason, len(svc.received)), ("busy", 1), "no Retry-After: no retry")

    def test_a_smaller_retry_after_in_the_body_wins_over_the_whole_seconds_of_the_header(self):
        # ai-gateway #2141: the header holds whole seconds (1), the body the queue's estimate (0.2). A retry after the
        # header's 1 s would not fit this 0.6 s deadline; after the body's 0.2 s it does
        both = (429, {"error": "busy", "retry_after": 0.2}, {"Retry-After": "1"}, 0.0)
        svc = self.svc([both])
        spans, status = self.ask(svc, f"ask {NAME} now", wait=0.6)
        self.assertEqual((status.state, len(spans), len(svc.received)), ("ok", 1, 2))
        # a larger body, a 0 and a body that is no number leave the header's 1 s: no retry fits 0.6 s
        for body in (5, 0, "soon", None):
            with self.subTest(body=body):
                svc = self.svc([(429, {"error": "busy", "retry_after": body}, {"Retry-After": "1"}, 0.0)])
                _spans, status = self.ask(svc, f"ask {NAME} now", wait=0.6)
                self.assertEqual((status.reason, len(svc.received)), ("busy", 1))
        # a tiny body waits at least RETRY_MIN_S: the wait the retry asks for, not the clock (Windows ticks in 15 ms)
        from unittest import mock
        from maisecrets.detection import remote
        real_sleep, waits = time.sleep, []
        svc = self.svc([(429, {"error": "busy", "retry_after": 0.001}, {}, 0.0)])
        with mock.patch.object(remote.time, "sleep", side_effect=lambda s: (waits.append(s), real_sleep(s))[1]):
            _spans, status = self.ask(svc, f"ask {NAME} now", wait=1.0)
        self.assertEqual(status.state, "ok")
        self.assertIn(remote.RETRY_MIN_S, waits)

    def test_no_piece_and_no_retry_after_rate_limited(self):
        text = J([dots(700), "\n", dots(700), "\n", dots(700)])
        self.assertGreaterEqual(len(rm.plan_pieces(text, SIZE)), 3)
        limited = (429, {"error": "rate_limited", "retry_after": 0.05}, {}, 0.0)
        svc = self.svc([(200, [], {}, 0.0), limited])
        _spans, status = self.ask(svc, text)
        self.assertEqual((status.state, status.reason, len(svc.received)), ("partial", "rate_limited", 2))
        self.assertEqual(status.checked_to, rm.plan_pieces(text, SIZE)[0][2])

    def test_the_secret_is_proven_once_per_text_not_per_piece(self):
        shared = "".join(("test", "-container-", "x" * 26))
        svc = self.svc(secret=shared)
        text = J([dots(700), "\n", dots(700), "\n", dots(700)])
        _spans, status = self.ask(svc, text, secret=shared)
        pieces = len(rm.plan_pieces(text, SIZE))
        self.assertGreaterEqual(pieces, 3)
        self.assertEqual((status.state, len(svc.received), len(svc.challenges)), ("ok", pieces, 1))

    def test_a_504_of_the_service_is_a_timeout(self):
        svc = self.svc([(504, {"error": "ner_timeout"}, {}, 0.0)])
        _spans, status = self.ask(svc, f"ask {NAME} now")
        self.assertEqual((status.state, status.reason), ("unavailable", "timeout"))

    def test_each_piece_waits_at_most_its_own_timeout_and_the_deadline_ends_the_text(self):
        # review H1: the deadline bounds the sum of the pieces; a piece never waits longer than `timeout`
        text = J([dots(700), "\n", dots(700), "\n", dots(700)])
        pieces = len(rm.plan_pieces(text, SIZE))
        svc = self.svc([(200, [], {}, 0.3)] * pieces)
        _spans, status = self.ask(svc, text, wait=3.0, timeout=0.6)
        self.assertEqual((status.state, len(svc.received)), ("ok", pieces), "together longer than one timeout")
        t = time.monotonic()
        svc = self.svc([(200, None, {}, 3.0)])            # a service that hangs
        _spans, status = self.ask(svc, f"ask {NAME} now", wait=3.0, timeout=0.2)
        self.assertLess(time.monotonic() - t, 1.0, "a short text waits its timeout, not the deadline")
        self.assertEqual((status.state, status.reason), ("unavailable", "timeout"))
        t = time.monotonic()
        svc = self.svc([(200, [], {}, 0.0), (200, None, {}, 3.0)])      # the second piece hangs
        _spans, status = self.ask(svc, text, wait=3.0, timeout=0.3)
        self.assertLess(time.monotonic() - t, 1.5, "a later piece waits its own timeout, not the deadline")
        self.assertEqual((status.state, status.reason), ("partial", "timeout"))
        svc = self.svc([(200, None, {}, 0.5)])
        _spans, status = self.ask(svc, f"ask {NAME} now", wait=0.2, timeout=2.0)
        self.assertEqual(status.reason, "timeout", "a deadline before the timeout ends the request")
        svc = self.svc([(200, None, {}, 0.5)])
        det = rm.RemoteDetector(svc.url, timeout=0.1)
        self.assertEqual(det.ask(f"ask {NAME} now", [])[1].reason, "timeout", "without a deadline: the timeout")

    def test_a_503_that_names_another_error_is_no_busy_slot_and_gets_no_retry(self):
        # gateway review G1: temporarily_unavailable (its store) with Retry-After 5 must not cost 5 s
        for error in ("temporarily_unavailable", "ner_unavailable"):
            with self.subTest(error):
                svc = self.svc([(503, {"error": error}, {"Retry-After": "0.1"}, 0.0)])
                t = time.monotonic()
                _spans, status = self.ask(svc, f"ask {NAME} now", wait=3.0, timeout=2.0)
                self.assertEqual((status.state, status.reason, len(svc.received)), ("unavailable", "unavailable", 1))
                self.assertLess(time.monotonic() - t, 0.5)
        svc = self.svc([(503, {"error": "temporarily_unavailable"}, {"Retry-After": "5"}, 0.0)])
        t = time.monotonic()
        _spans, status = self.ask(svc, f"ask {NAME} now", wait=8.0, timeout=2.0)
        self.assertLess(time.monotonic() - t, 1.0, "no wait of 5 s for an outage")
        self.assertNotEqual(status.reason, "busy")
        svc = self.svc([(503, {}, {"Retry-After": "0.1"}, 0.0)])       # an older gateway's busy slot: no error
        spans, status = self.ask(svc, f"ask {NAME} now", wait=2.0, timeout=1.0)
        self.assertEqual((status.state, len(svc.received)), ("ok", 2))

    def test_a_second_busy_of_a_piece_gets_no_second_retry(self):
        # review L5: two busy answers in a row with time to spare: one retry, two requests, the piece unchecked
        svc = self.svc([BUSY, BUSY])
        _spans, status = self.ask(svc, f"ask {NAME} now", wait=3.0, timeout=1.0)
        self.assertEqual((status.state, status.reason, len(svc.received)), ("unavailable", "busy", 2))

    def test_every_body_holds_at_most_max_chars_code_points(self):
        # gateway review G3: the gateway counts the code points of the decoded inputs; escapes and characters
        # outside the BMP (two escapes, one character) must not make a piece longer
        emoji = "\\ud83d" + "\\ude00"
        unit = J(["r\\u00e9sum\\u00e9 ", emoji, " line", "\\r\\n"])
        plain_unit = rm.unescape_json(unit)[0]
        text = unit * (SIZE // len(plain_unit))
        text += "x" * (SIZE + 1 - len(rm.unescape_json(text)[0]))
        plain = rm.unescape_json(text)[0]
        self.assertEqual(len(plain), SIZE + 1, "max_chars + 1 code points")
        self.assertLess(len(plain), len(text), "premise: the escapes make the text longer than its characters")
        self.assertTrue(any(ord(c) > 0xFFFF for c in plain), "premise: a character outside the BMP")
        svc = self.svc()
        _spans, status = self.ask(svc, text, wait=3.0, timeout=2.0)
        self.assertEqual(status.state, "ok")
        self.assertGreater(len(svc.received), 1)
        for r in svc.received:
            self.assertLessEqual(len(r["inputs"]), SIZE)

    def test_kind_goes_out_only_when_given_and_only_in_the_hf_format(self):
        svc = self.svc()
        self.ask(svc, "a text", kind="prompt")
        self.ask(svc, "a text")
        self.assertEqual([r.get("kind") for r in svc.received], ["prompt", None])
        self.assertEqual(sorted(svc.received[1]), ["inputs"], "no kind: the body of before")
        body = json.loads(rm.RemoteDetector(svc.url, format="presidio")._body("t", "result"))
        self.assertNotIn("kind", body)

    def test_partial_and_its_offsets_fit_the_schema(self):
        schema = contract.json.loads(contract.SCHEMA.read_text())["$defs"]["response"]
        det = detector()
        base = det.findings_with(TEXT, channel="tool")
        r = rm.Result(base.findings, rm.RemoteStatus("hf", "m", "partial", "busy", 0, 1.0, 10, 40))
        doc = contract.result_response(det, r)
        self.assertEqual(problems(doc, schema), [])
        self.assertEqual((doc["engine"]["remote"]["checked_to"], doc["engine"]["remote"]["total"]), (10, 40))
        self.assertEqual(rm.RemoteStatus().checked_to, 0, "an older caller's status keeps working")



def lines_of(n: int) -> str:
    """n lines of 500 characters, each with its number at the start (L0, L1, …): one piece per line at SIZE."""
    return J(f"L{i}" + dots(497) + "\n" for i in range(n))


def piece_of(text: str) -> int:
    """The number of the piece a request holds: its first line marker (each piece reads the next line's start)."""
    return min(int(m) for m in re.findall(r"L(\d)", text))


class ParallelPiecesTests(unittest.TestCase):
    """#105: up to `parallel` pieces of one text in flight at once. They start in order; checked_to stays the end of
    the pieces checked without a gap; the spans are kept in the order of the pieces, whatever order they end in."""

    def svc(self, by_text) -> Scripted:
        s = Scripted(by_text=by_text)
        self.addCleanup(s.close)
        return s

    def ask(self, svc, text, wait=3.0, parallel=3, **kw):
        det = rm.RemoteDetector(svc.url, max_chars=SIZE, parallel=parallel, **kw)
        return det.ask(text, [], time.monotonic() + wait)

    def test_five_pieces_take_the_time_of_two_and_at_most_three_are_in_flight(self):
        text = lines_of(5)
        self.assertEqual(len(rm.plan_pieces(text, SIZE)), 5, "premise: five pieces")
        svc = self.svc(lambda t: (200, [], {}, 0.4))
        t = time.monotonic()
        _spans, status = self.ask(svc, text, wait=3.0, timeout=2.0)
        took = time.monotonic() - t
        self.assertEqual((status.state, status.checked_to, len(svc.received)), ("ok", len(text), 5))
        self.assertLess(took, 2 * 0.4 + 0.35, "two rounds of 0.4 s, not five")
        self.assertEqual(svc.most_at_once, 3, "at most three requests of one text at once")
        self.assertEqual(sorted(piece_of(r["inputs"]) for r in svc.received), [0, 1, 2, 3, 4])
        svc = self.svc(lambda t: (200, [], {}, 0.2))
        _spans, status = self.ask(svc, text, parallel=2, timeout=2.0)
        self.assertEqual((status.state, svc.most_at_once), ("ok", 2), "parallel=2: two at once")
        svc = self.svc(lambda t: (200, [], {}, 0.1))
        _spans, status = self.ask(svc, text, parallel=1, timeout=2.0)
        self.assertEqual((status.state, svc.most_at_once), ("ok", 1), "parallel=1: one after the other")
        self.assertEqual([piece_of(r["inputs"]) for r in svc.received], [0, 1, 2, 3, 4], "in order")

    def test_a_later_piece_that_ends_first_does_not_move_checked_to(self):
        text = lines_of(3)
        plan = rm.plan_pieces(text, SIZE)
        for slow, state, checked_to in ((0, "unavailable", 0), (1, "partial", plan[0][2])):
            with self.subTest(slow=slow):
                # the slow piece outlasts the deadline by 2 s, the fast ones get 2 s of margin on a loaded runner
                svc = self.svc(lambda t, slow=slow: (200, None, {}, 4.0 if piece_of(t) == slow else 0.0))
                spans, status = self.ask(svc, text, wait=2.0, timeout=4.0)
                self.assertEqual(len(svc.received), 3, "premise: all three were sent at once")
                self.assertEqual((status.state, status.reason, status.checked_to), (state, "timeout", checked_to))
                self.assertTrue(all(s < status.checked_to for s, _e, _t, _sc in spans))

    def test_spans_are_kept_in_the_order_of_the_pieces_when_they_end_out_of_order(self):
        # the cut falls on the space inside the name: the first piece reads it whole, the second piece reads it
        # whole too and (a model at a cut) gives the surname alone, which starts in its own core. One after the
        # other, the whole name of the first piece is kept and the surname drops. Here the second piece ends first:
        # kept in the order they end, the surname would win and the given name would stay in clear text
        text = J([dots(780), NAME, dots(900)])
        plan = rm.plan_pieces(text, SIZE)
        at, sur = text.index(NAME), text.index(NAME) + NAME.rindex(" ") + 1
        self.assertEqual(plan[0][2], sur, "premise: the second core starts at the surname")
        surname = NAME[NAME.rindex(" ") + 1:]

        def answer(t):
            spans = [{"entity_group": "PER", "start": m.start(), "end": m.end(), "score": 0.97}
                     for m in re.finditer(re.escape(NAME), t)]
            if NAME in t and not t.startswith(dots(700)):    # every later piece: the surname alone, too
                i = t.index(NAME) + NAME.rindex(" ") + 1
                spans.append({"entity_group": "PER", "start": i, "end": i + len(surname), "score": 0.9})
            return (200, spans, {}, 0.5 if t.startswith(dots(700)) else 0.0)
        svc = self.svc(answer)
        spans, status = self.ask(svc, text, timeout=2.0)
        self.assertEqual(status.state, "ok")
        self.assertEqual([(s, e) for s, e, _t, _sc in spans], [(at, at + len(NAME))], "once, whole")

    def test_busy_with_retry_after_on_one_piece_is_sent_again_once(self):
        text = lines_of(4)
        seen: dict = {}

        def answer(t):
            n = piece_of(t)
            seen[n] = seen.get(n, 0) + 1
            if n == 2 and seen[n] == 1:
                return (429, {"error": "busy", "retry_after": 0.2}, {}, 0.0)
            return (200, [], {}, 0.1)
        svc = self.svc(answer)
        _spans, status = self.ask(svc, text, timeout=2.0)
        self.assertEqual((status.state, status.checked_to), ("ok", len(text)))
        self.assertEqual(seen, {0: 1, 1: 1, 2: 2, 3: 1}, "the busy piece twice, every other once")
        seen.clear()
        svc = self.svc(lambda t: (429, {"error": "busy", "retry_after": 0.1}, {}, 0.0) if piece_of(t) == 1 else
                       (200, [], {}, 0.0))
        _spans, status = self.ask(svc, text, timeout=2.0)
        self.assertEqual((status.state, status.reason, status.checked_to),
                         ("partial", "busy", rm.plan_pieces(text, SIZE)[0][2]), "a second busy: no second retry")
        self.assertEqual(sum(piece_of(r["inputs"]) == 1 for r in svc.received), 2)

    def test_rate_limited_starts_no_further_piece(self):
        text = lines_of(5)
        plan = rm.plan_pieces(text, SIZE)
        limited = (429, {"error": "rate_limited", "retry_after": 0.05}, {}, 0.0)
        svc = self.svc(lambda t: limited if piece_of(t) == 1 else (200, [], {}, 0.3))
        det = rm.RemoteDetector(svc.url, max_chars=SIZE, parallel=3, timeout=2.0)
        begun: list = []                             # each piece that starts builds its body first
        real = det._body
        det._body = lambda text, kind=None: (begun.append(piece_of(text)), real(text, kind))[1]
        _spans, status = det.ask(text, [], time.monotonic() + 3.0)
        time.sleep(0.3)                              # a piece started late would arrive now
        self.assertEqual(sorted(piece_of(r["inputs"]) for r in svc.received), [0, 1, 2],
                         "the three in flight; no piece after rate_limited")
        self.assertEqual(sorted(begun), [0, 1, 2], "no piece even starts after rate_limited")
        self.assertEqual((status.state, status.reason, status.checked_to), ("partial", "rate_limited", plan[0][2]))

    def test_the_deadline_stops_the_pieces_in_flight_and_in_the_queue(self):
        text = lines_of(5)
        plan = rm.plan_pieces(text, SIZE)
        # margins for a loaded runner: piece 0 has 1.5 s to end, the others end 1.5 s after the deadline
        svc = self.svc(lambda t: (200, None, {}, 0.0 if piece_of(t) == 0 else 3.0))
        t = time.monotonic()
        _spans, status = self.ask(svc, text, wait=1.5, timeout=4.0)
        self.assertLess(time.monotonic() - t, 2.5, "ask() leaves at the deadline, not with the pieces in flight")
        self.assertEqual((status.state, status.reason, status.checked_to), ("partial", "timeout", plan[0][2]))
        time.sleep(2.0)                              # the pieces in flight end; nothing may start after them
        self.assertEqual(sorted(piece_of(r["inputs"]) for r in svc.received), [0, 1, 2, 3],
                         "the fifth piece waited in the queue and was never sent")
        # a request that ends after the deadline all the same (a late parse, a slow thread): the pieces in flight
        # end without an error, and still no piece of the queue starts after ask() gave up
        det = rm.RemoteDetector("http://127.0.0.1:1/", max_chars=SIZE, parallel=3, timeout=2.0)
        asked: list = []

        def late(body, deadline, gate=None):
            n = piece_of(json.loads(body)["inputs"])
            asked.append(n)
            # after the deadline (1.5 s), before the text's thread gives up (1 s later): a piece of the queue that
            # started now would show
            time.sleep(0.0 if n == 0 else 2.0)
            return b"[]"
        det._request = late
        begun: list = []                             # each piece that starts builds its body first
        real = det._body
        det._body = lambda t, kind=None: (begun.append(piece_of(t)), real(t, kind))[1]
        _spans, status = det.ask(text, [], time.monotonic() + 1.5)
        self.assertEqual((status.state, status.checked_to), ("partial", plan[0][2]))
        time.sleep(1.5)
        self.assertEqual(sorted(asked), [0, 1, 2, 3], "no request after the deadline")
        self.assertEqual(sorted(begun), [0, 1, 2, 3], "no piece starts after the deadline")

    def test_a_piece_behind_a_failed_one_sends_no_further_request(self):
        # piece 2 waits for its Retry-After while piece 1 fails with rate_limited: it does not send again. Piece 0,
        # in front of the failed one, still ends and is checked
        text = lines_of(4)
        plan = rm.plan_pieces(text, SIZE)
        seen: dict = {}

        def answer(t):
            n = piece_of(t)
            seen[n] = seen.get(n, 0) + 1
            if n == 1:
                return (429, {"error": "rate_limited", "retry_after": 30}, {}, 0.1)
            if n == 2 and seen[n] == 1:
                return (429, {"error": "busy", "retry_after": 0.3}, {}, 0.0)
            return (200, [], {}, 0.6 if n == 0 else 0.0)
        svc = self.svc(answer)
        _spans, status = self.ask(svc, text, wait=3.0, timeout=2.0)
        time.sleep(0.4)                              # a retry of piece 2 would arrive by now
        self.assertEqual((status.state, status.reason, status.checked_to), ("partial", "rate_limited", plan[0][2]))
        self.assertEqual(seen, {0: 1, 1: 1, 2: 1}, "piece 2 sent once, piece 3 never")

    def test_a_request_that_hangs_past_its_cap_does_not_hold_the_text_thread(self):
        # a request that ignores its deadline (a name lookup that hangs): the thread of ask() ends one second after
        # the deadline, not when the request ends
        text = lines_of(4)
        det = rm.RemoteDetector("http://127.0.0.1:1/", max_chars=SIZE, parallel=3, timeout=2.0)

        def hang(body, deadline, gate=None):
            time.sleep(0.0 if piece_of(json.loads(body)["inputs"]) == 0 else 4.0)
            return b"[]"
        det._request = hang
        before = {t for t in threading.enumerate() if t.name == "maisecrets-remote"}
        _spans, status = det.ask(text, [], time.monotonic() + 0.4)
        mine = [t for t in threading.enumerate() if t.name == "maisecrets-remote" and t not in before]
        self.assertEqual((status.state, status.reason), ("partial", "timeout"))
        self.assertEqual(len(mine), 1, "premise: the thread of this text runs on after ask() returned")
        mine[0].join(2.0)
        self.assertFalse(mine[0].is_alive(), "it ended about one second after the deadline")

    def test_a_piece_that_waits_in_the_queue_of_the_service_waits_to_the_deadline(self):
        # netcup, 85fa9339: three pieces at once queue in the container; the third answer comes after one piece's
        # timeout, but well before the hook's deadline. With pieces at once it is waited for, so the text is checked
        # whole; one after the other each request still waits only `timeout`
        text = lines_of(3)
        for parallel, state in ((3, "ok"), (1, "partial")):
            with self.subTest(parallel=parallel):
                arrived = {"n": 0}
                lock = threading.Lock()

                def answer(t):
                    with lock:
                        arrived["n"] += 1
                        nth = arrived["n"]
                    return (200, [], {}, 0.6 if nth == 3 else 0.05)
                svc = self.svc(answer)
                _spans, status = self.ask(svc, text, wait=2.0, parallel=parallel, timeout=0.3)
                self.assertEqual(len(svc.received), 3)
                self.assertEqual(status.state, state, status)
                if state == "ok":
                    self.assertEqual(status.checked_to, len(text), "the whole text was checked")
                else:
                    self.assertEqual(status.reason, "timeout")

    def test_a_text_of_one_piece_is_asked_in_the_thread_of_ask_as_before(self):
        svc = self.svc(lambda t: (200, None, {}, 0.0))
        det = rm.RemoteDetector(svc.url, max_chars=SIZE, parallel=3)
        names: list = []
        real = det._request
        det._request = lambda body, deadline, gate=None: (names.append(threading.current_thread().name),
                                                          real(body, deadline, gate))[1]
        spans, status = det.ask(f"ask {NAME} now", [], time.monotonic() + 2.0)
        self.assertEqual((status.state, len(spans), names), ("ok", 1, ["maisecrets-remote"]))

    def test_parallel_is_a_whole_number_from_1_to_the_maximum(self):
        self.assertEqual(rm.RemoteDetector("http://127.0.0.1:1/").parallel, 1, "one after the other by default")
        for bad in (0, rm.PARALLEL_MAX + 1, True, 2.0, "2", None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    rm.RemoteDetector("http://127.0.0.1:1/", parallel=bad)


if __name__ == "__main__":
    unittest.main()
