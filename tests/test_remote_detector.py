"""The remote detector (maisecrets/detection/remote.py): a named-entity service the library asks after its rules. Each
test runs a fake service on a loopback port (or a Unix socket) that answers in one wire format, slowly, not at all
or with nonsense, and checks the promises: the service only adds, a failing service leaves the deterministic result
as it is and the status says why, the service never sees a deterministic finding, and no text leaves the computer
unless the caller allows it."""
from __future__ import annotations

import json
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

from maisecrets.detection import NO_REFERENCES, NO_SOURCES, Active, Detector, Host, contract  # noqa: E402
from maisecrets.detection import remote as rm  # noqa: E402
from test_detection_entry_point import problems  # noqa: E402

NAME = "Anna Kowalczyk"                       # a name no deterministic rule takes
PHONE = "+49 171 " + "4829173"                # a finding of the rules (the number of docs/DETECTION.md)
TEXT = f"Please ask {NAME} about the build; call her at {PHONE} today."


def detector() -> Detector:
    return Detector(regions=Active(regions=["generic"], languages=["en"], source="test"), sources=NO_SOURCES,
                    references=NO_REFERENCES, host=Host(user="", year=2026))


class Service:
    """A fake service. `answer(text)` returns the JSON it sends; `received` keeps each request body."""

    def __init__(self, fmt: str = "hf", answer=None, delay: float = 0.0, status: int = 200, unix: str = "",
                 drip: float = 0.0):
        self.fmt, self.delay, self.status, self.received, self.paths = fmt, delay, status, [], []
        self.drip = drip            # seconds between the bytes of the body: a service that dribbles its answer
        self.answer = answer or self.names
        svc = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - http.server API
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                svc.received.append(json.loads(body))
                svc.paths.append(self.path)
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


class RemoteDetectorTests(unittest.TestCase):
    def setUp(self):
        self.det = detector()
        self.base = self.det.findings(TEXT, channel="tool")
        self.assertTrue(any(m.type == "PHONE" for m in self.base), "premise: the rules find the number")
        self.assertFalse(any(m.type == "NAME" for m in self.base), "premise: the rules leave the name")

    def run_with(self, svc: Service, **kw) -> rm.Result:
        self.addCleanup(svc.close)
        return self.det.findings_with(TEXT, channel="tool", remote=rm.RemoteDetector(svc.url, format=svc.fmt, **kw))

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
        self.assertEqual((r.findings, r.remote.reason, svc.received), (self.base, "refused", []))
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
        ner._request = lambda body, deadline: json.dumps(
            [{"entity_group": "PER", "start": 65, "end": 70, "score": 0.9}]).encode()
        spans, status = ner.ask(text, [(56, 71), (60, 63)])
        self.assertEqual((spans, status.state), ([], "ok"))

    def test_a_costly_answer_ends_at_the_deadline_too(self):
        text = "a" * 20000
        ner = rm.RemoteDetector("http://127.0.0.1:1/", timeout=0.05, max_chars=10 ** 6)
        ner._request = lambda body, deadline: json.dumps(
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

    def test_a_text_over_the_limit_is_not_sent(self):
        svc = Service("hf")
        r = self.run_with(svc, max_chars=10)
        self.assertEqual((r.findings, r.remote.state, svc.received), (self.base, "too_long", []))

    def test_a_deadline_that_has_passed_sends_nothing(self):
        svc = Service("hf")
        self.addCleanup(svc.close)
        r = self.det.findings_with(TEXT, channel="tool", remote=rm.RemoteDetector(svc.url),
                                   deadline=time.monotonic() - 1)
        self.assertEqual((r.findings, r.remote.reason, svc.received), (self.base, "timeout", []))

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


if __name__ == "__main__":
    unittest.main()
