"""The load line of /maisecrets:ner from GET /metrics of mcpgate/ner (ai-gateway #1869), against a fake sidecar that
answers the JSON shape of the service, an older one without /metrics, and one that wants a token. No text is sent.

Run: python3 -m unittest tests.test_ner_metrics -v
"""
from __future__ import annotations

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp home, never the real one

from maisecrets import ner_metrics  # noqa: E402


class Sidecar:
    """GET /metrics as mcpgate/ner answers it: each call moves the counters as one busy worker of four would."""

    def __init__(self, mode: str = "json"):
        self.mode, self.calls, self.accept = mode, 0, []
        self.want = ner_metrics.bearer_of("testsecret-" + "m" * 24)
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.accept.append(self.headers.get("Accept"))
                if self.path != "/metrics" or outer.mode == "old":
                    return self._send(404, b"not found")
                if outer.mode == "token":
                    return self._send(401, b"{}")
                if outer.mode == "secret" and self.headers.get("Authorization") != "Bearer " + outer.want:
                    return self._send(401, b"{}")
                outer.calls += 1
                n = outer.calls
                doc = {"ner": {"workers": 4, "busy_workers": 1, "waiting_requests": 2 if outer.mode == "busy" else 0,
                               "worker_busy_seconds_total": 10.0 + n * 1.0, "chars_total": 1000 * n,
                               "requests_total": {"ok": n}},
                       "cgroup": {"cpu_usage_seconds_total": 50.0 + n * 2.0, "cpu_limit_cores": 4,
                                  "cpu_periods_total": 100 * n, "cpu_throttled_periods_total": 10 * n,
                                  "memory_bytes": 600 * 2**20, "memory_limit_bytes": 1536 * 2**20},
                       "info": {"model": "test-model"}}
                if outer.mode == "text":
                    return self._send(200, b"# HELP ner_workers\nner_workers 4\n")
                self._send(200, json.dumps(doc).encode())

            def _send(self, code, body):
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class LoadLineTests(unittest.TestCase):
    def side(self, mode: str = "json") -> Sidecar:
        s = Sidecar(mode)
        self.addCleanup(s.close)
        return s

    def test_two_samples_give_the_share_in_use_cpu_throttling_and_memory(self):
        s = self.side()
        line = ner_metrics.load_line(s.url, gap=0.5)
        # one busy-second per sample and 0.5 s apart over 4 workers: 50 %; 2 CPU-seconds over 0.5 s and 4 cores: 100 %
        import re
        used = int(re.search(r"4 workers, (\d+) % in use", line).group(1))
        # 1 busy-second per sample over 4 workers: 50 % at a gap of 0.5 s, less when the samples lie further apart
        self.assertTrue(20 <= used <= 50, line)
        self.assertIn("0 waiting", line)
        self.assertIn("throttled 10 %", line)
        self.assertIn("memory 600 of 1536 MB", line)
        self.assertNotIn("saturated", line)
        self.assertEqual(s.accept, ["application/json"] * 2, "the JSON form: no parser of the text format")

    def test_waiting_requests_read_as_saturated(self):
        line = ner_metrics.load_line(self.side("busy").url, gap=0.1)
        self.assertIn("2 waiting", line)
        self.assertTrue(line.endswith("(saturated: requests wait for a worker)"), line)

    def test_a_service_without_metrics_or_with_a_token_or_text_only_gives_no_load_data(self):
        for mode, why in (("old", "has no /metrics"), ("token", "wants a metrics token"),
                          ("text", "no answer it can read")):
            with self.subTest(mode=mode):
                line = ner_metrics.load_line(self.side(mode).url, gap=0.1)
                self.assertTrue(line.startswith("load: no load data ("), line)
                self.assertIn(why, line)
        self.assertIn("no load data", ner_metrics.load_line("http://127.0.0.1:9", gap=0.1))

    def test_a_container_with_a_secret_gets_the_metrics_bearer_not_the_text_bearer(self):
        import hashlib
        import hmac
        secret = "testsecret-" + "m" * 24
        s = self.side("secret")
        self.assertIn("4 workers", ner_metrics.load_line(s.url, gap=0.1, bearer=ner_metrics.bearer_of(secret)))
        text_bearer = hmac.new(secret.encode(), b"bearer", hashlib.sha256).hexdigest()
        self.assertNotEqual(ner_metrics.bearer_of(secret), text_bearer)
        self.assertIn("wants a metrics token", ner_metrics.load_line(s.url, gap=0.1, bearer=text_bearer))

    def test_a_server_that_dribbles_ends_at_the_deadline(self):
        import socket
        import time as _t
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        self.addCleanup(srv.close)

        def dribble():
            c, _ = srv.accept()
            c.recv(4096)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
            for _ in range(40):
                try:
                    c.sendall(b"{")
                except OSError:
                    return
                _t.sleep(0.3)
            c.close()
        threading.Thread(target=dribble, daemon=True).start()
        t0 = _t.monotonic()
        doc, why = ner_metrics.sample(f"http://127.0.0.1:{srv.getsockname()[1]}", timeout=1.0)
        self.assertLess(_t.monotonic() - t0, 3.0)
        self.assertIsNone(doc)
        self.assertIn("in time", why)

    def test_a_counter_that_falls_or_is_no_number_is_left_out(self):
        before = {"ner": {"workers": 4, "worker_busy_seconds_total": 9.0}, "cgroup": {"cpu_limit_cores": "4"}}
        after = {"ner": {"workers": 4, "worker_busy_seconds_total": 1.0, "waiting_requests": True}}
        self.assertEqual(ner_metrics.load(before, after, 1.0), {"workers": 4})


if __name__ == "__main__":
    unittest.main()
