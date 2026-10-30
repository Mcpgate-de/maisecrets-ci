"""examples/ner_service.py binds 127.0.0.1 unless --host names another address (gateway request, 2026-10-30: in a
container, a published port cannot reach a service on 127.0.0.1). No model is loaded: a stub finder answers.

Run: python3 -m unittest tests.test_ner_service -v
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

_spec = importlib.util.spec_from_file_location("ner_service", ROOT / "examples" / "ner_service.py")
ner_service = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ner_service)


def handler():
    return ner_service.make_handler(lambda text: [], {"model": "stub"})


class HostTests(unittest.TestCase):
    def serve(self, **kw):
        server = ner_service.make_server(handler(), port=0, **kw)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.handle_request, daemon=True).start()
        return server

    def test_the_default_binds_the_loopback_address(self):
        self.assertEqual(self.serve().server_address[0], "127.0.0.1")

    def test_host_binds_the_given_address_and_answers(self):
        server = self.serve(host="0.0.0.0")
        self.assertEqual(server.server_address[0], "0.0.0.0")
        port = server.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/info", timeout=5) as r:
            self.assertEqual(json.load(r)["model"], "stub")

    def test_a_unix_socket_takes_no_host(self):
        with tempfile.TemporaryDirectory() as d, redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            ner_service.main([d, "--unix", os.path.join(d, "s.sock"), "--host", "0.0.0.0"])


if __name__ == "__main__":
    unittest.main()
