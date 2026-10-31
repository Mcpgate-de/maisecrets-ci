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
import urllib.error
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
    return ner_service.make_handler(lambda text, labels: [], {"model": "stub"})


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


class LabelTests(unittest.TestCase):
    """The multi-label contract (gateway request, 2026-10-31): without "parameters" PER only, as before; with
    "parameters": {"labels": [...]} the spans of those types; a label /info does not list is a 400, never a part."""

    def setUp(self):
        self.asked = []

        def find(text, labels):
            self.asked.append(labels)
            return [x for x in [(0, 5, 0.9, "PER"), (9, 13, 0.8, "ORG")] if x[3] in labels]
        server = ner_service.make_server(
            ner_service.make_handler(find, {"model": "stub", "labels": ["LOC", "ORG", "PER"]}), port=0)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.url = f"http://127.0.0.1:{server.server_address[1]}/"

    def post(self, doc):
        req = urllib.request.Request(self.url, json.dumps(doc).encode(), {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def test_a_request_without_parameters_asks_for_persons_only(self):
        status, spans = self.post({"inputs": "Maria at Acme"})
        self.assertEqual((status, self.asked), (200, [("PER",)]))
        self.assertEqual([s["entity_group"] for s in spans], ["PER"])

    def test_labels_ask_for_those_types_and_each_span_names_its_type(self):
        status, spans = self.post({"inputs": "Maria at Acme", "parameters": {"labels": ["PER", "ORG", "PER"]}})
        self.assertEqual((status, self.asked), (200, [("PER", "ORG")]))
        self.assertEqual([(s["entity_group"], s["word"]) for s in spans], [("PER", "Maria"), ("ORG", "Acme")])

    def test_one_label_gets_only_its_type(self):
        status, spans = self.post({"inputs": "Maria at Acme", "parameters": {"labels": ["ORG"]}})
        self.assertEqual((status, [s["word"] for s in spans]), (200, ["Acme"]))

    def test_a_label_the_model_does_not_know_or_an_empty_list_is_refused(self):
        for params in ({"labels": ["MISC"]}, {"labels": []}, {"labels": "PER"}, ["PER"]):
            with self.subTest(params=params):
                self.assertEqual(self.post({"inputs": "x", "parameters": params})[0], 400)
        self.assertEqual(self.asked, [])

    def test_info_lists_the_labels_and_health_answers(self):
        with urllib.request.urlopen(self.url + "info", timeout=5) as r:
            self.assertEqual(json.load(r)["labels"], ["LOC", "ORG", "PER"])
        with urllib.request.urlopen(self.url + "health", timeout=5) as r:
            self.assertEqual((r.status, json.load(r)), (200, {"status": "ok"}))


if __name__ == "__main__":
    unittest.main()
