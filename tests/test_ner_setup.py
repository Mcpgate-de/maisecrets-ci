"""/maisecrets:ner (maisecrets/ner_setup.py): one source of names for tool results, set only by a prompt the person
typed. local is the service on this computer, url a service of the team, off the rules alone; the tuning keys of
the setting stay when the source changes. /maisecrets:ner and /maisecrets:status say whether the source answers.

Run: python3 -m unittest tests.test_ner_setup -v
"""
from __future__ import annotations

import io
import json
import os
import sys
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import cli, events, hooks, ner_setup, settings  # noqa: E402
from maisecrets.vault import HOME, load_config  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE, CODEX  # noqa: E402

TEST_CONFIG = {"backend": "jsonfile", "allow_plaintext_store": True}
CONFIG = Path(HOME, "config.json")


def tearDownModule():  # noqa: N802 - unittest hook
    _reset()
    _hygiene.assert_pristine()


def _reset(**user) -> None:
    CONFIG.write_text(json.dumps({**TEST_CONFIG, **user}))
    try:
        os.unlink(events.EVENTS)
    except FileNotFoundError:
        pass


def _prompt(text: str, client: dict = CLAUDE, **extra) -> dict:
    return hooks.user_prompt({"prompt": text, "session_id": "S1", **client, **extra})


def _conf() -> dict:
    return load_config().get("remote_detector")


def _weakened() -> list:
    try:
        return [json.loads(x) for x in events.EVENTS.read_text().splitlines() if "weakened" in x]
    except FileNotFoundError:
        return []


class Service:
    """A fake service: /health and /info, or nothing (down)."""

    def __init__(self, info=None):
        info = info or {"model": "d3 int8", "labels": ["DATE", "LOC", "ORG", "PER"]}

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - http.server API
                doc = {"/health": {"status": "ok"}, "/info": info}.get(self.path)
                body = json.dumps(doc or {}).encode()
                self.send_response(200 if doc else 404)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.server = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class SetTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_local_sets_the_service_on_this_computer_and_on_is_the_same(self):
        for word in ("local", "on", "LOCAL"):
            with self.subTest(word=word):
                _reset()
                out = _prompt(f"/maisecrets:ner {word}")
                self.assertEqual(_conf(), {"url": "http://127.0.0.1:8765/", "format": "hf"})
                self.assertIn("127.0.0.1:8765", json.dumps(out))

    def test_codex_takes_the_sentence_alone_as_the_prompt(self):
        out = _prompt("maisecrets: ner local", CODEX)
        self.assertEqual(out.get("decision"), "block")          # the prompt does not reach the model
        self.assertEqual(_conf()["url"], "http://127.0.0.1:8765/")

    def test_a_url_on_the_network_allows_the_network_and_says_where_the_text_goes(self):
        out = _prompt("/maisecrets:ner url http://10.0.0.5:8765/")
        self.assertEqual(_conf(), {"url": "http://10.0.0.5:8765/", "format": "hf", "allow_network": True})
        self.assertIn("private network", json.dumps(out))

    def test_off_keeps_the_tuning_keys_and_a_new_source_replaces_the_old_one(self):
        _reset(remote_detector={"url": "http://10.0.0.5:8765/", "allow_network": True, "model": "m",
                                "timeout_ms": 500, "classes": {"PER": "NAME"}})
        _prompt("/maisecrets:ner local")
        self.assertEqual(_conf(), {"timeout_ms": 500, "classes": {"PER": "NAME"}, "url": "http://127.0.0.1:8765/",
                                   "format": "hf"})
        _prompt("/maisecrets:ner off")
        self.assertEqual(_conf(), {"timeout_ms": 500, "classes": {"PER": "NAME"}})

    def test_an_address_it_cannot_use_changes_nothing(self):
        for url in ("ftp://h/", "http://user:pw@h/", "h:8765", "http://h:99999/", "http://h/?a=1"):
            with self.subTest(url=url):
                _reset()
                out = _prompt(f"/maisecrets:ner url {url}")
                self.assertEqual(_conf(), {})
                self.assertIn("Nothing was changed", json.dumps(out))

    def test_only_a_typed_prompt_changes_the_source(self):
        _prompt("/maisecrets:ner url http://10.0.0.5:8765/", {**CLAUDE, "source": "schedule_wakeup"})
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}):
            _prompt("/maisecrets:ner local")
        self.assertEqual(_conf(), {})

    def test_a_tool_call_that_carries_the_sentence_is_refused(self):
        out = hooks.pre_tool({"tool_name": "Bash", "session_id": "S1", **CLAUDE,
                              "tool_input": {"command": "claude -p '/maisecrets:ner url http://10.0.0.5:8765/'"}})
        self.assertEqual(json.dumps(out).count('"deny"'), 1, out)

    def test_a_sentence_inside_a_longer_prompt_is_text(self):
        self.assertIsNone(settings.parse_prompt("please run /maisecrets:ner local for me"))

    def test_turning_it_off_or_a_service_on_the_network_is_recorded_as_a_weakening(self):
        _prompt("/maisecrets:ner local")
        self.assertEqual(_weakened(), [])
        _prompt("/maisecrets:ner url http://10.0.0.5:8765/")
        _prompt("/maisecrets:ner off")
        self.assertEqual(len(_weakened()), 2)


class ReportTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def run_ner(self, *args) -> tuple:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.cmd_ner(list(args))
        return code, buf.getvalue()

    def test_off_says_how_to_turn_it_on(self):
        code, out = self.run_ner()
        self.assertEqual(code, 0)
        self.assertIn("off", out)
        self.assertIn("/maisecrets:ner local", out)

    def test_a_service_that_answers_names_its_model_and_types(self):
        svc = Service()
        self.addCleanup(svc.close)
        _reset(remote_detector={"url": svc.url, "format": "hf"})
        code, out = self.run_ner()
        self.assertEqual(code, 0)
        self.assertIn("model d3 int8, types DATE, LOC, ORG, PER", out)

    def test_the_local_service_down_gives_the_start_command_when_docker_is_there(self):
        _reset(remote_detector={"url": ner_setup.LOCAL_URL, "format": "hf"})
        with mock.patch.object(ner_setup, "probe", return_value=(False, "the service: does not answer")), \
                mock.patch.object(ner_setup.shutil, "which", side_effect=lambda n: "/x/podman" if n == "podman"
                                  else None):
            code, out = self.run_ner()
        self.assertEqual(code, 3)
        self.assertIn("start: podman run -d --name ner --restart unless-stopped -p 127.0.0.1:8765:8765 mcpgate/ner",
                      out)
        self.assertIn("rules mask tool results alone", out)

    def test_without_docker_it_names_the_three_ways(self):
        _reset(remote_detector={"url": ner_setup.LOCAL_URL, "format": "hf"})
        with mock.patch.object(ner_setup, "probe", return_value=(False, "the service: does not answer")), \
                mock.patch.object(ner_setup.shutil, "which", return_value=None):
            code, out = self.run_ner()
        self.assertEqual(code, 1)
        self.assertNotIn("start:", out)
        for words in ("Neither docker nor podman", "/maisecrets:ner url URL", "/maisecrets:ner off"):
            self.assertIn(words, out)

    def test_a_service_on_the_network_without_allow_network_is_not_asked(self):
        ok, line = ner_setup.probe({"url": "http://10.0.0.5:8765/"})
        self.assertFalse(ok)
        self.assertIn("not asked", line)

    def test_status_names_the_source_and_whether_it_answers(self):
        svc = Service()
        self.addCleanup(svc.close)
        _reset(remote_detector={"url": svc.url, "format": "hf"})
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli.cmd_status([])
        self.assertIn(f"names from a service: {svc.url} (on this computer)", buf.getvalue())
        self.assertIn("the service: answers", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
