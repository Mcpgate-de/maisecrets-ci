"""The remote detector in the plugin (maisecrets/remote_layer.py, setting remote_detector): the real PostToolUse hook
against a fake service. It adds a name to a tool result, stores it so its placeholder resolves, never hunts it in
another text, asks once per hook call, leaves a typed prompt alone, and answers byte for byte as without it when the
service is off, down or not allowed."""
from __future__ import annotations

import json
import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import HOME, Vault, is_weak, load_config  # noqa: E402
from test_remote_detector import NAME, PHONE, Service  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

CONFIG = Path(HOME, "config.json")
OTHER = "Bartholomew Quist"
KEY = re.compile(r"NAME_c\d+")     # the key of a stored name; the brackets are left out on purpose


def tearDownModule():  # noqa: N802 - unittest hook
    _reset()
    _hygiene.assert_pristine()


def _reset(**user) -> None:
    CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True, **user}))
    for f in ("index.json", "vault.json", "audit.log", "events.log"):
        try:
            os.unlink(Path(HOME, f))
        except FileNotFoundError:
            pass
    hooks._live_cache.clear()


def _reset_keep_store(**user) -> None:
    CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True, **user}))
    hooks._live_cache.clear()


def _post(response) -> dict:
    return hooks.post_tool({"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "S1", **CLAUDE,
                            "tool_input": {"command": "cat notes.txt"}, "tool_response": response})


def _out(answer: dict):
    return answer.get("hookSpecificOutput", {}).get("updatedToolOutput")


class RemoteLayerTests(unittest.TestCase):
    def setUp(self):
        self.svc = Service("hf", answer=self.names)
        self.addCleanup(self.svc.close)

    @staticmethod
    def names(text: str):
        out = []
        for n in (NAME, OTHER):
            at = text.find(n)
            while at >= 0:
                out.append({"entity_group": "PER", "start": at, "end": at + len(n), "score": 0.9})
                at = text.find(n, at + 1)
        return out

    def on(self, **extra) -> None:
        _reset(remote_detector={"url": self.svc.url, "format": "hf", "model": "fake@1", **extra})

    def test_a_name_in_a_tool_result_is_masked_and_its_placeholder_resolves(self):
        _reset()
        self.assertEqual(_post({"stdout": f"please ask {NAME} today\n", "stderr": ""}), {},
                         "premise: the rules alone leave the name")
        self.on()
        out = _out(_post({"stdout": f"please ask {NAME} today\n", "stderr": ""}))
        self.assertNotIn(NAME, json.dumps(out))
        key = KEY.search(out["stdout"]).group(0)
        v = Vault(load_config())
        self.assertEqual(v.get(key, "S1"), (NAME, "ok"), "stored: the agent can write the name back")
        self.assertTrue(v._index["entries"][key]["weak"], "never hunted in other texts")

    def test_a_name_the_model_found_is_not_hunted_in_a_later_result(self):
        self.on()
        _post({"stdout": f"please ask {NAME} today\n", "stderr": ""})
        _reset_keep_store(remote_detector={})
        self.assertEqual(_post({"stdout": f"and ask {NAME} again\n", "stderr": ""}), {}, "no service now: no mask")

    def test_one_request_per_hook_call_and_each_string_gets_its_own_spans(self):
        self.on()
        out = _out(_post({"stdout": f"ask {NAME} first", "stderr": f"then {OTHER} later", "note": f"phone {PHONE}"}))
        self.assertEqual(len(self.svc.received), 1)
        self.assertNotIn(NAME, json.dumps(out))
        self.assertNotIn(OTHER, json.dumps(out))
        self.assertNotIn(PHONE, self.svc.received[0]["inputs"], "a finding of the rules goes out as filler")

    def test_a_dead_slow_or_refused_service_answers_as_without_it(self):
        _reset()
        response = {"stdout": f"ask {NAME}, call {PHONE}\n", "stderr": ""}
        baseline = _post(response)
        self.assertIn("PHONE", json.dumps(baseline), "premise: the rules mask the number")
        slow = Service("hf", answer=self.names, delay=1.0)
        self.addCleanup(slow.close)
        for name, conf in (("dead", {"url": "http://127.0.0.1:1/"}),
                           ("slow", {"url": slow.url, "timeout_ms": 100}),
                           ("not allowed", {"url": "http://10.0.0.5:9/"}),
                           ("a setting it cannot read", {"url": self.svc.url, "format": "xml"})):
            with self.subTest(name):
                _reset(remote_detector=conf)
                self.assertEqual(_post(response), baseline)
        self.assertEqual(self.svc.received, [], "the unreadable setting sent nothing")

    def test_only_a_service_on_this_computer_may_read_the_rules_findings(self):
        from maisecrets import remote_layer
        ner, _ = remote_layer.from_config({"remote_detector": {"url": self.svc.url, "mask": False}})
        self.assertFalse(ner.mask)
        ner, _ = remote_layer.from_config({"remote_detector": {"url": self.svc.url}})
        self.assertTrue(ner.mask, "the filler is the default")
        ner, _ = remote_layer.from_config({"remote_detector": {"url": "http://10.0.0.5:9/", "allow_network": True,
                                                              "mask": False}})
        self.assertTrue(ner.mask, "another host always gets the filler")
        self.on(mask=False)
        _post({"stdout": f"ask {NAME}, call {PHONE}\n", "stderr": ""})
        self.assertIn(PHONE, self.svc.received[0]["inputs"])

    def test_a_name_in_a_key_is_asked_in_the_same_request(self):
        self.on()
        out = _out(_post({"stdout": "ok", "stderr": "", "owners": {NAME: "lead"}}))
        self.assertEqual(len(self.svc.received), 1)
        self.assertNotIn(NAME, json.dumps(out))

    def test_a_stored_value_without_a_shape_goes_out_as_filler(self):
        self.on()
        stored = "plain" + "wordpass" + "2026"            # a value with no shape, stored by the person (put)
        Vault(load_config()).put(stored, "SECRET", "manual", session="S1")
        hooks._live_cache.clear()
        out = _out(_post({"stdout": f"ask {NAME}, the pass is {stored}\n", "stderr": ""}))
        sent = self.svc.received[0]["inputs"]
        self.assertNotIn(stored, sent)
        self.assertIn("_" * len(stored), sent)
        self.assertNotIn(stored, json.dumps(out), "premise: the hook masks it afterwards")

    def test_the_wait_is_capped_at_five_seconds(self):
        from maisecrets import remote_layer
        ner, _ = remote_layer.from_config({"remote_detector": {"url": self.svc.url, "timeout_ms": 3000000}})
        self.assertEqual(ner.timeout, 5.0)
        for bad in (10 ** 400, float("inf"), "300", True):
            ner, why = remote_layer.from_config({"remote_detector": {"url": self.svc.url, "timeout_ms": bad}})
            self.assertEqual((ner, why), (None, "timeout_ms is no number of milliseconds"))

    def test_off_sends_nothing_and_a_typed_prompt_is_not_sent(self):
        _reset()
        _post({"stdout": f"please ask {NAME} today\n", "stderr": ""})
        self.on()
        hooks.user_prompt({"hook_event_name": "UserPromptSubmit", "session_id": "S1", **CLAUDE,
                           "prompt": f"please write to {NAME}"})
        self.assertEqual(self.svc.received, [])


class WeakMarkTests(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_a_model_finding_is_weak_until_a_rule_finds_the_value_too(self):
        self.assertTrue(is_weak("remote:hf", NAME, tool=True))
        v = Vault(load_config())
        (e,) = v.put_many([(NAME, "NAME", "remote:hf")], session="S1", tool=True)
        self.assertTrue(v._index["entries"][e.key]["weak"])
        v.put_many([(NAME, "NAME", "remote:presidio")], session="S1", tool=True)
        self.assertTrue(v._index["entries"][e.key]["weak"], "a second model finding is no evidence")
        v.put_many([(NAME, "NAME", "name-after-label")], session="S1", tool=True)
        self.assertFalse(v._index["entries"][e.key]["weak"], "a rule's finding is")

    def test_a_hunted_value_stays_hunted_when_the_model_finds_it(self):
        v = Vault(load_config())
        (e,) = v.put_many([(OTHER, "NAME", "name-after-label")], session="S1", tool=True)
        v.put_many([(OTHER, "NAME", "remote:hf")], session="S1", tool=True)
        self.assertFalse(v._index["entries"][e.key]["weak"])


if __name__ == "__main__":
    unittest.main()
