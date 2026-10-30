"""A message to another Claude session (SendMessage) goes out with placeholders instead of the values that the
receiving session's prompt hook would block (maisecrets/hooks.py, _pre_send_message). Before, the receiver dropped
the message and the sender never learned it (2026-10-30). The real client is measured in the harness scenario
send_message_masks_a_value.

Run: python3 -m unittest tests.test_send_message -v
"""
from __future__ import annotations

import json
import os
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import HOME  # noqa: E402

OPEN = "⟦"
RNG = random.Random(31)


def token() -> str:
    """A GitLab token shape, made at run time."""
    return "glp" + "at-" + "".join(RNG.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789")
                                   for _ in range(20))


def send(tool_input) -> dict:
    return hooks.pre_tool({"tool_name": "SendMessage", "tool_input": tool_input, "session_id": "S1",
                           "hook_event_name": "PreToolUse"})


def _clean() -> None:
    """No stored value and no cache of live values left for the next module (one that switches the store to the
    keychain would look its key up for them)."""
    for name in ("index.json", "vault.json", "audit.log", "events.log", "hooks.log"):
        Path(HOME, name).unlink(missing_ok=True)
    hooks._live_cache.clear()


def tearDownModule():  # noqa: N802 - unittest hook
    _clean()
    import _hygiene
    _hygiene.assert_pristine()


class SendMessageTests(unittest.TestCase):
    def setUp(self):
        Path(HOME, "config.json").write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True}))
        _clean()

    def tearDown(self):
        _clean()

    def test_a_value_in_the_message_goes_out_as_a_placeholder(self):
        value = token()
        out = send({"to": "peer", "message": f"status: the token is {value}", "summary": "status"})
        hso = out["hookSpecificOutput"]
        self.assertNotIn(value, hso["updatedInput"]["message"])
        self.assertIn(OPEN + "SECRET_c", hso["updatedInput"]["message"])
        self.assertEqual(hso["updatedInput"]["to"], "peer")
        self.assertIn("placeholders", hso["additionalContext"])
        self.assertNotIn("permissionDecision", hso)    # the normal permission rules apply

    def test_the_value_is_stored_and_the_receiving_hook_lets_the_message_through(self):
        import re
        from maisecrets.vault import Vault
        value = token()
        out = send({"to": "peer", "message": f"status: the token is {value}"})
        rewritten = out["hookSpecificOutput"]["updatedInput"]["message"]
        key = re.search(OPEN + r"(SECRET_c\d+)", rewritten).group(1)
        self.assertEqual(value, Vault().get(key, human=True)[0])
        hooks._live_cache.clear()
        wrapped = ('<cross-session-message from="uds:/tmp/cc-socks/1.sock" from-name="sender" from-mode="bypass">\n'
                   f"{rewritten}\n</cross-session-message>")
        received = hooks.user_prompt({"prompt": wrapped, "session_id": "S2", "prompt_id": "p"})
        self.assertNotEqual("block", received.get("decision"), received)
        # the same message with the value in it is what the receiver blocked before
        raw = wrapped.replace(rewritten, f"status: the token is {value}")
        blocked = hooks.user_prompt({"prompt": raw, "session_id": "S2", "prompt_id": "p"})
        self.assertEqual("block", blocked.get("decision"))

    def test_every_text_field_is_masked(self):
        value = token()
        out = send({"to": "peer", "message": f"a {value}", "content": f"a {value}", "summary": f"about {value}"})
        new = out["hookSpecificOutput"]["updatedInput"]
        for field in ("message", "content", "summary"):
            with self.subTest(field=field):
                self.assertNotIn(value, new[field])

    def test_a_message_without_a_value_is_left_alone(self):
        for tool_input in ({"to": "peer", "message": "the build is green"}, {"to": "peer"},
                           {"to": "peer", "message": 3}, "not a dict"):
            with self.subTest(tool_input=str(tool_input)[:20]):
                self.assertEqual(send(tool_input), {})


if __name__ == "__main__":
    unittest.main()
