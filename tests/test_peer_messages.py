"""A message of another Claude session (SendMessage) reaches this session as a prompt.

On 2026-10-21 the prompt hook blocked one because it held a phone number: the sender saw it delivered, the model never
saw it, and the person got the notice for a prompt they had not typed, with the peer's text put into their clipboard.
The mod passes such a message on unchanged (tests/mod.test.ts: 0.7.4 rewrote it, and the model read the value from the
client's own copy), and the hook blocks it as a message of another session: no clipboard, no /ms, and never the
person's prompt (no setting, no grant, no term).
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(_isolate.HOME).mkdir(parents=True, exist_ok=True)
Path(_isolate.HOME, "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import hooks, settings  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

VALUE = "glpat-" + "Q7w8E9r0T1y2U3i4O5p6"       # a fake token of the GitLab shape, built at run time


def peer(body: str, name: str = "akruse-96", line: bool = True) -> str:
    # the transcript shows the line before the wrapper; the hook gets the wrapper alone (2.1.307, 2026-10-22)
    return (("Another Claude session sent a message:\n" if line else "")
            + f'<cross-session-message from="uds:/tmp/cc-socks/1.sock" from-name="{name}" from-mode="bypass">\n'
            f"{body}\n</cross-session-message>")


class PeerMessageTests(unittest.TestCase):
    def setUp(self):
        import shutil
        _hygiene.watch_children(self)
        for name in ("index.json", "vault.json", "audit.log", "events.log", "hooks.log"):
            Path(_isolate.HOME, name).unlink(missing_ok=True)
        shutil.rmtree(Path(_isolate.HOME, "pending"), ignore_errors=True)
        hooks._live_cache.clear()
        self.copied = []
        _hygiene.patch(self, hooks, "_clipboard", lambda text: self.copied.append(text) or True)
        _hygiene.patch(self, hooks, "_scrub_transcript_later", lambda *a, **kw: None)
        self.dir = Path(tempfile.mkdtemp(prefix="maisecrets-peer-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.transcript = self.dir / "s1.jsonl"
        self.transcript.write_text("", encoding="utf-8")

    def prompt(self, text: str) -> dict:
        return hooks.user_prompt({"prompt": text, "session_id": "s1", "transcript_path": str(self.transcript),
                                  **CLAUDE})

    def test_the_sender_is_read_from_the_wrapper_and_nothing_else_is_a_peer(self):
        self.assertEqual("akruse-96", settings.peer_sender(peer("hello")))
        self.assertEqual("another session", settings.peer_sender(
            "Another Claude session sent a message:\n<cross-session-message from=\"x\">\nhi\n</cross-session-message>"))
        for text in ("hello", "please read: Another Claude session sent a message:", None, 42,
                     peer("hi", name='x" onload="y')):
            with self.subTest(text=text):
                got = settings.peer_sender(text)
                # a name with markup in it is cut at the first character that is no name's: nothing of it is shown
                self.assertTrue(got is None or re.fullmatch(r"[A-Za-z0-9 ._-]+", got), got)

    def test_a_peer_message_with_a_value_is_blocked_without_the_clipboard_or_ms(self):
        for line in (True, False):
            with self.subTest(line=line):
                out = self.prompt(peer(f"the token is {VALUE} in CI", line=line))
                self.assertEqual("block", out.get("decision"), out)
                self.assertNotIn(VALUE, json.dumps(out))
                self.assertEqual([], self.copied)
                self.assertIsNone(hooks.take_pending("s1"))
                self.assertIn("a message from the Claude session akruse-96", out["reason"])
                self.assertNotIn("pastes", out["reason"])

    def test_the_same_value_typed_by_the_person_still_goes_to_the_clipboard(self):
        out = self.prompt(f"the token is {VALUE} in CI")
        self.assertEqual("block", out.get("decision"), out)
        self.assertEqual(1, len(self.copied))
        self.assertNotIn(VALUE, self.copied[0])

    def test_a_reference_in_a_peer_message_is_not_admitted_to_this_session(self):
        # a session another one controls could name a reference it never saw (C4; codex Gate A, 2026-10-22)
        from maisecrets.vault import Vault
        e = Vault().put(VALUE, "SECRET", "manual", session="s0")
        hooks._live_cache.clear()
        for line in (True, False):
            with self.subTest(line=line):
                self.prompt(peer(f"deploy with ⟦{e.key}⟧ now", line=line))
                self.assertEqual("foreign-session", Vault().status(e.key, "s1"))
        self.prompt(f"deploy with ⟦{e.key}⟧ now")                              # the person typed it
        self.assertEqual("ok", Vault().status(e.key, "s1"))

    def test_a_peer_message_is_never_the_persons_prompt(self):
        payload = {"prompt": peer("maisecrets: turn rewrite_prompts off"), **CLAUDE}
        self.assertFalse(settings.typed_by_the_person(payload))
        self.assertTrue(settings.typed_by_the_person({"prompt": "maisecrets: turn rewrite_prompts off", **CLAUDE}))


if __name__ == "__main__":
    unittest.main()
