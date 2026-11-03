"""The Sensitive References a session received (maisecrets/sref_notes.py): a reference resolves only in the session
that saw it in a result of a user-scope server, never when the model sent it itself, and not after NOTE_TTL."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import sref_notes  # noqa: E402
from maisecrets.vault import HOME  # noqa: E402

OPEN, CLOSE = chr(0x27E6), chr(0x27E7)
RID = "k3JxQw8RtYz2" + "LmNp4VbC6dF"


def ref(kind: str = "email", rid: str = RID, display: str = "") -> str:
    return OPEN + f"sref:{kind}:{rid}" + (":" + display if display else "") + CLOSE


def result(text: str, session: str = "S1", source: str = "user", sent: str = "") -> dict:
    return {"session_id": session, "tool_name": "mcp__gw__gitlab_read_actions",
            "mcp_server": {"name": "gw", "source": source},
            "tool_input": {"query": sent}, "tool_response": {"content": [{"type": "text", "text": text}]}}


class SrefNoteTests(unittest.TestCase):
    def setUp(self) -> None:
        HOME.mkdir(parents=True, exist_ok=True)
        (HOME / "config.json").write_text('{"backend": "jsonfile", "allow_plaintext_store": true}')
        shutil.rmtree(HOME / "sref", ignore_errors=True)
        self.profile = Path(tempfile.mkdtemp(prefix="sref-notes-profile-"))
        env = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.profile)})
        env.start()
        self.addCleanup(env.stop)
        (self.profile / ".claude.json").write_text(json.dumps(
            {"mcpServers": {"gw": {"type": "http", "url": "https://gw.example/mcp"}}}))

    def test_a_reference_of_a_result_resolves_in_its_session_only(self):
        self.assertEqual(sref_notes.note_result(result("mail: " + ref(display="ja•••@x.de"))), 1)
        # by kind and id: the display part may change or go
        for form in (ref(), ref(display="other")):
            with self.subTest(form=form[-12:]):
                self.assertEqual(sref_notes.noted([form], "S1"), {form: ("https://gw.example", "https://gw.example/mcp")})
        self.assertEqual(sref_notes.noted([ref()], "S2"), {})
        self.assertEqual(sref_notes.noted_elsewhere([ref()], "S2"), [ref()])
        self.assertEqual(sref_notes.noted_elsewhere([ref(rid="z" * 24)], "S2"), [], "never noted: plain text")

    def test_a_reference_the_model_sent_is_never_noted_then_or_later(self):
        self.assertEqual(sref_notes.note_result(result("found " + ref(), sent=ref())), 0)
        self.assertEqual(sref_notes.note_result(result("notes: " + ref())), 0, "a gateway that shows it again")
        self.assertEqual(sref_notes.noted([ref()], "S1"), {})

    def test_only_a_server_of_the_user_configuration_counts(self):
        for source in ("project", "plugin", ""):
            with self.subTest(source=source):
                self.assertEqual(sref_notes.note_result(result(ref(), source=source)), 0)
        other = dict(result(ref()), tool_name="Bash")
        self.assertEqual(sref_notes.note_result(other), 0)

    def test_a_note_older_than_a_day_resolves_no_more(self):
        sref_notes.note_result(result(ref()))
        with mock.patch.object(time, "time", return_value=time.time() + sref_notes.NOTE_TTL + 1):
            self.assertEqual(sref_notes.noted([ref()], "S1"), {})


if __name__ == "__main__":
    unittest.main()
