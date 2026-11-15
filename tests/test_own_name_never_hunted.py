"""#53: the plugin's own name, stored as a value by a version before the fix, is no longer hunted after the next
session start (hooks/dispatch.py, in a child process with the temp home), and a prompt that types it is not
blocked for it."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import vault  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CLAUDE = {"cwd": "/tmp"}


def run_hook(event: str, payload: dict) -> dict:
    r = subprocess.run([sys.executable, str(ROOT / "hooks" / "dispatch.py"), event], input=json.dumps(payload),
                       capture_output=True, text=True, timeout=60, env=dict(os.environ))
    assert r.returncode == 0, r.stderr[-500:]
    return json.loads(r.stdout) if r.stdout.strip() else {}


class OwnNameTests(unittest.TestCase):
    def test_the_session_start_stops_the_hunt_for_the_own_name(self):
        own = vault.OWN_NAME
        entry = vault.Vault().put(own, "SECRET", "manual", session="O1")
        v = vault.Vault()
        v._index["entries"][entry.key].pop("weak", None)      # as a version before #53 stored it
        v._save_index()
        self.assertIn(entry.key, vault.Vault().live_fingerprints().values())
        run_hook("session-start", {"hook_event_name": "SessionStart", "session_id": "O1", **CLAUDE})
        self.assertNotIn(entry.key, vault.Vault().live_fingerprints().values())
        out = run_hook("user-prompt", {"hook_event_name": "UserPromptSubmit", "session_id": "O1", "source": "user",
                                       "transcript_path": "", **CLAUDE, "prompt": f"how does {own} store a value?"})
        self.assertNotEqual(out.get("decision"), "block", out)


if __name__ == "__main__":
    unittest.main()
