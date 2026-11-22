"""The result of an Agent or Task call keeps the ids and the output file of the client (#31).

Claude Code renders the pointer of a background agent ("agentId: …", "output_file: …") from the result the PostToolUse
hook returns, and keeps that result in the transcript. When the hook masked the agent id, the model could not continue
the agent with SendMessage, and the report of the agent could not prove itself by its task id (C19). The report text
and every other field are masked as before.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
CONFIG = '{"backend": "jsonfile", "allow_plaintext_store": true}'
Path(_isolate.HOME).mkdir(parents=True, exist_ok=True)
Path(_isolate.HOME, "config.json").write_text(CONFIG)

from maisecrets import hooks  # noqa: E402
from maisecrets.vault import Vault  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

VALUE = "glpat-" + "Q7w8E9r0T1y2U3i4O5p6"       # a fake token of the GitLab shape, built at run time
AID = "a4361971f5e1ea583"                      # the shape of a Claude Code 2.1.330 agent id: "a" and 16 hex
OUT = f"/private/tmp/claude-501/-tmp-proj/4afa3163-abcb-4b90-b82a-4b3adeabd421/tasks/{AID}.output"


def _empty_store() -> None:
    for name in ("index.json", "vault.json", "audit.log", "events.log", "hooks.log"):
        Path(_isolate.HOME, name).unlink(missing_ok=True)
    hooks._live_cache.clear()


def pointer(**extra) -> dict:
    """The result of a background Agent call, with the keys of the 2.1.330 payload (harness/golden)."""
    return {"isAsync": True, "status": "async_launched", "agentId": AID, "description": "check the token",
            "resolvedModel": "m", "prompt": "check the token", "outputFile": OUT, "canReadOutputFile": True,
            "canContinueAgent": True, **extra}


class AgentPointerTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):  # noqa: N802 - unittest hook
        _hygiene.assert_children_ended()

    def setUp(self):
        _hygiene.watch_children(self)
        _empty_store()
        self.addCleanup(_empty_store)

    def post(self, response: dict, tool: str = "Agent") -> dict:
        """The result the model sees: the hook's replacement, or the result as it was."""
        out = hooks.post_tool({"tool_name": tool, "session_id": "s1", **CLAUDE, "tool_input": {"prompt": "x"},
                               "tool_response": response})
        return (out or {}).get("hookSpecificOutput", {}).get("updatedToolOutput", response)

    def store(self, value: str) -> None:
        Vault().put(value, "SECRET", "manual", session="s1")
        hooks._live_cache.clear()

    def test_the_agent_id_and_the_output_file_keep_their_text_and_the_task_text_is_masked(self):
        self.store(AID)
        self.store(OUT)
        seen = self.post(pointer(prompt=f"check the token {VALUE}"))
        self.assertEqual(seen["agentId"], AID)
        self.assertEqual(seen["outputFile"], OUT)
        self.assertNotIn(VALUE, json.dumps(seen))
        self.assertIn("⟦", seen["prompt"])

    def test_the_task_tool_and_a_task_id_keep_their_text(self):
        self.store(AID)
        seen = self.post({"status": "remote_launched", "taskId": AID, "outputFile": OUT, "sessionUrl": "u"},
                         tool="Task")
        self.assertEqual((seen["taskId"], seen["outputFile"]), (AID, OUT))

    def test_a_foreground_report_is_masked_and_keeps_its_agent_id(self):
        self.store(AID)
        done = {"status": "completed", "agentId": AID, "content": [{"type": "text", "text": f"the token is {VALUE}"}],
                "totalTokens": 1, "totalToolUseCount": 0, "totalDurationMs": 1}
        seen = self.post(done)
        self.assertEqual(seen["agentId"], AID)
        self.assertNotIn(VALUE, json.dumps(seen))

    def test_sendmessage_keeps_only_its_resumed_agent_id(self):
        self.store(AID)
        seen = self.post({"success": True, "message": f"sent, token {VALUE}", "resumedAgentId": AID, "agentId": AID},
                         tool="SendMessage")
        self.assertEqual(seen["resumedAgentId"], AID)
        self.assertNotEqual(seen["agentId"], AID, "only resumedAgentId of a SendMessage result is the client's id")
        self.assertNotIn(VALUE, json.dumps(seen))

    def test_the_folder_of_the_output_file_is_masked_and_its_name_is_kept(self):
        from maisecrets import terms
        name = "Quarz" + "feldmann"
        self.assertTrue(terms.add_typed(name)[0])
        self.addCleanup(lambda: terms.PERSONAL.unlink(missing_ok=True))
        self.store(AID)
        hidden = "\U000E0041\U000E0042\U000E0043\U000E0044"      # Unicode tag characters: they spell ABCD unseen
        out = f"/private/tmp/claude-501/-Users-{name}-proj/4afa{hidden}3163/tasks/{AID}.output"
        seen = self.post(pointer(outputFile=out))["outputFile"]
        self.assertTrue(seen.endswith(f"/tasks/{AID}.output"), seen)
        self.assertNotIn(name, seen)
        self.assertNotIn("\U000E0041", seen)
        self.assertEqual(self.post(pointer(outputFile=out))["agentId"], AID)

    def test_a_value_in_an_id_field_of_another_shape_or_tool_is_still_masked(self):
        self.store(AID)
        # an id with a space is no id of the client; an output file that does not end with the id is no pointer
        for response in (pointer(agentId=f"{AID} {VALUE}"), pointer(outputFile=f"/tmp/{VALUE}.output")):
            self.assertNotIn(VALUE, json.dumps(self.post(response)))
        # another tool's result with the same key
        self.assertNotEqual(self.post({"agentId": AID}, tool="WebFetch")["agentId"], AID)
        # a relative output file is masked
        self.store("tasks/" + AID + ".output")
        self.assertNotEqual(self.post(pointer(outputFile=f"tasks/{AID}.output"))["outputFile"], f"tasks/{AID}.output")


if __name__ == "__main__":
    unittest.main()
