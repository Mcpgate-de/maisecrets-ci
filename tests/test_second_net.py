"""The second net of the mod in Python (maisecrets/second_net.py): the marker of the tool-result hooks, and
mask_result's note on names that the name service did not check.

Run: python3 -m unittest tests.test_second_net -v
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one

from maisecrets import second_net  # noqa: E402


NONCE = "0123456789abcdef" * 2


def setUpModule():
    # no band of a result that another test module checked in this process (#105, B11)
    from maisecrets import remote_layer
    remote_layer.NER_DOWN["band"] = None


class MarkTests(unittest.TestCase):
    def test_the_marker_carries_the_nonce_and_for_masked_the_hash_of_the_output(self):
        self.assertEqual(second_net.mark({}, "post-tool", NONCE)["hookSpecificOutput"],
                         {"hookEventName": "PostToolUse", "additionalContext": f"[maisecrets: result checked {NONCE}]"})
        out = {"stdout": "a", "stderr": ""}
        masked = second_net.mark({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": out,
                                                         "additionalContext": "note"}}, "post-tool", NONCE)
        self.assertEqual(masked["hookSpecificOutput"]["additionalContext"],
                         f"note\n\n[maisecrets: result masked {NONCE} {second_net.output_hash(out)}]")
        self.assertEqual(second_net.mark({"decision": "block", "reason": "r"}, "post-tool", NONCE),
                         {"decision": "block", "reason": "r"}, "a Codex answer stays as it is")
        self.assertEqual(second_net.mark({}, "pre-tool", NONCE), {}, "only the tool-result events")

    def test_the_marker_of_a_result_with_a_rest_carries_the_share_and_the_mode_only(self):
        # #105, B11: the mod's band reads them; a failed call never carries a rest of an earlier result
        from maisecrets import remote_layer
        with mock.patch.dict(remote_layer.NER_DOWN, {"band": (70, "rules")}):
            self.assertEqual(second_net.mark({}, "post-tool", NONCE)["hookSpecificOutput"]["additionalContext"],
                             f"[maisecrets: result checked {NONCE} rest 70 rules]")
            out = {"stdout": "a"}
            masked = second_net.mark({"hookSpecificOutput": {"updatedToolOutput": out}}, "post-tool", NONCE)
            self.assertEqual(masked["hookSpecificOutput"]["additionalContext"],
                             f"[maisecrets: result masked {NONCE} {second_net.output_hash(out)} rest 70 rules]")
            self.assertEqual(second_net.mark({}, "post-tool-failure", NONCE)["hookSpecificOutput"]["additionalContext"],
                             f"[maisecrets: result checked {NONCE}]")
        with mock.patch.dict(remote_layer.NER_DOWN, {"band": None}):
            self.assertEqual(second_net.mark({}, "post-tool", NONCE)["hookSpecificOutput"]["additionalContext"],
                             f"[maisecrets: result checked {NONCE}]")

    def test_the_hash_takes_the_strings_and_keys_in_a_fixed_order(self):
        # the mod computes the same (tests/mod.test.ts hashOf): keys sorted, each before its value, NUL between
        import hashlib
        want = hashlib.sha256("a\0x\0b\0y".encode()).hexdigest()[:16]
        self.assertEqual(second_net.output_hash({"b": "y", "a": ["x", 1, None]}), want)
        self.assertNotEqual(second_net.output_hash("x"), second_net.output_hash("y"))


class MarkAnswersTests(unittest.TestCase):
    def hooks(self):
        class Hooks:
            seen: list = []

            @staticmethod
            def _out(obj):
                Hooks.seen.append(obj)

            @staticmethod
            def post_tool(payload):
                Hooks._out({})
                return {}
        return Hooks

    def test_only_the_mod_switches_the_marker_on_with_a_nonce_of_its_form(self):
        for value in ("", "1", "zz" * 16):
            with self.subTest(value=value), mock.patch.dict(os.environ, {second_net.ENV: value}):
                h = self.hooks()
                second_net.mark_answers(h, "post-tool")
                h.post_tool({"tool_response": "x"})
                self.assertEqual(h.seen, [{}])

    def test_a_payload_with_no_result_gets_no_marker(self):
        with mock.patch.dict(os.environ, {second_net.ENV: NONCE}):
            empty = self.hooks()
            second_net.mark_answers(empty, "post-tool")
            empty.post_tool({"session_id": "S1"})
            self.assertEqual(empty.seen, [{}], "no tool_response: nothing was scanned")
            full = self.hooks()
            second_net.mark_answers(full, "post-tool")
            full.post_tool({"tool_response": "x"})
            self.assertEqual(full.seen[0]["hookSpecificOutput"]["additionalContext"],
                             f"[maisecrets: result checked {NONCE}]")


class MaskResultTests(unittest.TestCase):
    def test_the_note_on_unchecked_names_goes_with_the_result(self):
        def add_note(payload, result, codex, load_config):
            return {**result, "hookSpecificOutput": {"hookEventName": "PostToolUse",
                                                     "additionalContext": "names: not checked"}}
        from maisecrets import remote_layer
        # a band of an earlier result in this process is not this result's (#105, B11)
        with mock.patch("maisecrets.tool_withhold.with_unchecked_names", add_note), \
                mock.patch.dict(remote_layer.NER_DOWN, {"band": (49, "rules")}):
            out = second_net.mask_result({"session_id": "S1", "tool_name": "Bash", "texts": ["nothing here"]})
        self.assertEqual(out, {"texts": ["nothing here"], "changed": False, "note": "names: not checked"})

    def test_a_result_the_name_setting_withholds_is_withheld(self):
        def withhold(payload, result, codex, load_config):
            return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": "[withheld]"}}
        with mock.patch("maisecrets.tool_withhold.with_unchecked_names", withhold):
            out = second_net.mask_result({"session_id": "S1", "tool_name": "Bash", "texts": ["a", "b"]})
        self.assertEqual(out, {"withheld": True})


if __name__ == "__main__":
    unittest.main()
