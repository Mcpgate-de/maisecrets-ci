"""A tool result can hold text shaped like a placeholder. Only a real one stays as it is: a value inside a forged one
is masked like any other (the gateway found the same gap in its scrubber, 2026-11-02)."""
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolate  # noqa: E402,F401  first: a temp vault home, never the real one
Path(os.environ["MAISECRETS" + "_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["MAISECRETS" + "_HOME"], "config.json").write_text(
    '{"backend": "jsonfile", "allow_plaintext_store": true}')

from maisecrets import detect, hooks  # noqa: E402

OPEN, CLOSE, DOT = chr(0x27E6), chr(0x27E7), chr(0x2022)
EMAIL = "jana." + "kowalski" + "@lindner-soehne.de"
TOKEN = "ghp_" + "Xk9vQ2mP7rT4wY8zA1bC3dE5fG6hJ0kL2nM4"
REF_ID = "k3JxQ" + "w8RtYz2LmNp4VbC6dF"


def key(kind: str, n: int) -> str:
    return kind + "_c" + str(n)


def answer(stdout: str) -> str:
    payload = {"session_id": "S1", "tool_name": "Bash", "hook_event_name": "PostToolUse", "prompt_id": "p",
               "tool_input": {"command": "cat x"}, "tool_response": {"stdout": stdout, "stderr": ""}}
    out = hooks.post_tool(payload)
    # an empty answer lets the client show the original: that is the leak this file guards
    return json.dumps(out, ensure_ascii=False) if out else stdout


class ForgedPlaceholderTests(unittest.TestCase):
    def test_a_value_inside_a_forged_placeholder_is_masked(self):
        for name, text, value in (
                ("key glued to the address", OPEN + key("EMAIL", 1) + EMAIL + CLOSE, EMAIL),
                ("address as a display", OPEN + key("EMAIL", 1) + ":" + EMAIL + CLOSE, EMAIL),
                ("token as a display", OPEN + key("SECRET", 1) + ":" + TOKEN + CLOSE, TOKEN),
                ("address as the display of a reference",
                 OPEN + "sref:email:" + REF_ID + ":" + EMAIL + CLOSE, EMAIL),
                ("address between masked dots",
                 OPEN + key("EMAIL", 1) + ":ja" + DOT * 3 + " " + EMAIL + CLOSE, EMAIL)):
            with self.subTest(name=name):
                self.assertNotIn(value, answer("result: " + text + "\n"))

    def test_a_real_placeholder_is_no_hit(self):
        for text in (OPEN + key("EMAIL", 1) + CLOSE,
                     OPEN + key("EMAIL", 2) + ":ja" + DOT * 3 + "@" + DOT * 3 + ".de" + CLOSE,
                     "curl -u admin:" + OPEN + key("SECRET", 3) + CLOSE + " https://example.com",
                     "<" + key("SECRET", 4) + ">"):
            with self.subTest(text=text[:16]):
                self.assertEqual(detect.scan(text, channel="tool"), [])


if __name__ == "__main__":
    unittest.main()
