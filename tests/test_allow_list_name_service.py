"""The allow list holds for a name-service finding (remote_layer.py, Detector.findings_with) as it holds for a rule's
finding: one exact value, never a part of a longer one. Before this, a value on the list was still masked whenever the
service named it again (test_an_exact_value_… and test_the_library_detector_… were red on 0.9.12).

A placeholder here is built from OPEN and CLOSE, so the file holds none. Synthetic names only.
Run: python3 -m unittest tests.test_allow_list_name_service -v
"""
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

from maisecrets import detect, hooks  # noqa: E402
from maisecrets.detection import NO_REFERENCES, Active, Detector, Host  # noqa: E402
from maisecrets.detection.core import Sources  # noqa: E402
from maisecrets.placeholder import OPEN  # noqa: E402
from maisecrets.user_rules import ALLOW_FILE  # noqa: E402
from maisecrets.vault import HOME, Vault, load_config  # noqa: E402
from test_remote_detector import NAME, Service  # noqa: E402
import _hygiene  # noqa: E402
from _hygiene import CLAUDE  # noqa: E402

CONFIG = Path(HOME, "config.json")
LONGER = NAME + " Quist"               # a longer value that holds the allowed one
KEY = re.compile(r"NAME_c\d+")
FILES = ("index.json", "vault.json", "audit.log", "events.log", "ner-rate.json", "allow.txt", "allowed.json",
         ".not-a-secret-pending.json", ".weakenings-shown")
SESSION = "S1"


def _reset(**user) -> None:
    CONFIG.write_text(json.dumps({"backend": "jsonfile", "allow_plaintext_store": True, **user}))
    for f in FILES:
        try:
            os.unlink(Path(HOME, f))
        except FileNotFoundError:
            pass
    hooks._live_cache.clear()
    detect.reset_rules()


def tearDownModule():  # noqa: N802 - unittest hook
    _reset()
    _hygiene.assert_pristine()


def _post(stdout: str, client=CLAUDE) -> dict:
    hooks._live_cache.clear()
    return hooks.post_tool({"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": SESSION, **client,
                            "tool_input": {"command": "cat notes.txt"},
                            "tool_response": {"stdout": stdout, "stderr": ""}})


def _out(answer: dict) -> str:
    return answer["hookSpecificOutput"]["updatedToolOutput"]["stdout"]


def _prompt(prompt: str, source: str | None = "user", client=CLAUDE, **extra) -> dict:
    hooks._live_cache.clear()
    payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "session_id": SESSION,
               "transcript_path": "", **client, **extra}
    if source is not None:
        payload["source"] = source
    return hooks.user_prompt(payload)


def _allow_text() -> str:
    try:
        return ALLOW_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _entries() -> dict:
    return Vault(load_config())._index["entries"]


class _ServiceBase(unittest.TestCase):
    """A fake name service on this computer that names NAME (and LONGER, where it stands)."""

    def setUp(self):
        _reset()
        self.addCleanup(_reset)
        _hygiene.patch(self, hooks, "_clipboard", lambda t: True)
        self.svc = Service("hf", answer=self.names)
        self.addCleanup(self.svc.close)

    @staticmethod
    def names(text: str):
        out, at = [], 0
        while True:
            at = text.find(NAME, at)
            if at < 0:
                return out
            end = at + len(LONGER) if text.startswith(LONGER, at) else at + len(NAME)
            out.append({"entity_group": "PER", "start": at, "end": end, "score": 0.9})
            at = end

    def on(self) -> None:
        cfg = json.loads(CONFIG.read_text())
        cfg["remote_detector"] = {"url": self.svc.url, "format": "hf", "model": "fake@1"}
        CONFIG.write_text(json.dumps(cfg))
        hooks._live_cache.clear()

    def allow(self, *lines: str) -> None:
        ALLOW_FILE.write_text("".join(f"{x}\n" for x in lines), encoding="utf-8")
        detect.reset_rules()


# ------------------------------------------------------------ the gap: the allow list and the name service --
class AllowListHoldsForTheNameServiceTests(_ServiceBase):
    def test_premise_the_service_masks_the_name(self):
        self.on()
        self.assertNotIn(NAME, _out(_post(f"please ask {NAME} today\n")))

    def test_an_exact_value_on_the_allow_list_is_not_masked_when_the_service_names_it(self):
        self.allow(NAME)
        self.on()
        self.assertEqual(_post(f"please ask {NAME} today\n"), {})
        self.assertTrue(self.svc.received, "the service was asked")

    def test_a_longer_value_that_holds_the_allowed_one_stays_masked(self):
        self.allow(NAME)
        self.on()
        out = _out(_post(f"please ask {LONGER} today\n"))
        self.assertNotIn(NAME, out)
        self.assertRegex(out, re.escape(OPEN) + KEY.pattern)

    def test_an_empty_or_comment_only_allow_list_changes_nothing(self):
        self.on()
        before = _out(_post(f"please ask {NAME} today\n"))
        for text in ("", "# only a comment\n\n"):
            _reset()
            self.on()
            ALLOW_FILE.write_text(text, encoding="utf-8")
            detect.reset_rules()
            self.assertEqual(_out(_post(f"please ask {NAME} today\n")), before)

    def test_the_library_detector_holds_the_allow_list_for_a_model_finding(self):
        class Allowed(Sources):
            def allow_list(self):
                return frozenset({NAME}), frozenset()

        class Remote:
            format = "hf"

            def ask(self, text, _occupied, _deadline):
                spans = [(m.start(), m.end(), "NAME", 0.9) for m in re.finditer(re.escape(LONGER) + "|"
                                                                               + re.escape(NAME), text)]
                return spans, "ok"

        det = Detector(regions=Active(regions=["generic"], languages=["en"], source="test"), sources=Allowed(),
                       references=NO_REFERENCES, host=Host(user="", year=2026))
        found = det.findings_with(f"ask {NAME} and {LONGER}", channel="tool", remote=Remote()).findings
        self.assertEqual([m.value for m in found if m.kind.startswith("remote:")], [LONGER])


if __name__ == "__main__":
    unittest.main()
